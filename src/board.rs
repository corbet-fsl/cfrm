use crate::{
    admission::{
        decode, signature, verify_admission, verify_device_authorization, AdmissionGrant,
        AdmissionTrust, DeviceAuthorization, MAX_INTEGER,
    },
    Error,
};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnionEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresenceUpdate {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub endpoint: Option<OnionEndpoint>,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct BoardLimits {
    pub max_members: usize,
    pub max_devices_per_member: usize,
    pub max_lease_seconds: u64,
    pub max_replay_entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePresence {
    pub admission: AdmissionGrant,
    pub authorization: DeviceAuthorization,
    pub update: PresenceUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPresence {
    pub member_id: String,
    pub devices: Vec<DevicePresence>,
}

impl OnionEndpoint {
    pub fn validate(&self) -> Result<(), Error> {
        if self.port == 0
            || self.host.len() != 62
            || !self.host.is_ascii()
            || !self.host.ends_with(".onion")
        {
            return Err(Error::InvalidInput);
        }
        let name = &self.host[..56];
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        let raw = BASE32_NOPAD
            .decode(name.to_uppercase().as_bytes())
            .map_err(|_| Error::InvalidInput)?;
        if raw.len() != 35 || raw[34] != 3 {
            return Err(Error::InvalidInput);
        }
        let mut digest = Sha3_256::new();
        digest.update(b".onion checksum");
        digest.update(&raw[..32]);
        digest.update([3]);
        if raw[32..34] != digest.finalize()[..2] {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

pub fn presence_bytes(update: &PresenceUpdate) -> Result<Vec<u8>, Error> {
    if update.sequence == 0
        || update.sequence > MAX_INTEGER
        || update.issued_at == 0
        || update.expires_at <= update.issued_at
        || update.expires_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    decode::<32>(&update.member_id)?;
    decode::<32>(&update.chat_public_key)?;
    if let Some(endpoint) = &update.endpoint {
        endpoint.validate()?;
    }
    serde_json::to_vec(&serde_json::json!([
        "cfrm.presence.v1",
        update.community_id,
        update.member_id,
        update.chat_public_key,
        update.sequence,
        update.issued_at,
        update.expires_at,
        update.endpoint
    ]))
    .map_err(|_| Error::InvalidInput)
}

/// Public rows remain independently verifiable even if the board is dishonest.
pub fn verify_presence(
    grant: &AdmissionGrant,
    authorization: &DeviceAuthorization,
    update: &PresenceUpdate,
    trust: &AdmissionTrust,
    max_lease_seconds: u64,
    now: u64,
) -> Result<(), Error> {
    verify_admission(grant, trust, now)?;
    verify_device_authorization(authorization, grant, now)?;
    if update.community_id != grant.community_id
        || update.member_id != grant.member_id
        || update.chat_public_key != grant.chat_public_key
    {
        return Err(Error::Admission);
    }
    let bytes = presence_bytes(update)?;
    if update.issued_at > now
        || now >= update.expires_at
        || update.expires_at > grant.expires_at
        || update.expires_at > authorization.expires_at
        || update.expires_at - update.issued_at > max_lease_seconds
    {
        return Err(Error::Expired);
    }
    signature(&update.chat_public_key, &bytes, &update.signature)
}

struct Entry {
    presence: DevicePresence,
    retain_until: u64,
}

/// Ephemeral directory only. Full snapshots have no recipient lookup argument.
/// Hosts authorize access and bound incoming bytes before deserializing requests.
pub struct MeetingBoard {
    trust: AdmissionTrust,
    limits: BoardLimits,
    entries: BTreeMap<(String, String), Entry>,
    last_now: u64,
}

impl MeetingBoard {
    pub fn new(trust: AdmissionTrust, limits: BoardLimits) -> Result<Self, Error> {
        if !crate::admission::scope(&trust.community_id)
            || decode::<32>(&trust.policy_digest).is_err()
            || limits.max_members == 0
            || limits.max_devices_per_member == 0
            || limits.max_lease_seconds == 0
            || limits.max_lease_seconds > MAX_INTEGER
            || limits.max_replay_entries < limits.max_devices_per_member
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            trust,
            limits,
            entries: BTreeMap::new(),
            last_now: 0,
        })
    }

    fn tick(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_now || now > MAX_INTEGER {
            return Err(Error::ClockRollback);
        }
        self.last_now = now;
        self.entries.retain(|_, entry| now < entry.retain_until);
        Ok(())
    }

    pub fn apply(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        update: &PresenceUpdate,
        now: u64,
    ) -> Result<(), Error> {
        verify_presence(
            grant,
            authorization,
            update,
            &self.trust,
            self.limits.max_lease_seconds,
            now,
        )?;
        self.tick(now)?;
        let key = (update.member_id.clone(), update.chat_public_key.clone());
        if let Some(entry) = self.entries.get(&key) {
            if update.sequence <= entry.presence.update.sequence {
                return if update == &entry.presence.update {
                    Ok(())
                } else {
                    Err(Error::Replay)
                };
            }
        } else if self.entries.len() >= self.limits.max_replay_entries {
            return Err(Error::Capacity);
        }
        if update.endpoint.is_some() {
            let mut online = BTreeMap::<&str, usize>::new();
            for (other, entry) in &self.entries {
                if other != &key
                    && entry.presence.update.endpoint.is_some()
                    && now < entry.presence.update.expires_at
                {
                    *online.entry(&other.0).or_default() += 1;
                }
            }
            if online.get(update.member_id.as_str()).copied().unwrap_or(0)
                >= self.limits.max_devices_per_member
                || (!online.contains_key(update.member_id.as_str())
                    && online.len() >= self.limits.max_members)
            {
                return Err(Error::Capacity);
            }
        }
        // A short disconnect lease must not erase the floor while an older,
        // longer signed online lease could still be replayed.
        let retain_until = now
            .checked_add(self.limits.max_lease_seconds)
            .ok_or(Error::InvalidInput)?;
        self.entries.insert(
            key,
            Entry {
                presence: DevicePresence {
                    admission: grant.clone(),
                    authorization: authorization.clone(),
                    update: update.clone(),
                },
                retain_until,
            },
        );
        Ok(())
    }

    pub fn snapshot(&mut self, now: u64) -> Result<Vec<MemberPresence>, Error> {
        self.tick(now)?;
        let mut members = BTreeMap::<String, Vec<DevicePresence>>::new();
        for ((member, _), entry) in &self.entries {
            if entry.presence.update.endpoint.is_some() && now < entry.presence.update.expires_at {
                members
                    .entry(member.clone())
                    .or_default()
                    .push(entry.presence.clone());
            }
        }
        Ok(members
            .into_iter()
            .map(|(member_id, devices)| MemberPresence { member_id, devices })
            .collect())
    }
}
