//! Blind resource tickets, independent of introduction and reciprocity budgets.
//! Issuance sees a permanent member and a blinded request. Redemption sees only
//! a bearer token and opaque challenge binding, never a reader/profile identity.
use crate::{
    admission::{decode, digest, MAX_INTEGER},
    permits::{Permit, PermitEpoch, RedemptionStamp, ISSUANCE_REQUEST_BYTES},
    Error,
};
use data_encoding::BASE64URL_NOPAD as B64;
use serde::{Deserialize, Serialize};

pub const KEY_ACCESS_EPOCH_PREFIX: &str = "cfrm.key-access.v1/";

pub fn validate_key_access_epoch(epoch: &PermitEpoch) -> Result<String, Error> {
    if !epoch.epoch_id.starts_with(KEY_ACCESS_EPOCH_PREFIX)
        || epoch.epoch_id.len() == KEY_ACCESS_EPOCH_PREFIX.len()
    {
        return Err(Error::PolicyMismatch);
    }
    epoch.context_id()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyAccessIssueRequest {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub context_id: String,
    pub request_id: String,
    pub blinded_request: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

/// The existing root-authorized device signs this exact domain-separated JSON.
pub fn key_access_issue_bytes(request: &KeyAccessIssueRequest) -> Result<Vec<u8>, Error> {
    if !crate::admission::scope(&request.community_id)
        || request.issued_at == 0
        || request.issued_at >= request.expires_at
        || request.expires_at > MAX_INTEGER
        || request.blinded_request.len() > ISSUANCE_REQUEST_BYTES * 2
    {
        return Err(Error::InvalidInput);
    }
    for value in [
        &request.member_id,
        &request.chat_public_key,
        &request.context_id,
        &request.request_id,
    ] {
        decode::<32>(value)?;
    }
    if decode::<32>(&request.request_id)? == [0; 32] {
        return Err(Error::InvalidInput);
    }
    let blinded = B64
        .decode(request.blinded_request.as_bytes())
        .map_err(|_| Error::InvalidInput)?;
    if blinded.len() != ISSUANCE_REQUEST_BYTES
        || B64.encode(&blinded) != request.blinded_request
        || blinded[..32] != decode::<32>(&request.context_id)?
    {
        return Err(Error::InvalidInput);
    }
    serde_json::to_vec(&serde_json::json!([
        "cfrm.key-access.issue.v1",
        request.community_id,
        request.member_id,
        request.chat_public_key,
        request.context_id,
        request.request_id,
        digest(&blinded),
        request.issued_at,
        request.expires_at
    ]))
    .map_err(|_| Error::InvalidInput)
}

pub fn key_access_commitment(
    epoch: &PermitEpoch,
    challenge_digest: &str,
    expires_at: u64,
) -> Result<String, Error> {
    let context = validate_key_access_epoch(epoch)?;
    if decode::<32>(challenge_digest)? == [0; 32]
        || expires_at <= epoch.valid_from
        || expires_at > epoch.expires_at
    {
        return Err(Error::InvalidInput);
    }
    Ok(digest(
        &serde_json::to_vec(&serde_json::json!([
            "cfrm.profile-key-ticket.v1",
            context,
            challenge_digest,
            expires_at
        ]))
        .map_err(|_| Error::InvalidInput)?,
    ))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyAccessRedemption {
    pub permit: Permit,
    pub challenge_digest: String,
    pub expires_at: u64,
    pub claim: String,
}

/// Verifies a shared redeemer's exact opaque binding. The holder additionally
/// consumes its local random challenge once before key release.
pub fn verify_key_access_stamp(
    epoch: &PermitEpoch,
    stamp: &RedemptionStamp,
    challenge_digest: &str,
    expires_at: u64,
    now: u64,
) -> Result<(), Error> {
    let context = validate_key_access_epoch(epoch)?;
    epoch.check_time(now, false)?;
    if now >= expires_at
        || stamp.context_id != context
        || stamp.expires_at != epoch.expires_at
        || stamp.commitment != key_access_commitment(epoch, challenge_digest, expires_at)?
    {
        return Err(Error::Admission);
    }
    crate::admission::signature(
        &epoch.redemption_public_key,
        &stamp.signing_bytes()?,
        &stamp.signature,
    )
}

#[cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
mod native {
    use super::*;
    use crate::{
        admission::{
            signature, verify_admission, verify_device_authorization, AdmissionGrant,
            AdmissionTrust, DeviceAuthorization,
        },
        allocation::{sql_integer, stored_integer},
        permit_issuer::{PermitIssuer, PermitRedeemer},
        permits::RedemptionRequest,
    };
    use ed25519_dalek::SigningKey;
    use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
    use std::{path::Path, time::Duration};

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct KeyAccessPolicy {
        pub maximum_per_member: u32,
        pub maximum_members: u32,
        pub max_authorization_seconds: u64,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    pub struct KeyAccessIssuance {
        pub context_id: String,
        pub request_id: String,
        pub blind_signature: Vec<u8>,
    }

    /// One shared durable quota store for every replica; no device-local quota.
    /// The RSA and redemption keys must be dedicated to this purpose/epoch.
    pub struct KeyAccessIssuer {
        connection: Connection,
        trust: AdmissionTrust,
        epoch: PermitEpoch,
        context: String,
        policy: KeyAccessPolicy,
        issuer: PermitIssuer,
    }

    impl KeyAccessIssuer {
        pub fn open(
            path: impl AsRef<Path>,
            trust: AdmissionTrust,
            epoch: PermitEpoch,
            policy: KeyAccessPolicy,
            private_der: &[u8],
        ) -> Result<Self, Error> {
            let context = validate_key_access_epoch(&epoch)?;
            if trust.community_id != epoch.community_id
                || policy.maximum_per_member == 0
                || policy.maximum_members == 0
                || policy.max_authorization_seconds == 0
                || policy.max_authorization_seconds > MAX_INTEGER
            {
                return Err(Error::InvalidInput);
            }
            decode::<32>(&trust.policy_digest)?;
            let issuer = PermitIssuer::from_pkcs1_der(&epoch, private_der)?;
            let mut connection = Connection::open(path)?;
            connection.busy_timeout(Duration::from_secs(5))?;
            connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
                CREATE TABLE IF NOT EXISTS cfrm_permit_epochs (context TEXT PRIMARY KEY,key_digest TEXT NOT NULL UNIQUE) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS cfrm_key_access_clock (singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor INTEGER NOT NULL);
                INSERT INTO cfrm_key_access_clock VALUES(1,0) ON CONFLICT DO NOTHING;
                CREATE TABLE IF NOT EXISTS cfrm_key_access_config (context TEXT PRIMARY KEY,config BLOB NOT NULL,expires_at INTEGER NOT NULL) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS cfrm_key_access_members (context TEXT NOT NULL,member TEXT NOT NULL,issued INTEGER NOT NULL,PRIMARY KEY(context,member)) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS cfrm_key_access_issues (context TEXT NOT NULL,member TEXT NOT NULL,request TEXT NOT NULL,digest TEXT NOT NULL,signature BLOB NOT NULL,PRIMARY KEY(context,member,request)) WITHOUT ROWID;")?;
            let config = serde_json::to_vec(&serde_json::json!({"epoch":epoch,"policy":policy,
                "admissionPolicy":trust.policy_digest,"issuerKey":trust.issuer_public_key}))
            .map_err(|_| Error::InvalidInput)?;
            let key_digest = digest(
                &B64.decode(epoch.public_key_der.as_bytes())
                    .map_err(|_| Error::InvalidInput)?,
            );
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let prior: Option<String> = transaction
                .query_row(
                    "SELECT context FROM cfrm_permit_epochs WHERE key_digest=?1",
                    [&key_digest],
                    |row| row.get(0),
                )
                .optional()?;
            if prior.as_ref().is_some_and(|value| value != &context) {
                return Err(Error::PolicyMismatch);
            }
            transaction.execute("INSERT INTO cfrm_permit_epochs(context,key_digest) VALUES(?1,?2) ON CONFLICT(context) DO NOTHING",params![context,key_digest])?;
            let previous: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT config FROM cfrm_key_access_config WHERE context=?1",
                    [&context],
                    |row| row.get(0),
                )
                .optional()?;
            if previous.as_ref().is_some_and(|value| value != &config) {
                return Err(Error::PolicyMismatch);
            }
            transaction.execute("INSERT INTO cfrm_key_access_config VALUES(?1,?2,?3) ON CONFLICT(context) DO NOTHING",params![context,config,sql_integer(epoch.expires_at)?])?;
            transaction.commit()?;
            Ok(Self {
                connection,
                trust,
                epoch,
                context,
                policy,
                issuer,
            })
        }

        pub fn issue(
            &mut self,
            grant: &AdmissionGrant,
            authorization: &DeviceAuthorization,
            request: &KeyAccessIssueRequest,
            clock: impl Fn() -> u64,
        ) -> Result<KeyAccessIssuance, Error> {
            let signed = key_access_issue_bytes(request)?;
            if request.community_id != self.epoch.community_id
                || request.context_id != self.context
                || request.member_id != grant.member_id
            {
                return Err(Error::Admission);
            }
            signature(&request.chat_public_key, &signed, &request.signature)?;
            let mut signed_request = signed;
            signed_request.extend_from_slice(&decode::<64>(&request.signature)?);
            let request_digest = digest(&signed_request);
            let envelope = B64
                .decode(request.blinded_request.as_bytes())
                .map_err(|_| Error::InvalidInput)?;
            let before = clock();
            self.epoch.check_time(before, false)?;
            verify_admission(grant, &self.trust, before)?;
            verify_device_authorization(authorization, grant, before)?;
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = clock();
            let floor = stored_integer(transaction.query_row(
                "SELECT floor FROM cfrm_key_access_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )?)?;
            if now < before || now < floor || now > MAX_INTEGER {
                return Err(Error::ClockRollback);
            }
            self.epoch.check_time(now, false)?;
            verify_admission(grant, &self.trust, now)?;
            verify_device_authorization(authorization, grant, now)?;
            let prior:Option<(String,Vec<u8>)>=transaction.query_row("SELECT digest,signature FROM cfrm_key_access_issues WHERE context=?1 AND member=?2 AND request=?3",
                params![self.context,request.member_id,request.request_id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            let retry = prior.is_some();
            let blind_signature = if let Some((digest, signature)) = prior {
                if digest != request_digest {
                    return Err(Error::Replay);
                }
                if signature.len() != crate::permits::RSA_BYTES {
                    return Err(Error::Storage);
                }
                signature
            } else {
                self.epoch.check_time(now, true)?;
                if request.chat_public_key != grant.chat_public_key
                    || request.issued_at < self.epoch.valid_from
                    || request.issued_at > now
                    || request.expires_at <= now
                    || request.expires_at > self.epoch.issue_until
                    || request.expires_at - request.issued_at
                        > self.policy.max_authorization_seconds
                {
                    return Err(Error::Expired);
                }
                let count: Option<i64> = transaction
                    .query_row(
                        "SELECT issued FROM cfrm_key_access_members WHERE context=?1 AND member=?2",
                        params![self.context, request.member_id],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(count) = count {
                    if stored_integer(count)? >= u64::from(self.policy.maximum_per_member) {
                        return Err(Error::Capacity);
                    }
                } else {
                    let members: i64 = transaction.query_row(
                        "SELECT COUNT(*) FROM cfrm_key_access_members WHERE context=?1",
                        [&self.context],
                        |r| r.get(0),
                    )?;
                    if stored_integer(members)? >= u64::from(self.policy.maximum_members) {
                        return Err(Error::Capacity);
                    }
                }
                let signature = self.issuer.blind_sign(&envelope[32..])?;
                transaction.execute("INSERT INTO cfrm_key_access_members VALUES(?1,?2,1) ON CONFLICT(context,member) DO UPDATE SET issued=issued+1",params![self.context,request.member_id])?;
                transaction.execute(
                    "INSERT INTO cfrm_key_access_issues VALUES(?1,?2,?3,?4,?5)",
                    params![
                        self.context,
                        request.member_id,
                        request.request_id,
                        request_digest,
                        signature
                    ],
                )?;
                signature
            };
            let completed = clock();
            if completed < now || completed > MAX_INTEGER {
                return Err(Error::ClockRollback);
            }
            self.epoch.check_time(completed, false)?;
            if !retry {
                self.epoch.check_time(completed, true)?;
                if completed >= request.expires_at {
                    return Err(Error::Expired);
                }
            }
            verify_admission(grant, &self.trust, completed)?;
            verify_device_authorization(authorization, grant, completed)?;
            transaction.execute(
                "UPDATE cfrm_key_access_clock SET floor=?1 WHERE singleton=1",
                [sql_integer(completed)?],
            )?;
            transaction.commit()?;
            Ok(KeyAccessIssuance {
                context_id: self.context.clone(),
                request_id: request.request_id.clone(),
                blind_signature,
            })
        }

        /// Remove expired quota/retry data while preserving the key-reuse registry
        /// and monotonic clock. Expired epochs cannot issue or recover new tickets.
        pub fn prune_expired(&mut self, now: u64) -> Result<(), Error> {
            if now == 0 || now > MAX_INTEGER {
                return Err(Error::InvalidInput);
            }
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let floor = stored_integer(tx.query_row(
                "SELECT floor FROM cfrm_key_access_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )?)?;
            if now < floor {
                return Err(Error::ClockRollback);
            }
            for table in ["cfrm_key_access_issues", "cfrm_key_access_members"] {
                tx.execute(&format!("DELETE FROM {table} WHERE context IN (SELECT context FROM cfrm_key_access_config WHERE expires_at<=?1)"),[sql_integer(now)?])?;
            }
            tx.execute(
                "DELETE FROM cfrm_key_access_config WHERE expires_at<=?1",
                [sql_integer(now)?],
            )?;
            tx.execute(
                "UPDATE cfrm_key_access_clock SET floor=?1 WHERE singleton=1",
                [sql_integer(now)?],
            )?;
            tx.commit()?;
            Ok(())
        }
    }

    pub struct KeyAccessRedeemer {
        epoch: PermitEpoch,
        redeemer: PermitRedeemer,
    }
    impl KeyAccessRedeemer {
        pub fn open(
            path: impl AsRef<Path>,
            epoch: PermitEpoch,
            key: SigningKey,
        ) -> Result<Self, Error> {
            validate_key_access_epoch(&epoch)?;
            Ok(Self {
                redeemer: PermitRedeemer::open(path, &epoch, key)?,
                epoch,
            })
        }
        pub fn redeem(
            &mut self,
            request: &KeyAccessRedemption,
            clock: impl Fn() -> u64,
        ) -> Result<RedemptionStamp, Error> {
            let commitment =
                key_access_commitment(&self.epoch, &request.challenge_digest, request.expires_at)?;
            let now = clock();
            if now >= request.expires_at {
                return Err(Error::Expired);
            }
            if decode::<32>(&request.claim)? == [0; 32] {
                return Err(Error::InvalidInput);
            }
            let anonymous = RedemptionRequest {
                permit: request.permit.clone(),
                commitment,
                claim: request.claim.clone(),
            };
            // The final check occurs inside the redeemer transaction too: return an
            // out-of-epoch clock on an expired challenge so no late spend commits.
            let epoch_end = self.epoch.expires_at;
            self.redeemer.redeem(&anonymous, || {
                let at = clock();
                if at >= request.expires_at || at < now {
                    epoch_end
                } else {
                    at
                }
            })
        }
        pub fn prune_expired(&mut self, now: u64) -> Result<(), Error> {
            self.redeemer.prune_expired(now)
        }
    }
}

#[cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
pub use native::{KeyAccessIssuance, KeyAccessIssuer, KeyAccessPolicy, KeyAccessRedeemer};
