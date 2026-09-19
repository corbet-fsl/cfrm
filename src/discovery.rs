//! Authenticated, bounded discovery requests. Storage contains ciphertext only.
use crate::{
    admission::{self, AdmissionGrant, AdmissionTrust, DeviceAuthorization, MAX_INTEGER},
    Error,
};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileEnvelope {
    pub version: u32,
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub profile_epoch: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub profile_digest: String,
    pub discriminators: BTreeMap<String, u32>,
    pub ciphertext: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CachedProfile {
    pub admission: AdmissionGrant,
    pub authorization: DeviceAuthorization,
    pub envelope: ProfileEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveryLease {
    pub lease_id: String,
    pub sequence: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum DiscoveryOperation {
    Publish {
        publication: CachedProfile,
        lease: DiscoveryLease,
    },
    Heartbeat {
        lease: DiscoveryLease,
    },
    Disconnect {
        #[serde(rename = "leaseId")]
        lease_id: String,
        sequence: u64,
    },
    Query {
        filters: BTreeMap<String, u32>,
        limit: usize,
        after: Option<String>,
    },
    Fetch {
        #[serde(rename = "memberId")]
        member_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveryRequest {
    pub version: u32,
    pub admission: AdmissionGrant,
    pub authorization: DeviceAuthorization,
    pub session_id: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub operation: DiscoveryOperation,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoverySummary {
    pub member_id: String,
    pub chat_public_key: String,
    pub profile_digest: String,
    pub sequence: u64,
    pub discriminators: BTreeMap<String, u32>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum DiscoveryResponse {
    Updated,
    Page {
        entries: Vec<DiscoverySummary>,
        #[serde(rename = "nextCursor")]
        next_cursor: Option<String>,
    },
    Profile {
        publication: Option<CachedProfile>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum DiscriminatorDomain {
    Range { minimum: u32, maximum: u32 },
    Enum { values: Vec<u32> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveryLimits {
    pub max_request_bytes: usize,
    pub max_record_bytes: usize,
    pub max_response_bytes: usize,
    pub max_ciphertext_bytes: usize,
    pub max_discriminator_bytes: usize,
    pub max_profile_ttl_seconds: u64,
    pub max_lease_seconds: u64,
    pub max_request_seconds: u64,
    pub max_members: usize,
    pub max_devices_per_member: usize,
    pub max_replay_entries: usize,
    pub max_results: usize,
    pub max_scan: usize,
    pub publish_limit: u64,
    pub publish_window_seconds: u64,
    pub discriminator_limit: u64,
    pub discriminator_window_seconds: u64,
    pub read_limit: u64,
    pub read_window_seconds: u64,
    pub registry: BTreeMap<String, DiscriminatorDomain>,
}

/// Only the cryptographic service can construct this capability. Storage is a
/// trusted implementation boundary, not an independently exposed HTTP endpoint.
#[derive(Clone, Debug)]
pub struct VerifiedDiscoveryRequest {
    pub(crate) trust_digest: String,
    pub(crate) community_id: String,
    pub(crate) member_id: String,
    pub(crate) chat_public_key: String,
    pub(crate) session_id: String,
    pub(crate) request_id: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
    pub(crate) operation: DiscoveryOperation,
}

impl VerifiedDiscoveryRequest {
    pub fn trust_digest(&self) -> &str {
        &self.trust_digest
    }
    pub fn community_id(&self) -> &str {
        &self.community_id
    }
    pub fn member_id(&self) -> &str {
        &self.member_id
    }
    pub fn chat_public_key(&self) -> &str {
        &self.chat_public_key
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn operation(&self) -> &DiscoveryOperation {
        &self.operation
    }
}

/// Execute validation, replay consumption, quotas and the operation atomically.
/// Do not retain a request, query, fetch target, or response after the call.
/// Replay markers must be opaque hashes, without their operation or target.
pub trait DiscoveryStore: Send + Sync {
    fn execute(
        &self,
        request: &VerifiedDiscoveryRequest,
        limits: &DiscoveryLimits,
        now: u64,
    ) -> Result<DiscoveryResponse, Error>;
}

pub struct DiscoveryService<S> {
    trust: AdmissionTrust,
    limits: DiscoveryLimits,
    store: S,
}

fn positive(value: u64) -> bool {
    value > 0 && value <= MAX_INTEGER
}

fn field_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl DiscoveryLimits {
    pub fn validate(&self) -> Result<(), Error> {
        for value in [
            self.max_request_bytes,
            self.max_record_bytes,
            self.max_response_bytes,
            self.max_ciphertext_bytes,
            self.max_discriminator_bytes,
            self.max_members,
            self.max_devices_per_member,
            self.max_replay_entries,
            self.max_results,
            self.max_scan,
        ] {
            if value == 0 || value as u128 > MAX_INTEGER as u128 {
                return Err(Error::InvalidInput);
            }
        }
        for value in [
            self.max_profile_ttl_seconds,
            self.max_lease_seconds,
            self.max_request_seconds,
            self.publish_limit,
            self.publish_window_seconds,
            self.discriminator_limit,
            self.discriminator_window_seconds,
            self.read_limit,
            self.read_window_seconds,
        ] {
            if !positive(value) {
                return Err(Error::InvalidInput);
            }
        }
        if self.max_ciphertext_bytes < 16
            || self.max_ciphertext_bytes > 16 * 1024 * 1024
            || self.max_record_bytes > self.max_request_bytes
            || self.max_record_bytes > self.max_response_bytes
            || self.max_results > self.max_scan
            || self.max_scan == usize::MAX
            || self.registry.len() > 32
            || self.max_discriminator_bytes > 4096
        {
            return Err(Error::InvalidInput);
        }
        for (name, domain) in &self.registry {
            if !field_name(name) {
                return Err(Error::InvalidInput);
            }
            match domain {
                DiscriminatorDomain::Range { minimum, maximum } if minimum <= maximum => (),
                DiscriminatorDomain::Enum { values }
                    if !values.is_empty()
                        && values.len() <= 64
                        && values.windows(2).all(|pair| pair[0] < pair[1]) =>
                {
                    ()
                }
                _ => return Err(Error::InvalidInput),
            }
        }
        Ok(())
    }

    pub fn validate_discriminators(&self, fields: &BTreeMap<String, u32>) -> Result<(), Error> {
        if serde_json::to_vec(fields)
            .map_err(|_| Error::InvalidInput)?
            .len()
            > self.max_discriminator_bytes
        {
            return Err(Error::Capacity);
        }
        for (name, value) in fields {
            let valid = match self.registry.get(name) {
                Some(DiscriminatorDomain::Range { minimum, maximum }) => {
                    value >= minimum && value <= maximum
                }
                Some(DiscriminatorDomain::Enum { values }) => values.binary_search(value).is_ok(),
                None => false,
            };
            if !valid {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }
}

fn profile_shape(profile: &ProfileEnvelope) -> Result<(), Error> {
    if profile.version != 1
        || !admission::scope(&profile.community_id)
        || !positive(profile.sequence)
        || !positive(profile.issued_at)
        || profile.expires_at <= profile.issued_at
        || profile.expires_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    for value in [
        &profile.member_id,
        &profile.chat_public_key,
        &profile.profile_epoch,
    ] {
        admission::decode::<32>(value)?;
    }
    admission::decode::<12>(&profile.nonce)?;
    if profile.discriminators.keys().any(|key| !field_name(key)) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// SHA-256 of ciphertext (including the GCM tag), never of public profile text.
pub fn ciphertext_digest(ciphertext: &[u8]) -> String {
    admission::digest(ciphertext)
}

/// Reusable owner signature. Sorted discriminator pairs are part of the digest
/// binding, so an index cannot mix filters from one version with another blob.
pub fn profile_signing_bytes(profile: &ProfileEnvelope) -> Result<Vec<u8>, Error> {
    profile_shape(profile)?;
    admission::decode::<32>(&profile.profile_digest)?;
    let pairs: Vec<_> = profile.discriminators.iter().collect();
    serde_json::to_vec(&serde_json::json!([
        "cfrm.cached-profile.v1",
        profile.community_id,
        profile.member_id,
        profile.chat_public_key,
        profile.profile_epoch,
        profile.sequence,
        profile.issued_at,
        profile.expires_at,
        profile.nonce,
        profile.profile_digest,
        pairs
    ]))
    .map_err(|_| Error::InvalidInput)
}

/// AES-256-GCM authenticated metadata. The ciphertext digest is deliberately
/// omitted because including it here would make encryption circular.
pub fn profile_aad_bytes(profile: &ProfileEnvelope) -> Result<Vec<u8>, Error> {
    profile_shape(profile)?;
    let pairs: Vec<_> = profile.discriminators.iter().collect();
    serde_json::to_vec(&serde_json::json!([
        "cfrm.cached-profile.aad.v1",
        profile.community_id,
        profile.member_id,
        profile.chat_public_key,
        profile.profile_epoch,
        profile.sequence,
        profile.issued_at,
        profile.expires_at,
        profile.nonce,
        pairs
    ]))
    .map_err(|_| Error::InvalidInput)
}

pub fn verify_cached_profile(
    publication: &CachedProfile,
    trust: &AdmissionTrust,
    limits: &DiscoveryLimits,
    now: u64,
) -> Result<(), Error> {
    let profile = &publication.envelope;
    let bytes = profile_signing_bytes(profile)?;
    admission::verify_admission(&publication.admission, trust, now)?;
    admission::verify_device_authorization(
        &publication.authorization,
        &publication.admission,
        now,
    )?;
    if profile.community_id != publication.admission.community_id
        || profile.member_id != publication.admission.member_id
        || profile.chat_public_key != publication.admission.chat_public_key
    {
        return Err(Error::Admission);
    }
    if now < profile.issued_at
        || now >= profile.expires_at
        || profile.issued_at < publication.admission.issued_at
        || profile.issued_at < publication.authorization.issued_at
        || profile.expires_at > publication.admission.expires_at
        || profile.expires_at > publication.authorization.expires_at
        || profile.expires_at - profile.issued_at > limits.max_profile_ttl_seconds
    {
        return Err(Error::Expired);
    }
    limits.validate_discriminators(&profile.discriminators)?;
    let encoded_limit = limits
        .max_ciphertext_bytes
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .map(|n| n / 3)
        .ok_or(Error::Capacity)?;
    if profile.ciphertext.len() > encoded_limit
        || serde_json::to_vec(publication)
            .map_err(|_| Error::InvalidInput)?
            .len()
            > limits.max_record_bytes
    {
        return Err(Error::Capacity);
    }
    let ciphertext = BASE64URL_NOPAD
        .decode(profile.ciphertext.as_bytes())
        .map_err(|_| Error::InvalidInput)?;
    if ciphertext.len() < 16
        || ciphertext.len() > limits.max_ciphertext_bytes
        || BASE64URL_NOPAD.encode(&ciphertext) != profile.ciphertext
        || ciphertext_digest(&ciphertext) != profile.profile_digest
    {
        return Err(Error::InvalidInput);
    }
    admission::signature(&profile.chat_public_key, &bytes, &profile.signature)
}

/// Fixed-order outer array; the operation object and all nested objects use
/// recursively lexicographically sorted keys (serde_json's default map order).
pub fn request_signing_bytes(request: &DiscoveryRequest) -> Result<Vec<u8>, Error> {
    if request.version != 1
        || !positive(request.issued_at)
        || request.expires_at <= request.issued_at
        || request.expires_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    for value in [
        &request.session_id,
        &request.request_id,
        &request.admission.member_id,
        &request.admission.chat_public_key,
    ] {
        admission::decode::<32>(value)?;
    }
    if !admission::scope(&request.admission.community_id) {
        return Err(Error::InvalidInput);
    }
    serde_json::to_vec(&serde_json::json!([
        "cfrm.discovery-request.v1",
        request.admission.community_id,
        request.admission.policy_digest,
        request.admission.member_id,
        request.admission.chat_public_key,
        request.session_id,
        request.request_id,
        request.issued_at,
        request.expires_at,
        serde_json::to_value(&request.operation).map_err(|_| Error::InvalidInput)?
    ]))
    .map_err(|_| Error::InvalidInput)
}

impl<S: DiscoveryStore> DiscoveryService<S> {
    pub fn new(trust: AdmissionTrust, limits: DiscoveryLimits, store: S) -> Result<Self, Error> {
        limits.validate()?;
        if !admission::scope(&trust.community_id) {
            return Err(Error::InvalidInput);
        }
        admission::decode::<32>(&trust.policy_digest)?;
        let issuer = ed25519_dalek::VerifyingKey::from_bytes(&trust.issuer_public_key)
            .map_err(|_| Error::Admission)?;
        if issuer.is_weak() {
            return Err(Error::Admission);
        }
        Ok(Self {
            trust,
            limits,
            store,
        })
    }

    pub fn limits(&self) -> &DiscoveryLimits {
        &self.limits
    }

    pub fn execute_bytes(&self, input: &[u8], now: u64) -> Result<DiscoveryResponse, Error> {
        if input.len() > self.limits.max_request_bytes {
            return Err(Error::Capacity);
        }
        let request: DiscoveryRequest =
            serde_json::from_slice(input).map_err(|_| Error::InvalidInput)?;
        self.execute(&request, now)
    }

    pub fn execute(
        &self,
        request: &DiscoveryRequest,
        now: u64,
    ) -> Result<DiscoveryResponse, Error> {
        if !positive(now) {
            return Err(Error::ClockRollback);
        }
        if serde_json::to_vec(request)
            .map_err(|_| Error::InvalidInput)?
            .len()
            > self.limits.max_request_bytes
        {
            return Err(Error::Capacity);
        }
        let bytes = request_signing_bytes(request)?;
        admission::verify_admission(&request.admission, &self.trust, now)?;
        admission::verify_device_authorization(&request.authorization, &request.admission, now)?;
        if now < request.issued_at
            || now >= request.expires_at
            || request.issued_at < request.admission.issued_at
            || request.issued_at < request.authorization.issued_at
            || request.expires_at - request.issued_at > self.limits.max_request_seconds
            || request.expires_at > request.admission.expires_at
            || request.expires_at > request.authorization.expires_at
        {
            return Err(Error::Expired);
        }
        admission::signature(
            &request.admission.chat_public_key,
            &bytes,
            &request.signature,
        )?;
        match &request.operation {
            DiscoveryOperation::Publish { publication, lease } => {
                if publication.admission != request.admission
                    || publication.authorization != request.authorization
                {
                    return Err(Error::Admission);
                }
                verify_cached_profile(publication, &self.trust, &self.limits, now)?;
                self.verify_lease(lease, request, now)?;
            }
            DiscoveryOperation::Heartbeat { lease } => self.verify_lease(lease, request, now)?,
            DiscoveryOperation::Disconnect { lease_id, sequence } => {
                admission::decode::<32>(lease_id)?;
                if lease_id != &request.session_id || !positive(*sequence) {
                    return Err(Error::InvalidInput);
                }
            }
            DiscoveryOperation::Query {
                filters,
                limit,
                after,
            } => {
                self.limits.validate_discriminators(filters)?;
                if *limit == 0 || *limit > self.limits.max_results {
                    return Err(Error::Capacity);
                }
                if let Some(after) = after {
                    admission::decode::<32>(after)?;
                }
            }
            DiscoveryOperation::Fetch { member_id } => {
                admission::decode::<32>(member_id)?;
            }
        }
        let verified = VerifiedDiscoveryRequest {
            trust_digest: admission::digest(
                &serde_json::to_vec(&serde_json::json!([
                    "cfrm.discovery-trust.v1",
                    self.trust.community_id,
                    self.trust.policy_digest,
                    BASE64URL_NOPAD.encode(&self.trust.issuer_public_key)
                ]))
                .map_err(|_| Error::InvalidInput)?,
            ),
            community_id: request.admission.community_id.clone(),
            member_id: request.admission.member_id.clone(),
            chat_public_key: request.admission.chat_public_key.clone(),
            session_id: request.session_id.clone(),
            request_id: request.request_id.clone(),
            issued_at: request.issued_at,
            expires_at: request.expires_at,
            operation: request.operation.clone(),
        };
        let result = self.store.execute(&verified, &self.limits, now)?;
        if serde_json::to_vec(&result)
            .map_err(|_| Error::Storage)?
            .len()
            > self.limits.max_response_bytes
        {
            return Err(Error::Capacity);
        }
        Ok(result)
    }

    fn verify_lease(
        &self,
        lease: &DiscoveryLease,
        request: &DiscoveryRequest,
        now: u64,
    ) -> Result<(), Error> {
        admission::decode::<32>(&lease.lease_id)?;
        if lease.lease_id != request.session_id
            || !positive(lease.sequence)
            || !positive(lease.expires_at)
        {
            return Err(Error::InvalidInput);
        }
        if lease.expires_at <= now
            || lease.expires_at > request.admission.expires_at
            || lease.expires_at > request.authorization.expires_at
            || lease.expires_at.saturating_sub(request.issued_at) > self.limits.max_lease_seconds
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
}
