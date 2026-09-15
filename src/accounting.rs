//! Wire and verification boundary for the experimental private account relation.
//!
//! These types do not enable `AllocationLedger::resolve_private`. A host must
//! supply the pinned, complete proof verifier; signatures alone do not establish
//! a valid hidden account transition.

use crate::{
    admission::{decode, signature, MAX_INTEGER},
    Error,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// BN254 scalar modulus, big endian. Commitments must be canonical field values.
const MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

pub(crate) fn field(value: &[u8; 32], nonzero: bool) -> Result<(), Error> {
    if value >= &MODULUS || (nonzero && *value == [0; 32]) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub use crate::accounting_policy::AccountPolicy;

/// Complete public input. The role, peer, nonce, group, balances and map paths
/// belong exclusively to the private witness and cannot be added to this wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatement {
    pub protocol_version: u32,
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub policy_digest: [u8; 32],
    pub enrollment_root: [u8; 32],
    pub now: u64,
    pub valid_until: u64,
    pub genesis: bool,
    pub previous_version: u64,
    pub next_version: u64,
    pub previous_state: [u8; 32],
    pub next_state: [u8; 32],
    pub settlement_marker: [u8; 32],
    pub policy: AccountPolicy,
}

pub fn statement_bytes(value: &AccountStatement) -> Result<Vec<u8>, Error> {
    value.policy.validate()?;
    field(&value.enrollment_root, true)?;
    field(&value.previous_state, !value.genesis)?;
    field(&value.next_state, true)?;
    field(&value.settlement_marker, false)?;
    if value.protocol_version != 2
        || value.now < value.policy.policy_valid_from
        || value.now >= value.policy.policy_valid_until
        || value.valid_until != value.policy.proof_valid_until(value.now)?
        || value.next_version > MAX_INTEGER
        || (value.genesis
            && (value.previous_version != 0
                || value.next_version != 0
                || value.previous_state != [0; 32]
                || value.settlement_marker != [0; 32]))
        || (!value.genesis && value.previous_version.checked_add(1) != Some(value.next_version))
        || value.policy.digest(&value.community)? != value.policy_digest
    {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.statement.v2\0".to_vec();
    bytes.extend_from_slice(&value.protocol_version.to_be_bytes());
    for digest in [
        value.community,
        value.owner,
        value.policy_digest,
        value.enrollment_root,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.extend_from_slice(&value.now.to_be_bytes());
    bytes.extend_from_slice(&value.valid_until.to_be_bytes());
    bytes.push(u8::from(value.genesis));
    bytes.extend_from_slice(&value.previous_version.to_be_bytes());
    bytes.extend_from_slice(&value.next_version.to_be_bytes());
    for digest in [
        value.previous_state,
        value.next_state,
        value.settlement_marker,
    ] {
        bytes.extend_from_slice(&digest);
    }
    value.policy.append(&mut bytes);
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountProofScope {
    pub circuit_digest: [u8; 32],
    pub verifying_key_digest: [u8; 32],
}

/// Security-critical host dependency, configured independently of a request.
/// `verify` must verify the actual proof against *all* supplied public inputs
/// with the circuit and VK named by `scope`. There is no permissive default.
/// A mock implementation tests storage only, never cryptographic acceptance.
pub trait AccountProofVerifier {
    fn scope(&self) -> AccountProofScope;
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountRequest {
    pub statement: AccountStatement,
    pub request_id: [u8; 32],
    pub proof_scope: AccountProofScope,
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub proof: Vec<u8>,
    pub signature: String,
}

pub fn account_request_bytes(value: &AccountRequest) -> Result<Vec<u8>, Error> {
    if value.request_id == [0; 32]
        || value.issued_at != value.statement.now
        || value.issued_at >= value.expires_at
        || value.expires_at > MAX_INTEGER
        || value.expires_at > value.statement.valid_until
        || value.proof.is_empty()
    {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.request.v1\0".to_vec();
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(&value.proof_scope.circuit_digest);
    bytes.extend_from_slice(&value.proof_scope.verifying_key_digest);
    bytes.extend_from_slice(&decode::<32>(&value.chat_public_key)?);
    bytes.extend_from_slice(&value.issued_at.to_be_bytes());
    bytes.extend_from_slice(&value.expires_at.to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(statement_bytes(&value.statement)?));
    bytes.extend_from_slice(&Sha256::digest(&value.proof));
    Ok(bytes)
}

pub fn account_request_digest(value: &AccountRequest) -> Result<[u8; 32], Error> {
    let mut bytes = account_request_bytes(value)?;
    bytes.extend_from_slice(&decode::<64>(&value.signature)?);
    Ok(Sha256::digest(bytes).into())
}

/// The operator certifies acceptance of an opaque state. Peers additionally
/// need the private reservation proof and current cmsg consent before release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountAcceptance {
    pub statement: AccountStatement,
    pub request_id: [u8; 32],
    pub request_digest: [u8; 32],
    pub proof_scope: AccountProofScope,
    pub accepted_at: u64,
    pub signature: String,
}

pub fn account_acceptance_bytes(value: &AccountAcceptance) -> Result<Vec<u8>, Error> {
    if value.request_id == [0; 32]
        || value.accepted_at < value.statement.now
        || value.accepted_at >= value.statement.valid_until
        || value.accepted_at > MAX_INTEGER
    {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.acceptance.v1\0".to_vec();
    bytes.extend_from_slice(&value.request_id);
    bytes.extend_from_slice(&value.request_digest);
    bytes.extend_from_slice(&value.proof_scope.circuit_digest);
    bytes.extend_from_slice(&value.proof_scope.verifying_key_digest);
    bytes.extend_from_slice(&value.accepted_at.to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(statement_bytes(&value.statement)?));
    Ok(bytes)
}

pub fn verify_account_acceptance(
    value: &AccountAcceptance,
    operator_key: &[u8; 32],
) -> Result<(), Error> {
    signature(
        &data_encoding::BASE64URL_NOPAD.encode(operator_key),
        &account_acceptance_bytes(value)?,
        &value.signature,
    )
}

/// A fresh, authenticated request can recover an old accepted response after
/// its original device/request expires. A new device needs root authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatusRequest {
    pub community: [u8; 32],
    pub owner: [u8; 32],
    pub request_id: Option<[u8; 32]>,
    pub challenge: [u8; 32],
    pub chat_public_key: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

pub fn account_status_bytes(value: &AccountStatusRequest) -> Result<Vec<u8>, Error> {
    if value.challenge == [0; 32]
        || value.issued_at == 0
        || value.issued_at >= value.expires_at
        || value.expires_at > MAX_INTEGER
        || value.request_id == Some([0; 32])
    {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.status.v1\0".to_vec();
    bytes.extend_from_slice(&value.community);
    bytes.extend_from_slice(&value.owner);
    bytes.push(u8::from(value.request_id.is_some()));
    bytes.extend_from_slice(&value.request_id.unwrap_or([0; 32]));
    bytes.extend_from_slice(&value.challenge);
    bytes.extend_from_slice(&decode::<32>(&value.chat_public_key)?);
    bytes.extend_from_slice(&value.issued_at.to_be_bytes());
    bytes.extend_from_slice(&value.expires_at.to_be_bytes());
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountStatusResponse {
    /// Binds the fresh challenge, owner, requested lookup and caller authority.
    pub status_request_digest: [u8; 32],
    pub observed_at: u64,
    pub acceptance: Option<AccountAcceptance>,
    pub signature: String,
}

pub fn account_status_response_bytes(value: &AccountStatusResponse) -> Result<Vec<u8>, Error> {
    if value.observed_at == 0 || value.observed_at > MAX_INTEGER {
        return Err(Error::InvalidInput);
    }
    let mut bytes = b"cfrm.account.status-response.v1\0".to_vec();
    bytes.extend_from_slice(&value.status_request_digest);
    bytes.extend_from_slice(&value.observed_at.to_be_bytes());
    bytes.push(u8::from(value.acceptance.is_some()));
    let accepted = match &value.acceptance {
        Some(acceptance) => {
            if acceptance.accepted_at > value.observed_at {
                return Err(Error::InvalidInput);
            }
            let mut signed = account_acceptance_bytes(acceptance)?;
            signed.extend_from_slice(&decode::<64>(&acceptance.signature)?);
            Sha256::digest(signed).into()
        }
        None => [0; 32],
    };
    bytes.extend_from_slice(&accepted);
    Ok(bytes)
}

/// Verify the reply to the *exact* fresh status challenge. An old signed
/// acceptance alone is insufficient evidence that it is the current state.
pub fn verify_account_status_response(
    value: &AccountStatusResponse,
    request: &AccountStatusRequest,
    operator_key: &[u8; 32],
) -> Result<(), Error> {
    let mut signed_request = account_status_bytes(request)?;
    signed_request.extend_from_slice(&decode::<64>(&request.signature)?);
    let request_digest: [u8; 32] = Sha256::digest(signed_request).into();
    if value.status_request_digest != request_digest
        || value.observed_at < request.issued_at
        || value.observed_at >= request.expires_at
    {
        return Err(Error::Replay);
    }
    if let Some(acceptance) = &value.acceptance {
        if acceptance.statement.owner != request.owner
            || acceptance.statement.community != request.community
            || request
                .request_id
                .is_some_and(|id| id != acceptance.request_id)
        {
            return Err(Error::Admission);
        }
        verify_account_acceptance(acceptance, operator_key)?;
    }
    signature(
        &data_encoding::BASE64URL_NOPAD.encode(operator_key),
        &account_status_response_bytes(value)?,
        &value.signature,
    )
}
