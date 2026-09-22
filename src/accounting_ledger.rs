//! Durable host boundary for the experimental account-state proof relation.
//!
//! The database stores named opaque states and owner-specific markers, never a
//! peer, conversation tuple, balance or private receipt. Its trusted dependencies
//! are the configured proof verifier, independently admitted common enrollment
//! checkpoints, trusted time and durable SQLite storage. It does not establish
//! a consistent log against an equivocating operator or restore lost openings.

use crate::{
    accounting::{
        account_acceptance_bytes, account_request_bytes, account_request_digest,
        account_status_bytes, account_status_response_bytes, field, verify_account_acceptance,
        AccountAcceptance, AccountPolicy, AccountProofScope, AccountProofVerifier, AccountRequest,
        AccountStatusRequest, AccountStatusResponse,
    },
    admission::{
        decode, signature, verify_admission, verify_device_authorization, AdmissionGrant,
        AdmissionTrust, DeviceAuthorization, MAX_INTEGER,
    },
    allocation::{sql_integer, stored_integer},
    storage::{Connection, Transaction},
    Error,
};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

mod tuning;
pub use tuning::WaitingPeriodTuning;
use tuning::{check_config, config_bytes, StoredConfig};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountLedgerPolicy {
    pub account: AccountPolicy,
    pub max_authorization_seconds: u64,
    pub max_proof_bytes: usize,
    /// Common checkpoint slots have exactly this duration. Only one root can be
    /// admitted for a slot; publication is a trusted operator operation.
    pub checkpoint_period_seconds: u64,
}

pub struct AccountLedger<V: AccountProofVerifier> {
    connection: Connection,
    trust: AdmissionTrust,
    community: [u8; 32],
    policy: AccountLedgerPolicy,
    policy_digest: [u8; 32],
    config: Vec<u8>,
    tuning_revision: u64,
    proof_scope: AccountProofScope,
    verifier: V,
    operator: SigningKey,
}

fn check_time(now: u64, floor: u64) -> Result<(), Error> {
    if now == 0 || now < floor || now > MAX_INTEGER {
        return Err(Error::ClockRollback);
    }
    Ok(())
}

fn clock_floor(transaction: &Transaction<'_>) -> Result<u64, Error> {
    stored_integer(transaction.query_row(
        "SELECT clock_floor FROM cfrm_accounts_config WHERE singleton=1",
        [],
        |row| row.get::<_, i64>(0),
    )?)
}

fn advance_clock(transaction: &Transaction<'_>, now: u64) -> Result<(), Error> {
    transaction.execute(
        "UPDATE cfrm_accounts_config SET clock_floor=?1 WHERE singleton=1",
        [sql_integer(now)?],
    )?;
    Ok(())
}

fn cached(
    transaction: &Transaction<'_>,
    owner: &[u8; 32],
    request: &[u8; 32],
    operator_key: &[u8; 32],
) -> Result<Option<AccountAcceptance>, Error> {
    let result: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT acceptance FROM cfrm_accounts_requests WHERE owner=?1 AND request_id=?2",
            params![owner.as_slice(), request.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    result
        .map(|bytes| {
            let result: AccountAcceptance =
                serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
            verify_account_acceptance(&result, operator_key).map_err(|_| Error::Storage)?;
            if result.statement.owner != *owner || result.request_id != *request {
                return Err(Error::Storage);
            }
            Ok(result)
        })
        .transpose()
}

// Check mutable database predicates both before expensive verification and in
// the final write transaction. Policy and request bytes remain immutably
// borrowed across verification; no preflight database result authorizes commit.
fn check_pending(
    transaction: &Transaction<'_>,
    request: &AccountRequest,
    root_key: &[u8; 32],
    grant: &AdmissionGrant,
    authorization: &DeviceAuthorization,
    policy: &AccountLedgerPolicy,
    now: u64,
) -> Result<(), Error> {
    let statement = &request.statement;
    if request.expires_at - request.issued_at > policy.max_authorization_seconds
        || now < request.issued_at
        || now >= request.expires_at
        || request.expires_at > grant.expires_at
        || request.expires_at > authorization.expires_at
        || request.expires_at > policy.account.policy_valid_until
    {
        return Err(Error::Expired);
    }
    let slot = statement.now / policy.checkpoint_period_seconds;
    if now / policy.checkpoint_period_seconds != slot {
        return Err(Error::Expired);
    }
    let checkpoint: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT root FROM cfrm_accounts_checkpoints WHERE slot=?1",
            [sql_integer(slot)?],
            |row| row.get(0),
        )
        .optional()?;
    if checkpoint.as_deref() != Some(statement.enrollment_root.as_slice()) {
        return Err(Error::Admission);
    }
    let prior: Option<(Vec<u8>, i64, Vec<u8>)> = transaction
        .query_row(
            "SELECT root_key,version,state FROM cfrm_accounts WHERE owner=?1",
            [statement.owner.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match prior {
        None if statement.genesis => {}
        Some((key, version, state))
            if !statement.genesis
                && key.as_slice() == root_key
                && stored_integer(version)? == statement.previous_version
                && state.as_slice() == statement.previous_state => {}
        _ => return Err(Error::Replay),
    }
    if statement.settlement_marker != [0; 32] {
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM cfrm_accounts_markers WHERE owner=?1 AND marker=?2)",
            params![
                statement.owner.as_slice(),
                statement.settlement_marker.as_slice()
            ],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Error::Replay);
        }
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    pub fn open(
        path: impl AsRef<Path>,
        trust: AdmissionTrust,
        policy: AccountLedgerPolicy,
        verifier: V,
        operator: SigningKey,
    ) -> Result<Self, Error> {
        Self::with_connection(Connection::open(path)?, trust, policy, verifier, operator)
    }

    #[cfg(all(feature = "turso", not(target_arch = "wasm32")))]
    pub fn open_remote(
        config: crate::storage::RemoteConfig,
        trust: AdmissionTrust,
        policy: AccountLedgerPolicy,
        verifier: V,
        operator: SigningKey,
    ) -> Result<Self, Error> {
        Self::with_connection(
            Connection::open_remote(config)?,
            trust,
            policy,
            verifier,
            operator,
        )
    }

    fn with_connection(
        mut connection: Connection,
        trust: AdmissionTrust,
        mut policy: AccountLedgerPolicy,
        verifier: V,
        operator: SigningKey,
    ) -> Result<Self, Error> {
        if !crate::admission::scope(&trust.community_id)
            || policy.max_authorization_seconds == 0
            || policy.max_authorization_seconds > MAX_INTEGER
            || policy.max_proof_bytes == 0
            || policy.max_proof_bytes > i32::MAX as usize
            || policy.checkpoint_period_seconds == 0
            || policy.checkpoint_period_seconds > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        decode::<32>(&trust.policy_digest)?;
        let community: [u8; 32] = Sha256::digest(trust.community_id.as_bytes()).into();
        let mut policy_digest = policy.account.digest(&community)?;
        let proof_scope = verifier.scope();
        if proof_scope.circuit_digest == [0; 32] || proof_scope.verifying_key_digest == [0; 32] {
            return Err(Error::InvalidInput);
        }
        let mut tuning_revision = 0;
        let mut config = config_bytes(
            &trust,
            &policy,
            &proof_scope,
            operator.verifying_key().to_bytes(),
            tuning_revision,
        )?;
        connection.configure_local(Duration::from_secs(5))?;
        connection.execute_batch("
            CREATE TABLE IF NOT EXISTS cfrm_accounts_config (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1), config BLOB NOT NULL,
              clock_floor INTEGER NOT NULL CHECK(clock_floor>=0));
            CREATE TABLE IF NOT EXISTS cfrm_accounts_checkpoints (
              slot INTEGER PRIMARY KEY CHECK(slot>=0), root BLOB NOT NULL CHECK(length(root)=32));
            CREATE TABLE IF NOT EXISTS cfrm_accounts (
              owner BLOB PRIMARY KEY CHECK(length(owner)=32), root_key BLOB NOT NULL CHECK(length(root_key)=32),
              version INTEGER NOT NULL CHECK(version>=0), state BLOB NOT NULL CHECK(length(state)=32),
              latest_request BLOB NOT NULL CHECK(length(latest_request)=32)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS cfrm_accounts_markers (
              owner BLOB NOT NULL REFERENCES cfrm_accounts(owner), marker BLOB NOT NULL CHECK(length(marker)=32),
              PRIMARY KEY(owner,marker)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS cfrm_accounts_requests (
              owner BLOB NOT NULL REFERENCES cfrm_accounts(owner), request_id BLOB NOT NULL CHECK(length(request_id)=32),
              acceptance BLOB NOT NULL, PRIMARY KEY(owner,request_id)) WITHOUT ROWID;")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT config FROM cfrm_accounts_config WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            let stored: StoredConfig =
                serde_json::from_slice(&prior).map_err(|_| Error::PolicyMismatch)?;
            // The supplied wait is a bootstrap value. A restart loads the
            // durably tuned wait while every immutable setting stays pinned.
            policy.account.abandon_after = stored.policy.account.abandon_after;
            policy.account.validate()?;
            tuning_revision = stored.tuning_revision;
            if tuning_revision > MAX_INTEGER {
                return Err(Error::PolicyMismatch);
            }
            config = config_bytes(
                &trust,
                &policy,
                &proof_scope,
                operator.verifying_key().to_bytes(),
                tuning_revision,
            )?;
            if prior != config {
                return Err(Error::PolicyMismatch);
            }
            policy_digest = policy.account.digest(&community)?;
        } else {
            transaction.execute("INSERT INTO cfrm_accounts_config VALUES(1,?1,0)", [&config])?;
        }
        transaction.commit()?;
        Ok(Self {
            connection,
            trust,
            community,
            policy,
            policy_digest,
            config,
            tuning_revision,
            proof_scope,
            verifier,
            operator,
        })
    }

    /// Trusted local publication operation. The caller must have independently
    /// verified the common enrollment tree and root/device/delegation authority.
    /// Never expose this as a member-controlled endpoint or derive it from that
    /// member's proof. A signed but individually tagged root is not common.
    pub fn admit_checkpoint(&mut self, slot: u64, root: [u8; 32]) -> Result<(), Error> {
        field(&root, true)?;
        let end = slot
            .checked_add(1)
            .and_then(|n| n.checked_mul(self.policy.checkpoint_period_seconds))
            .filter(|end| *end <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        if end == 0 {
            return Err(Error::InvalidInput);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT root FROM cfrm_accounts_checkpoints WHERE slot=?1",
                [sql_integer(slot)?],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            if prior.as_slice() != root {
                return Err(Error::PolicyMismatch);
            }
        } else {
            transaction.execute(
                "INSERT INTO cfrm_accounts_checkpoints VALUES(?1,?2)",
                params![sql_integer(slot)?, root.as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Verify, authorize and commit one named owner update. An exact retry
    /// returns its original signed response even after the original request
    /// expires, provided the caller supplies current root/device authorization.
    pub fn apply(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountRequest,
        clock: impl Fn() -> u64,
    ) -> Result<AccountAcceptance, Error> {
        if request.proof.len() > self.policy.max_proof_bytes {
            return Err(Error::InvalidInput);
        }
        let statement = &request.statement;
        if statement.community != self.community || request.proof_scope != self.proof_scope {
            return Err(Error::PolicyMismatch);
        }
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        if decode::<32>(&grant.member_id)? != statement.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        signature(
            &request.chat_public_key,
            &account_request_bytes(request)?,
            &request.signature,
        )?;
        let request_digest = account_request_digest(request)?;
        let root_key = decode::<32>(&authorization.root_public_key)?;
        let operator_key = self.operator.verifying_key().to_bytes();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = clock();
        check_time(now, clock_floor(&transaction)?.max(before))?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        if let Some(result) = cached(
            &transaction,
            &statement.owner,
            &request.request_id,
            &operator_key,
        )? {
            if result.request_digest != request_digest {
                return Err(Error::Replay);
            }
            advance_clock(&transaction, now)?;
            transaction.commit()?;
            return Ok(result);
        }
        check_config(&transaction, &self.config)?;
        if statement.policy != self.policy.account || statement.policy_digest != self.policy_digest
        {
            return Err(Error::PolicyMismatch);
        }
        check_pending(
            &transaction,
            request,
            &root_key,
            grant,
            authorization,
            &self.policy,
            now,
        )?;
        // Release every SQLite lock before invoking an external or slow
        // verifier. Other owners and competing devices can commit meanwhile.
        transaction.rollback()?;
        self.verifier.verify(statement, &request.proof)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let completed = clock();
        check_time(completed, clock_floor(&transaction)?.max(now))?;
        if completed >= grant.expires_at || completed >= authorization.expires_at {
            return Err(Error::Expired);
        }
        verify_admission(grant, &self.trust, completed)?;
        verify_device_authorization(authorization, grant, completed)?;
        // A concurrent exact request may already have committed. Recover its
        // original response before applying expiry/CAS checks to a fresh write.
        if let Some(result) = cached(
            &transaction,
            &statement.owner,
            &request.request_id,
            &operator_key,
        )? {
            if result.request_digest != request_digest {
                return Err(Error::Replay);
            }
            advance_clock(&transaction, completed)?;
            transaction.commit()?;
            return Ok(result);
        }
        check_config(&transaction, &self.config)?;
        if statement.policy != self.policy.account || statement.policy_digest != self.policy_digest
        {
            return Err(Error::PolicyMismatch);
        }
        check_pending(
            &transaction,
            request,
            &root_key,
            grant,
            authorization,
            &self.policy,
            completed,
        )?;
        let mut acceptance = AccountAcceptance {
            statement: statement.clone(),
            request_id: request.request_id,
            request_digest,
            proof_scope: self.proof_scope.clone(),
            accepted_at: completed,
            signature: String::new(),
        };
        acceptance.signature = BASE64URL_NOPAD.encode(
            &self
                .operator
                .sign(&account_acceptance_bytes(&acceptance)?)
                .to_bytes(),
        );
        let response = serde_json::to_vec(&acceptance).map_err(|_| Error::Storage)?;
        if statement.genesis {
            transaction.execute(
                "INSERT INTO cfrm_accounts VALUES(?1,?2,?3,?4,?5)",
                params![
                    statement.owner.as_slice(),
                    root_key.as_slice(),
                    sql_integer(statement.next_version)?,
                    statement.next_state.as_slice(),
                    request.request_id.as_slice()
                ],
            )?;
        } else {
            // Marker insertion intentionally precedes the state update: both
            // must roll back together on any later database/signing failure.
            if statement.settlement_marker != [0; 32] {
                transaction.execute(
                    "INSERT INTO cfrm_accounts_markers VALUES(?1,?2)",
                    params![
                        statement.owner.as_slice(),
                        statement.settlement_marker.as_slice()
                    ],
                )?;
            }
            let changed = transaction.execute(
                "UPDATE cfrm_accounts SET version=?1,state=?2,latest_request=?3 WHERE owner=?4 AND version=?5 AND state=?6",
                params![sql_integer(statement.next_version)?, statement.next_state.as_slice(), request.request_id.as_slice(),
                    statement.owner.as_slice(), sql_integer(statement.previous_version)?, statement.previous_state.as_slice()])?;
            if changed != 1 {
                return Err(Error::Replay);
            }
        }
        transaction.execute(
            "INSERT INTO cfrm_accounts_requests VALUES(?1,?2,?3)",
            params![
                statement.owner.as_slice(),
                request.request_id.as_slice(),
                response
            ],
        )?;
        advance_clock(&transaction, completed)?;
        transaction.commit()?;
        Ok(acceptance)
    }

    /// Authenticated recovery for either a specific request or the latest
    /// acceptance. This returns no private opening and grants no fresh credit.
    /// The signed response binds the fresh request challenge and observation
    /// time; a historical acceptance by itself does not attest to freshness.
    pub fn status(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountStatusRequest,
        clock: impl Fn() -> u64,
    ) -> Result<AccountStatusResponse, Error> {
        let bytes = account_status_bytes(request)?;
        if request.community != self.community
            || decode::<32>(&grant.member_id)? != request.owner
            || request.chat_public_key != grant.chat_public_key
        {
            return Err(Error::Admission);
        }
        if request.expires_at - request.issued_at > self.policy.max_authorization_seconds {
            return Err(Error::Expired);
        }
        let before = clock();
        check_time(before, 0)?;
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        signature(&request.chat_public_key, &bytes, &request.signature)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = clock();
        check_time(now, before.max(clock_floor(&transaction)?))?;
        verify_admission(grant, &self.trust, now)?;
        verify_device_authorization(authorization, grant, now)?;
        if now < request.issued_at || now >= request.expires_at {
            return Err(Error::Expired);
        }
        let request_id = match request.request_id {
            Some(id) => Some(id),
            None => {
                let value: Option<Vec<u8>> = transaction
                    .query_row(
                        "SELECT latest_request FROM cfrm_accounts WHERE owner=?1",
                        [request.owner.as_slice()],
                        |row| row.get(0),
                    )
                    .optional()?;
                value
                    .map(|value| value.try_into().map_err(|_| Error::Storage))
                    .transpose()?
            }
        };
        let result = request_id
            .map(|id| {
                cached(
                    &transaction,
                    &request.owner,
                    &id,
                    &self.operator.verifying_key().to_bytes(),
                )
            })
            .transpose()?
            .flatten();
        let mut signed_request = bytes;
        signed_request.extend_from_slice(&decode::<64>(&request.signature)?);
        let mut response = AccountStatusResponse {
            status_request_digest: Sha256::digest(signed_request).into(),
            observed_at: now,
            acceptance: result,
            signature: String::new(),
        };
        response.signature = BASE64URL_NOPAD.encode(
            &self
                .operator
                .sign(&account_status_response_bytes(&response)?)
                .to_bytes(),
        );
        advance_clock(&transaction, now)?;
        transaction.commit()?;
        Ok(response)
    }
}
