//! Trusted, durable live tuning. This is never a member-controlled endpoint.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaitingPeriodTuning {
    pub revision: u64,
    pub seconds: u64,
    pub policy_digest: [u8; 32],
    pub state_policy_digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredConfig {
    format: String,
    community_id: String,
    admission_policy_digest: String,
    issuer_public_key: [u8; 32],
    pub policy: AccountLedgerPolicy,
    proof_scope: AccountProofScope,
    operator_key: [u8; 32],
    pub tuning_revision: u64,
}

pub(super) fn config_bytes(
    trust: &AdmissionTrust,
    policy: &AccountLedgerPolicy,
    proof_scope: &AccountProofScope,
    operator_key: [u8; 32],
    tuning_revision: u64,
) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&StoredConfig {
        format: "cfrm.account.database.v2".into(),
        community_id: trust.community_id.clone(),
        admission_policy_digest: trust.policy_digest.clone(),
        issuer_public_key: trust.issuer_public_key,
        policy: policy.clone(),
        proof_scope: proof_scope.clone(),
        operator_key,
        tuning_revision,
    })
    .map_err(|_| Error::InvalidInput)
}

pub(super) fn check_config(transaction: &Transaction<'_>, expected: &[u8]) -> Result<(), Error> {
    let stored: Vec<u8> = transaction.query_row(
        "SELECT config FROM cfrm_accounts_config WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if stored != expected {
        return Err(Error::PolicyMismatch);
    }
    Ok(())
}

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Current local snapshot. Call `reload_policy` to observe another writer's update.
    pub fn account_policy(&self) -> &AccountPolicy {
        &self.policy.account
    }

    pub fn waiting_period(&self) -> Result<WaitingPeriodTuning, Error> {
        Ok(WaitingPeriodTuning {
            revision: self.tuning_revision,
            seconds: self.policy.account.abandon_after,
            policy_digest: self.policy_digest,
            state_policy_digest: self.policy.account.state_digest(&self.community)?,
        })
    }

    /// Change only the waiting period for future outgoing reservations. The
    /// current circuit commits each existing slot's original deadline. No
    /// account, balance, admission counter or event history is reset here.
    ///
    /// The host must authorize this operation separately from member requests.
    /// `expected_revision` prevents concurrent operators from overwriting a
    /// newer decision. New writes on stale ledger handles fail closed.
    pub fn update_waiting_period(
        &mut self,
        expected_revision: u64,
        seconds: u64,
        clock: impl Fn() -> u64,
    ) -> Result<WaitingPeriodTuning, Error> {
        if expected_revision != self.tuning_revision {
            return Err(Error::PolicyMismatch);
        }
        let mut policy = self.policy.clone();
        policy.account.abandon_after = seconds;
        policy.account.validate()?;
        let revision = expected_revision
            .checked_add(1)
            .filter(|v| *v <= MAX_INTEGER)
            .ok_or(Error::InvalidInput)?;
        let digest = policy.account.digest(&self.community)?;
        let config = config_bytes(
            &self.trust,
            &policy,
            &self.proof_scope,
            self.operator.verifying_key().to_bytes(),
            revision,
        )?;
        let before = clock();
        check_time(before, 0)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_config(&transaction, &self.config)?;
        let now = clock();
        check_time(now, clock_floor(&transaction)?.max(before))?;
        if now < policy.account.policy_valid_from || now >= policy.account.policy_valid_until {
            return Err(Error::Expired);
        }
        policy.account.reservation_deadline(now)?;
        transaction.execute(
            "UPDATE cfrm_accounts_config SET config=?1 WHERE singleton=1",
            [&config],
        )?;
        advance_clock(&transaction, now)?;
        transaction.commit()?;
        self.config = config;
        self.policy = policy;
        self.policy_digest = digest;
        self.tuning_revision = revision;
        self.waiting_period()
    }

    /// Refresh the snapshot after a trusted waiting-period update. All other
    /// policy, proof, authority and database configuration must remain identical.
    pub fn reload_policy(&mut self) -> Result<WaitingPeriodTuning, Error> {
        let config: Vec<u8> = self.connection.query_row(
            "SELECT config FROM cfrm_accounts_config WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let stored: StoredConfig = serde_json::from_slice(&config).map_err(|_| Error::Storage)?;
        let mut policy = self.policy.clone();
        policy.account.abandon_after = stored.policy.account.abandon_after;
        policy.account.validate()?;
        if stored.tuning_revision < self.tuning_revision
            || stored.tuning_revision > MAX_INTEGER
            || config
                != config_bytes(
                    &self.trust,
                    &policy,
                    &self.proof_scope,
                    self.operator.verifying_key().to_bytes(),
                    stored.tuning_revision,
                )?
        {
            return Err(Error::PolicyMismatch);
        }
        self.policy_digest = policy.account.digest(&self.community)?;
        self.policy = policy;
        self.tuning_revision = stored.tuning_revision;
        self.config = config;
        self.waiting_period()
    }
}
