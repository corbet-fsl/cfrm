//! Validated private-account policy and immutable state binding.

use crate::{admission::MAX_INTEGER, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountPolicy {
    pub initial_credit: u32,
    /// Mature total capacity, including both available and reserved units.
    pub maximum_available: u32,
    pub outgoing_reservation: u32,
    pub incoming_reservation: u32,
    pub policy_revision: u64,
    pub policy_valid_from: u64,
    pub policy_valid_until: u64,
    pub newcomer_period: u64,
    pub rate_window: u64,
    pub newcomer_admissions: u32,
    pub maximum_admissions: u32,
    pub refill_period: u64,
    pub refill_units: u32,
    /// Waiting period for new outgoing reservations. Existing slots retain their deadline.
    pub abandon_after: u64,
}

impl AccountPolicy {
    /// Deadline for a new outgoing reservation. A settlement interval must
    /// remain before policy expiry, or the promised refund would be unusable.
    pub fn reservation_deadline(&self, now: u64) -> Result<u64, Error> {
        let horizon = self.proof_valid_until(now)?;
        let deadline = now
            .checked_add(self.abandon_after)
            .ok_or(Error::InvalidInput)?;
        if deadline < horizon || deadline >= self.policy_valid_until {
            return Err(Error::Expired);
        }
        Ok(deadline)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.maximum_available == 0
            || self.initial_credit > self.maximum_available
            || self.outgoing_reservation == 0
            || self.incoming_reservation == 0
            || self.outgoing_reservation > self.maximum_available
            || self.incoming_reservation > self.maximum_available
            || self.initial_credit < self.outgoing_reservation
            || self.initial_credit < self.incoming_reservation
            || self.newcomer_admissions == 0
            || self.newcomer_admissions > self.maximum_admissions
            || self.refill_units == 0
            || self.refill_units > self.initial_credit
            || self.abandon_after < self.rate_window
            || [
                self.newcomer_period,
                self.rate_window,
                self.refill_period,
                self.abandon_after,
            ]
            .into_iter()
            .any(|duration| duration == 0 || duration > MAX_INTEGER)
            || self.policy_revision == 0
            || self.policy_revision > MAX_INTEGER
            || self.policy_valid_from == 0
            || self.policy_valid_from >= self.policy_valid_until
            || self.policy_valid_until > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    /// Capacity grows with permanent account age; this never issues credit.
    /// `created_at` is the end of the authenticated genesis proof window, never
    /// the current device's enrollment or a caller-controlled profile timestamp.
    pub fn capacity_at(&self, created_at: u64, now: u64) -> Result<u32, Error> {
        self.validate_age(created_at, now)?;
        Ok(
            if now < created_at || now - created_at < self.newcomer_period {
                self.initial_credit
            } else {
                self.maximum_available
            },
        )
    }

    /// Both incoming and outgoing reservations consume the same window count.
    pub fn admission_limit_at(&self, created_at: u64, now: u64) -> Result<u32, Error> {
        self.validate_age(created_at, now)?;
        Ok(
            if now < created_at || now - created_at < self.newcomer_period {
                self.newcomer_admissions
            } else {
                self.maximum_admissions
            },
        )
    }

    /// All members in one rate window use the same public proof horizon.
    /// The ledger checks this again after verification, so proving an earlier
    /// timestamp cannot authorize a transition after its validity window.
    pub fn proof_valid_until(&self, now: u64) -> Result<u64, Error> {
        self.validate()?;
        if now < self.policy_valid_from || now >= self.policy_valid_until {
            return Err(Error::Expired);
        }
        let end = (now / self.rate_window + 1)
            .checked_mul(self.rate_window)
            .ok_or(Error::InvalidInput)?;
        Ok(end.min(self.policy_valid_until))
    }

    fn validate_age(&self, created_at: u64, now: u64) -> Result<(), Error> {
        self.validate()?;
        if created_at < self.policy_valid_from
            || created_at > self.policy_valid_until
            || now > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        if created_at > self.proof_valid_until(now)? {
            return Err(Error::ClockRollback);
        }
        if now >= self.policy_valid_until {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub(crate) fn append(&self, bytes: &mut Vec<u8>) {
        for value in [
            self.initial_credit,
            self.maximum_available,
            self.outgoing_reservation,
            self.incoming_reservation,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        for value in [
            self.policy_revision,
            self.policy_valid_from,
            self.policy_valid_until,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.newcomer_period.to_be_bytes());
        bytes.extend_from_slice(&self.rate_window.to_be_bytes());
        bytes.extend_from_slice(&self.newcomer_admissions.to_be_bytes());
        bytes.extend_from_slice(&self.maximum_admissions.to_be_bytes());
        bytes.extend_from_slice(&self.refill_period.to_be_bytes());
        bytes.extend_from_slice(&self.refill_units.to_be_bytes());
        bytes.extend_from_slice(&self.abandon_after.to_be_bytes());
    }

    /// Stable state binding for live waiting-period tuning. Every economic and
    /// protocol field except `abandon_after` remains committed here.
    pub fn state_digest(&self, community: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.validate()?;
        let mut policy = Vec::new();
        self.append(&mut policy);
        policy.truncate(policy.len() - 8);
        let mut bytes = b"cfrm.account-state-policy.v1\0".to_vec();
        bytes.extend_from_slice(community);
        bytes.extend_from_slice(&policy);
        bytes.push(32);
        Ok(Sha256::digest(bytes).into())
    }

    pub fn digest(&self, community: &[u8; 32]) -> Result<[u8; 32], Error> {
        self.validate()?;
        let mut bytes = b"cfrm.account-policy.v2\0".to_vec();
        bytes.extend_from_slice(community);
        self.append(&mut bytes);
        bytes.push(32); // Circuit's indexed Merkle tree capacity, not a credit default.
        Ok(Sha256::digest(bytes).into())
    }
}
