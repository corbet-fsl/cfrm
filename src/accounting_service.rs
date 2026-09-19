//! Transport-neutral authenticated account service and bounded real verifier.
//! Member requests never supply clocks, checkpoints, executable paths or policy.

use crate::{
    accounting::{
        AccountAcceptance, AccountPolicy, AccountProofScope, AccountProofVerifier, AccountRequest,
        AccountStatement, AccountStatusRequest, AccountStatusResponse,
    },
    accounting_ledger::{AccountLedger, WaitingPeriodTuning},
    admission::{AdmissionGrant, DeviceAuthorization},
    Error,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountServiceRequest {
    Apply {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountRequest,
    },
    Status {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    content = "value",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum AccountServiceResponse {
    Apply(AccountAcceptance),
    Status(AccountStatusResponse),
}

/// Hosts supply their own trusted clock, HTTP/onion transport and access control
/// for local administration. The member wire format exposes only apply/status.
pub struct AccountService<V: AccountProofVerifier, C: Fn() -> u64> {
    ledger: AccountLedger<V>,
    clock: C,
    max_request_bytes: usize,
}

impl<V: AccountProofVerifier, C: Fn() -> u64> AccountService<V, C> {
    pub fn new(
        ledger: AccountLedger<V>,
        clock: C,
        max_request_bytes: usize,
    ) -> Result<Self, Error> {
        if max_request_bytes == 0 || max_request_bytes > 16 * 1024 * 1024 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            ledger,
            clock,
            max_request_bytes,
        })
    }

    /// Enforce this bound while reading the transport body too, before allocation.
    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    pub fn handle_json(&mut self, body: &[u8]) -> Result<Vec<u8>, Error> {
        if body.len() > self.max_request_bytes {
            return Err(Error::Capacity);
        }
        let request = serde_json::from_slice(body).map_err(|_| Error::InvalidInput)?;
        serde_json::to_vec(&self.handle(request)?).map_err(|_| Error::InvalidInput)
    }

    pub fn handle(
        &mut self,
        request: AccountServiceRequest,
    ) -> Result<AccountServiceResponse, Error> {
        // Observe another administrator's durable tuning before new requests.
        // The ledger still rechecks configuration at commit; racing changes fail closed.
        self.ledger.reload_policy()?;
        match request {
            AccountServiceRequest::Apply {
                grant,
                authorization,
                request,
            } => self
                .ledger
                .apply(&grant, &authorization, &request, &self.clock)
                .map(AccountServiceResponse::Apply),
            AccountServiceRequest::Status {
                grant,
                authorization,
                request,
            } => self
                .ledger
                .status(&grant, &authorization, &request, &self.clock)
                .map(AccountServiceResponse::Status),
        }
    }

    /// Public configuration only. The embedding authenticates its distribution.
    pub fn policy(&mut self) -> Result<(AccountPolicy, WaitingPeriodTuning), Error> {
        let tuning = self.ledger.reload_policy()?;
        Ok((self.ledger.account_policy().clone(), tuning))
    }

    /// Trusted local administration, absent from AccountServiceRequest.
    /// Independently verify the common enrollment tree before calling this.
    pub fn publish_verified_checkpoint(&mut self, slot: u64, root: [u8; 32]) -> Result<(), Error> {
        self.ledger.admit_checkpoint(slot, root)
    }

    /// Trusted local administration. The host must authorize the administrator.
    pub fn tune_waiting_period(
        &mut self,
        expected_revision: u64,
        seconds: u64,
    ) -> Result<WaitingPeriodTuning, Error> {
        self.ledger.reload_policy()?;
        self.ledger
            .update_waiting_period(expected_revision, seconds, &self.clock)
    }
}

/// Fixed operator configuration. Use an absolute executable and the shipped
/// runtime/accounting/node-verifier.mjs, never paths from member requests.
#[derive(Clone, Debug)]
pub struct ProcessVerifierConfig {
    pub node: PathBuf,
    pub script: PathBuf,
    pub artifact_config: PathBuf,
    pub scope: AccountProofScope,
    pub timeout: Duration,
    pub maximum_parallel: usize,
    pub max_proof_bytes: usize,
    pub node_heap_megabytes: usize,
}

#[derive(Clone)]
pub struct ProcessAccountVerifier {
    config: Arc<ProcessVerifierConfig>,
    active: Arc<AtomicUsize>,
}

impl ProcessAccountVerifier {
    pub fn new(config: ProcessVerifierConfig) -> Result<Self, Error> {
        if !config.node.is_absolute()
            || !config.script.is_absolute()
            || !config.artifact_config.is_absolute()
            || config.scope.circuit_digest == [0; 32]
            || config.scope.verifying_key_digest == [0; 32]
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(300)
            || !(1..=64).contains(&config.maximum_parallel)
            || !(1..=1024 * 1024).contains(&config.max_proof_bytes)
            || !(64..=4096).contains(&config.node_heap_megabytes)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            config: Arc::new(config),
            active: Arc::new(AtomicUsize::new(0)),
        })
    }
}

struct ActivePermit(Arc<AtomicUsize>);
impl Drop for ActivePermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl AccountProofVerifier for ProcessAccountVerifier {
    fn scope(&self) -> AccountProofScope {
        self.config.scope.clone()
    }

    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        if proof.is_empty() || proof.len() > self.config.max_proof_bytes {
            return Err(Error::InvalidInput);
        }
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.config.maximum_parallel).then_some(n + 1)
            })
            .map_err(|_| Error::Capacity)?;
        let _permit = ActivePermit(self.active.clone());
        let bytes = serde_json::to_vec(&serde_json::json!({"statement": statement,
            "proof": data_encoding::HEXLOWER.encode(proof), "proofScope": self.config.scope}))
        .map_err(|_| Error::InvalidInput)?;
        let mut child = Command::new(&self.config.node)
            .arg(format!(
                "--max-old-space-size={}",
                self.config.node_heap_megabytes
            ))
            .arg(&self.config.script)
            .arg(&self.config.artifact_config)
            .env_remove("NODE_OPTIONS")
            .env_remove("NODE_PATH")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::CryptoProvider)?;
        // Dedicated bounded readers avoid pipe deadlock. Kill and reap on every
        // deadline/error before joining them. The shipped worker spawns no children.
        let mut stdin = child.stdin.take().ok_or(Error::CryptoProvider)?;
        let stdout = child.stdout.take().ok_or(Error::CryptoProvider)?;
        let writer = thread::spawn(move || stdin.write_all(&bytes));
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(4097).read_to_end(&mut bytes).map(|_| bytes)
        });
        let deadline = Instant::now() + self.config.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let wrote = writer.join().ok().is_some_and(|v| v.is_ok());
        let output = reader
            .join()
            .map_err(|_| Error::CryptoProvider)?
            .map_err(|_| Error::CryptoProvider)?;
        if !wrote || !status.is_some_and(|v| v.success()) || output.len() > 4096 {
            return Err(Error::CryptoProvider);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Verdict {
            verified: bool,
            proof_scope: AccountProofScope,
        }
        let verdict: Verdict =
            serde_json::from_slice(&output).map_err(|_| Error::CryptoProvider)?;
        if !verdict.verified || verdict.proof_scope != self.config.scope {
            return Err(Error::CryptoProvider);
        }
        Ok(())
    }
}
