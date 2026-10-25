//! Service composition and supervised lifetime. Cryptographic, storage, match
//! and quota decisions remain in Assurance, Gather and Volatile's owners.
use crate::*;
use cgth::{clkp, cmbl, cmmr, cswb, cthl};
use cmmr::{Clock, Store};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

mod accounting;
mod partial;
mod recover;
pub use recover::Recover;
pub mod valkey;

/// One explicit common epoch for the single-process service incarnation.
/// This is deployment input, never a member-supplied expiry or key.
#[derive(Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomEpochConfiguration {
    pub epoch: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
}

pub struct Configuration {
    pub community: String,
    pub incarnation: String,
    pub admission_action: String,
    pub origins: Vec<String>,
    pub request_bytes: usize,
    pub presence: cswb::Limits,
    pub lookup: clkp::LookupLimits,
    pub rooms: cmbl::Limits,
    pub room_epoch: RoomEpochConfiguration,
}
pub struct Parts<C, R, Q, N = cvtl::RedisNetwork> {
    /// One already-open service-owned connection; all children clone this handle.
    pub storage: cvtl::Volatile<C, N>,
    pub clock: C,
    pub tokens: R,
    pub throttle: cthl::Throttle<Q>,
}
pub struct Service<S, C, R, Q, F> {
    assurance: csrn::Assurance,
    gather: Option<cgth::Gather<S, C, R, Q>>,
    accounting: Option<cgth::accounting::AccountGather<S, C, R, Q>>,
    storage: S,
    clock: C,
    contact: F,
    configuration: Configuration,
    room_quota: Option<u16>,
}
impl<C, R, Q, F, N> Service<cvtl::Volatile<C, N>, C, R, Q, F>
where
    C: Clock + Clone,
    R: cswb::Tokens + Clone,
    Q: cthl::Store,
    N: cvtl::Network,
    F: Fn(&str) -> cshm::ContactCheck,
{
    pub fn new(
        assurance: csrn::Assurance,
        parts: Parts<C, R, Q, N>,
        configuration: Configuration,
        contact: F,
    ) -> Result<Self, ErrorCode> {
        if configuration.origins.is_empty() {
            return Err(ErrorCode::Origin);
        }
        for origin in &configuration.origins {
            let parsed = url::Url::parse(origin).map_err(|_| ErrorCode::Origin)?;
            if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != *origin {
                return Err(ErrorCode::Origin);
            }
        }
        if configuration.admission_action.is_empty()
            || configuration.request_bytes == 0
            || configuration.request_bytes > 1_048_576
            || configuration.room_epoch.epoch == 0
            || configuration.room_epoch.valid_from_ms == 0
            || configuration.room_epoch.valid_from_ms >= configuration.room_epoch.valid_until_ms
            || configuration.room_epoch.valid_until_ms > cmmr::MAX_TIME
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let presence = cswb::Switchboard::new(
            parts.storage.clone(),
            parts.clock.clone(),
            parts.tokens.clone(),
            configuration.community.clone(),
            configuration.presence,
        )
        .map_err(|_| ErrorCode::InvalidRequest)?;
        let lookup = clkp::Lookup::new(parts.storage.clone(), parts.tokens, configuration.lookup)
            .map_err(|_| ErrorCode::InvalidRequest)?;
        let rooms = cmbl::Assembly::new(
            parts.storage.clone(),
            configuration.community.clone(),
            configuration.incarnation.clone(),
            configuration.rooms,
        )
        .map_err(|_| ErrorCode::InvalidRequest)?;
        Ok(Self {
            assurance,
            gather: Some(cgth::Gather::new(presence, parts.throttle, rooms, lookup)),
            accounting: None,
            storage: parts.storage,
            clock: parts.clock,
            contact,
            configuration,
            room_quota: None,
        })
    }
}

impl<S: Store + Clone, C: Clock, R: cswb::Tokens, Q: cthl::Store, F: Fn(&str) -> cshm::ContactCheck>
    Service<S, C, R, Q, F>
{
    /// Install the concrete authenticated native owner once. The serial service
    /// keeps this owner and the current Charter together through every operation.
    pub fn with_accounting(
        mut self,
        configuration: cgth::accounting::Configuration,
        native: cgth::accounting::verification::NativeExtensionVerifier,
        limits: cgth::accounting::verification::ExtensionLimits,
    ) -> Result<Self, ErrorCode>
    where
        C: Clone,
    {
        if configuration.community != self.configuration.community || self.accounting.is_some() {
            return Err(ErrorCode::InvalidRequest);
        }
        let gather = self.gather.take().ok_or(ErrorCode::AuthorityUnavailable)?;
        self.accounting = Some(
            cgth::accounting::AccountGather::new(
                gather,
                configuration,
                native,
                limits,
                self.clock.clone(),
            )
            .map_err(error)?,
        );
        Ok(self)
    }

    async fn execute(&mut self, origin: &str, call: Call) -> Result<Reply, ErrorCode> {
        if !self
            .configuration
            .origins
            .iter()
            .any(|allowed| allowed == origin)
        {
            return Err(ErrorCode::Origin);
        }
        if call.version != 1 {
            return Err(ErrorCode::UnsupportedVersion);
        }
        if self.storage.state() != cmmr::State::Ready {
            return Err(ErrorCode::AuthorityUnavailable);
        }
        let action = call.request.info().name;
        // One community-wide cheap quota before profile/signature/storage work.
        // A member identifier from unverified input never selects a new bucket.
        match (&self.gather, &self.accounting) {
            (Some(gather), None) => gather.preflight(b"forum", action).await,
            (None, Some(gather)) => gather.preflight(b"forum", action).await,
            _ => return Err(ErrorCode::AuthorityUnavailable),
        }
        .map_err(error)?;
        // Partial owners still refuse governed operations. Complete accounting
        // routes retain their original per-operation joins; MLS handover has no
        // corresponding owner capability and continues to refuse.
        if matches!(&call.request, Request::RoomHandover(_))
            || (self.accounting.is_none()
                && !matches!(
                    call.request.info().requirement,
                    Requirement::PublishedPolicy | Requirement::Credential
                ))
        {
            return Err(ErrorCode::AuthorityUnavailable);
        }
        let now_ms = self
            .clock
            .now()
            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        let now = now_ms / 1000;
        let charter = self
            .assurance
            .current(now)
            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        let verification = cswb::Verification {
            charter,
            action: &self.configuration.admission_action,
        };
        let settings = crbk::ForumSettings::from_snapshot(
            charter
                .settings(now)
                .map_err(|_| ErrorCode::AuthorityUnavailable)?,
        )
        .map_err(|error| {
            // The Forum cannot run without the community's quota: say which setting.
            eprintln!("forum settings refused: {error}");
            ErrorCode::AuthorityUnavailable
        })?;
        if settings.lease_ms > self.configuration.presence.lease_ms {
            return Err(ErrorCode::AuthorityUnavailable);
        }
        let mut authority_deadline = charter
            .valid_until()
            .checked_mul(1000)
            .ok_or(ErrorCode::AuthorityUnavailable)?;
        let output = if let Some(gather) = self.accounting.as_mut() {
            if let Request::Settings(_) = &call.request {
                settings_output(charter, &settings)?
            } else {
                accounting::execute(
                    gather,
                    origin,
                    &call.request,
                    &verification,
                    &self.contact,
                    &mut authority_deadline,
                    accounting::RoomHost {
                        storage: &self.storage,
                        configuration: &self.configuration,
                    },
                )
                .await?
            }
        } else {
            partial::Partial {
                gather: self
                    .gather
                    .as_mut()
                    .ok_or(ErrorCode::AuthorityUnavailable)?,
                storage: &self.storage,
                clock: &self.clock,
                contact: &self.contact,
                configuration: &self.configuration,
                room_quota: &mut self.room_quota,
            }
            .execute(
                origin,
                &call.request,
                &verification,
                &settings,
                &mut authority_deadline,
            )
            .await?
        };
        let completed_at_ms = match &self.accounting {
            Some(gather) => gather.observed_now().map_err(error)?,
            None => self
                .clock
                .now()
                .map_err(|_| ErrorCode::AuthorityUnavailable)?,
        };
        if completed_at_ms < now_ms || completed_at_ms >= authority_deadline {
            return Err(ErrorCode::AuthorityUnavailable);
        }
        Ok(Reply::new(output))
    }
}

fn settings_output(
    charter: &csrn::cchr::VerifiedCharter,
    settings: &crbk::ForumSettings,
) -> Result<Output, ErrorCode> {
    Ok(Output::Settings(SettingsOutput {
        heartbeat_ms: settings.heartbeat_ms,
        lease_ms: settings.lease_ms,
        minimum_client_version: settings.minimum_client_version.to_string(),
        room_passes_per_epoch: settings.room_passes_per_epoch,
        revision: charter.revision(),
        policy_epoch: charter.policy_epoch(),
        valid_until: charter.valid_until(),
        publication: charter
            .publication(csrn::cchr::Kind::Settings)
            .signed_bytes()
            .to_vec(),
    }))
}

fn room_quota(value: u64) -> Result<u16, ErrorCode> {
    u16::try_from(value)
        .ok()
        .filter(|quota| (1..=1024).contains(quota))
        .ok_or(ErrorCode::AuthorityUnavailable)
}

fn live(value: cswb::Live) -> LiveOutput {
    LiveOutput {
        revision: value.revision.0.to_vec(),
        expires_at_ms: value.deadline,
    }
}
fn revision(bytes: &[u8]) -> Result<cmmr::Revision, ErrorCode> {
    Ok(cmmr::Revision(
        bytes.try_into().map_err(|_| ErrorCode::InvalidRequest)?,
    ))
}
fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ErrorCode> {
    serde_json::to_vec(value).map_err(|_| ErrorCode::InvalidRequest)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ErrorCode> {
    serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)
}
fn error(value: cgth::Error) -> ErrorCode {
    match value {
        cgth::Error::QuotaExceeded | cgth::Error::Rooms(cmbl::Error::Capacity) => {
            ErrorCode::Capacity
        }
        cgth::Error::Rooms(cmbl::Error::Invalid) => ErrorCode::InvalidRequest,
        cgth::Error::Rooms(cmbl::Error::Refused) => ErrorCode::Rejected,
        cgth::Error::Rooms(cmbl::Error::ResumeRequired | cmbl::Error::Conflict) => {
            ErrorCode::ResetRequired
        }
        cgth::Error::Presence(cswb::Error::Invalid)
        | cgth::Error::Lookup(clkp::LookupError::Invalid) => ErrorCode::InvalidRequest,
        cgth::Error::Presence(
            cswb::Error::Absent
            | cswb::Error::Expired
            | cswb::Error::Stale
            | cswb::Error::Storage(cmmr::Error::Conflict),
        )
        | cgth::Error::Lookup(
            clkp::LookupError::ResetRequired
            | clkp::LookupError::Cursor(clkp::CursorError::ResetRequired),
        ) => ErrorCode::ResetRequired,
        cgth::Error::Presence(cswb::Error::DeviceUnavailable) => ErrorCode::Rejected,
        _ => ErrorCode::AuthorityUnavailable,
    }
}

enum Command {
    Call {
        origin: String,
        call: Call,
        reply: oneshot::Sender<Result<Reply, ErrorCode>>,
    },
    Start(oneshot::Sender<Result<csrn::feed::Request, ErrorCode>>),
    Next(oneshot::Sender<Result<Option<csrn::feed::Request>, ErrorCode>>),
    Feed {
        id: u64,
        bytes: Vec<u8>,
        announcement: bool,
        reply: oneshot::Sender<Result<(), ErrorCode>>,
    },
    Failed {
        id: u64,
        jitter: u64,
        reply: oneshot::Sender<Result<(), ErrorCode>>,
    },
}
/// A bounded controller channel, never a callback that can manufacture authority.
#[derive(Clone)]
pub struct Handle {
    sender: mpsc::Sender<Command>,
    request_bytes: usize,
}
struct Fence<S: Store>(S);
impl<S: Store> Drop for Fence<S> {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl<S, C, R, Q, F> Service<S, C, R, Q, F>
where
    S: Store + Recover + Clone + 'static,
    C: Clock + 'static,
    R: cswb::Tokens + 'static,
    Q: cthl::Store + Send + Sync + 'static,
    F: Fn(&str) -> cshm::ContactCheck + Send + Sync + 'static,
{
    /// Once queued, an admitted mutation runs to completion even when HTTP or
    /// its reply receiver disappears. Panic/drop fences this shared store.
    pub fn spawn(
        mut self,
        capacity: usize,
        maintenance: Duration,
    ) -> Result<(Handle, tokio::task::JoinHandle<()>), ErrorCode> {
        if capacity == 0 || capacity > 4096 || maintenance.is_zero() {
            return Err(ErrorCode::InvalidRequest);
        }
        let (sender, mut receiver) = mpsc::channel(capacity);
        let handle = Handle {
            sender,
            request_bytes: self.configuration.request_bytes,
        };
        let task = tokio::spawn(async move {
            let _fence = Fence(self.storage.clone());
            let mut interval = tokio::time::interval(maintenance);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut backoff = recover::Backoff::default();
            loop {
                tokio::select! {
                    command=receiver.recv()=>{
                        let Some(command)=command else { break; };
                        match command {
                            Command::Call {origin,call,reply}=>{ let result=self.execute(&origin,call).await;let _=reply.send(result); },
                            command=>{
                                let now=self.clock.now().map(|now|now/1000).map_err(|_|ErrorCode::AuthorityUnavailable);
                                match command {
                                    Command::Start(reply)=>{let _=reply.send(now.and_then(|now|self.assurance.start(now).map_err(|_|ErrorCode::AuthorityUnavailable)));},
                                    Command::Next(reply)=>{let _=reply.send(now.and_then(|now|self.assurance.next(now).map_err(|_|ErrorCode::AuthorityUnavailable)));},
                                    Command::Feed{id,bytes,announcement,reply}=>{let _=reply.send(now.and_then(|now|if announcement {self.assurance.on_announcement(id,&bytes,now)} else {self.assurance.on_feed(id,&bytes,now)}.map_err(|_|ErrorCode::AuthorityUnavailable)));},
                                    Command::Failed{id,jitter,reply}=>{let _=reply.send(now.and_then(|now|self.assurance.on_error(id,now,jitter).map_err(|_|ErrorCode::AuthorityUnavailable)));},
                                    Command::Call{..}=>unreachable!("call handled above"),
                                }
                            }
                        }
                    },
                    _=interval.tick()=>{
                        // A fenced store is probed again with bounded backoff and a
                        // failed tick is retried; neither ends the service.
                        let (gather, accounting) = (&self.gather, &self.accounting);
                        let tick = backoff.tick(&self.storage, || async {
                            match (gather, accounting) {
                                (Some(gather), None) => Some(gather.expire().await.is_ok()),
                                (None, Some(gather)) => Some(gather.expire().await.is_ok()),
                                _ => None,
                            }
                        }).await;
                        if tick == recover::Tick::Broken { break; }
                    }
                }
            }
            self.assurance.stop();
        });
        Ok((handle, task))
    }
}
impl Handle {
    /// A controller whose owner never answers, for timeout tests.
    #[cfg(test)]
    pub(crate) fn stalled() -> (Self, impl Sized) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                sender,
                request_bytes: 1_048_576,
            },
            receiver,
        )
    }
    fn submit(&self, command: Command) -> Result<(), ErrorCode> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => ErrorCode::Capacity,
            mpsc::error::TrySendError::Closed(_) => ErrorCode::AuthorityUnavailable,
        })
    }
    pub async fn execute(&self, origin: String, call: Call) -> Result<Reply, ErrorCode> {
        if encode(&call)?.len() > self.request_bytes {
            return Err(ErrorCode::TooLarge);
        }
        let (reply, result) = oneshot::channel();
        self.submit(Command::Call {
            origin,
            call,
            reply,
        })?;
        result.await.map_err(|_| ErrorCode::AuthorityUnavailable)?
    }
    pub async fn start_feed(&self) -> Result<csrn::feed::Request, ErrorCode> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Start(reply))?;
        result.await.map_err(|_| ErrorCode::AuthorityUnavailable)?
    }
    pub async fn next_feed(&self) -> Result<Option<csrn::feed::Request>, ErrorCode> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Next(reply))?;
        result.await.map_err(|_| ErrorCode::AuthorityUnavailable)?
    }
    pub async fn complete_feed(
        &self,
        id: u64,
        bytes: Vec<u8>,
        announcement: bool,
    ) -> Result<(), ErrorCode> {
        if bytes.len() > self.request_bytes {
            return Err(ErrorCode::TooLarge);
        }
        let (reply, result) = oneshot::channel();
        self.submit(Command::Feed {
            id,
            bytes,
            announcement,
            reply,
        })?;
        result.await.map_err(|_| ErrorCode::AuthorityUnavailable)?
    }
    pub async fn failed_feed(&self, id: u64, jitter: u64) -> Result<(), ErrorCode> {
        let (reply, result) = oneshot::channel();
        self.submit(Command::Failed { id, jitter, reply })?;
        result.await.map_err(|_| ErrorCode::AuthorityUnavailable)?
    }
}
