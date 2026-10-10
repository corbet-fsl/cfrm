//! Service composition and supervised lifetime. Cryptographic, storage, match
//! and quota decisions remain in Assurance, Gather and Volatile's owners.
use crate::*;
use cgth::{clkp, cmbl, cmmr, cswb, cthl};
use cmmr::{Clock, Store};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

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
    pub maximum_snapshot_age: u64,
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
    gather: cgth::Gather<S, C, R, Q>,
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
            || configuration.maximum_snapshot_age == 0
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
            gather: cgth::Gather::new(presence, parts.throttle, rooms, lookup),
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
        self.gather
            .preflight(b"forum", action)
            .await
            .map_err(error)?;
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
            maximum_snapshot_age: self.configuration.maximum_snapshot_age,
        };
        let settings = crbk::ForumSettings::from_snapshot(
            charter
                .settings(now)
                .map_err(|_| ErrorCode::AuthorityUnavailable)?,
        )
        .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        if settings.lease_ms > self.configuration.presence.lease_ms {
            return Err(ErrorCode::AuthorityUnavailable);
        }
        let mut authority_deadline = charter
            .valid_until()
            .checked_mul(1000)
            .ok_or(ErrorCode::AuthorityUnavailable)?;
        let output = match &call.request {
            Request::Settings(_) => Output::Settings(SettingsOutput {
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
            }),
            Request::Challenge(input) => {
                let publication = cswb::Publication::from_signed(input.publication.clone())
                    .map_err(|_| ErrorCode::InvalidRequest)?;
                let challenge = self
                    .gather
                    .challenge(origin, &publication, &verification, &self.contact)
                    .await
                    .map_err(error)?;
                Output::Challenge(ChallengeOutput {
                    challenge: encode(&challenge)?,
                })
            }
            Request::Enter(input) => {
                if !input.record_proof.is_empty() {
                    return Err(ErrorCode::InvalidRequest);
                }
                let challenge = decode(&input.challenge)?;
                let publication = cswb::Publication::from_signed(input.publication.clone())
                    .map_err(|_| ErrorCode::InvalidRequest)?;
                let (session, live) = self
                    .gather
                    .admit(
                        cswb::EntryProof {
                            origin,
                            challenge: &challenge,
                            signature: &input.signature,
                            publication: &publication,
                        },
                        &verification,
                        &self.contact,
                    )
                    .await
                    .map_err(error)?;
                Output::Enter(EnterOutput {
                    session: encode(&session)?,
                    revision: live.revision.0.to_vec(),
                    expires_at_ms: live.deadline,
                })
            }
            request if request.possession().is_some() => {
                let possession = request.possession().ok_or(ErrorCode::InvalidRequest)?;
                let session: cswb::Session = decode(&possession.session)?;
                let proof = cswb::Possession {
                    nonce: possession
                        .request_nonce
                        .as_slice()
                        .try_into()
                        .map_err(|_| ErrorCode::InvalidRequest)?,
                    signature: possession.signature.clone(),
                };
                let body = request.unsigned_bytes()?;
                let current = self
                    .gather
                    .authorize(
                        cswb::RequestProof {
                            origin,
                            session: &session,
                            action,
                            body: &body,
                            possession: &proof,
                        },
                        &verification,
                        &self.contact,
                    )
                    .await
                    .map_err(error)?;
                authority_deadline = authority_deadline.min(current.authority_until());
                match request {
                    Request::RoomEpoch(_) | Request::RoomIssue(_) => {
                        let quota = room_quota(settings.room_passes_per_epoch)?;
                        if self.room_quota.is_none() {
                            let epoch = self.configuration.room_epoch;
                            let current_time = self
                                .clock
                                .now()
                                .map_err(|_| ErrorCode::AuthorityUnavailable)?;
                            if current_time < epoch.valid_from_ms
                                || current_time >= epoch.valid_until_ms
                            {
                                return Err(ErrorCode::AuthorityUnavailable);
                            }
                            let issuer = cmbl::passes::issuer::BudgetedIssuer::create(
                                self.storage.clone(),
                                self.configuration.community.clone(),
                                epoch.epoch,
                                epoch.valid_from_ms,
                                epoch.valid_until_ms,
                                quota,
                            )
                            .await
                            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
                            self.gather.install_room_issuer(issuer).map_err(error)?;
                            self.room_quota = Some(quota);
                        }
                        if self.room_quota != Some(quota) {
                            return Err(ErrorCode::AuthorityUnavailable);
                        }
                        // RSA creation and original storage calls may await. Never
                        // extend a sealed admission past its exclusive deadline.
                        let current_time = self
                            .clock
                            .now()
                            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
                        if current_time >= current.authority_until() {
                            return Err(ErrorCode::ResetRequired);
                        }
                        let live = self.gather.read(&session, &current).await.map_err(error)?;
                        authority_deadline = authority_deadline.min(live.deadline);
                        match request {
                            Request::RoomEpoch(_) => {
                                let epoch =
                                    self.gather.room_epoch(current_time).await.map_err(error)?;
                                Output::RoomEpoch(RoomEpochOutput {
                                    incarnation: self.configuration.incarnation.clone(),
                                    epoch: encode(epoch)?,
                                })
                            }
                            Request::RoomIssue(input) => {
                                let operation = input
                                    .operation
                                    .as_slice()
                                    .try_into()
                                    .map_err(|_| ErrorCode::InvalidRequest)?;
                                let blinded = decode(&input.blinded_request)?;
                                let signature = self
                                    .gather
                                    .issue_room_pass(&current, operation, &blinded, current_time)
                                    .await
                                    .map_err(error)?;
                                Output::RoomIssue(RoomIssueOutput { signature })
                            }
                            _ => return Err(ErrorCode::InvalidRequest),
                        }
                    }
                    Request::Heartbeat(input) => Output::Heartbeat(live(
                        self.gather
                            .heartbeat(&session, &current, revision(&input.expected_revision)?)
                            .await
                            .map_err(error)?,
                    )),
                    Request::Replace(input) => {
                        if !input.record_proof.is_empty() {
                            return Err(ErrorCode::InvalidRequest);
                        }
                        let publication = cswb::Publication::from_signed(input.publication.clone())
                            .map_err(|_| ErrorCode::InvalidRequest)?;
                        let admission = self
                            .gather
                            .replacement(
                                &session,
                                &current,
                                &publication,
                                &verification,
                                &self.contact,
                            )
                            .await
                            .map_err(error)?;
                        Output::Replace(live(
                            self.gather
                                .replace(
                                    &session,
                                    &current,
                                    revision(&input.expected_revision)?,
                                    admission,
                                )
                                .await
                                .map_err(error)?,
                        ))
                    }
                    Request::Depart(_) => {
                        self.gather.depart(&session).await.map_err(error)?;
                        Output::Depart(EmptyOutput {})
                    }
                    Request::Search(input) => {
                        let cursor = input.cursor.as_deref().map(decode).transpose()?;
                        let page = self
                            .gather
                            .page(
                                clkp::PageRequest {
                                    session: &session,
                                    current: &current,
                                    cursor: cursor.as_ref(),
                                    limit: input.page_size.into(),
                                },
                                &verification,
                                &self.contact,
                            )
                            .await
                            .map_err(error)?;
                        Output::Search(SearchOutput {
                            requester_revision: page.requester_revision.0.to_vec(),
                            entries: page
                                .entries
                                .into_iter()
                                .map(|entry| PublicationOutput {
                                    owner: entry.member.into_bytes(),
                                    revision: entry.revision,
                                    publication: entry.publication,
                                })
                                .collect(),
                            cursor: page.next.as_ref().map(encode).transpose()?,
                            watch: encode(&page.watch)?,
                        })
                    }
                    Request::Watch(input) => {
                        let cursor = decode(&input.cursor)?;
                        let delta = self
                            .gather
                            .watch(
                                clkp::WatchRequest {
                                    session: &session,
                                    current: &current,
                                    cursor: &cursor,
                                },
                                &verification,
                                &self.contact,
                            )
                            .await
                            .map_err(error)?;
                        Output::Watch(WatchOutput {
                            requester_revision: delta.requester_revision.0.to_vec(),
                            upserts: delta
                                .upserts
                                .into_iter()
                                .map(|entry| PublicationOutput {
                                    owner: entry.member.into_bytes(),
                                    revision: entry.revision,
                                    publication: entry.publication,
                                })
                                .collect(),
                            removed: delta.removed.into_iter().map(String::into_bytes).collect(),
                            cursor: delta.next.as_ref().map(encode).transpose()?,
                            watch: encode(&delta.watch)?,
                        })
                    }
                    Request::Ciphertext(input) => {
                        let owner = std::str::from_utf8(&input.owner)
                            .map_err(|_| ErrorCode::InvalidRequest)?;
                        let expected = u64::from_be_bytes(
                            input
                                .revision
                                .as_slice()
                                .try_into()
                                .map_err(|_| ErrorCode::InvalidRequest)?,
                        );
                        let ciphertext = self
                            .gather
                            .ciphertext(
                                clkp::PageRequest {
                                    session: &session,
                                    current: &current,
                                    cursor: None,
                                    limit: 1,
                                },
                                (owner, expected),
                                &verification,
                                &self.contact,
                            )
                            .await
                            .map_err(error)?;
                        Output::Ciphertext(CiphertextOutput { ciphertext })
                    }
                    _ => return Err(ErrorCode::InvalidRequest),
                }
            }
            Request::RoomConnect(input)
            | Request::RoomRenew(input)
            | Request::RoomDisconnect(input)
            | Request::RoomRead(input)
            | Request::RoomOrder(input)
            | Request::RoomRelay(input)
            | Request::RoomResume(input) => {
                if self.room_quota != Some(room_quota(settings.room_passes_per_epoch)?) {
                    return Err(ErrorCode::AuthorityUnavailable);
                }
                let command: cmbl::Request = decode(&input.command)?;
                let correct_action = matches!(
                    (&call.request, &command.action),
                    (Request::RoomConnect(_), cmbl::Action::Connect { .. })
                        | (Request::RoomRenew(_), cmbl::Action::Renew { .. })
                        | (Request::RoomDisconnect(_), cmbl::Action::Disconnect { .. })
                        | (Request::RoomRead(_), cmbl::Action::Read { .. })
                        | (Request::RoomOrder(_), cmbl::Action::Order { .. })
                        | (Request::RoomRelay(_), cmbl::Action::Relay { .. })
                        | (Request::RoomResume(_), cmbl::Action::Resume { .. })
                );
                if !correct_action {
                    return Err(ErrorCode::InvalidRequest);
                }
                let current_time = self
                    .clock
                    .now()
                    .map_err(|_| ErrorCode::AuthorityUnavailable)?;
                let epoch = self.gather.room_epoch(current_time).await.map_err(error)?;
                let verifier = cmbl::passes::Verifier::new(
                    epoch.clone(),
                    self.configuration.incarnation.clone(),
                )
                .map_err(|_| ErrorCode::AuthorityUnavailable)?;
                let outcome = self
                    .gather
                    .room(&command, &input.room_pass, &verifier, current_time)
                    .await
                    .map_err(error)?;
                let output = RoomOutput {
                    result: encode(&outcome)?,
                };
                match &call.request {
                    Request::RoomConnect(_) => Output::RoomConnect(output),
                    Request::RoomRenew(_) => Output::RoomRenew(output),
                    Request::RoomDisconnect(_) => Output::RoomDisconnect(output),
                    Request::RoomRead(_) => Output::RoomRead(output),
                    Request::RoomOrder(_) => Output::RoomOrder(output),
                    Request::RoomRelay(_) => Output::RoomRelay(output),
                    Request::RoomResume(_) => Output::RoomResume(output),
                    _ => return Err(ErrorCode::InvalidRequest),
                }
            }
            // MLS history/key handover still requires its original member owner.
            _ => return Err(ErrorCode::AuthorityUnavailable),
        };
        let completed_at_ms = self
            .clock
            .now()
            .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        if completed_at_ms < now_ms || completed_at_ms >= authority_deadline {
            return Err(ErrorCode::AuthorityUnavailable);
        }
        Ok(Reply::new(output))
    }
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
    S: Store + Clone + 'static,
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
                    _=interval.tick()=>{if self.gather.expire().await.is_err(){break;}}
                }
            }
            self.assurance.stop();
        });
        Ok((handle, task))
    }
}
impl Handle {
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
