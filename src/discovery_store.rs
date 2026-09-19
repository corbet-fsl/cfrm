//! Lease and quota state shared by the in-memory and Valkey discovery stores.
//! No request body, read target, profile key, or reader history is retained.
use crate::{
    admission::digest,
    discovery::{
        CachedProfile, DiscoveryLimits, DiscoveryOperation, DiscoveryResponse, DiscoveryStore,
        DiscoverySummary, VerifiedDiscoveryRequest,
    },
    Error,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct Counter {
    start: u64,
    used: u64,
}

impl Counter {
    fn take(&mut self, now: u64, window: u64, maximum: u64) -> Result<(), Error> {
        let start = now / window * window;
        if self.start != start {
            self.start = start;
            self.used = 0;
        }
        if self.used >= maximum {
            return Err(Error::Capacity);
        }
        self.used += 1;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct LeaseState {
    lease_id: String,
    sequence: u64,
    expires_at: u64,
    retain_until: u64,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct MemberControl {
    pub last_now: u64,
    pub retain_until: u64,
    leases: BTreeMap<String, LeaseState>,
    replay: BTreeMap<String, ReplayMarker>,
    publish: Counter,
    discriminate: Counter,
    read: Counter,
    pub profile_sequence: u64,
    pub profile_expires_at: u64,
    pub publication_hash: String,
    discriminator_hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct ReplayMarker {
    expires_at: u64,
    write_digest: Option<String>,
}

impl MemberControl {
    pub(crate) fn live_until(&self, now: u64) -> u64 {
        self.leases
            .values()
            .map(|v| v.expires_at)
            .filter(|v| *v > now)
            .max()
            .unwrap_or(0)
            .min(self.profile_expires_at)
    }
}

pub(crate) struct Change {
    pub control: MemberControl,
    pub publication: Option<CachedProfile>,
    pub retry: bool,
}

pub(crate) fn transition(
    mut state: MemberControl,
    request: &VerifiedDiscoveryRequest,
    limits: &DiscoveryLimits,
    now: u64,
) -> Result<Change, Error> {
    if now < state.last_now {
        return Err(Error::ClockRollback);
    }
    if request.issued_at > now || now >= request.expires_at {
        return Err(Error::Expired);
    }
    state.last_now = now;
    state.replay.retain(|_, marker| marker.expires_at > now);
    state.leases.retain(|_, lease| lease.retain_until > now);
    let marker = digest(
        &serde_json::to_vec(&(
            "cfrm.discovery.replay.v1",
            &request.community_id,
            &request.member_id,
            &request.session_id,
            &request.request_id,
        ))
        .map_err(|_| Error::InvalidInput)?,
    );
    let is_write = !matches!(
        request.operation,
        DiscoveryOperation::Query { .. } | DiscoveryOperation::Fetch { .. }
    );
    let write_digest = if is_write {
        Some(digest(
            &serde_json::to_vec(&(
                &request.chat_public_key,
                request.issued_at,
                request.expires_at,
                &request.operation,
            ))
            .map_err(|_| Error::InvalidInput)?,
        ))
    } else {
        None
    };
    if let Some(previous) = state.replay.get(&marker) {
        if write_digest.is_some() && previous.write_digest == write_digest {
            return Ok(Change {
                control: state,
                publication: None,
                retry: true,
            });
        }
        return Err(Error::Replay);
    }
    if state.replay.len() >= limits.max_replay_entries {
        return Err(Error::Capacity);
    }
    state.replay.insert(
        marker,
        ReplayMarker {
            expires_at: request.expires_at,
            write_digest,
        },
    );
    let longest_window = limits
        .publish_window_seconds
        .max(limits.discriminator_window_seconds)
        .max(limits.read_window_seconds)
        .max(limits.max_request_seconds)
        .max(limits.max_lease_seconds);
    state.retain_until = state
        .retain_until
        .max(now.checked_add(longest_window).ok_or(Error::InvalidInput)?);
    let mut publication = None;
    match &request.operation {
        DiscoveryOperation::Publish {
            publication: value,
            lease,
        } => {
            let serialized = serde_json::to_vec(value).map_err(|_| Error::InvalidInput)?;
            let hash = digest(&serialized);
            let sequence = value.envelope.sequence;
            if sequence < state.profile_sequence
                || (sequence == state.profile_sequence && hash != state.publication_hash)
            {
                return Err(Error::Replay);
            }
            // A fresh authenticated wrapper may repair an evicted slot after
            // the original request expired. Identical current bytes do not
            // create a publication or a covert public-field update.
            let same_publication =
                sequence == state.profile_sequence && hash == state.publication_hash;
            if !same_publication {
                state
                    .publish
                    .take(now, limits.publish_window_seconds, limits.publish_limit)?;
            }
            let discriminators = digest(
                &serde_json::to_vec(&value.envelope.discriminators)
                    .map_err(|_| Error::InvalidInput)?,
            );
            if !same_publication && state.discriminator_hash != discriminators {
                state.discriminate.take(
                    now,
                    limits.discriminator_window_seconds,
                    limits.discriminator_limit,
                )?;
            }
            update_lease(&mut state, request, lease, limits, now)?;
            state.profile_sequence = sequence;
            state.profile_expires_at = value.envelope.expires_at;
            state.publication_hash = hash;
            state.discriminator_hash = discriminators;
            state.retain_until = state.retain_until.max(value.envelope.expires_at);
            publication = Some(value.clone());
        }
        DiscoveryOperation::Heartbeat { lease } => {
            update_lease(&mut state, request, lease, limits, now)?;
        }
        DiscoveryOperation::Disconnect { lease_id, sequence } => {
            let previous = state
                .leases
                .get_mut(&request.chat_public_key)
                .ok_or(Error::Replay)?;
            if previous.lease_id != *lease_id || *sequence <= previous.sequence {
                return Err(Error::Replay);
            }
            previous.sequence = *sequence;
            previous.expires_at = now;
            previous.retain_until = previous.retain_until.max(
                now.checked_add(limits.max_request_seconds)
                    .ok_or(Error::InvalidInput)?,
            );
        }
        DiscoveryOperation::Query { .. } | DiscoveryOperation::Fetch { .. } => {
            state
                .read
                .take(now, limits.read_window_seconds, limits.read_limit)?;
        }
    }
    Ok(Change {
        control: state,
        publication,
        retry: false,
    })
}

fn update_lease(
    state: &mut MemberControl,
    request: &VerifiedDiscoveryRequest,
    lease: &crate::discovery::DiscoveryLease,
    limits: &DiscoveryLimits,
    now: u64,
) -> Result<(), Error> {
    if let Some(previous) = state.leases.get(&request.chat_public_key) {
        if lease.sequence <= previous.sequence {
            return Err(Error::Replay);
        }
        // A different session may replace a device, but cannot replay its older lease.
    } else if state.leases.len() >= limits.max_devices_per_member {
        return Err(Error::Capacity);
    }
    if lease.expires_at <= now {
        return Err(Error::Expired);
    }
    let retain_until = lease.expires_at.max(
        now.checked_add(limits.max_request_seconds)
            .ok_or(Error::InvalidInput)?,
    );
    state.leases.insert(
        request.chat_public_key.clone(),
        LeaseState {
            lease_id: lease.lease_id.clone(),
            sequence: lease.sequence,
            expires_at: lease.expires_at,
            retain_until,
        },
    );
    state.retain_until = state.retain_until.max(retain_until);
    Ok(())
}

pub(crate) fn summary(publication: &CachedProfile, expires_at: u64) -> DiscoverySummary {
    let envelope = &publication.envelope;
    DiscoverySummary {
        member_id: envelope.member_id.clone(),
        chat_public_key: envelope.chat_public_key.clone(),
        profile_digest: envelope.profile_digest.clone(),
        sequence: envelope.sequence,
        discriminators: envelope.discriminators.clone(),
        expires_at,
    }
}

/// Reserve enough bytes for a full cursor even on the final page. The cursor
/// advances only past entries actually returned or nonmatching entries scanned.
pub(crate) struct QueryPage {
    entries: Vec<DiscoverySummary>,
    bytes: usize,
    maximum: usize,
    last_scanned: Option<String>,
}

impl QueryPage {
    pub(crate) fn new(maximum: usize) -> Result<Self, Error> {
        let bytes = serde_json::to_vec(&DiscoveryResponse::Page {
            entries: Vec::new(),
            next_cursor: Some("A".repeat(43)),
        })
        .map_err(|_| Error::Storage)?
        .len();
        if bytes > maximum {
            return Err(Error::Capacity);
        }
        Ok(Self {
            entries: Vec::new(),
            bytes,
            maximum,
            last_scanned: None,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn consider(
        &mut self,
        member: &str,
        entry: Option<DiscoverySummary>,
    ) -> Result<bool, Error> {
        if let Some(entry) = entry {
            let length = serde_json::to_vec(&entry)
                .map_err(|_| Error::Storage)?
                .len();
            let next = self
                .bytes
                .checked_add(length)
                .and_then(|n| n.checked_add(usize::from(!self.entries.is_empty())))
                .ok_or(Error::Capacity)?;
            if next > self.maximum {
                // Do not return a nonadvancing cursor for an impossible first
                // entry. A configuration error needs a clear terminal failure.
                if self.entries.is_empty() && self.last_scanned.is_none() {
                    return Err(Error::Capacity);
                }
                return Ok(false);
            }
            self.bytes = next;
            self.entries.push(entry);
        }
        self.last_scanned = Some(member.to_owned());
        Ok(true)
    }

    pub(crate) fn finish(self, more: bool) -> DiscoveryResponse {
        DiscoveryResponse::Page {
            entries: self.entries,
            next_cursor: if more { self.last_scanned } else { None },
        }
    }
}

#[derive(Default)]
struct Community {
    last_now: u64,
    controls: BTreeMap<String, MemberControl>,
    profiles: BTreeMap<String, (CachedProfile, u64)>,
}

/// Deterministic reference store and single-process embedding. A restart loses
/// ephemeral discovery and quotas; durable reciprocity state lives elsewhere.
#[derive(Default)]
pub struct MemoryDiscoveryStore {
    communities: Mutex<BTreeMap<String, Community>>,
}

impl MemoryDiscoveryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DiscoveryStore for MemoryDiscoveryStore {
    fn execute(
        &self,
        request: &VerifiedDiscoveryRequest,
        limits: &DiscoveryLimits,
        now: u64,
    ) -> Result<DiscoveryResponse, Error> {
        let mut communities = self.communities.lock().map_err(|_| Error::Storage)?;
        let community = communities.entry(request.community_id.clone()).or_default();
        if now < community.last_now {
            return Err(Error::ClockRollback);
        }
        community.last_now = now;
        community
            .controls
            .retain(|_, value| value.retain_until > now);
        community.profiles.retain(|_, (_, until)| *until > now);
        if !community.controls.contains_key(&request.member_id)
            && community.controls.len() >= limits.max_members
        {
            return Err(Error::Capacity);
        }
        let change = transition(
            community
                .controls
                .get(&request.member_id)
                .cloned()
                .unwrap_or_default(),
            request,
            limits,
            now,
        )?;
        if change.retry {
            return Ok(DiscoveryResponse::Updated);
        }
        let live_until = change.control.live_until(now);
        let previous = community
            .profiles
            .get(&request.member_id)
            .map(|(value, _)| value.clone());
        let publication = change.publication.or(previous);
        if let Some(publication) = publication {
            if live_until > now {
                community
                    .profiles
                    .insert(request.member_id.clone(), (publication, live_until));
            } else {
                community.profiles.remove(&request.member_id);
            }
        }
        community
            .controls
            .insert(request.member_id.clone(), change.control);
        match &request.operation {
            DiscoveryOperation::Query {
                filters,
                limit,
                after,
            } => {
                let mut page = QueryPage::new(limits.max_response_bytes)?;
                let mut scanned = 0;
                let mut more = false;
                for (member, (publication, until)) in &community.profiles {
                    if after.as_ref().is_some_and(|cursor| member <= cursor) {
                        continue;
                    }
                    if scanned >= limits.max_scan || page.len() >= *limit {
                        more = true;
                        break;
                    }
                    let entry = filters
                        .iter()
                        .all(|(key, value)| {
                            publication.envelope.discriminators.get(key) == Some(value)
                        })
                        .then(|| summary(publication, *until));
                    if !page.consider(member, entry)? {
                        more = true;
                        break;
                    }
                    scanned += 1;
                }
                Ok(page.finish(more))
            }
            DiscoveryOperation::Fetch { member_id } => Ok(DiscoveryResponse::Profile {
                publication: community
                    .profiles
                    .get(member_id)
                    .map(|(value, _)| value.clone()),
            }),
            _ => Ok(DiscoveryResponse::Updated),
        }
    }
}
