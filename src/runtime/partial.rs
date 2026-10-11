//! Retained original partial-owner composition. The public service fences all
//! governed actions before reaching this path; its available calls are Settings
//! and the original credential challenge until native accounting is installed.
use super::*;

pub(super) struct Partial<'a, S, C, R, Q, F> {
    pub gather: &'a mut cgth::Gather<S, C, R, Q>,
    pub storage: &'a S,
    pub clock: &'a C,
    pub contact: &'a F,
    pub configuration: &'a Configuration,
    pub room_quota: &'a mut Option<u16>,
}
impl<S: Store + Clone, C: Clock, R: cswb::Tokens, Q: cthl::Store, F: Fn(&str) -> cshm::ContactCheck>
    Partial<'_, S, C, R, Q, F>
{
    pub async fn execute(
        &mut self,
        origin: &str,
        request: &Request,
        verification: &cswb::Verification<'_>,
        settings: &crbk::ForumSettings,
        deadline: &mut u64,
    ) -> Result<Output, ErrorCode> {
        let charter = verification.charter;
        let action = request.info().name;
        Ok(match request {
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
                    .challenge(origin, &publication, verification, self.contact)
                    .await
                    .map_err(error)?;
                *deadline = (*deadline).min(challenge.expires_at_ms);
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
                        verification,
                        self.contact,
                    )
                    .await
                    .map_err(error)?;
                *deadline = (*deadline).min(live.deadline);
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
                        verification,
                        self.contact,
                    )
                    .await
                    .map_err(error)?;
                *deadline = (*deadline).min(current.authority_until());
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
                            *self.room_quota = Some(quota);
                        }
                        if *self.room_quota != Some(quota) {
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
                        *deadline = (*deadline).min(live.deadline);
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
                                verification,
                                self.contact,
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
                                verification,
                                self.contact,
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
                                verification,
                                self.contact,
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
                                verification,
                                self.contact,
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
                if *self.room_quota != Some(room_quota(settings.room_passes_per_epoch)?) {
                    return Err(ErrorCode::AuthorityUnavailable);
                }
                let command: cmbl::Request = decode(&input.command)?;
                let correct_action = matches!(
                    (request, &command.action),
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
                match request {
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
        })
    }
}
