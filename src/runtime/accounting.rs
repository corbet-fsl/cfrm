//! Wire routing only. Gather owns the complete G1/device/native-record join.
use super::*;
use cgth::accounting::{self as owner, AccountGather, Read};
mod rooms;

pub(super) struct RoomHost<'a, S> {
    pub storage: &'a S,
    pub configuration: &'a Configuration,
}

pub(super) async fn execute<S, C, R, Q>(
    gather: &mut AccountGather<S, C, R, Q>,
    origin: &str,
    request: &Request,
    verification: &cswb::Verification<'_>,
    contact: &impl Fn(&str) -> cshm::ContactCheck,
    deadline: &mut u64,
    rooms: RoomHost<'_, S>,
) -> Result<Output, ErrorCode>
where
    S: Store + Clone,
    C: Clock,
    R: cswb::Tokens,
    Q: cthl::Store,
{
    match request {
        Request::Challenge(input) => {
            let publication = cswb::Publication::from_signed(input.publication.clone())
                .map_err(|_| ErrorCode::InvalidRequest)?;
            let challenge = gather
                .challenge(origin, &publication, verification, contact)
                .await
                .map_err(error)?;
            *deadline = (*deadline).min(challenge.expires_at_ms);
            Ok(Output::Challenge(ChallengeOutput {
                challenge: encode(&challenge)?,
            }))
        }
        Request::Enter(input) => {
            let challenge = decode(&input.challenge)?;
            let presentation: owner::record::Presentation = decode(&input.record_proof)?;
            let publication = cswb::Publication::from_signed(input.publication.clone())
                .map_err(|_| ErrorCode::InvalidRequest)?;
            let (session, live) = gather
                .admit(
                    cswb::EntryProof {
                        origin,
                        challenge: &challenge,
                        signature: &input.signature,
                        publication: &publication,
                    },
                    &presentation,
                    verification,
                    contact,
                )
                .await
                .map_err(error)?;
            *deadline = (*deadline).min(live.deadline);
            Ok(Output::Enter(EnterOutput {
                session: encode(&session)?,
                revision: live.revision.0.to_vec(),
                expires_at_ms: live.deadline,
            }))
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
            let current = gather
                .authorize(
                    cswb::RequestProof {
                        origin,
                        session: &session,
                        action: request.info().name,
                        body: &body,
                        possession: &proof,
                    },
                    verification,
                    contact,
                )
                .await
                .map_err(error)?;
            *deadline = (*deadline).min(current.authority_until());
            let read = Read {
                session: &session,
                current: &current,
            };
            match request {
                Request::RoomEpoch(_) | Request::RoomIssue(_) => {
                    rooms::member(
                        gather,
                        rooms,
                        request,
                        &current,
                        verification,
                        contact,
                        deadline,
                    )
                    .await
                }
                Request::Heartbeat(input) => {
                    let value = gather
                        .heartbeat(read, revision(&input.expected_revision)?, verification)
                        .await
                        .map_err(error)?;
                    *deadline = (*deadline).min(value.deadline);
                    Ok(Output::Heartbeat(live(value)))
                }
                Request::Replace(input) => {
                    let publication = cswb::Publication::from_signed(input.publication.clone())
                        .map_err(|_| ErrorCode::InvalidRequest)?;
                    let record: owner::PublicRecord = decode(&input.record_proof)?;
                    let value = gather
                        .replace(
                            owner::Replacement {
                                read,
                                expected: revision(&input.expected_revision)?,
                                publication: &publication,
                                record: &record,
                            },
                            verification,
                            contact,
                        )
                        .await
                        .map_err(error)?;
                    *deadline = (*deadline).min(value.deadline);
                    Ok(Output::Replace(live(value)))
                }
                Request::Depart(_) => {
                    gather.depart(read, verification).await.map_err(error)?;
                    Ok(Output::Depart(EmptyOutput {}))
                }
                Request::RoomList(input) => {
                    let cursor: Option<cmmr::Cursor> =
                        input.cursor.as_deref().map(decode).transpose()?;
                    let page = gather
                        .list_rooms(
                            read,
                            cursor.as_ref(),
                            input.page_size.into(),
                            verification,
                            contact,
                        )
                        .await
                        .map_err(error)?;
                    Ok(Output::RoomList(RoomListOutput {
                        rooms: page
                            .rooms
                            .into_iter()
                            .map(|room| ListedRoom {
                                room: room.room.to_vec(),
                                name: room.name,
                                description: room.description,
                                here_now: u32::try_from(room.here_now).unwrap_or(u32::MAX),
                            })
                            .collect(),
                        cursor: page.next.as_ref().map(encode).transpose()?,
                    }))
                }
                Request::Search(input) => {
                    let cursor = input.cursor.as_deref().map(decode).transpose()?;
                    let page = gather
                        .page(
                            owner::PageRequest {
                                read,
                                cursor: cursor.as_ref(),
                                limit: input.page_size.into(),
                            },
                            verification,
                            contact,
                        )
                        .await
                        .map_err(error)?;
                    Ok(Output::Search(SearchOutput {
                        requester_revision: page.requester_revision.0.to_vec(),
                        entries: page.entries.into_iter().map(publication).collect(),
                        cursor: page.next.as_ref().map(encode).transpose()?,
                        watch: encode(&page.watch)?,
                    }))
                }
                Request::Watch(input) => {
                    let cursor = decode(&input.cursor)?;
                    let delta = gather
                        .watch(
                            owner::WatchRequest {
                                read,
                                cursor: &cursor,
                            },
                            verification,
                            contact,
                        )
                        .await
                        .map_err(error)?;
                    Ok(Output::Watch(WatchOutput {
                        requester_revision: delta.requester_revision.0.to_vec(),
                        upserts: delta.upserts.into_iter().map(publication).collect(),
                        removed: delta.removed.into_iter().map(String::into_bytes).collect(),
                        cursor: delta.next.as_ref().map(encode).transpose()?,
                        watch: encode(&delta.watch)?,
                    }))
                }
                Request::Ciphertext(input) => {
                    let member =
                        std::str::from_utf8(&input.owner).map_err(|_| ErrorCode::InvalidRequest)?;
                    let revision = u64::from_be_bytes(
                        input
                            .revision
                            .as_slice()
                            .try_into()
                            .map_err(|_| ErrorCode::InvalidRequest)?,
                    );
                    let ciphertext = gather
                        .ciphertext(
                            owner::CiphertextRequest {
                                read,
                                member,
                                revision,
                            },
                            verification,
                            contact,
                        )
                        .await
                        .map_err(error)?;
                    Ok(Output::Ciphertext(CiphertextOutput { ciphertext }))
                }
                _ => Err(ErrorCode::AuthorityUnavailable),
            }
        }
        _ => {
            rooms::anonymous(
                gather,
                request,
                verification,
                rooms.configuration.room_epoch.valid_until_ms,
                deadline,
            )
            .await
        }
    }
}

fn publication(entry: clkp::Match) -> PublicationOutput {
    PublicationOutput {
        owner: entry.member.into_bytes(),
        revision: entry.revision,
        publication: entry.publication,
    }
}
