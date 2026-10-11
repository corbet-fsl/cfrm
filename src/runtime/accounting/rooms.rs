//! Existing wire envelopes routed to Gather's complete common-epoch authority.
use super::*;

pub(super) async fn member<S, C, R, Q>(
    gather: &mut AccountGather<S, C, R, Q>,
    host: RoomHost<'_, S>,
    request: &Request,
    current: &owner::Authorized,
    verification: &cswb::Verification<'_>,
    contact: &impl Fn(&str) -> cshm::ContactCheck,
    deadline: &mut u64,
) -> Result<Output, ErrorCode>
where
    S: Store + Clone,
    C: Clock,
    R: cswb::Tokens,
    Q: cthl::Store,
{
    let configured = host.configuration.room_epoch;
    gather
        .activate_rooms(
            host.storage.clone(),
            owner::RoomConfiguration {
                incarnation: host.configuration.incarnation.clone(),
                epoch: configured.epoch,
                valid_from_ms: configured.valid_from_ms,
                valid_until_ms: configured.valid_until_ms,
            },
            current,
            verification,
            contact,
        )
        .await
        .map_err(error)?;
    *deadline = (*deadline).min(configured.valid_until_ms);
    match request {
        Request::RoomEpoch(_) => {
            let epoch = gather
                .room_epoch(current, verification, contact)
                .await
                .map_err(error)?;
            Ok(Output::RoomEpoch(RoomEpochOutput {
                incarnation: host.configuration.incarnation.clone(),
                epoch: encode(&epoch)?,
            }))
        }
        Request::RoomIssue(input) => {
            let operation = input
                .operation
                .as_slice()
                .try_into()
                .map_err(|_| ErrorCode::InvalidRequest)?;
            let blinded = decode(&input.blinded_request)?;
            let signature = gather
                .issue_room_pass(current, operation, &blinded, verification, contact)
                .await
                .map_err(error)?;
            Ok(Output::RoomIssue(RoomIssueOutput { signature }))
        }
        _ => Err(ErrorCode::InvalidRequest),
    }
}

pub(super) async fn anonymous<S, C, R, Q>(
    gather: &mut AccountGather<S, C, R, Q>,
    request: &Request,
    verification: &cswb::Verification<'_>,
    configured_until: u64,
    deadline: &mut u64,
) -> Result<Output, ErrorCode>
where
    S: Store,
    C: Clock,
    R: cswb::Tokens,
    Q: cthl::Store,
{
    let input = match request {
        Request::RoomConnect(input)
        | Request::RoomRenew(input)
        | Request::RoomDisconnect(input)
        | Request::RoomRead(input)
        | Request::RoomOrder(input)
        | Request::RoomRelay(input)
        | Request::RoomResume(input) => input,
        // Original MLS history/key handover still requires its member owner.
        _ => return Err(ErrorCode::AuthorityUnavailable),
    };
    let command: cmbl::Request = decode(&input.command)?;
    if !matches!(
        (request, &command.action),
        (Request::RoomConnect(_), cmbl::Action::Connect { .. })
            | (Request::RoomRenew(_), cmbl::Action::Renew { .. })
            | (Request::RoomDisconnect(_), cmbl::Action::Disconnect { .. })
            | (Request::RoomRead(_), cmbl::Action::Read { .. })
            | (Request::RoomOrder(_), cmbl::Action::Order { .. })
            | (Request::RoomRelay(_), cmbl::Action::Relay { .. })
            | (Request::RoomResume(_), cmbl::Action::Resume { .. })
    ) {
        return Err(ErrorCode::InvalidRequest);
    }
    *deadline = (*deadline).min(configured_until);
    let outcome = gather
        .room(&command, &input.room_pass, verification)
        .await
        .map_err(error)?;
    let output = RoomOutput {
        result: encode(&outcome)?,
    };
    Ok(match request {
        Request::RoomConnect(_) => Output::RoomConnect(output),
        Request::RoomRenew(_) => Output::RoomRenew(output),
        Request::RoomDisconnect(_) => Output::RoomDisconnect(output),
        Request::RoomRead(_) => Output::RoomRead(output),
        Request::RoomOrder(_) => Output::RoomOrder(output),
        Request::RoomRelay(_) => Output::RoomRelay(output),
        Request::RoomResume(_) => Output::RoomResume(output),
        _ => return Err(ErrorCode::InvalidRequest),
    })
}
