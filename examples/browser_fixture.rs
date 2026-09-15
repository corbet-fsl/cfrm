//! TEST FIXTURE ONLY. Synthetic identities and policy, not an operator service.
//! JSON-lines stdin/stdout lets a separate CI harness bridge browser requests.
//! No sockets, production configuration, private client checkpoints or profiles.
use cfrm::{
    admission::{
        admission_bytes, device_authorization_bytes, member_id, AdmissionGrant, AdmissionTrust,
        DeviceAuthorization,
    },
    allocation::{
        allocation_bytes, policy_digest, AllocationLedger, AllocationPolicy, AllocationRequest,
    },
    board::{presence_bytes, DevicePresence, OnionEndpoint, PresenceUpdate},
    permit_issuer::{PermitIssuer, PermitRedeemer},
    permits::{PermitEpoch, RedemptionRequest, ISSUANCE_REQUEST_BYTES},
    Error,
};
use data_encoding::BASE64URL_NOPAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use openssl::rsa::Rsa;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("fixture clock")
        .as_secs()
}

fn board_row(
    trust: &AdmissionTrust,
    issuer: &SigningKey,
    root: &SigningKey,
    device: &SigningKey,
    started: u64,
) -> Result<DevicePresence, Error> {
    let root_key = B64.encode(&root.verifying_key().to_bytes());
    let device_key = device.verifying_key().to_bytes();
    let mut admission = AdmissionGrant {
        version: 1,
        issuer_key_id: B64.encode(&Sha256::digest(trust.issuer_public_key)),
        community_id: trust.community_id.clone(),
        member_id: member_id(&trust.community_id, &root_key)?,
        chat_public_key: B64.encode(&device_key),
        policy_digest: trust.policy_digest.clone(),
        issued_at: started - 1,
        expires_at: started + 1200,
        signature: String::new(),
    };
    admission.signature = B64.encode(&issuer.sign(&admission_bytes(&admission)?).to_bytes());
    let mut authorization = DeviceAuthorization {
        version: 1,
        community_id: trust.community_id.clone(),
        member_id: admission.member_id.clone(),
        root_public_key: root_key,
        device_public_key: admission.chat_public_key.clone(),
        issued_at: admission.issued_at,
        expires_at: admission.expires_at,
        signature: String::new(),
    };
    authorization.signature = B64.encode(
        &root
            .sign(&device_authorization_bytes(&authorization)?)
            .to_bytes(),
    );
    let mut checksum = sha3::Sha3_256::new();
    checksum.update(b".onion checksum");
    checksum.update(device_key);
    checksum.update([3]);
    let mut onion = device_key.to_vec();
    onion.extend_from_slice(&checksum.finalize()[..2]);
    onion.push(3);
    let mut update = PresenceUpdate {
        community_id: trust.community_id.clone(),
        member_id: admission.member_id.clone(),
        chat_public_key: admission.chat_public_key.clone(),
        sequence: 1,
        issued_at: started - 1,
        expires_at: started + 300,
        endpoint: Some(OnionEndpoint {
            host: format!(
                "{}.onion",
                data_encoding::BASE32_NOPAD
                    .encode(&onion)
                    .to_ascii_lowercase()
            ),
            port: 443,
        }),
        signature: String::new(),
    };
    update.signature = B64.encode(&device.sign(&presence_bytes(&update)?).to_bytes());
    Ok(DevicePresence {
        admission,
        authorization,
        update,
    })
}

fn board_fixture(
    trust: &AdmissionTrust,
    issuer: &SigningKey,
    started: u64,
) -> Result<Value, Error> {
    // Seeds match the existing synthetic sender and recipient roots. These are
    // public test identities, never production signing material or product limits.
    let root = SigningKey::from_bytes(&[25; 32]);
    let device = SigningKey::from_bytes(&[26; 32]);
    let primary = board_row(trust, issuer, &root, &device, started)?;
    let mut later_update = primary.update.clone();
    later_update.sequence = 2;
    later_update
        .endpoint
        .as_mut()
        .ok_or(Error::InvalidInput)?
        .port = 444;
    later_update.signature = B64.encode(&device.sign(&presence_bytes(&later_update)?).to_bytes());
    let second_device = board_row(
        trust,
        issuer,
        &root,
        &SigningKey::from_bytes(&[29; 32]),
        started,
    )?;
    let third_device = board_row(
        trust,
        issuer,
        &root,
        &SigningKey::from_bytes(&[30; 32]),
        started,
    )?;
    let other_member = board_row(
        trust,
        issuer,
        &SigningKey::from_bytes(&[27; 32]),
        &SigningKey::from_bytes(&[31; 32]),
        started,
    )?;
    let excess_member = board_row(
        trust,
        issuer,
        &SigningKey::from_bytes(&[28; 32]),
        &SigningKey::from_bytes(&[32; 32]),
        started,
    )?;
    let mut issuer_only = board_row(
        trust,
        issuer,
        &root,
        &SigningKey::from_bytes(&[33; 32]),
        started,
    )?;
    // The eligibility grant and presence signature are genuine, but the issuer
    // cannot replace the member root's device authorization with its own signature.
    issuer_only.authorization.signature = B64.encode(
        &issuer
            .sign(&device_authorization_bytes(&issuer_only.authorization)?)
            .to_bytes(),
    );
    Ok(json!({
        "trust": { "communityId": trust.community_id, "policyDigest": trust.policy_digest, "issuerPublicKey": B64.encode(&trust.issuer_public_key) },
        "limits": { "maxMembers": 2, "maxDevicesPerMember": 2, "maxLeaseSeconds": 600, "maxReplayEntries": 8 },
        "primary": primary, "laterUpdate": later_update, "secondDevice": second_device,
        "thirdDevice": third_device, "otherMember": other_member, "excessMember": excess_member,
        "issuerOnly": issuer_only,
    }))
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Command {
    Config,
    Issue {
        #[serde(rename = "blindedRequest")]
        blinded_request: String,
        nonce: String,
    },
    Redeem {
        request: RedemptionRequest,
    },
}

struct Fixture {
    epoch: PermitEpoch,
    issuer: PermitIssuer,
    redeemer: PermitRedeemer,
    ledger: AllocationLedger,
    grant: AdmissionGrant,
    authorization: DeviceAuthorization,
    device: SigningKey,
    recipient_id: String,
    other_recipient_id: String,
    policy_id: String,
    board: Value,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let started = now();
        let community = "cfrm-browser-synthetic";
        let issuer_key = SigningKey::from_bytes(&[17; 32]);
        let root = SigningKey::from_bytes(&[25; 32]);
        let device = SigningKey::from_bytes(&[26; 32]);
        let root_key = B64.encode(&root.verifying_key().to_bytes());
        let sender_id = member_id(community, &root_key)?;
        let recipient_id = member_id(
            community,
            &B64.encode(&SigningKey::from_bytes(&[27; 32]).verifying_key().to_bytes()),
        )?;
        let other_recipient_id = member_id(
            community,
            &B64.encode(&SigningKey::from_bytes(&[28; 32]).verifying_key().to_bytes()),
        )?;
        let trust = AdmissionTrust {
            community_id: community.into(),
            policy_digest: B64.encode(&[42; 32]),
            issuer_public_key: issuer_key.verifying_key().to_bytes(),
        };
        let mut grant = AdmissionGrant {
            version: 1,
            issuer_key_id: B64.encode(&Sha256::digest(trust.issuer_public_key)),
            community_id: community.into(),
            member_id: sender_id.clone(),
            chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
            policy_digest: trust.policy_digest.clone(),
            issued_at: started - 1,
            expires_at: started + 1200,
            signature: String::new(),
        };
        grant.signature = B64.encode(&issuer_key.sign(&admission_bytes(&grant)?).to_bytes());
        let mut authorization = DeviceAuthorization {
            version: 1,
            community_id: community.into(),
            member_id: sender_id,
            root_public_key: root_key,
            device_public_key: grant.chat_public_key.clone(),
            issued_at: grant.issued_at,
            expires_at: grant.expires_at,
            signature: String::new(),
        };
        authorization.signature = B64.encode(
            &root
                .sign(&device_authorization_bytes(&authorization)?)
                .to_bytes(),
        );
        let rsa = Rsa::generate(3072)?;
        let stamp_key = SigningKey::from_bytes(&[71; 32]);
        // All constants below are synthetic test values, not product defaults.
        let epoch = PermitEpoch {
            community_id: community.into(),
            epoch_id: "synthetic-shared-epoch".into(),
            valid_from: started - 1,
            issue_until: started + 600,
            expires_at: started + 900,
            public_key_der: B64.encode(&rsa.public_key_to_der()?),
            redemption_public_key: B64.encode(&stamp_key.verifying_key().to_bytes()),
        };
        let issuer = PermitIssuer::from_pkcs1_der(&epoch, &rsa.private_key_to_der()?)?;
        let redeemer = PermitRedeemer::open(":memory:", &epoch, stamp_key)?;
        let policy = AllocationPolicy {
            initial_credits: 2,
            periodic_credits: 0,
            period_seconds: 100,
            credit_cap: 2,
            max_authorization_seconds: 601,
            max_request_bytes: ISSUANCE_REQUEST_BYTES,
        };
        let policy_id = policy_digest(&policy)?;
        let board = board_fixture(&trust, &issuer_key, started)?;
        let ledger = AllocationLedger::open(":memory:", trust, policy)?;
        Ok(Self {
            epoch,
            issuer,
            redeemer,
            ledger,
            grant,
            authorization,
            device,
            recipient_id,
            other_recipient_id,
            policy_id,
            board,
        })
    }

    fn handle(&mut self, command: Command) -> Result<Value, Error> {
        match command {
            Command::Config => Ok(
                json!({ "epoch": self.epoch, "contextId": self.epoch.context_id()?, "senderId": self.grant.member_id, "recipientId": self.recipient_id, "otherRecipientId": self.other_recipient_id, "fixtureOnly": true, "board": self.board }),
            ),
            Command::Issue {
                blinded_request,
                nonce,
            } => {
                // This synthetic device signs ONLY the bounded blinded request.
                // Browser private state never enters this example process.
                if blinded_request.len() > ISSUANCE_REQUEST_BYTES * 2 || nonce.len() != 43 {
                    return Err(Error::InvalidInput);
                }
                let mut request = AllocationRequest {
                    community_id: self.grant.community_id.clone(),
                    member_id: self.grant.member_id.clone(),
                    chat_public_key: self.grant.chat_public_key.clone(),
                    policy_digest: self.policy_id.clone(),
                    nonce,
                    blinded_request,
                    issued_at: self.epoch.valid_from,
                    expires_at: self.epoch.issue_until,
                    signature: String::new(),
                };
                request.signature =
                    B64.encode(&self.device.sign(&allocation_bytes(&request)?).to_bytes());
                let response = self.issuer.issue(
                    &mut self.ledger,
                    &self.grant,
                    &self.authorization,
                    &request,
                    now,
                )?;
                Ok(
                    json!({ "blindSignature": B64.encode(&response.blind_signature), "remainingCredits": response.reservation.remaining_credits }),
                )
            }
            Command::Redeem { request } => {
                Ok(serde_json::to_value(self.redeemer.redeem(&request, now)?)
                    .map_err(|_| Error::InvalidInput)?)
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        if (&mut input)
            .take(16 * 1024 + 1)
            .read_until(b'\n', &mut line)?
            == 0
        {
            break;
        }
        if line.len() > 16 * 1024 {
            return Err("fixture input bound exceeded".into());
        }
        let result = serde_json::from_slice::<Command>(&line)
            .map_err(|_| Error::InvalidInput)
            .and_then(|command| fixture.handle(command));
        let response = match result {
            Ok(value) => json!({ "ok": true, "value": value }),
            Err(error) => json!({ "ok": false, "error": format!("{error:?}") }),
        };
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
