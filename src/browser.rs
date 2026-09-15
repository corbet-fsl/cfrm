//! Browser-only adapters for public meeting-board verification and bearer permits. These never
//! fetch, choose an issuer, sign private RSA operations or expose private claims.
//! JavaScript owns trusted configuration, encrypted storage and Tor transport.
use crate::{
    admission::{decode, AdmissionGrant, AdmissionTrust, DeviceAuthorization, MAX_INTEGER},
    board::{BoardLimits, MeetingBoard, PresenceUpdate},
    permits::{Permit, PermitEpoch, PreparedPermit, RecipientClaim, RedemptionStamp},
    Error,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{de::DeserializeOwned, Deserialize};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

const MAX_JSON: usize = 8192;
const MAX_STORE: usize = 16 * 1024;
const STORE_HEADER: &[u8] = b"cfrm-browser-store-v1\0";

fn js_error(error: Error) -> JsValue {
    JsValue::from_str(&format!("cfrm:{error:?}"))
}

fn now() -> Result<u64, JsValue> {
    let seconds = js_sys::Date::now() / 1000.0;
    if !seconds.is_finite() || seconds < 1.0 || seconds > MAX_INTEGER as f64 {
        return Err(js_error(Error::Expired));
    }
    Ok(seconds as u64)
}

fn parse<T: DeserializeOwned>(json: &str) -> Result<T, JsValue> {
    if json.len() > MAX_JSON {
        return Err(js_error(Error::InvalidInput));
    }
    serde_json::from_str(json).map_err(|_| js_error(Error::InvalidInput))
}

/// Configuration belongs to the caller's independently trusted catalogue, not
/// to the untrusted roster response. Keys use canonical base64url encoding.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoardTrustInput {
    community_id: String,
    policy_digest: String,
    issuer_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BoardLimitsInput {
    max_members: usize,
    max_devices_per_member: usize,
    max_lease_seconds: u64,
    max_replay_entries: usize,
}

/// Verifies public rows against pinned trust and groups certified devices under
/// their permanent member identity. No network access or recipient lookup occurs.
/// Replay and clock floors last for this instance only. A valid partial snapshot
/// does not prove completeness, current availability, or absence of revocation.
#[wasm_bindgen]
pub struct BrowserMeetingBoard {
    board: MeetingBoard,
}

#[wasm_bindgen]
impl BrowserMeetingBoard {
    #[wasm_bindgen(constructor)]
    pub fn new(pinned_trust_json: &str, limits_json: &str) -> Result<BrowserMeetingBoard, JsValue> {
        let trust: BoardTrustInput = parse(pinned_trust_json)?;
        let limits: BoardLimitsInput = parse(limits_json)?;
        let issuer_public_key = decode::<32>(&trust.issuer_public_key).map_err(js_error)?;
        if ed25519_dalek::VerifyingKey::from_bytes(&issuer_public_key)
            .map_err(|_| js_error(Error::Admission))?
            .is_weak()
        {
            return Err(js_error(Error::Admission));
        }
        let mut board = MeetingBoard::new(
            AdmissionTrust {
                community_id: trust.community_id,
                policy_digest: trust.policy_digest,
                issuer_public_key,
            },
            BoardLimits {
                max_members: limits.max_members,
                max_devices_per_member: limits.max_devices_per_member,
                max_lease_seconds: limits.max_lease_seconds,
                max_replay_entries: limits.max_replay_entries,
            },
        )
        .map_err(js_error)?;
        // Establish the clock floor when the trusted verifier is constructed.
        board.snapshot(now()?).map_err(js_error)?;
        Ok(Self { board })
    }

    /// All three signed objects are untrusted and bounded independently before
    /// deserialization. The core checks root ownership, lease and sequence rules.
    pub fn apply(
        &mut self,
        admission_json: &str,
        authorization_json: &str,
        presence_json: &str,
    ) -> Result<(), JsValue> {
        let admission: AdmissionGrant = parse(admission_json)?;
        let authorization: DeviceAuthorization = parse(authorization_json)?;
        let presence: PresenceUpdate = parse(presence_json)?;
        self.board
            .apply(&admission, &authorization, &presence, now()?)
            .map_err(js_error)
    }

    /// Returns only currently unexpired public rows, retaining the independently
    /// verifiable originals. This does not attest that the operator showed all rows.
    pub fn snapshot(&mut self) -> Result<String, JsValue> {
        serde_json::to_string(&self.board.snapshot(now()?).map_err(js_error)?)
            .map_err(|_| js_error(Error::InvalidInput))
    }
}

fn epoch(json: &str, expected_context: &str) -> Result<PermitEpoch, JsValue> {
    decode::<32>(expected_context).map_err(js_error)?;
    let epoch: PermitEpoch = parse(json)?;
    if epoch.context_id().map_err(js_error)? != expected_context {
        return Err(js_error(Error::Admission));
    }
    Ok(epoch)
}

fn aad(kind: &str, epoch: &PermitEpoch, context: &[u8]) -> Result<Vec<u8>, JsValue> {
    if context.is_empty() || context.len() > 128 {
        return Err(js_error(Error::InvalidInput));
    }
    serde_json::to_vec(&serde_json::json!([
        "cfrm.browser.checkpoint.v1",
        kind,
        epoch.context_id().map_err(js_error)?,
        data_encoding::BASE64URL_NOPAD.encode(context),
    ]))
    .map_err(|_| js_error(Error::InvalidInput))
}

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, JsValue> {
    let key: Zeroizing<[u8; 32]> =
        Zeroizing::new(key.try_into().map_err(|_| js_error(Error::InvalidInput))?);
    Ok(XChaCha20Poly1305::new((&*key).into()))
}

fn seal(bytes: &[u8], key: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsValue> {
    if bytes.len() > MAX_JSON {
        return Err(js_error(Error::InvalidInput));
    }
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| js_error(Error::CryptoProvider))?;
    let encrypted = cipher(key)?
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: bytes, aad })
        .map_err(|_| js_error(Error::Storage))?;
    Ok([STORE_HEADER, nonce.as_slice(), &encrypted].concat())
}

fn open(bytes: &[u8], key: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let offset = STORE_HEADER.len();
    if bytes.len() < offset + 24 + 16 || bytes.len() > MAX_STORE || !bytes.starts_with(STORE_HEADER)
    {
        return Err(js_error(Error::Storage));
    }
    cipher(key)?
        .decrypt(
            XNonce::from_slice(&bytes[offset..offset + 24]),
            Payload {
                msg: &bytes[offset + 24..],
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| js_error(Error::Storage))
}

/// Call free() when finished. The private checkpoint is exported only encrypted;
/// JavaScript must durably save seal() before submitting issuanceRequest().
/// Same-origin JavaScript can inspect Wasm memory; this is not a sandbox for JS.
#[wasm_bindgen]
pub struct BrowserPreparedPermit {
    epoch: PermitEpoch,
    prepared: PreparedPermit,
}

#[wasm_bindgen]
impl BrowserPreparedPermit {
    #[wasm_bindgen(constructor)]
    pub fn new(
        epoch_json: &str,
        expected_context_id: &str,
    ) -> Result<BrowserPreparedPermit, JsValue> {
        let epoch = epoch(epoch_json, expected_context_id)?;
        let prepared = PreparedPermit::new(&epoch, now()?).map_err(js_error)?;
        Ok(Self { epoch, prepared })
    }

    #[wasm_bindgen(js_name = issuanceRequest)]
    pub fn issuance_request(&self) -> Vec<u8> {
        self.prepared.issuance_request()
    }

    /// Returns only the public bearer permit JSON, after Rust verifies the reply.
    pub fn finalize(&self, blind_signature: &[u8]) -> Result<String, JsValue> {
        serde_json::to_string(
            &self
                .prepared
                .finalize(blind_signature, now()?)
                .map_err(js_error)?,
        )
        .map_err(|_| js_error(Error::InvalidInput))
    }

    pub fn seal(&self, wrapping_key: &[u8], storage_context: &[u8]) -> Result<Vec<u8>, JsValue> {
        seal(
            &self.prepared.export_private(),
            wrapping_key,
            &aad("prepared", &self.epoch, storage_context)?,
        )
    }

    pub fn restore(
        epoch_json: &str,
        expected_context_id: &str,
        encrypted: &[u8],
        wrapping_key: &[u8],
        storage_context: &[u8],
    ) -> Result<BrowserPreparedPermit, JsValue> {
        let epoch = epoch(epoch_json, expected_context_id)?;
        epoch.check_time(now()?, false).map_err(js_error)?;
        let bytes = open(
            encrypted,
            wrapping_key,
            &aad("prepared", &epoch, storage_context)?,
        )?;
        let prepared = PreparedPermit::restore_private(&epoch, &bytes).map_err(js_error)?;
        Ok(Self { epoch, prepared })
    }
}

/// Expected peer data comes from the authenticated cmsg invitation and local
/// identity, never from an issuer or a sender-supplied redemption claim.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Introduction {
    sender_id: String,
    recipient_id: String,
    introduction_id: String,
    challenge: String,
}

impl Introduction {
    fn matches(&self, claim: &RecipientClaim) -> bool {
        self.sender_id == claim.binding.sender_id
            && self.recipient_id == claim.binding.recipient_id
            && self.introduction_id == claim.binding.introduction_id
            && self.challenge == claim.binding.challenge
    }
}

/// The binding stays private. Persist seal() before anonymousRequest() is sent.
/// An exact retry uses restore() and independently expected invitation metadata.
#[wasm_bindgen]
pub struct BrowserRecipientClaim {
    epoch: PermitEpoch,
    claim: RecipientClaim,
}

impl Drop for BrowserRecipientClaim {
    fn drop(&mut self) {
        self.claim.binding.sender_id.zeroize();
        self.claim.binding.recipient_id.zeroize();
        self.claim.binding.introduction_id.zeroize();
        self.claim.binding.challenge.zeroize();
        self.claim.binding.salt.zeroize();
        self.claim.request.claim.zeroize();
        self.claim.request.permit.serial.zeroize();
        self.claim.request.permit.randomizer.zeroize();
    }
}

#[wasm_bindgen]
impl BrowserRecipientClaim {
    #[wasm_bindgen(constructor)]
    pub fn new(
        epoch_json: &str,
        expected_context_id: &str,
        permit_json: &str,
        introduction_json: &str,
    ) -> Result<BrowserRecipientClaim, JsValue> {
        let epoch = epoch(epoch_json, expected_context_id)?;
        let permit: Permit = parse(permit_json)?;
        let intro: Introduction = parse(introduction_json)?;
        let claim = RecipientClaim::new(
            &epoch,
            permit,
            &intro.sender_id,
            &intro.recipient_id,
            decode(&intro.introduction_id).map_err(js_error)?,
            decode(&intro.challenge).map_err(js_error)?,
            now()?,
        )
        .map_err(js_error)?;
        Ok(Self { epoch, claim })
    }

    #[wasm_bindgen(js_name = anonymousRequest)]
    pub fn anonymous_request(&self) -> Result<String, JsValue> {
        self.claim
            .request
            .permit
            .verify(&self.epoch, now()?)
            .map_err(js_error)?;
        serde_json::to_string(&self.claim.request).map_err(|_| js_error(Error::InvalidInput))
    }

    #[wasm_bindgen(js_name = verifyStamp)]
    pub fn verify_stamp(&self, stamp_json: &str) -> Result<(), JsValue> {
        let stamp: RedemptionStamp = parse(stamp_json)?;
        self.claim
            .verify_stamp(&self.epoch, &stamp, now()?)
            .map_err(js_error)
    }

    pub fn seal(&self, wrapping_key: &[u8], storage_context: &[u8]) -> Result<Vec<u8>, JsValue> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(&self.claim).map_err(|_| js_error(Error::InvalidInput))?,
        );
        seal(
            &bytes,
            wrapping_key,
            &aad("recipient", &self.epoch, storage_context)?,
        )
    }

    pub fn restore(
        epoch_json: &str,
        expected_context_id: &str,
        encrypted: &[u8],
        wrapping_key: &[u8],
        storage_context: &[u8],
        expected_introduction_json: &str,
    ) -> Result<BrowserRecipientClaim, JsValue> {
        let epoch = epoch(epoch_json, expected_context_id)?;
        let bytes = open(
            encrypted,
            wrapping_key,
            &aad("recipient", &epoch, storage_context)?,
        )?;
        let claim: RecipientClaim =
            serde_json::from_slice(&bytes).map_err(|_| js_error(Error::Storage))?;
        let restored = Self { epoch, claim };
        let expected: Introduction = parse(expected_introduction_json)?;
        if !expected.matches(&restored.claim) {
            return Err(js_error(Error::Admission));
        }
        restored
            .claim
            .request
            .permit
            .verify(&restored.epoch, now()?)
            .map_err(js_error)?;
        Ok(restored)
    }
}
