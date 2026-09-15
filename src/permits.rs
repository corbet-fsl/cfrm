//! Aggregate bearer admission permits. These do not prove who owns a credit,
//! prevent collusive transfers, or implement private answer/close accounting.
use crate::{
    admission::{decode, digest, scope, signature, MAX_INTEGER},
    Error,
};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, PublicKey,
    Randomized, Secret, Sha384, Signature, PSS,
};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const RSA_BYTES: usize = 384;
pub const ISSUANCE_REQUEST_BYTES: usize = 32 + RSA_BYTES;
type RsaPublicKey = PublicKey<Sha384, PSS, Randomized>;

/// Obtain this shared descriptor from a pinned community catalogue. Accepting
/// an issuer's personalized descriptor would allow it to tag individual users.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermitEpoch {
    pub community_id: String,
    pub epoch_id: String,
    pub valid_from: u64,
    pub issue_until: u64,
    pub expires_at: u64,
    pub public_key_der: String,
    pub redemption_public_key: String,
}

fn bounded_decode(value: &str, size: usize) -> Result<Vec<u8>, Error> {
    if value.len() != size.div_ceil(3) * 4 - (3 - size % 3) % 3 {
        return Err(Error::InvalidInput);
    }
    let bytes = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| Error::InvalidInput)?;
    if bytes.len() != size || BASE64URL_NOPAD.encode(&bytes) != value {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}

fn random32() -> Result<[u8; 32], Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::CryptoProvider)?;
    Ok(bytes)
}

impl PermitEpoch {
    pub(crate) fn public_key(&self) -> Result<RsaPublicKey, Error> {
        if self.public_key_der.len() > 1067 {
            return Err(Error::InvalidInput);
        }
        let der = BASE64URL_NOPAD
            .decode(self.public_key_der.as_bytes())
            .map_err(|_| Error::InvalidInput)?;
        let key = RsaPublicKey::from_der(&der).map_err(|_| Error::InvalidInput)?;
        if BASE64URL_NOPAD.encode(&key.to_der().map_err(|_| Error::InvalidInput)?)
            != self.public_key_der
        {
            return Err(Error::InvalidInput);
        }
        let modulus = key.components().n();
        let exponent = key.components().e();
        let exponent = exponent
            .iter()
            .position(|byte| *byte != 0)
            .map(|start| &exponent[start..])
            .unwrap_or_default();
        if modulus.len() != RSA_BYTES || modulus[0] & 0x80 == 0 || exponent != [1, 0, 1] {
            return Err(Error::InvalidInput);
        }
        Ok(key)
    }

    pub fn context_id(&self) -> Result<String, Error> {
        if !scope(&self.community_id)
            || !scope(&self.epoch_id)
            || self.valid_from == 0
            || self.valid_from >= self.issue_until
            || self.issue_until > self.expires_at
            || self.expires_at > MAX_INTEGER
        {
            return Err(Error::InvalidInput);
        }
        self.public_key()?;
        let redemption_key = VerifyingKey::from_bytes(&decode(&self.redemption_public_key)?)
            .map_err(|_| Error::InvalidInput)?;
        if redemption_key.is_weak() {
            return Err(Error::InvalidInput);
        }
        Ok(digest(
            &serde_json::to_vec(&serde_json::json!([
                "cfrm.permit.epoch.v1",
                self.community_id,
                self.epoch_id,
                self.valid_from,
                self.issue_until,
                self.expires_at,
                self.public_key_der,
                self.redemption_public_key
            ]))
            .map_err(|_| Error::InvalidInput)?,
        ))
    }

    pub(crate) fn check_time(&self, now: u64, issuance: bool) -> Result<(), Error> {
        if now > MAX_INTEGER
            || now < self.valid_from
            || now
                >= if issuance {
                    self.issue_until
                } else {
                    self.expires_at
                }
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

/// Keep this state private and persist it before submitting an issuance request.
/// No private RSA key is constructed anywhere in the portable implementation.
pub struct PreparedPermit {
    epoch: PermitEpoch,
    context: [u8; 32],
    serial: [u8; 32],
    blinding: BlindingResult,
}

impl Drop for PreparedPermit {
    fn drop(&mut self) {
        self.blinding.secret.0.zeroize();
        self.serial.zeroize();
    }
}

impl PreparedPermit {
    pub fn new(epoch: &PermitEpoch, now: u64) -> Result<Self, Error> {
        let context = decode(&epoch.context_id()?)?;
        epoch.check_time(now, true)?;
        let serial = random32()?;
        let message = [context.as_slice(), serial.as_slice()].concat();
        let blinding = epoch
            .public_key()?
            .blind(&mut DefaultRng, &message)
            .map_err(|_| Error::CryptoProvider)?;
        if blinding.secret.0.len() != RSA_BYTES
            || blinding.blind_message.0.len() != RSA_BYTES
            || blinding.msg_randomizer.is_none()
        {
            return Err(Error::CryptoProvider);
        }
        Ok(Self {
            epoch: epoch.clone(),
            context,
            serial,
            blinding,
        })
    }

    /// Exact bytes to place in AllocationRequest.blinded_request (base64url).
    pub fn issuance_request(&self) -> Vec<u8> {
        [self.context.as_slice(), &self.blinding.blind_message.0].concat()
    }

    /// Sensitive, fixed-size local checkpoint; encrypt using application storage.
    /// Never submit these bytes to the issuer or put them in diagnostics.
    pub fn export_private(&self) -> Zeroizing<Vec<u8>> {
        let randomizer = self.blinding.msg_randomizer.expect("randomized suite");
        Zeroizing::new(
            [
                self.context.as_slice(),
                self.serial.as_slice(),
                randomizer.0.as_slice(),
                &self.blinding.blind_message.0,
                &self.blinding.secret.0,
            ]
            .concat(),
        )
    }

    pub fn restore_private(epoch: &PermitEpoch, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 96 + 2 * RSA_BYTES || bytes[..32] != decode::<32>(&epoch.context_id()?)? {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            epoch: epoch.clone(),
            context: bytes[..32].try_into().map_err(|_| Error::InvalidInput)?,
            serial: bytes[32..64].try_into().map_err(|_| Error::InvalidInput)?,
            blinding: BlindingResult {
                msg_randomizer: Some(MessageRandomizer(
                    bytes[64..96].try_into().map_err(|_| Error::InvalidInput)?,
                )),
                blind_message: BlindMessage(bytes[96..96 + RSA_BYTES].to_vec()),
                secret: Secret(bytes[96 + RSA_BYTES..].to_vec()),
            },
        })
    }

    pub fn finalize(&self, blind_signature: &[u8], now: u64) -> Result<Permit, Error> {
        self.epoch.check_time(now, false)?;
        if blind_signature.len() != RSA_BYTES {
            return Err(Error::InvalidInput);
        }
        let message = [self.context.as_slice(), self.serial.as_slice()].concat();
        let result = self
            .epoch
            .public_key()?
            .finalize(
                &BlindSignature(blind_signature.to_vec()),
                &self.blinding,
                &message,
            )
            .map_err(|_| Error::Signature)?;
        Ok(Permit {
            context_id: BASE64URL_NOPAD.encode(&self.context),
            serial: BASE64URL_NOPAD.encode(&self.serial),
            randomizer: BASE64URL_NOPAD
                .encode(&self.blinding.msg_randomizer.ok_or(Error::InvalidInput)?.0),
            signature: BASE64URL_NOPAD.encode(&result.0),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permit {
    pub context_id: String,
    pub serial: String,
    pub randomizer: String,
    pub signature: String,
}

impl Permit {
    pub fn verify(&self, epoch: &PermitEpoch, now: u64) -> Result<(), Error> {
        if self.context_id != epoch.context_id()? {
            return Err(Error::Admission);
        }
        epoch.check_time(now, false)?;
        let message = [
            decode::<32>(&self.context_id)?.as_slice(),
            decode::<32>(&self.serial)?.as_slice(),
        ]
        .concat();
        let randomizer = MessageRandomizer(decode(&self.randomizer)?);
        let signature = Signature(bounded_decode(&self.signature, RSA_BYTES)?);
        epoch
            .public_key()?
            .verify(&signature, Some(randomizer), &message)
            .map_err(|_| Error::Signature)
    }

    pub fn token_id(&self) -> Result<String, Error> {
        decode::<32>(&self.context_id)?;
        decode::<32>(&self.serial)?;
        Ok(digest(
            &serde_json::to_vec(&serde_json::json!([
                "cfrm.permit.spend.v1",
                self.context_id,
                self.serial
            ]))
            .map_err(|_| Error::InvalidInput)?,
        ))
    }
}

/// Private, recipient-held opening. Do not send this object to the operator.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientBinding {
    pub sender_id: String,
    pub recipient_id: String,
    pub introduction_id: String,
    pub challenge: String,
    pub salt: String,
}

impl RecipientBinding {
    fn commitment(&self, epoch: &PermitEpoch, permit: &Permit) -> Result<String, Error> {
        for value in [
            &self.sender_id,
            &self.recipient_id,
            &self.introduction_id,
            &self.challenge,
            &self.salt,
        ] {
            decode::<32>(value)?;
        }
        if self.sender_id == self.recipient_id {
            return Err(Error::InvalidInput);
        }
        Ok(digest(
            &serde_json::to_vec(&serde_json::json!([
                "cfrm.permit.recipient.v1",
                epoch.context_id()?,
                permit.token_id()?,
                self.sender_id,
                self.recipient_id,
                self.introduction_id,
                self.challenge,
                self.salt
            ]))
            .map_err(|_| Error::InvalidInput)?,
        ))
    }
}

/// This is the only part of a recipient claim submitted to the operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedemptionRequest {
    pub permit: Permit,
    pub commitment: String,
    pub claim: String,
}

/// Persist privately before redemption. Reuse the same claim after a lost reply.
/// A cmsg adapter obtains sender_id from validated MLS and recipient_id locally.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientClaim {
    pub request: RedemptionRequest,
    pub binding: RecipientBinding,
}

impl RecipientClaim {
    pub fn new(
        epoch: &PermitEpoch,
        permit: Permit,
        sender_id: &str,
        recipient_id: &str,
        introduction_id: [u8; 32],
        challenge: [u8; 32],
        now: u64,
    ) -> Result<Self, Error> {
        permit.verify(epoch, now)?;
        let binding = RecipientBinding {
            sender_id: sender_id.into(),
            recipient_id: recipient_id.into(),
            introduction_id: BASE64URL_NOPAD.encode(&introduction_id),
            challenge: BASE64URL_NOPAD.encode(&challenge),
            salt: BASE64URL_NOPAD.encode(&random32()?),
        };
        let commitment = binding.commitment(epoch, &permit)?;
        Ok(Self {
            request: RedemptionRequest {
                permit,
                commitment,
                claim: BASE64URL_NOPAD.encode(&random32()?),
            },
            binding,
        })
    }

    pub fn verify_stamp(
        &self,
        epoch: &PermitEpoch,
        stamp: &RedemptionStamp,
        now: u64,
    ) -> Result<(), Error> {
        self.request.permit.verify(epoch, now)?;
        if self.request.commitment != self.binding.commitment(epoch, &self.request.permit)?
            || stamp.context_id != epoch.context_id()?
            || stamp.token_id != self.request.permit.token_id()?
            || stamp.commitment != self.request.commitment
            || stamp.claim != self.request.claim
            || stamp.expires_at != epoch.expires_at
        {
            return Err(Error::Admission);
        }
        signature(
            &epoch.redemption_public_key,
            &stamp.signing_bytes()?,
            &stamp.signature,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedemptionStamp {
    pub context_id: String,
    pub token_id: String,
    pub commitment: String,
    pub claim: String,
    pub expires_at: u64,
    pub signature: String,
}

impl RedemptionStamp {
    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>, Error> {
        for value in [
            &self.context_id,
            &self.token_id,
            &self.commitment,
            &self.claim,
        ] {
            decode::<32>(value)?;
        }
        if self.expires_at == 0 || self.expires_at > MAX_INTEGER {
            return Err(Error::InvalidInput);
        }
        serde_json::to_vec(&serde_json::json!([
            "cfrm.permit.redeemed.v1",
            self.context_id,
            self.token_id,
            self.commitment,
            self.claim,
            self.expires_at
        ]))
        .map_err(|_| Error::InvalidInput)
    }
}
