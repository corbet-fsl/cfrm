//! Native aggregate permit issuer and durable anonymous redemption authority.
//! OpenSSL owns every RSA private operation; the portable Rust RSA dependency
//! is used only for blinding, unblinding and public verification (see docs).
use crate::{admission::{decode, digest, AdmissionGrant, DeviceAuthorization, MAX_INTEGER}, allocation::{sql_integer, stored_integer, AllocationLedger, AllocationRequest, Reservation}, permits::{PermitEpoch, RedemptionRequest, RedemptionStamp, ISSUANCE_REQUEST_BYTES, RSA_BYTES}, Error};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use openssl::{pkey::{PKey, Private}, pkey_ctx::PkeyCtx, rsa::{Padding, Rsa}};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, time::Duration};

pub struct PermitIssuer { epoch: PermitEpoch, key: PKey<Private> }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceResponse { pub reservation: Reservation, pub blind_signature: Vec<u8> }

impl PermitIssuer {
    /// Import an operator-managed, dedicated RSA-3072 key. Never share this key
    /// with TLS, another blind-signature purpose, or another permit epoch.
    pub fn from_pkcs1_der(epoch: &PermitEpoch, private_der: &[u8]) -> Result<Self, Error> {
        epoch.context_id()?;
        if private_der.len() > 4096 { return Err(Error::InvalidInput); }
        let rsa = Rsa::private_key_from_der(private_der).map_err(|_| Error::CryptoProvider)?;
        if !rsa.check_key().map_err(|_| Error::CryptoProvider)? || rsa.n().num_bits() != 3072 || rsa.e().to_vec() != [1, 0, 1] { return Err(Error::InvalidInput); }
        let der = rsa.public_key_to_der().map_err(|_| Error::CryptoProvider)?;
        if BASE64URL_NOPAD.encode(&der) != epoch.public_key_der { return Err(Error::Admission); }
        let key = PKey::from_rsa(rsa).map_err(|_| Error::CryptoProvider)?;
        Ok(Self { epoch: epoch.clone(), key })
    }

    fn blind_sign(&self, blinded: &[u8]) -> Result<Vec<u8>, Error> {
        let modulus = self.key.rsa().map_err(|_| Error::CryptoProvider)?.n().to_vec();
        if blinded.len() != RSA_BYTES || blinded.iter().all(|byte| *byte == 0) || blinded >= modulus.as_slice() { return Err(Error::InvalidInput); }
        let mut context = PkeyCtx::new(&self.key).map_err(|_| Error::CryptoProvider)?;
        context.sign_init().map_err(|_| Error::CryptoProvider)?;
        context.set_rsa_padding(Padding::NONE).map_err(|_| Error::CryptoProvider)?;
        let mut result = Vec::new();
        context.sign_to_vec(blinded, &mut result).map_err(|_| Error::CryptoProvider)?;
        if result.len() != RSA_BYTES { return Err(Error::CryptoProvider); }
        // Fault check the private operation before committing or returning it.
        let mut verifier = PkeyCtx::new(&self.key).map_err(|_| Error::CryptoProvider)?;
        verifier.verify_init().map_err(|_| Error::CryptoProvider)?;
        verifier.set_rsa_padding(Padding::NONE).map_err(|_| Error::CryptoProvider)?;
        if !verifier.verify(blinded, &result).map_err(|_| Error::CryptoProvider)? { return Err(Error::CryptoProvider); }
        Ok(result)
    }

    pub fn issue(&self, ledger: &mut AllocationLedger, grant: &AdmissionGrant, authorization: &DeviceAuthorization, request: &AllocationRequest, clock: impl Fn() -> u64) -> Result<IssuanceResponse, Error> {
        let context = self.epoch.context_id()?;
        if request.community_id != self.epoch.community_id || request.issued_at < self.epoch.valid_from || request.expires_at > self.epoch.issue_until { return Err(Error::Admission); }
        // The fixed envelope is covered by the device's existing request signature.
        if request.blinded_request.len() > ISSUANCE_REQUEST_BYTES * 2 { return Err(Error::InvalidInput); }
        let envelope = BASE64URL_NOPAD.decode(request.blinded_request.as_bytes()).map_err(|_| Error::InvalidInput)?;
        if envelope.len() != ISSUANCE_REQUEST_BYTES || envelope[..32] != decode::<32>(&context)? { return Err(Error::Admission); }
        let key_digest = digest(&BASE64URL_NOPAD.decode(self.epoch.public_key_der.as_bytes()).map_err(|_| Error::InvalidInput)?);
        let (reservation, blind_signature) = ledger.issue_with(grant, authorization, request, clock, |transaction, envelope, now| {
            self.epoch.check_time(now, true)?;
            let existing: Option<String> = transaction.query_row("SELECT context FROM cfrm_permit_epochs WHERE key_digest=?1", [&key_digest], |row| row.get(0)).optional()?;
            if existing.as_ref().is_some_and(|value| value != &context) { return Err(Error::PolicyMismatch); }
            transaction.execute("INSERT INTO cfrm_permit_epochs(context,key_digest) VALUES(?1,?2) ON CONFLICT(context) DO NOTHING", params![context,key_digest])?;
            self.blind_sign(&envelope[32..])
        })?;
        // A generic reservation never authorizes a second signing operation.
        if blind_signature.len() != RSA_BYTES { return Err(Error::Replay); }
        Ok(IssuanceResponse { reservation, blind_signature })
    }
}

/// One shared store per redemption epoch, used by every replica. Separate,
/// unsynchronised copies would permit double spending. No pair IDs are stored.
pub struct PermitRedeemer { connection: Connection, epoch: PermitEpoch, key: SigningKey }

impl PermitRedeemer {
    pub fn open(path: impl AsRef<Path>, epoch: &PermitEpoch, key: SigningKey) -> Result<Self, Error> {
        let context = epoch.context_id()?;
        if BASE64URL_NOPAD.encode(&key.verifying_key().to_bytes()) != epoch.redemption_public_key { return Err(Error::Admission); }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS cfrm_redemption_config (singleton INTEGER PRIMARY KEY CHECK(singleton=1), context TEXT NOT NULL, clock_floor INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS cfrm_redemptions (token TEXT PRIMARY KEY, claim TEXT NOT NULL, commitment TEXT NOT NULL, stamp BLOB NOT NULL) WITHOUT ROWID;")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<String> = transaction.query_row("SELECT context FROM cfrm_redemption_config WHERE singleton=1", [], |row| row.get(0)).optional()?;
        match existing {
            Some(existing) if existing != context => return Err(Error::PolicyMismatch),
            None => { transaction.execute("INSERT INTO cfrm_redemption_config(singleton,context,clock_floor) VALUES(1,?1,0)", [&context])?; },
            _ => {},
        }
        transaction.commit()?;
        Ok(Self { connection, epoch: epoch.clone(), key })
    }

    /// Submit only RedemptionRequest through the anonymous transport. A lost
    /// reply is retried with the same claim; changing the claim cannot win again.
    /// The recipient verifies the returned stamp against its private opening.
    pub fn redeem(&mut self, request: &RedemptionRequest, clock: impl Fn() -> u64) -> Result<RedemptionStamp, Error> {
        let before = clock();
        request.permit.verify(&self.epoch, before)?;
        decode::<32>(&request.claim)?; decode::<32>(&request.commitment)?;
        let token = request.permit.token_id()?;
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = clock();
        let floor = stored_integer(transaction.query_row("SELECT clock_floor FROM cfrm_redemption_config WHERE singleton=1", [], |row| row.get::<_, i64>(0))?)?;
        if now > MAX_INTEGER || now < before || now < floor { return Err(Error::ClockRollback); }
        self.epoch.check_time(now, false)?;
        let prior: Option<(String, String, Vec<u8>)> = transaction.query_row("SELECT claim,commitment,stamp FROM cfrm_redemptions WHERE token=?1", [&token], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?;
        let stamp = match prior {
            Some((claim, commitment, bytes)) => {
                if claim != request.claim || commitment != request.commitment { return Err(Error::Replay); }
                let stamp: RedemptionStamp = serde_json::from_slice(&bytes).map_err(|_| Error::Storage)?;
                if stamp.context_id != self.epoch.context_id()? || stamp.token_id != token || stamp.claim != claim || stamp.commitment != commitment || stamp.expires_at != self.epoch.expires_at { return Err(Error::Storage); }
                crate::admission::signature(&self.epoch.redemption_public_key, &stamp.signing_bytes()?, &stamp.signature).map_err(|_| Error::Storage)?;
                stamp
            },
            None => {
                let mut stamp = RedemptionStamp { context_id: self.epoch.context_id()?, token_id: token.clone(), commitment: request.commitment.clone(), claim: request.claim.clone(), expires_at: self.epoch.expires_at, signature: String::new() };
                stamp.signature = BASE64URL_NOPAD.encode(&self.key.sign(&stamp.signing_bytes()?).to_bytes());
                let bytes = serde_json::to_vec(&stamp).map_err(|_| Error::InvalidInput)?;
                transaction.execute("INSERT INTO cfrm_redemptions(token,claim,commitment,stamp) VALUES(?1,?2,?3,?4)", params![token,request.claim,request.commitment,bytes])?;
                stamp
            },
        };
        let completed_at = clock();
        if completed_at < now || completed_at > MAX_INTEGER { return Err(Error::ClockRollback); }
        self.epoch.check_time(completed_at, false)?;
        transaction.execute("UPDATE cfrm_redemption_config SET clock_floor=?1 WHERE singleton=1", [sql_integer(completed_at)?])?;
        transaction.commit()?;
        Ok(stamp)
    }
}
