//! Loads only the genuine four-artifact owner output; never generates a proof.
use cblc::{
    artifacts::{ArtifactBytes, ExtensionArtifacts, NativeVerifierOptions},
    publication::PublicVerifierMaterial,
    verification::NativeExtensionVerifier,
};
use cgth::accounting::record;
use ed25519_dalek::Signer as _;
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Fixture {
    pub material: PublicVerifierMaterial,
    pub signed_balance: Vec<u8>,
    pub trusted_key_ring: Vec<u8>,
    pub trusted_period_seconds: u64,
    pub trusted_owner: [u8; 32],
    pub now: u64,
    pub presentation_seed: [u8; 32],
    pub record: record::Record,
    pub proof: String,
    pub artifacts: String,
    #[serde(skip)]
    directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactConfiguration {
    directory: PathBuf,
    manifest_sha256: String,
}
impl Fixture {
    pub fn load() -> Self {
        let path = PathBuf::from(
            std::env::var_os("CBLC_RECORD_EPOCH_FIXTURE")
                .expect("The genuine retained CBLC four-artifact fixture is required"),
        );
        let path = path.canonicalize().unwrap();
        let mut fixture: Self = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        fixture.directory = path.parent().unwrap().to_owned();
        assert_eq!(
            data_encoding::BASE64URL_NOPAD.encode(&fixture.trusted_owner),
            cblc::admission::member_id(&[7; 48])
        );
        assert_eq!(fixture.record.owner, fixture.trusted_owner);
        assert_eq!(
            fixture.record.epoch,
            fixture.material.record_epoch.clone().unwrap()
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&fixture.presentation_seed);
        assert_eq!(
            key.verifying_key().to_bytes(),
            fixture.record.presentation_key
        );
        fixture
    }
    pub fn native(&self, executable: PathBuf) -> NativeExtensionVerifier {
        let configuration: ArtifactConfiguration =
            serde_json::from_slice(&std::fs::read(self.directory.join(&self.artifacts)).unwrap())
                .unwrap();
        assert_eq!(configuration.directory, PathBuf::from("."));
        let directory = self
            .directory
            .join(configuration.directory)
            .canonicalize()
            .unwrap();
        let manifest = std::fs::read(directory.join("manifest.json")).unwrap();
        let circuit = std::fs::read(directory.join("circuits.json")).unwrap();
        let keys = std::fs::read(directory.join("keys.json")).unwrap();
        let g1 = std::fs::read(directory.join("setup/g1.dat")).unwrap();
        let g2 = std::fs::read(directory.join("setup/g2.dat")).unwrap();
        let pin = data_encoding::HEXLOWER
            .decode(configuration.manifest_sha256.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(pin, self.material.manifest_sha256);
        let artifacts = ExtensionArtifacts::authenticate(ArtifactBytes {
            manifest: &manifest,
            manifest_sha256: pin,
            circuit: &circuit,
            keys: &keys,
            srs_g1: &g1,
            srs_g2: &g2,
        })
        .unwrap();
        assert_eq!(artifacts.scope(), self.material.proof_scope);
        let options = NativeVerifierOptions {
            executable,
            timeout: Duration::from_secs(180),
            maximum_parallel: 1,
            max_proof_bytes: 1024 * 1024,
            threads: 1,
            memory_megabytes: 8192,
        };
        NativeExtensionVerifier::new(options.clone(), options, artifacts).unwrap()
    }
    pub fn presentation(&self, context: record::Context) -> record::Presentation {
        let key = ed25519_dalek::SigningKey::from_bytes(&self.presentation_seed);
        let signature = key
            .sign(&self.record.presentation_bytes(&context).unwrap())
            .to_bytes()
            .to_vec();
        record::Presentation {
            record: self.record.clone(),
            context,
            public_key: key.verifying_key().to_bytes(),
            signature,
            proof: self.proof.clone(),
        }
    }
}
