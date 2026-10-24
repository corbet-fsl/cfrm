//! Real issuer signatures, current Charter, Profile, Guard and encrypted storage.
//! Fixture device custody is test setup; no accepting verifier is supplied.
use super::fixture::Fixture as NativeFixture;
use cgth::cswb::Publication;
use ckmg::passkey::{PrfOutput, store_cipher};
use cpfl::{DeviceSigner, Draft, PortableCodec};
use csgn::{Kind, SecretKey, Signer};
use ed25519_dalek::{Digest, Sha512, Signer as _, SigningKey};
use serde_json::{Value, json};

pub const ORIGIN: &str = "https://forum.example.test";
pub const ACTION: &str = "community.admit";
pub fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}
struct Device(SigningKey);
impl DeviceSigner for Device {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn hpke_public_key(&self) -> Result<[u8; 32], cpfl::Error> {
        Ok(self.0.verifying_key().to_montgomery().to_bytes())
    }
    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], cpfl::Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}
pub(super) struct G1 {
    pub publication: Publication,
    pub device: SigningKey,
}
pub(super) const PERIOD_KEY: &str = "fixture.record_epoch_period_seconds";
fn issuer(community: &str) -> Signer {
    Signer::new(community, SecretKey::from_seed(&mut [31; 32]), 1, 2000).unwrap()
}
fn sign(issuer: &mut Signer, kind: Kind, value: Value, now: u64) -> Vec<u8> {
    issuer
        .sign(kind, &serde_json::to_vec(&value).unwrap(), now, now + 300)
        .unwrap()
}
pub(super) fn feed(native: &NativeFixture, _lease_ms: u64, revision: u64) -> Value {
    let community = &native.material.community;
    let now = native.now;
    let epoch = native.material.policy_epoch;
    let mut issuer = issuer(community);
    assert_eq!(issuer.key_ring().to_cbor(), native.trusted_key_ring);
    let mut book = crbk::Rulebook::default();
    crbk::define_forum_settings(&mut book).unwrap();
    crbk::RecordEpochSettings::define(&mut book, PERIOD_KEY).unwrap();
    for (key, value) in [
        ("forum.room_passes_per_epoch", json!(4)),
        (PERIOD_KEY, json!(native.trusted_period_seconds)),
    ] {
        book.set_community(key, Some(value)).unwrap();
    }
    crbk::RecordEpochSettings::validate_catalogue(&book, PERIOD_KEY).unwrap();
    let mut settings = serde_json::to_value(book.resolve(&Default::default()).unwrap()).unwrap();
    settings["action/community.admit"] = json!({"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]});
    let schema: cshm::Schema =
        serde_json::from_value(json!({"community":community,"version":1,"public":[],"private":[]}))
            .unwrap();
    let mut feed = json!({"revision":revision,"policy_epoch":epoch,"key_ring":issuer.key_ring().to_cbor(),"balance":native.signed_balance});
    let manifest = json!({"purpose":"cplc.trust.v1","community":community,"revision":revision,"policy_epoch":epoch,"key_ring":issuer.key_ring().to_cbor(),"schema_version":1,"balance_revision":native.material.revision});
    feed["manifest"] = json!(sign(&mut issuer, Kind::SettingsSnapshot, manifest, now));
    for (name, kind, content) in [
        ("settings", Kind::SettingsSnapshot, settings),
        ("schema", Kind::SchemaSnapshot, json!(schema)),
        (
            "schema_versions",
            Kind::SchemaSnapshot,
            json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[{"schema":schema,"changes":null}]}),
        ),
        ("communities", Kind::CommunitiesSnapshot, json!([community])),
        (
            "revocations",
            Kind::RevocationListSnapshot,
            json!({"members":[],"devices":[]}),
        ),
    ] {
        feed[name] = json!(sign(
            &mut issuer,
            kind,
            json!({"community":community,"revision":revision,"policy_epoch":epoch,"content":content}),
            now
        ));
    }
    feed
}
impl G1 {
    pub async fn new(native: &NativeFixture, member: &str, revision: u64, lease_ms: u64) -> Self {
        let now = native.now;
        let community = native.material.community.as_str();
        let mut issuer = issuer(community);
        let mut charter = cchr::Charter::new(cchr::Configuration {
            origin: "https://identity.example.test".into(),
            community: community.into(),
            key_ring: issuer.key_ring().to_cbor(),
            minimum_revision: 1,
            ring_revision: 0,
        })
        .unwrap();
        charter
            .install(
                &serde_json::to_vec(&feed(native, lease_ms, 1)).unwrap(),
                now,
            )
            .unwrap();
        let mut device = Device(SigningKey::from_bytes(&[13; 32]));
        let credential = sign(
            &mut issuer,
            Kind::Credential,
            json!(cgrd::Credential {
                purpose: cgrd::CredentialPurpose::CommunityCredentialV2,
                issuance_action: ACTION.into(),
                community: community.into(),
                member: member.into(),
                handle: "mountain".into(),
                schema_version: 1,
                policy_epoch: native.material.policy_epoch,
                gates: vec![],
                pins: vec![],
                devices: vec![device.public_key()],
            }),
            now,
        );
        let draft = Draft::new(
            member.into(),
            cshm::Profile {
                community: community.into(),
                schema_version: 1,
                public: Default::default(),
                private: Default::default(),
            },
        )
        .unwrap();
        let cipher = store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), community).unwrap();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, community)
            .await
            .unwrap();
        let current = charter.current(now).unwrap();
        let policy = current.admission_policy(ACTION, now, 300).unwrap();
        let signed_schema = current.publication(cchr::Kind::Schema).signed_bytes();
        // Original maintained conversion for deterministic test device custody.
        // Production uses the fresh-authorized Keys lender, never caller keys.
        let hpke: [u8; 32] = Sha512::digest(device.0.as_bytes())[..32]
            .try_into()
            .unwrap();
        let custody =
            cnvl::Custodian::from_keys(&hpke, &[44; 32], community, member, device.public_key())
                .unwrap();
        draft
            .prepare_publication(
                &credential,
                &policy,
                signed_schema,
                revision,
                1,
                vec![1],
                0,
                &mut device,
                &custody,
                &PortableCodec,
                &clean,
                &|_: &str| None,
            )
            .unwrap()
            .commit_publication(
                &mut store,
                cpfl::Validation {
                    policy,
                    signed_schema,
                    contact: &clean,
                },
                [1; 32],
                vec![],
            )
            .await
            .unwrap();
        let signed = store.load_pending().unwrap()[0].bytes.clone();
        let ciphertext = cpfl::Publication::from_bytes(&signed).unwrap().envelope;
        Self {
            publication: Publication { signed, ciphertext },
            device: device.0,
        }
    }
}
