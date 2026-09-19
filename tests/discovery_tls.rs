#![cfg(all(
    feature = "discovery-valkey",
    feature = "permit-issuer",
    not(target_arch = "wasm32")
))]
//! Actual loopback TLS, using only the process-owned preinstalled Valkey.
//! No external cache is contacted and no cache keys are written or removed.
mod common;
#[path = "common/discovery.rs"]
mod fixtures;
use cfrm::{
    discovery::{DiscoveryResponse, DiscoveryService},
    discovery_control::SqliteDiscoveryControl,
    discovery_valkey::{ValkeyConfig, ValkeyDiscoveryStore},
    Error,
};
use common::{encoded, Fixture};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    panic::{catch_unwind, AssertUnwindSafe},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

fn ca(common_name: &str) -> (PKey<Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    (key, cert.build())
}

fn server_certificate(ca_key: &PKey<Private>, ca_cert: &X509) -> (PKey<Private>, X509) {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    cert.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name.build()).unwrap();
    cert.set_issuer_name(ca_cert.subject_name()).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap(),
    )
    .unwrap();
    cert.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert.x509v3_context(Some(ca_cert), None))
        .unwrap();
    cert.append_extension(san).unwrap();
    cert.sign(ca_key, MessageDigest::sha256()).unwrap();
    (key, cert.build())
}

struct OwnedTlsServer {
    child: Child,
    directory: tempfile::TempDir,
    port: u16,
    root: Vec<u8>,
}

impl OwnedTlsServer {
    fn start() -> Option<Self> {
        let version = Command::new("valkey-server").arg("--version").output();
        let installed = version.as_ref().is_ok_and(|output| output.status.success());
        if !installed {
            assert!(
                std::env::var_os("CFRM_REQUIRE_VALKEY").is_none(),
                "CFRM_REQUIRE_VALKEY requires the preinstalled Valkey TLS fixture"
            );
            eprintln!("SKIP actual TLS regression: preinstalled valkey-server unavailable");
            return None;
        }
        assert!(
            String::from_utf8_lossy(&version.unwrap().stdout).contains("v=9.1.2"),
            "TLS regression uses the pinned Valkey 9.1.2 fixture"
        );
        let directory = tempfile::tempdir().unwrap();
        let (ca_key, ca_cert) = ca("cfrm process-owned TLS test CA");
        let (server_key, server_cert) = server_certificate(&ca_key, &ca_cert);
        let root = ca_cert.to_pem().unwrap();
        fs::write(directory.path().join("root.pem"), &root).unwrap();
        fs::write(
            directory.path().join("server.pem"),
            server_cert.to_pem().unwrap(),
        )
        .unwrap();
        fs::write(
            directory.path().join("server-key.pem"),
            server_key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let child = Command::new("valkey-server")
            .args([
                "--bind",
                "127.0.0.1",
                "--protected-mode",
                "yes",
                "--port",
                "0",
                "--tls-port",
                &port.to_string(),
                "--tls-auth-clients",
                "no",
                "--save",
                "",
                "--appendonly",
                "no",
                "--maxmemory",
                "16mb",
                "--maxmemory-policy",
                "noeviction",
            ])
            .arg("--tls-cert-file")
            .arg(directory.path().join("server.pem"))
            .arg("--tls-key-file")
            .arg(directory.path().join("server-key.pem"))
            .arg("--tls-ca-cert-file")
            .arg(directory.path().join("root.pem"))
            .arg("--dir")
            .arg(directory.path())
            .arg("--logfile")
            .arg(directory.path().join("server.log"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut owned = Self {
            child,
            directory,
            port,
            root,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                owned.child.try_wait().unwrap().is_none(),
                "owned TLS cache exited before readiness"
            );
            if TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned TLS cache readiness deadline"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Some(owned)
    }

    fn config(&self, host: &str, root: Vec<u8>, namespace: &str) -> ValkeyConfig {
        ValkeyConfig {
            url: format!("rediss://{host}:{}/", self.port),
            namespace: namespace.into(),
            pool_size: 1,
            connect_timeout: Duration::from_millis(300),
            io_timeout: Duration::from_millis(300),
            pool_timeout: Duration::from_millis(750),
            allow_plaintext_loopback: false,
            root_certificate_pem: Some(root),
        }
    }

    fn store(&self, host: &str, root: Vec<u8>, name: &str) -> Result<ValkeyDiscoveryStore, Error> {
        let control = Arc::new(SqliteDiscoveryControl::open(
            self.directory.path().join(format!("{name}.sqlite")),
            Duration::from_secs(1),
        )?);
        ValkeyDiscoveryStore::connect(self.config(host, root, name), control)
    }

    fn confirm_owned_tls_endpoint(&mut self) {
        // The production store constructor is called before this helper. The
        // test never preinstalls a rustls provider on the production code's behalf.
        let url = format!("rediss://localhost:{}/", self.port);
        let client = redis::Client::build_with_tls(
            url.as_str(),
            redis::TlsCertificates {
                client_tls: None,
                root_cert: Some(self.root.clone()),
            },
        )
        .unwrap();
        let mut connection = client
            .get_connection_with_timeout(Duration::from_secs(1))
            .unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        connection
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let info: String = redis::cmd("INFO")
            .arg("server")
            .query(&mut connection)
            .unwrap();
        let process_id = info
            .lines()
            .find_map(|line| line.strip_prefix("process_id:"))
            .map(str::trim);
        assert_eq!(
            process_id,
            Some(self.child.id().to_string().as_str()),
            "TLS endpoint is not the owned child"
        );
        assert!(self.child.try_wait().unwrap().is_none());
        assert_eq!(
            redis::cmd("PING").query::<String>(&mut connection).unwrap(),
            "PONG"
        );
    }
}

impl Drop for OwnedTlsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn actual_rediss_uses_custom_root_and_rejects_wrong_root_or_hostname_without_panic() {
    let Some(mut server) = OwnedTlsServer::start() else {
        return;
    };
    // First use of rustls in this test binary goes through production. Before
    // the provider fix this panics instead of producing a usable TLS client.
    let trusted = catch_unwind(AssertUnwindSafe(|| {
        server.store("localhost", server.root.clone(), "trusted")
    }))
    .expect("production TLS constructor must not panic")
    .unwrap();
    server.confirm_owned_tls_endpoint();
    let fixture = Fixture::new();
    let service =
        DiscoveryService::new(fixture.trust.clone(), fixtures::limits(), trusted).unwrap();
    let result = catch_unwind(AssertUnwindSafe(|| {
        service.execute(&fixtures::fetch(&fixture, 1, 110, 5), 110)
    }))
    .expect("production TLS request must not panic");
    assert_eq!(
        result.unwrap(),
        DiscoveryResponse::Profile { publication: None }
    );
    drop(service);

    let (_, wrong_ca) = ca("different untrusted test CA");
    for (host, root, name) in [
        ("localhost", wrong_ca.to_pem().unwrap(), "wrong-root"),
        // Certificate has DNS localhost only: connecting to this same loopback
        // socket under its IP address must fail hostname verification.
        ("127.0.0.1", server.root.clone(), "wrong-hostname"),
    ] {
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let store = server.store(host, root, name)?;
            let service = DiscoveryService::new(fixture.trust.clone(), fixtures::limits(), store)?;
            service.execute(&fixtures::fetch(&fixture, 2, 110, 5), 110)
        }))
        .expect("untrusted TLS peer must return a bounded error, not panic");
        assert!(matches!(result, Err(Error::Storage) | Err(Error::Capacity)));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "TLS rejection exceeded configured bounds"
        );
    }
}
