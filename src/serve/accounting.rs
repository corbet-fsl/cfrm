//! Native host loads bounded public artifacts into RAM. The accounting owner
//! authenticates every byte against the independently configured manifest pin.
use super::*;
use cgth::accounting::{artifacts, verification};
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Configuration {
    pub period_key: String,
    pub period_seconds: u64,
    artifact_directory: PathBuf,
    manifest_sha256: [u8; 32],
    executable: PathBuf,
    timeout_ms: u64,
    max_proof_bytes: usize,
    threads: usize,
    memory_megabytes: usize,
    global_burst: u32,
    subject_burst: u32,
    replenish_ms: u64,
    maximum_keys: NonZeroUsize,
}

impl Configuration {
    pub fn verifier(&self) -> Result<verification::NativeExtensionVerifier, ErrorCode> {
        if !self.artifact_directory.is_absolute() || !self.executable.is_absolute() {
            return Err(ErrorCode::InvalidRequest);
        }
        let manifest = read(&self.artifact_directory, "manifest.json", 65_536)?;
        let circuit = read(&self.artifact_directory, "circuits.json", 64 * 1024 * 1024)?;
        let keys = read(&self.artifact_directory, "keys.json", 1024 * 1024)?;
        let g1 = read(&self.artifact_directory, "setup/g1.dat", 128 * 1024 * 1024)?;
        let g2 = read(&self.artifact_directory, "setup/g2.dat", 128)?;
        let artifacts = artifacts::ExtensionArtifacts::authenticate(artifacts::ArtifactBytes {
            manifest: &manifest,
            manifest_sha256: self.manifest_sha256,
            circuit: &circuit,
            keys: &keys,
            srs_g1: &g1,
            srs_g2: &g2,
        })
        .map_err(|_| ErrorCode::AuthorityUnavailable)?;
        // The Forum actor serializes native proof work. No request can expand
        // this fixed concurrency or alter the verifier's execution limits.
        let options = artifacts::NativeVerifierOptions {
            executable: self.executable.clone(),
            timeout: Duration::from_millis(self.timeout_ms),
            maximum_parallel: 1,
            max_proof_bytes: self.max_proof_bytes,
            threads: self.threads,
            memory_megabytes: self.memory_megabytes,
        };
        verification::NativeExtensionVerifier::new(options.clone(), options, artifacts)
            .map_err(|_| ErrorCode::AuthorityUnavailable)
    }
    pub fn limits(&self) -> verification::ExtensionLimits {
        verification::ExtensionLimits {
            global_burst: self.global_burst,
            subject_burst: self.subject_burst,
            replenish: Duration::from_millis(self.replenish_ms),
            maximum_keys: self.maximum_keys,
        }
    }
}

fn read(directory: &Path, name: &str, maximum: usize) -> Result<Vec<u8>, ErrorCode> {
    let file =
        std::fs::File::open(directory.join(name)).map_err(|_| ErrorCode::AuthorityUnavailable)?;
    let mut bytes = Vec::new();
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::AuthorityUnavailable)?;
    if bytes.len() > maximum {
        return Err(ErrorCode::TooLarge);
    }
    Ok(bytes)
}
