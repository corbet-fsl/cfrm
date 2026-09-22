#!/usr/bin/env bash
set -euo pipefail
test "${CI:-}" = true
test -n "${ARTIFACT_ROOT:-}"
test -n "${CARGO_TARGET_DIR:-}"
mkdir -p "$ARTIFACT_ROOT" .ci-work/turso
capture() {
  local status=$?
  trap - EXIT
  printf '%s\n' "$status" > "$ARTIFACT_ROOT/validation-status.txt"
  cp Cargo.lock "$ARTIFACT_ROOT/Cargo.lock"
  (cd "$ARTIFACT_ROOT" && find . -type f ! -path ./SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  exit "$status"
}
trap capture EXIT
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  # Add the new optional SDK graph without updating retained existing packages.
  cargo metadata --format-version=1 > .ci-work/turso/dependency-metadata.json
fi
cp Cargo.lock "$ARTIFACT_ROOT/Cargo.lock"
curl --location --fail --silent --show-error \
  https://github.com/tursodatabase/libsql/releases/download/libsql-server-v0.24.32/libsql-server-x86_64-unknown-linux-gnu.tar.xz \
  --output .ci-work/turso/sqld.tar.xz
printf '%s  %s\n' 71720fc8648c19efef416efebd47145ef59b62e198770533530a858e1336879f .ci-work/turso/sqld.tar.xz | sha256sum --check
tar --extract --xz --file .ci-work/turso/sqld.tar.xz --directory .ci-work/turso --no-same-owner
export SQLD_BINARY="$(realpath .ci-work/turso/libsql-server-x86_64-unknown-linux-gnu/sqld)"
export TURSO_CONTRACT_WORK="$(realpath .ci-work/turso)"
rustc --version > "$ARTIFACT_ROOT/rust-version.txt"
node --version > "$ARTIFACT_ROOT/node-version.txt"
cargo fmt --all -- --check
timeout --kill-after=15 1200 cargo test --locked --features turso,permit-issuer --lib --test accounting_ledger --test accounting_service --test key_access \
  -- --test-threads=2 2>&1 | tee "$ARTIFACT_ROOT/local-storage.log"
timeout --kill-after=15 600 node .ci/turso-contract.mjs 2>&1 | tee "$ARTIFACT_ROOT/remote-storage.log"
cmp Cargo.lock "$ARTIFACT_ROOT/Cargo.lock"
