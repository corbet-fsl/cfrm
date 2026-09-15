#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA"
mkdir -p "$artifact_dir"
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  cargo update --workspace
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
cp Cargo.lock "$artifact_dir/Cargo.lock"
result=0
test -d "$OPENSSL_INCLUDE_DIR/openssl"
test -d "$OPENSSL_LIB_DIR"
export OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
timeout 1200 cargo test --locked --all-features --all-targets -- --test-threads=2 || result=$?
timeout 1200 cargo check --locked --target wasm32-unknown-unknown --no-default-features --features permits --lib || result=$?
timeout 120 node --test test/*.test.js || result=$?
cargo fmt --all
tar --create --file "$artifact_dir/formatted-source.tar" src/*.rs tests/*.rs tests/common/mod.rs
(cd "$artifact_dir" && sha256sum Cargo.lock formatted-source.tar > SHA256SUMS)
printf 'Validation status: %s\n' "$result"
exit "$result"
