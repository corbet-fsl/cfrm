#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
suite="${CHECK_SUITE:-core}"
case "$suite" in
  core|browser) ;;
  *) printf 'Unknown check suite\n'; exit 2 ;;
esac
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/$suite"
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
if test "$suite" = browser; then
  native_ready=0
  bindings_ready=0
  test -x "$BROWSER_BIN"
  test -x "$WASM_LINKER"
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER="$WASM_LINKER"
  if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
    cargo update --manifest-path .ci/browser-bindgen/Cargo.toml --workspace
  fi
  cp .ci/browser-bindgen/Cargo.lock "$artifact_dir/browser-helper-Cargo.lock"
  if timeout 1200 cargo build --locked --no-default-features --features permit-issuer --example browser_fixture \
      2>&1 | tee "$artifact_dir/browser-native-build.log"; then
    native_ready=1
    sha256sum "$CARGO_TARGET_DIR/debug/examples/browser_fixture" > "$artifact_dir/browser-fixture.sha256"
  else result=$?; fi
  # Generated bindings are disposable; a failed build must not test older output.
  rm -rf -- browser/pkg
  if timeout 1200 cargo build --locked --target wasm32-unknown-unknown --no-default-features --features browser --lib \
      2>&1 | tee "$artifact_dir/browser-wasm-build.log"; then
    if timeout 1200 cargo run --locked --manifest-path .ci/browser-bindgen/Cargo.toml -- \
        "$CARGO_TARGET_DIR/wasm32-unknown-unknown/debug/cfrm.wasm" browser/pkg cfrm \
        2>&1 | tee "$artifact_dir/browser-bindgen.log"; then
      bindings_ready=1
    else result=$?; fi
  else result=$?; fi
  if test "$native_ready" = 1 && test "$bindings_ready" = 1; then
    export BROWSER_BIN BROWSER_EVIDENCE="$artifact_dir/browser-evidence.json"
    export BROWSER_FIXTURE="$CARGO_TARGET_DIR/debug/examples/browser_fixture"
    timeout 300 node .ci/browser-check.mjs 2>&1 | tee "$artifact_dir/browser-harness.log" || result=$?
  fi
  # Preserve generated glue and diagnostics even when initialization/tests fail.
  tar --create --file "$artifact_dir/browser-package.tar" browser/contract.mjs browser/README.md .ci/browser-check.mjs examples/browser_fixture.rs
  if test -d browser/pkg; then
    tar --append --file "$artifact_dir/browser-package.tar" browser/pkg
  fi
  printf '%s\n' "$result" > "$artifact_dir/validation-status.txt"
  (
    cd "$artifact_dir"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  printf 'Browser validation status: %s\n' "$result"
  exit "$result"
fi
timeout 1200 cargo test --locked --all-features --all-targets -- --test-threads=2 || result=$?
timeout 1200 cargo check --locked --target wasm32-unknown-unknown --no-default-features --features permits --lib || result=$?
timeout 120 node --test test/*.test.js || result=$?
cargo fmt --all
tar --create --file "$artifact_dir/formatted-source.tar" src/*.rs tests/*.rs tests/common/mod.rs examples/*.rs
(cd "$artifact_dir" && sha256sum Cargo.lock formatted-source.tar > SHA256SUMS)
printf 'Validation status: %s\n' "$result"
exit "$result"
