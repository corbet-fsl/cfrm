#!/usr/bin/env bash
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="${ARTIFACT_ROOT:?}/${CI_COMMIT_SHA:?}/product-services"
mkdir -p "$artifact_dir"
capture() {
  local status=$?
  trap - EXIT
  set +e
  test ! -f Cargo.lock || cp Cargo.lock "$artifact_dir/Cargo.lock"
  cargo fmt --all
  tar -cf "$artifact_dir/formatted-source.tar" src/*.rs src/accounting_ledger/*.rs tests/*.rs tests/common/*.rs tests/accounting_ledger/*.rs examples/*.rs
  printf '%s\n' "$status" > "$artifact_dir/validation-status.txt"
  (cd "$artifact_dir" && find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  exit "$status"
}
trap capture EXIT
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  cargo generate-lockfile
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
cp Cargo.lock "$artifact_dir/Cargo.lock"
result=0
export CFRM_REQUIRE_VALKEY=1
VALKEY_TEST_ROOT="$artifact_dir/valkey-tools"
export VALKEY_TEST_ROOT
bash .ci/prepare-valkey.sh
export PATH="$VALKEY_TEST_ROOT/bin:$PATH"
valkey-server --version | tee "$artifact_dir/valkey-version.txt"
if command -v pkg-config >/dev/null && pkg-config --exists openssl; then
  OPENSSL_INCLUDE_DIR="$(pkg-config --variable=includedir openssl)"
  OPENSSL_LIB_DIR="$(pkg-config --variable=libdir openssl)"
  export OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
fi
if test -n "${OPENSSL_LIB_DIR:-}"; then
  export LD_LIBRARY_PATH="$OPENSSL_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
if test -n "${WASM_LINKER:-}"; then
  test -x "$WASM_LINKER"
  export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER="$WASM_LINKER"
fi
timeout 1200 cargo test --locked --all-features --tests --no-fail-fast -- --test-threads=2 2>&1 | tee "$artifact_dir/native.log" || result=$?
timeout 1200 cargo check --locked --target wasm32-unknown-unknown --no-default-features --features browser --lib 2>&1 | tee "$artifact_dir/wasm.log" || result=$?
timeout 180 node --test test/*.test.js 2>&1 | tee "$artifact_dir/browser-js.log" || result=$?
if test -z "${BROWSER_BIN:-}"; then
  BROWSER_BIN="$(command -v chromium || command -v chromium-browser || command -v google-chrome)"
fi
export BROWSER_BIN
PROFILE_BROWSER_EVIDENCE="$artifact_dir/profile-browser.json" timeout --kill-after=15 180 node browser/profiles/run-browser.mjs \
  2>&1 | tee "$artifact_dir/profile-browser.log" || result=$?
if timeout 600 npm ci --prefix runtime/accounting --ignore-scripts --no-audit --no-fund; then
  timeout 180 node --test runtime/accounting/test/*.test.mjs 2>&1 | tee "$artifact_dir/accounting-js.log" || result=$?
else result=$?; fi
exit "$result"
