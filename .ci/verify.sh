#!/usr/bin/env bash
# .ci/verify.sh for cfrm — ports ALL Linux verification gates from
# .github/workflows/ci.yml (resolve selftest, check, dependency-policy
# first-party, coverage) in CI order, environment, and flags.
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"

# CI uses Node lts/*; the job-local pin is nodejs 24.18.1, so require major 24.
# Re-pin deliberately when lts moves; never float.
node --version | grep -q '^v24\.' || { echo 'CI requires Node major 24' >&2; exit 2; }
# A C compiler covers lock-evidenced cc edges (minicov via wasm-bindgen-test);
# the Ubuntu image supplies gcc, the job supplies pinned clang (cc wrapper).
command -v cc >/dev/null || { echo 'missing cc for lock-evidenced cc edges' >&2; exit 2; }
clang --version
# Wasm target on stable is guaranteed by run-cached.sh (helper readiness +
# exclusive provisioning); no toolchain mutation here under the shared lock.

# --- resolve pure selftest (committed graph only; update refresh excluded) ---
python3 .github/check-first-party.py

# --- check job (stable) in exact CI order ---
rustc --version
rustc --version
cargo fmt --all
git diff --exit-code -- '*.rs' > format.patch
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
command -v wasm-pack >/dev/null || { echo 'missing wasm-pack' >&2; exit 2; }
# CI pairs setup-chrome stable with its driver and records webdriver.json from
# CHROME_BINARY; the runner supplies pinned nix chromium+chromedriver instead.
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "missing chromium at $CHROME_BIN" >&2; exit 2; }
# Stock runners discover a google-chrome binary; link the pinned chromium
# under that name job-locally so discovery is deterministic.
mkdir -p "$RUNNER_TEMP/bin"
ln -sf "$CHROME_BIN" "$RUNNER_TEMP/bin/google-chrome"
export PATH="$RUNNER_TEMP/bin:$PATH"
python3 - <<'PYTHON'
import json, os
with open('webdriver.json', 'w') as output:
    json.dump({'goog:chromeOptions': {'binary': os.environ['CHROME_BIN']}}, output)
PYTHON
wasm-pack test --headless --chrome --locked --no-default-features --lib
cargo run --locked --example export
npm ci --ignore-scripts --no-audit --no-fund
npx --no-install tsc --strict --noEmit --lib es2022,dom generated/client.ts
node .github/check-api.mjs

# --- coverage job (nightly only) ---
# Select nightly exactly as CI's nightly job does; every bare cargo/rustc
# below resolves nightly via RUSTC/CARGO/PATH/RUSTUP_TOOLCHAIN.
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex "/tests/" --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text > coverage.txt
)
python3 .github/check-coverage.py coverage.lcov coverage.json coverage.txt
