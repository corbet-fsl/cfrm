#!/usr/bin/env bash
# Isolated feasibility experiment; production private accounting remains closed.
set -euo pipefail
rustc --version
cargo --version
node --version
artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/private-accounting"
export HASH_SCHEME="${HASH_SCHEME:-sha256-v1}"
export ACCOUNTING_MODE="${ACCOUNTING_MODE:-settlement-v1}"
case "$HASH_SCHEME" in
  sha256-v1) ;;
  poseidon2-bn254-fixed-128-v1) artifact_dir="$artifact_dir-$HASH_SCHEME" ;;
  *) printf 'Unknown accounting commitment scheme\n'; exit 2 ;;
esac
case "$ACCOUNTING_MODE" in
  settlement-v1) ;;
  account-state-v2)
    test "$HASH_SCHEME" = poseidon2-bn254-fixed-128-v1
    test -n "${ACCOUNT_POLICY_JSON:-}"
    export ACCOUNT_POLICY_JSON
    artifact_dir="$ARTIFACT_ROOT/$CI_COMMIT_SHA/private-accounting-account-state-v2"
    ;;
  *) printf 'Unknown accounting relation\n'; exit 2 ;;
esac
case "${CHECK_PHASE:-full}" in
  full) ;;
  startup)
    test -n "${REUSE_ARTIFACT_DIR:-}"
    [[ "${REUSE_ARTIFACT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || exit 2
    [[ "${BROWSER_BUNDLE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || exit 2
    artifact_dir="$artifact_dir-startup"
    ;;
  startup-build)
    artifact_dir="$artifact_dir-startup-build"
    ;;
  compile)
    test "$ACCOUNTING_MODE" = account-state-v2
    artifact_dir="$artifact_dir-compile"
    export CIRCUIT_PACKAGE="${CIRCUIT_PACKAGE:-account-state}"
    case "$CIRCUIT_PACKAGE" in
      account-state) ;;
      peer-reservation) artifact_dir="$artifact_dir-peer-reservation" ;;
      *) printf 'Unknown circuit package\n'; exit 2 ;;
    esac
    ;;
  ledger)
    test "$ACCOUNTING_MODE" = account-state-v2
    test -n "${REUSE_ARTIFACT_DIR:-}"
    [[ "${REUSE_ARTIFACT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || exit 2
    artifact_dir="$artifact_dir-ledger"
    ;;
  profile)
    [[ "${CIRCUIT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || exit 2
    artifact_dir="$artifact_dir-profile-$CIRCUIT_SHA256"
    ;;
  *) printf 'Unknown private accounting check phase\n'; exit 2 ;;
esac
mkdir -p "$artifact_dir"
artifact_dir="$(realpath "$artifact_dir")"
cd experiments/private-accounting
capture() {
  local result=$?
  trap - EXIT
  set +e
  printf '%s\n' "$result" > "$artifact_dir/validation-status.txt"
  test ! -f package-lock.json || cp package-lock.json "$artifact_dir/package-lock.json"
  test ! -f native/Cargo.lock || cp native/Cargo.lock "$artifact_dir/native-Cargo.lock"
  test ! -f setup-lock.json || cp setup-lock.json "$artifact_dir/setup-lock.json"
  test ! -f account-state/setup-lock.json || cp account-state/setup-lock.json "$artifact_dir/account-state-setup-lock.json"
  test ! -f ../../Cargo.lock || cp ../../Cargo.lock "$artifact_dir/cfrm-Cargo.lock"
  test ! -f ../../runtime/accounting/package-lock.json || cp ../../runtime/accounting/package-lock.json "$artifact_dir/runtime-package-lock.json"
  for name in manifest.json circuit.json circuit-stats.json; do
    test ! -f "public/$name" || cp "public/$name" "$artifact_dir/$name"
  done
  if test -d public/peer-reservation; then
    mkdir -p "$artifact_dir/peer-reservation"
    for name in circuit.json vk.bin stats.json; do
      test ! -f "public/peer-reservation/$name" || cp "public/peer-reservation/$name" "$artifact_dir/peer-reservation/$name"
    done
  fi
  if test -d dist; then tar --create --file "$artifact_dir/browser-package.tar" dist; fi
  (
    cd "$artifact_dir"
    find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
  )
  printf 'Private accounting experiment status: %s\n' "$result"
  exit "$result"
}
trap capture EXIT
if test "${CHECK_PHASE:-full}" = startup; then
  # Diagnose the exact retained browser bundle without installing dependencies,
  # starting native fixtures, loading proof setup, or generating another proof.
  printf '%s  %s\n' "$REUSE_ARTIFACT_SHA256" "$REUSE_ARTIFACT_DIR/SHA256SUMS" | sha256sum --check --strict
  (cd "$REUSE_ARTIFACT_DIR"; sha256sum --check --strict SHA256SUMS > "$artifact_dir/reuse-validation.log")
  cmp package-lock.json "$REUSE_ARTIFACT_DIR/package-lock.json"
  startup_package="$(mktemp -d "$artifact_dir/startup-package.XXXXXXXX")"
  tar --extract --file "$REUSE_ARTIFACT_DIR/browser-package.tar" --directory "$startup_package" --no-same-owner
  export BROWSER_CHECK_PHASE=startup BROWSER_BUNDLE_SHA
  export BROWSER_DIST="$startup_package/dist" BROWSER_EVIDENCE="$artifact_dir/browser-evidence.json"
  printf '%s\n' "$BROWSER_BUNDLE_SHA" > "$artifact_dir/browser-bundle-source.txt"
  printf '%s\n' "$REUSE_ARTIFACT_SHA256" > "$artifact_dir/reused-manifest.sha256"
  startup_result=0
  timeout --kill-after=15 120 node browser-check.mjs 2>&1 | tee "$artifact_dir/browser-startup.log" || startup_result=$?
  rm -rf -- "$startup_package"
  exit "$startup_result"
fi
export BROWSER_CHECK_PHASE=proof
if test "${CHECK_PHASE:-full}" = full; then
  available_kib="$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)"
  printf 'Available memory before proof work: %s KiB\n' "$available_kib"
  cat /proc/pressure/memory
  df -h "$artifact_dir"
  if test "$available_kib" -lt 8388608; then
    printf 'Proof validation requires at least 8 GiB available memory\n'
    exit 1
  fi
fi
timeout 600 npm ci --prefix ../../runtime/accounting --ignore-scripts --no-audit --no-fund \
  2>&1 | tee "$artifact_dir/runtime-npm-install.log"
if test "${RESOLVE_DEPENDENCIES:-0}" = 1; then
  timeout 600 npm install --package-lock-only --ignore-scripts --no-audit --no-fund \
    2>&1 | tee "$artifact_dir/npm-resolution.log"
  if test -f native/Cargo.lock; then
    cargo update --manifest-path native/Cargo.toml --workspace
  else
    cargo generate-lockfile --manifest-path native/Cargo.toml
  fi
  date -u +%FT%TZ > "$artifact_dir/dependency-resolution-time.txt"
fi
test -f package-lock.json
test -f native/Cargo.lock
# Both configured CI executors are Linux x86_64 with glibc. Pin that optional
# binary selection: the bundler's autodetection selects musl on this Nix worker.
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64
timeout 600 npm ci --libc=glibc --ignore-scripts --no-audit --no-fund \
  2>&1 | tee "$artifact_dir/npm-install.log"
if test "${CHECK_PHASE:-full}" = startup-build; then
  # Bundle current imports without compiling circuits or initializing proof setup.
  export BROWSER_BUILD_DIR="$artifact_dir/browser-bundle"
  export NAPI_RS_NATIVE_LIBRARY_PATH="$PWD/node_modules/@rolldown/binding-linux-x64-gnu"
  timeout 300 node --input-type=module <<'JS' 2>&1 | tee "$artifact_dir/browser-build.log"
const { build } = await import('vite');
await build({ publicDir: false, build: { outDir: process.env.BROWSER_BUILD_DIR } });
JS
  export BROWSER_CHECK_PHASE=startup BROWSER_BUNDLE_SHA="$CI_COMMIT_SHA"
  export BROWSER_DIST="$BROWSER_BUILD_DIR" BROWSER_EVIDENCE="$artifact_dir/browser-evidence.json"
  timeout --kill-after=15 120 node browser-check.mjs 2>&1 | tee "$artifact_dir/browser-startup.log"
  exit 0
fi
if test "${CHECK_PHASE:-full}" = compile; then
  export ACCOUNTING_ARTIFACT_DIR="$artifact_dir"
  if test "$CIRCUIT_PACKAGE" = peer-reservation; then
    timeout 600 node peer-reservation/compile.mjs "$artifact_dir" \
      2>&1 | tee "$artifact_dir/circuit-compile.log"
    exit 0
  fi
  timeout 600 node --input-type=module <<'JS' 2>&1 | tee "$artifact_dir/circuit-compile.log"
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
const compiled = await compile(createFileManager(resolve('account-state')));
if (!compiled.program?.bytecode) throw new Error('No compiled circuit');
await writeFile(resolve(process.env.ACCOUNTING_ARTIFACT_DIR, 'circuit.json'), JSON.stringify(compiled.program));
const sources = [];
for (const name of ['Nargo.toml','src/main.nr','src/indexed.nr']) {
  sources.push({name,sha256:createHash('sha256').update(await readFile('account-state/'+name)).digest('hex')});
}
await writeFile(resolve(process.env.ACCOUNTING_ARTIFACT_DIR, 'circuit-sources.json'), JSON.stringify(sources,null,2));
console.log('Account-state circuit compilation passed; no proof or browser execution implied');
JS
  exit 0
fi
if test "${CHECK_PHASE:-full}" = profile; then
  test -n "$CIRCUIT_PATH"
  test -n "$CIRCUIT_SHA256"
  export CIRCUIT_PATH CIRCUIT_SHA256
  PROFILE_ARTIFACT_DIR="$artifact_dir" timeout 300 node profile.mjs \
    2>&1 | tee "$artifact_dir/circuit-profile.log"
  exit 0
fi
if test "${CHECK_PHASE:-full}" = ledger; then
  # Reuse public proofs and their independently retained synthetic enrollment.
  # Pin the entire prior evidence manifest before reading its artifacts.
  printf '%s  %s\n' "$REUSE_ARTIFACT_SHA256" "$REUSE_ARTIFACT_DIR/SHA256SUMS" | sha256sum --check --strict
  (cd "$REUSE_ARTIFACT_DIR"; sha256sum --check --strict SHA256SUMS > "$artifact_dir/reuse-validation.log")
  cmp package-lock.json "$REUSE_ARTIFACT_DIR/package-lock.json"
  mkdir replay-package
  tar --extract --file "$REUSE_ARTIFACT_DIR/browser-package.tar" --directory replay-package --no-same-owner
  cp -R replay-package/dist public
  timeout 1200 cargo build --locked --manifest-path ../../Cargo.toml --no-default-features --features sqlite \
    --release --example account_ledger_fixture 2>&1 | tee "$artifact_dir/ledger-fixture-build.log"
  export ACCOUNTING_LEDGER_FIXTURE="$CARGO_TARGET_DIR/release/examples/account_ledger_fixture"
  export ACCOUNTING_ARTIFACT_DIR="$artifact_dir" REUSE_ARTIFACT_DIR REUSE_ARTIFACT_SHA256
  sha256sum "$ACCOUNTING_LEDGER_FIXTURE" > "$artifact_dir/ledger-fixture.sha256"
  timeout --kill-after=15 1200 node account-state/replay-ledger.mjs 2>&1 | tee "$artifact_dir/ledger-replay.log"
  exit 0
fi
test -x "$BROWSER_BIN"
if test "$ACCOUNTING_MODE" = account-state-v2; then
  test -n "$CMSG_SOURCE_ARCHIVE"
  test -n "$CMSG_SOURCE_SHA256"
  printf '%s  %s\n' "$CMSG_SOURCE_SHA256" "$CMSG_SOURCE_ARCHIVE" | sha256sum --check --strict
  cmsg_revision="$(git get-tar-commit-id < "$CMSG_SOURCE_ARCHIVE")"
  # cfrm declares exactly one external source in this manifest for this suite.
  expected_cmsg_revision="$(sed -n 's/^revision = "\([0-9a-f]\{40\}\)"$/\1/p' ../../.ci/archives.toml)"
  test "$cmsg_revision" = "$expected_cmsg_revision"
  cmsg_source="$PWD/.cmsg-source"
  mkdir -p "$cmsg_source"
  tar --extract --touch --file "$CMSG_SOURCE_ARCHIVE" --directory "$cmsg_source" --no-same-owner
  test -n "$CMSG_CARGO_TARGET_DIR"
  mkdir -p "$CMSG_CARGO_TARGET_DIR"
  # Reuse the cmsg dependency cache already validated by its portable suite.
  # The fixture is not benchmarked; a release rebuild adds no relevant evidence.
  CARGO_TARGET_DIR="$CMSG_CARGO_TARGET_DIR" flock "$CMSG_CARGO_TARGET_DIR.ci.lock" \
    timeout 1200 cargo build --locked --manifest-path "$cmsg_source/Cargo.toml" --example accounting_fixture \
    2>&1 | tee "$artifact_dir/cmsg-fixture-build.log"
  cp "$cmsg_source/Cargo.lock" "$artifact_dir/cmsg-Cargo.lock"
  printf '%s\n' "$cmsg_revision" > "$artifact_dir/cmsg-source-revision.txt"
  printf '%s\n' "$CMSG_SOURCE_SHA256" > "$artifact_dir/cmsg-source-archive.sha256"
  timeout 1200 cargo build --locked --manifest-path ../../Cargo.toml --no-default-features --features sqlite \
    --release --example account_ledger_fixture 2>&1 | tee "$artifact_dir/ledger-fixture-build.log"
  export ACCOUNTING_FIXTURE="$CMSG_CARGO_TARGET_DIR/debug/examples/accounting_fixture"
  export ACCOUNTING_LEDGER_FIXTURE="$CARGO_TARGET_DIR/release/examples/account_ledger_fixture"
  test -x "$ACCOUNTING_LEDGER_FIXTURE"
  sha256sum "$ACCOUNTING_LEDGER_FIXTURE" > "$artifact_dir/ledger-fixture.sha256"
  cargo fmt --manifest-path ../../Cargo.toml -- --check
  tar --create --file "$artifact_dir/formatted-ledger-source.tar" --directory ../.. src/accounting.rs src/accounting_policy.rs src/accounting_ledger.rs src/accounting_ledger/tuning.rs examples/account_ledger_fixture.rs
else
  timeout 1200 cargo build --locked --manifest-path native/Cargo.toml --release \
    2>&1 | tee "$artifact_dir/native-build.log"
  cargo fmt --manifest-path native/Cargo.toml -- --check
  tar --create --file "$artifact_dir/formatted-native-source.tar" native/src
  export ACCOUNTING_FIXTURE="$CARGO_TARGET_DIR/release/cfrm-private-accounting-fixture"
fi
CFRM_BUNDLER_BINDING="$PWD/node_modules/@rolldown/binding-linux-x64-gnu" \
  timeout 900 npm run build 2>&1 | tee "$artifact_dir/browser-build.log"
export BROWSER_BIN
test -x "$ACCOUNTING_FIXTURE"
sha256sum "$ACCOUNTING_FIXTURE" > "$artifact_dir/native-fixture.sha256"
if test "$ACCOUNTING_MODE" = account-state-v2; then
  export CFRM_RUNTIME_PROOF_CONFIG="$artifact_dir/runtime-verifier-config.json"
  node --input-type=module <<'JS'
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
const directory=resolve('public');
const manifest=await readFile(resolve(directory,'manifest.json'));
await writeFile(process.env.CFRM_RUNTIME_PROOF_CONFIG,JSON.stringify({directory,
  manifestSha256:createHash('sha256').update(manifest).digest('hex'),
  limits:{maxProofBytes:20000,memoryPages:32768}},null,2)+'\n');
JS
  case "${ACCOUNT_SCENARIOS:-answer close}" in
    'answer close'|answer|close) ;;
    *) printf 'Unknown account scenarios\n'; exit 2 ;;
  esac
  for scenario in ${ACCOUNT_SCENARIOS:-answer close}; do
    export ACCOUNT_SCENARIO="$scenario"
    export ACCOUNTING_ARTIFACT_DIR="$artifact_dir/$scenario"
    mkdir -p "$ACCOUNTING_ARTIFACT_DIR"
    export BROWSER_EVIDENCE="$ACCOUNTING_ARTIFACT_DIR/browser-evidence.json"
    timeout --kill-after=15 1200 npm test 2>&1 | tee "$ACCOUNTING_ARTIFACT_DIR/browser-harness.log"
    timeout --kill-after=15 600 node ../../runtime/accounting/real-proof-check.mjs \
      "$CFRM_RUNTIME_PROOF_CONFIG" "$BROWSER_EVIDENCE" \
      2>&1 | tee "$ACCOUNTING_ARTIFACT_DIR/runtime-verifier-evidence.log"
  done
else
  export BROWSER_EVIDENCE="$artifact_dir/browser-evidence.json"
  export ACCOUNTING_ARTIFACT_DIR="$artifact_dir"
  timeout --kill-after=15 1200 npm test 2>&1 | tee "$artifact_dir/browser-harness.log"
fi
