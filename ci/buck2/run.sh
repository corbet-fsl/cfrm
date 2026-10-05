#!/bin/sh
# Buck2 probe worker. Env: TOOL=buck|cargo|setup, MODE=cold|change, RUN_ID=<label>, REAPI=grpc://host:port
# cold: empty buck-out / empty CARGO_HOME+target. change: reuse the workspace of the previous run of the
# same tool and repo, plus a one-line change in library code.
set -eu
unset CI
export PATH=/nix/var/nix/profiles/system/sw/bin:/shared:$PATH
tool=${TOOL:?}; mode=${MODE:-cold}; id=${RUN_ID:?}
repo=${CI_REPO_NAME:?}
base=/workspaces/bakeoff/buck2
awk '/MemAvailable:/ { if ($2 < 8388608) exit 1 }' /proc/meminfo || { echo "Insufficient memory headroom"; exit 75; }
export XDG_CACHE_HOME="$base/xdg-cache"
export NIX_CONFIG="max-jobs = 1
cores = 16"
mkdir -p "$base"
nix build path:./ci/buck2/tools#tools --no-link --print-out-paths > "$base/tools-path"
tools=$(cat "$base/tools-path")
if [ "$tool" = setup ]; then
  "$tools/bin/buck-env" sh -c 'buck2 --version; rustc --version; cargo --version; gcc --version | head -1; rsync --version | head -1'
  echo "tools=$tools"; exit 0
fi
out="$base/runs/$id-$repo"; rm -rf "$out"; mkdir -p "$out"
ws="$base/$repo/$tool/src"
[ "$mode" = cold ] && rm -rf "$base/$repo/$tool"
mkdir -p "$ws"
rsync -rc --delete --exclude=.git --exclude=buck-out --exclude=target --exclude=.buckconfig.local ./ "$ws/"
git rev-parse HEAD > "$out/commit"
if [ "$mode" = change ]; then
  # one-line change in library code (the same for buck and cargo)
  lib=src/lib.rs; [ -f "$ws/$lib" ] || lib=src/main.rs
  printf 'pub const BAKEOFF_PROBE: u32 = 1;\n' >> "$ws/$lib"
fi
cd "$ws"
cg=/sys/fs/cgroup
cpu_of() { awk -v k="$1" '$1==k {print $2}' $cg/cpu.stat; }
run_step() { # name, command; time -v covers the process tree it waits for, the cgroup numbers cover daemons too
  u0=$(cpu_of user_usec); s0=$(cpu_of system_usec); m0=$(cat $cg/memory.current)
  : > "$out/$1.mem"; ( while :; do cat $cg/memory.current > "$out/$1.mem.now"; cat "$out/$1.mem.now" >> "$out/$1.mem"; sleep 0.5; done ) & sampler=$!
  command time -f '{"wall_s":%e,"user_s":%U,"system_s":%S,"rss_kib":%M,"exit":%x}' -o "$out/$1.time" \
    "$tools/bin/buck-env" sh -c "$2" > "$out/$1.log" 2>&1 || true
  kill $sampler 2>/dev/null || true
  u1=$(cpu_of user_usec); s1=$(cpu_of system_usec)
  peak=$(sort -n "$out/$1.mem" | tail -1)
  echo "{\"cg_user_s\":$(( (u1-u0)/1000000 )),\"cg_sys_s\":$(( (s1-s0)/1000000 )),\"cg_mem_peak_mib\":$(( peak/1048576 )),\"cg_mem_start_mib\":$(( m0/1048576 ))}" > "$out/$1.cg"
  echo "STEP $1 $(tail -1 "$out/$1.time") $(cat "$out/$1.cg")"
  grep -E "Cache hits|Commands:|Tests finished|BUILD (SUCCEEDED|FAILED)|test result" "$out/$1.log" | tail -6 || true
}
case "$tool" in
 buck)
    reapi=${REAPI:-grpc://10.42.4.117:9092}
    printf '[tools]\n  cc = %s\n  cxx = %s\n  ar = %s\n  bindir = %s\n\n[buck2_re_client]\n  action_cache_address = %s\n  cas_address = %s\n  engine_address = %s\n' \
      "$("$tools/bin/buck-env" sh -c 'command -v gcc')" "$("$tools/bin/buck-env" sh -c 'command -v g++')" "$("$tools/bin/buck-env" sh -c 'command -v ar')" "$("$tools/bin/buck-env" sh -c 'dirname $(command -v ld)')" "$reapi" "$reapi" "$reapi" > .buckconfig.local
    run_step build "buck2 --no-buckd build -j 16 //:"
    run_step test "buck2 --no-buckd test -j 16 //:" ;;
 cargo)
    export CARGO_HOME="$base/$repo/cargo/home" CARGO_TARGET_DIR="$base/$repo/cargo/target"
    mkdir -p "$CARGO_HOME"
    export CARGO_BUILD_JOBS=16 RUST_TEST_THREADS=16 CARGO_TERM_COLOR=never CARGO_INCREMENTAL=1
    run_step build "cargo build --locked --all-targets"
    run_step test "cargo test --locked" ;;
esac
echo "orphans: $(pgrep -u "$(id -u)" -f 'buck2|rustc|cargo' | wc -l)"
du -sk "$ws/buck-out" "$base/$repo/cargo" 2>/dev/null || true
