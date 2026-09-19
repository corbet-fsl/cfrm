#!/usr/bin/env bash
# Isolated CI dependency only. Never installs packages or starts a service.
set -euo pipefail
umask 077
valkey_root="${VALKEY_TEST_ROOT:?Set VALKEY_TEST_ROOT to the owned artifact/tools directory for this run}"
case "$valkey_root" in /*) ;; *) echo 'VALKEY_TEST_ROOT must be absolute' >&2; exit 2;; esac
if test "$valkey_root" = / || test -L "$valkey_root" || test -L "$valkey_root/bin"; then
  echo 'Refusing an unsafe Valkey staging directory' >&2
  exit 2
fi
if test "$(uname -s)" != Linux || test "$(uname -m)" != x86_64; then
  echo 'The pinned test artifact requires Linux x86_64' >&2
  exit 2
fi
mkdir -p "$valkey_root/bin"
valkey_stage="$(mktemp -d "$valkey_root/stage.XXXXXXXX")"
valkey_archive="$valkey_stage/valkey-9.1.2-jammy-x86_64.tar.gz"
valkey_url='https://download.valkey.io/releases/valkey-9.1.2-jammy-x86_64.tar.gz'
valkey_sha='33687af7a5457459a16c207a9c1971fc70f67e6ec1f011a876094b790741bd63'
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --retry 2 --connect-timeout 20 --max-time 180 --max-filesize 134217728 \
  "$valkey_url" --output "$valkey_archive"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  --retry 2 --connect-timeout 20 --max-time 60 --max-filesize 1024 \
  "$valkey_url.sha256" --output "$valkey_stage/official.sha256"
read -r valkey_official_sha valkey_official_name < "$valkey_stage/official.sha256"
if test "$valkey_official_sha" != "$valkey_sha" || test "$valkey_official_name" != 'valkey-9.1.2-jammy-x86_64.tar.gz'; then
  echo 'Official Valkey checksum does not match the reviewed release pin' >&2
  exit 1
fi
printf '%s  %s\n' "$valkey_sha" "$valkey_archive" | sha256sum --check --status

# Extract exactly one ordinary executable to an explicitly selected output file.
# No archive paths, symlinks, permissions or ownership are applied to the host.
python3 - "$valkey_archive" "$valkey_stage/server.elf" <<'PY'
import pathlib
import shutil
import sys
import tarfile

with tarfile.open(sys.argv[1], "r:gz") as archive:
    selected = []
    for index, member in enumerate(archive):
        if index >= 4096:
            raise SystemExit("Valkey archive contains too many entries")
        path = pathlib.PurePosixPath(member.name)
        if path.name != "valkey-server":
            continue
        if path.is_absolute() or ".." in path.parts or not member.isfile():
            raise SystemExit("Unsafe Valkey executable archive entry")
        if not 0 < member.size <= 128 * 1024 * 1024:
            raise SystemExit("Invalid Valkey executable size")
        selected.append(member)
    if len(selected) != 1:
        raise SystemExit("Expected exactly one regular valkey-server executable")
    with archive.extractfile(selected[0]) as source, open(sys.argv[2], "xb") as output:
        shutil.copyfileobj(source, output, length=1024 * 1024)
PY
chmod 0755 "$valkey_stage/server.elf"
printf '%s\n' "$valkey_url" > "$valkey_stage/source-url.txt"
sha256sum "$valkey_archive" "$valkey_stage/server.elf" > "$valkey_stage/SHA256SUMS"

if timeout 10 "$valkey_stage/server.elf" --version > "$valkey_stage/version.txt" 2> "$valkey_stage/direct-error.txt"; then
  printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$valkey_stage/server.elf" > "$valkey_root/bin/valkey-server"
else
  # Nix workers have no conventional /lib64 interpreter. Reuse the interpreter
  # and dependency directories of existing trusted executables, without altering
  # the checksum-pinned Valkey ELF or installing any runtime library.
  valkey_bash="$(readlink -f "$(command -v bash)")"
  valkey_loader="$(readelf -l "$valkey_bash" | awk '/Requesting program interpreter:/ {sub(/^.*interpreter: /, ""); sub(/\]$/, ""); print; exit}')"
  if ! test -x "$valkey_loader"; then
    echo 'No usable existing ELF interpreter for the pinned Valkey binary' >&2
    cat "$valkey_stage/direct-error.txt" >&2
    exit 1
  fi
  valkey_libs="$(dirname "$valkey_loader")"
  for valkey_command in bash curl; do
    valkey_existing="$(readlink -f "$(command -v "$valkey_command")")"
    ldd "$valkey_existing" >> "$valkey_stage/existing-libraries.txt"
  done
  while IFS= read -r valkey_library; do
    valkey_libs="$valkey_libs:$(dirname "$valkey_library")"
  done < <(awk '/=> \// {print $3}' "$valkey_stage/existing-libraries.txt" | sort -u)
  if command -v cc >/dev/null; then
    for valkey_library_name in libgcc_s.so.1 libstdc++.so.6 libatomic.so.1; do
      valkey_library="$(cc -print-file-name="$valkey_library_name")"
      if test -f "$valkey_library"; then valkey_libs="$valkey_libs:$(dirname "$valkey_library")"; fi
    done
  fi
  if test -n "${OPENSSL_LIB_DIR:-}" && test -d "$OPENSSL_LIB_DIR"; then
    valkey_libs="$valkey_libs:$OPENSSL_LIB_DIR"
  fi
  printf '#!/usr/bin/env bash\nexec %q --library-path %q %q "$@"\n' \
    "$valkey_loader" "$valkey_libs" "$valkey_stage/server.elf" > "$valkey_root/bin/valkey-server"
  printf '%s\n' "$valkey_loader" > "$valkey_stage/interpreter.txt"
fi
chmod 0755 "$valkey_root/bin/valkey-server"
timeout 10 "$valkey_root/bin/valkey-server" --version > "$valkey_stage/version.txt"
if ! grep -Eq '(^|[ =])9\.1\.2([ .]|$)' "$valkey_stage/version.txt"; then
  echo 'Pinned Valkey test executable reports an unexpected version' >&2
  exit 1
fi
cat "$valkey_stage/version.txt"
printf 'Prepared isolated Valkey test executable at %s\n' "$valkey_root/bin/valkey-server"
