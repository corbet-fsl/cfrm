#!/bin/sh
# Usage: fanout-worker.sh <prep|a|b> [F0|F1|F2]
set -eu
export PATH=/nix/var/nix/profiles/system/sw/bin:/shared:$PATH
mkdir -p /workspaces/bakeoff/fanout
tools=$(cat /workspaces/bakeoff/common/cfrm/tools-path)
exec "$tools/bin/bakeoff-env" python3 ci/bakeoff/fanout.py "$@"
