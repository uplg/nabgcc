#!/usr/bin/env bash
# The duplication gate: nose over the project's own code (the C firmware
# under src/ is the reference and stays as it is). Every family that must
# stay is in nose.ignore.json with its reason; anything else fails.
set -euo pipefail
cd "$(dirname "$0")/.."
exec nose query -r lapin -r tools/emu -r scripts -r .github \
    --exclude dist/ --exclude node_modules/ --exclude public/ \
    --exclude target/ --exclude obj/ --fail-on any "$@"
