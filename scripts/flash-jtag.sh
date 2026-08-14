#!/usr/bin/env bash
#
# Flash a firmware .bin to the Nabaztag V2 over JTAG, from the Mac, through
# the Alpine Pi rig (sysfsgpio + RAM stub). This is the primary flash path —
# no config mode, no WiFi AP, and the config sector (0x1F000) is preserved.
#
# Usage:
#   scripts/flash-jtag.sh [path/to/firmware.bin]   # default: bin/Nab.bin
#
# Env: JTAG_PI (default root@192.168.1.103)
#
set -euo pipefail

PI="${JTAG_PI:-root@192.168.1.103}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-${REPO_ROOT}/bin/Nab.bin}"

[ -f "${BIN}" ] || { echo "ERR: firmware not found: ${BIN}" >&2; exit 1; }
SIZE=$(wc -c < "${BIN}" | tr -d ' ')
[ "${SIZE}" -le $((0x1F000)) ] || { echo "ERR: ${SIZE} bytes > 124KB limit" >&2; exit 1; }

NAME=$(basename "${BIN}")
echo "==> Firmware: ${BIN} (${SIZE} bytes)"

echo "==> Syncing rig files to ${PI}:~/jtag/"
scp -q -o BatchMode=yes \
  "${REPO_ROOT}/tools/jtag/stub.bin" \
  "${REPO_ROOT}/tools/jtag/nabaztag-pi1-sysfs.cfg" \
  "${REPO_ROOT}/tools/jtag/flash-jtag.tcl" \
  "${BIN}" \
  "${PI}:~/jtag/"

echo "==> Splitting into 4KB sector chunks"
ssh -o BatchMode=yes "${PI}" "cd ~/jtag && rm -f chunk_* && split -b 4096 -d -a 3 '${NAME}' chunk_ && ls chunk_* | wc -l"

echo "==> Flashing over JTAG (bit-bang: allow ~10-15 min)"
# The flash runs under nohup ON THE PI: a dropped ssh session or a killed
# local pipeline can no longer abort a half-written flash.
ssh -o BatchMode=yes "${PI}" \
  "cd ~/jtag && rm -f flash.log && (nohup openocd -f nabaztag-pi1-sysfs.cfg -f flash-jtag.tcl \
     -c 'init; flash_rabbit ${NAME}; shutdown' > flash.log 2>&1 &) && echo launched"

echo "==> Waiting for completion (polling flash.log)"
while ssh -o BatchMode=yes "${PI}" 'pgrep openocd >/dev/null' 2>/dev/null; do
  sleep 20
done

RESULT=$(ssh -o BatchMode=yes "${PI}" \
  "grep -E 'Sector|Verify|error|Error|resetting' ~/jtag/flash.log | tail -8")
printf '%s\n' "${RESULT}"

if printf '%s' "${RESULT}" | grep -q "Verify OK"; then
  echo "==> Done. The rabbit reset into the new firmware."
else
  echo "ERR: flash did not verify — full log: ssh ${PI} cat '~/jtag/flash.log'" >&2
  exit 1
fi
