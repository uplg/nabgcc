#!/usr/bin/env bash
#
# Read live firmware state from the running rabbit over JTAG.
# Extracts symbol addresses from the CURRENT build's Nab.sym (they move
# between builds!) and generates the OpenOCD script accordingly.
#
# Requires: the flashed firmware == bin/Nab.bin (same build).
# The diag build (DIAG: comments in main.c) disables the watchdog, making
# halts safe. Never trust reads on a WDT-armed firmware.
#
# Usage: scripts/rabbit-spy.sh [n_samples] [interval_ms]
#
set -euo pipefail

PI="${JTAG_PI:-root@192.168.1.103}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYM="${REPO_ROOT}/obj/Nab.sym"
N="${1:-6}"
INTERVAL="${2:-2000}"

addr() { awk -v s="$1" '$4 == s {print "0x" $1; found=1} END {exit !found}' "${SYM}"; }

A_STATE=$(addr ieee80211_state)
A_MAC=$(addr rt2501_mac)
A_USB=$(addr usbhost_init_status)
A_EAPOL=$(addr eapol_state)
A_ENC=$(addr ieee80211_encryption)

TCL=$(mktemp)
cat > "${TCL}" <<EOF
init
for {set i 0} {\$i < ${N}} {incr i} {
    halt
    set mac [read_memory ${A_MAC} 8 6]
    set usb [read_memory ${A_USB} 8 1]
    set st  [read_memory ${A_STATE} 32 1]
    set eap [read_memory ${A_EAPOL} 8 1]
    set enc [read_memory ${A_ENC} 8 1]
    resume
    echo [format "SPY mac=%02x:%02x:%02x:%02x:%02x:%02x usb=%d state=%d eapol=%d enc=0x%02X" \\
      [lindex \$mac 0] [lindex \$mac 1] [lindex \$mac 2] [lindex \$mac 3] [lindex \$mac 4] [lindex \$mac 5] \\
      \$usb \$st \$eap \$enc]
    sleep ${INTERVAL}
}
shutdown
EOF

scp -q -o BatchMode=yes "${TCL}" "${PI}:~/jtag/spy-gen.tcl"
rm -f "${TCL}"
ssh -o BatchMode=yes "${PI}" 'cd ~/jtag && timeout 300 openocd -f nabaztag-pi1-sysfs.cfg -f spy-gen.tcl 2>&1 | grep -E "SPY|Error"'
