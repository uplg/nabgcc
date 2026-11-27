#!/usr/bin/env bash
# The Rust firmware against a real hostapd, on Linux (a VM: Docker's
# kernels lack mac80211_hwsim). Needs root, hostapd, dnsmasq, python3,
# iw, a Rust toolchain, and lapin built (lapin/build.sh, on any host).
# For each kind of network: a simulated radio, hostapd on it, DHCP and
# a web server serving a bytecode that prints 4242, and
# tools/emu/tests/hostapd.rs carrying frames between that radio and the
# emulated rabbit.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
work=/tmp/nabgcc-hostapd
# Built by whoever called sudo, with their toolchain; only the radios and
# the network need root.
user="${SUDO_USER:-$(id -un)}"
home=$(getent passwd "$user" | cut -d: -f6)
sudo -u "$user" mkdir -p "$work/target"
test_bin=$(sudo -u "$user" env CARGO_TARGET_DIR="$work/target" "$home/.cargo/bin/cargo" test --release \
    --no-run --test hostapd --manifest-path "$repo/tools/emu/Cargo.toml" 2>&1 |
    sed -n 's/.*Executable tests\/hostapd.rs (\(.*\))/\1/p')
[ -x "$test_bin" ] || { echo "the test did not build" >&2; exit 1; }

# What the server answers to anything: a bytecode printing 4242, in the
# envelope the boot bytecode expects.
python3 - "$work/bc" <<'PY'
import struct, sys
code = bytes([0, 0, 0, 3]) + struct.pack('<i', 4242) + bytes([95, 1])
bc = struct.pack('<I', 4) + struct.pack('<I', len(code)) + code + struct.pack('<H', 1) + struct.pack('<I', 0)
open(sys.argv[1], 'wb').write(b'amber' + b'%08x' % len(bc) + bc + b'Mind')
PY
cat > "$work/serve.py" <<'PY'
import http.server, sys
body = open(sys.argv[1], 'rb').read()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(('192.168.50.1', 80), H).serve_forever()
PY

common="interface=IFACE
driver=nl80211
ssid=Terrier
hw_mode=g
channel=6
"
declare -A security=(
  [open]=""
  [wpa]="wpa=1
wpa_passphrase=carotte-violette
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP"
  [wpa2]="wpa=2
wpa_passphrase=carotte-violette
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP"
  [transition]="wpa=2
wpa_passphrase=carotte-violette
sae_password=carotte-violette
wpa_key_mgmt=WPA-PSK SAE
rsn_pairwise=CCMP
ieee80211w=1
sae_pwe=2"
  [wpa3]="wpa=2
sae_password=carotte-violette
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=2"
  # Hash-to-element only: the association has to carry the RSN
  # extension element that says so.
  [wpa3h2e]="wpa=2
sae_password=carotte-violette
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
ieee80211w=2
sae_pwe=1"
)
declare -A config=([open]=open [wpa]=wpa [wpa2]=wpa2 [transition]=wpa2 [wpa3]=wpa2 [wpa3h2e]=wpa2)

status=0
for kind in ${KINDS:-open wpa wpa2 transition wpa3 wpa3h2e}; do
    pkill -x hostapd || true; pkill -x dnsmasq || true; pkill -f serve.py || true
    modprobe -r mac80211_hwsim 2>/dev/null || true
    modprobe mac80211_hwsim radios=1
    sleep 1
    iface=$(ls /sys/class/ieee80211/phy*/device/net 2>/dev/null | head -1)
    [ -n "$iface" ] || iface=$(iw dev | awk '/Interface/ {print $2; exit}')
    phy=$(ls /sys/class/ieee80211 | head -1)
    radio=$(cat /sys/class/ieee80211/$phy/macaddress)
    printf '%s%s\n' "${common//IFACE/$iface}" "${security[$kind]}" > "$work/$kind.conf"
    hostapd -B -P "$work/hostapd.pid" -f "$work/$kind.log" -dd "$work/$kind.conf"
    sleep 2
    ip addr flush dev "$iface"
    ip addr add 192.168.50.1/24 dev "$iface"
    dnsmasq --interface="$iface" --bind-interfaces --dhcp-range=192.168.50.100,192.168.50.150,1h \
        --address=/#/192.168.50.1 --pid-file="$work/dnsmasq.pid" --log-facility="$work/dnsmasq.log"
    python3 "$work/serve.py" "$work/bc" & sleep 1
    echo "== $kind (radio $radio on $iface)"
    if NABEMU_FIRMWARE=lapin NABEMU_HOSTAPD_RADIO="$radio" NABEMU_HOSTAPD_WIFI="${config[$kind]}" \
        "$test_bin" --nocapture --test-threads=1 2>&1 | grep -E "frames to hostapd|test result|panicked|never ran|hwsim refused|cipher errors|wifi|scan|state|^[0-9]+$" ; then :; fi
    grep -E "AP-STA-CONNECTED|EAPOL-4WAY-HS-COMPLETED|authenticated|SAE" "$work/$kind.log" | grep -v "^$" | tail -3 || true
done
pkill -x hostapd || true; pkill -x dnsmasq || true; pkill -f serve.py || true
exit $status
