#!/usr/bin/env bash
# Build the rabbit's firmware (an ELF for the emulator and a raw image).
set -euo pipefail
cd "$(dirname "$0")/fw"
cargo build --release
out=../target/thumbv4t-none-eabi/release
arm-none-eabi-size "$out/rescue" "$out/lapin" "$out/bench" "$out/selftest" 2>/dev/null || ls -l "$out"

# The images a rabbit takes (src/boot.rs): the rescue core in its 20 KB,
# then the application with its header's length and CRC filled in.
# lapin-full.bin is what gets flashed, or sent over the air: an update
# that brings the same rescue core rewrites the application alone.
arm-none-eabi-objcopy -O binary "$out/rescue" ../target/rescue.bin
for app in lapin bench selftest; do
    arm-none-eabi-objcopy -O binary "$out/$app" "../target/$app.bin"
    python3 - "../target/rescue.bin" "../target/$app.bin" "../target/$app-full.bin" <<'PY'
import struct, sys, zlib
rescue = open(sys.argv[1], 'rb').read()
app = bytearray(open(sys.argv[2], 'rb').read())
size = 20 * 1024
if len(rescue) > size - 8:
    sys.exit(f"the rescue core takes {len(rescue)} bytes, more than its {size - 8}")
core = rescue + b'\xff' * (size - 8 - len(rescue))
core += struct.pack('<II', 0x5250414C, zlib.crc32(core) & 0xFFFFFFFF)
if struct.unpack_from('<I', app, 0)[0] != 0x4150414C:
    sys.exit(f"{sys.argv[2]}: no application header")
if size + len(app) > 124 * 1024:
    sys.exit(f"{sys.argv[2]}: {len(app)} bytes do not fit after the rescue core")
struct.pack_into('<I', app, 4, len(app))
struct.pack_into('<I', app, 8, zlib.crc32(bytes(app[12:])) & 0xFFFFFFFF)
open(sys.argv[2], 'wb').write(app)
open(sys.argv[3], 'wb').write(core + app)
PY
done
ls -l ../target/*-full.bin | awk '{print $5, $NF}'

# The first image, which the C firmware (r3) writes once, as the server
# sends it to a rabbit that still runs it: the same rescue core, then the
# application packed (../pack, src/boot.rs). r3 writes the flash with its
# watchdog unfed; this is short enough for its slowest flash.
(cd .. && cargo run -q --profile host -p lapin-pack -- target/lapin-full.bin target/lapin-first.bin)
rescue_len=$(wc -c < ../target/rescue.bin)
echo "rescue core: $rescue_len bytes of its $((20 * 1024 - 8))"

# The code that runs from RAM while the flash is busy must reach nothing
# in the flash: every branch in the initialised data stays in RAM, and
# the only jump through a register is the return (`bx lr`, or Thumb's
# `pop {rN}` then `bx rN`).
if ! command -v arm-none-eabi-objdump >/dev/null; then
    echo "arm-none-eabi-objdump is missing: the code in RAM cannot be checked" >&2
    exit 1
fi
for elf in rescue lapin; do
    bad=$(arm-none-eabi-objdump -d -j .data "$out/$elf" | awk '
        /^[0-9a-f]+ <.*>:$/ { next }
        $3 ~ /^(b|bl|blx|b[a-z][a-z])(\.n|\.w)?$/ && $4 !~ /^(1[0-9a-f]{7})$/ { print }
        $3 ~ /^bx/ && $4 != "lr" && prev != "pop {" $4 "}" { print }
        $3 == "ldr" && $4 ~ /^pc,/ { print }
        $3 == "mov" && $4 ~ /^pc,/ { print }
        { prev = $3 " " $4 }')
    if [ -n "$bad" ]; then
        echo "$elf: code in RAM reaches outside it:" >&2
        echo "$bad" >&2
        exit 1
    fi
done
