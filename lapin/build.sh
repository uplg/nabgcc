#!/usr/bin/env bash
# Build the rabbit's firmware (an ELF for the emulator and a raw image).
set -euo pipefail
cd "$(dirname "$0")/fw"
cargo build --release
out=../target/thumbv4t-none-eabi/release
arm-none-eabi-objcopy -O binary "$out/lapin" ../target/lapin.bin 2>/dev/null || true
arm-none-eabi-size "$out/lapin" "$out/bench" "$out/selftest" 2>/dev/null || ls -l "$out"

# The code that runs from RAM while the flash is busy must reach nothing
# in the flash: every branch in the initialised data stays in RAM, and
# the only jump through a register is the return (`bx lr`, or Thumb's
# `pop {rN}` then `bx rN`).
if command -v arm-none-eabi-objdump >/dev/null; then
    bad=$(arm-none-eabi-objdump -d -j .data "$out/lapin" | awk '
        /^[0-9a-f]+ <.*>:$/ { next }
        $3 ~ /^(b|bl|blx|b[a-z][a-z])(\.n|\.w)?$/ && $4 !~ /^(1[0-9a-f]{7})$/ { print }
        $3 ~ /^bx/ && $4 != "lr" && prev != "pop {" $4 "}" { print }
        $3 == "ldr" && $4 ~ /^pc,/ { print }
        $3 == "mov" && $4 ~ /^pc,/ { print }
        { prev = $3 " " $4 }')
    if [ -n "$bad" ]; then
        echo "code in RAM reaches outside it:" >&2
        echo "$bad" >&2
        exit 1
    fi
fi
