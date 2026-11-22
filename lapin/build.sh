#!/usr/bin/env bash
# Build the rabbit's firmware (an ELF for the emulator and a raw image).
set -euo pipefail
cd "$(dirname "$0")/fw"
cargo build --release
out=../target/thumbv4t-none-eabi/release
arm-none-eabi-objcopy -O binary "$out/lapin" ../target/lapin.bin 2>/dev/null || true
arm-none-eabi-size "$out/lapin" "$out/bench" "$out/selftest" 2>/dev/null || ls -l "$out"
