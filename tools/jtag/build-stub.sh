#!/usr/bin/env bash
#
# Build the Nabaztag JTAG flash stub (stub.c -> stub.bin) with the same
# Docker toolchain used by scripts/build-nabgcc.sh.
#
# Usage: tools/jtag/build-stub.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

docker run --rm --platform linux/amd64 \
  -v "${REPO_ROOT}":/work \
  -w /work/tools/jtag \
  debian:bullseye-slim \
  bash -c '
    apt-get update -qq >/dev/null 2>&1 && \
    apt-get install -y -qq gcc-arm-none-eabi >/dev/null 2>&1 && \
    arm-none-eabi-gcc -mcpu=arm7tdmi -marm -Os -ffreestanding -nostdlib \
      -nostartfiles -fno-builtin -Wall -Wextra \
      -T stub.ld stub.c -o stub.elf && \
    arm-none-eabi-objcopy -O binary stub.elf stub.bin && \
    arm-none-eabi-objdump -d stub.elf > stub.lst && \
    arm-none-eabi-size stub.elf && \
    ls -la stub.bin
  '

echo "OK: tools/jtag/stub.bin"
