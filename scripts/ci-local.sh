#!/usr/bin/env bash
# Run, here and in order, what .github/workflows/emulator.yml runs: push
# only once this passes. Stops at the first failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

step() { printf '\n== %s\n' "$*"; }

cd "$root/lapin"
step "lapin: portable crates and the firmware"
(cd p256 && cargo test)
(cd core && cargo test)
(cd metal && cargo test)
(cd cref && cargo test --release)
./build.sh

cd "$root/tools/emu"
if [ ! -f tests/roms/arm.gba ] || [ ! -f tests/roms/thumb.gba ]; then
    echo "the instruction test ROMs are missing from tools/emu/tests/roms (see the README)" >&2
    exit 1
fi
step "emulator: format and lints"
cargo fmt --check
cargo clippy --release --all-targets -- -D warnings
step "emulator: every test, on r3"
cargo test --release
step "the acceptance tests, on lapin"
NABEMU_FIRMWARE=lapin cargo test --release --test boot --test board --test join --test link \
    --test network --test setup --test rfid --test factory --test flash --test garenne --test limits
step "the browser build"
cargo clippy --release --lib --target wasm32-unknown-unknown -- -D warnings
web/build.sh
node web/test.mjs
step "all green"
