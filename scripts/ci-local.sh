#!/usr/bin/env bash
# Run, here and in order, what .github/workflows/emulator.yml runs: push
# only once this passes. Stops at the first failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

step() { printf '\n== %s\n' "$*"; }

cd "$root/lapin"
step "lapin: portable crates and the firmware"
cargo test --profile host -p lapin-p256 -p lapin-core -p lapin-metal -p lapin-metal-cref
# The fuzzing harness's own tests: its access point must still take a
# station through every kind of network.
(cd fuzz && cargo test --release)
./build.sh

cd "$root/tools/emu"
if [ ! -f tests/roms/arm.gba ] || [ ! -f tests/roms/thumb.gba ]; then
    echo "the instruction test ROMs are missing from tools/emu/tests/roms (see the README)" >&2
    exit 1
fi
step "emulator: format and lints"
cargo fmt --check
cargo clippy --release --all-targets -- -D warnings
# The CI runs on Linux, where tests/hostapd.rs compiles: lint it here too.
rustup target add aarch64-unknown-linux-gnu >/dev/null
cargo clippy --release --all-targets --target aarch64-unknown-linux-gnu -- -D warnings
step "emulator: every test, on r3"
# nextest runs every test of every binary at once, on every core.
cargo nextest run --release --no-fail-fast
cargo test --release --doc
step "the acceptance tests, on lapin"
read -ra suites < <(sed -n 's/^lapin_suites: //p' "$root/.github/lapin-suites")
NABEMU_FIRMWARE=lapin cargo nextest run --release --no-fail-fast "${suites[@]}"
step "the browser build"
cargo clippy --release --lib --target wasm32-unknown-unknown -- -D warnings
web/build.sh
bun run --cwd web test
step "all green"
