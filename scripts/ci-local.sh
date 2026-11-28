#!/usr/bin/env bash
# Run, here and in order, what .github/workflows/emulator.yml runs: push
# only once this passes. Stops at the first failure.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

step() { printf '\n== %s\n' "$*"; }

cd "$root/lapin"
step "lapin: portable crates and the firmware"
crates=(-p lapin-p256 -p lapin-core -p lapin-metal -p lapin-metal-cref -p lapin-pack)
cargo fmt --all --check
cargo clippy --profile host "${crates[@]}" --all-targets -- -D warnings
(cd fw && cargo clippy --release -- -D warnings)
cargo test --profile host "${crates[@]}"
# The fuzzing harness's own tests: its access point must still take a
# station through every kind of network.
(cd fuzz && cargo fmt --check && cargo clippy --release --all-targets -- -D warnings && cargo test --release)
./build.sh

cd "$root/tools/emu"
if [ ! -f tests/roms/arm.gba ] || [ ! -f tests/roms/thumb.gba ]; then
    echo "the instruction test ROMs are missing from tools/emu/tests/roms (see the README)" >&2
    exit 1
fi
step "no duplication but what nose.ignore.json says must stay"
"$root/scripts/nose.sh" > /dev/null || { "$root/scripts/nose.sh"; exit 1; }
cd "$root/tools/emu"
step "emulator: format and lints"
cargo fmt --check
cargo clippy --release --all-targets -- -D warnings
# The CI runs on Linux, where tests/hostapd.rs compiles: lint it here too.
rustup target add aarch64-unknown-linux-gnu >/dev/null
cargo clippy --release --all-targets --target aarch64-unknown-linux-gnu -- -D warnings
# The suites that follow NABEMU_FIRMWARE run on each firmware; those that
# pick their images themselves (lapin_fixed) run once, with lapin.
on_r3=$("$root/scripts/lapin-suites.sh" r3)
on_lapin=$("$root/scripts/lapin-suites.sh" lapin)
read -ra suites <<<"$on_lapin"
step "emulator: every test, on r3"
# nextest runs every test of every binary at once, on every core.
cargo nextest run --release --no-fail-fast -E "$on_r3"
cargo test --release --doc
step "the acceptance tests, on lapin"
NABEMU_FIRMWARE=lapin cargo nextest run --release --no-fail-fast "${suites[@]}"
step "the browser build"
cargo clippy --release --lib --target wasm32-unknown-unknown -- -D warnings
web/build.sh
bun run --cwd web test
step "all green"
