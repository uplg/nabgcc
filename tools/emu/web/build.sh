#!/usr/bin/env bash
# Build the emulator for the browser, gather the firmwares the page
# offers, and build the page into web/dist. `bun run dev` serves the
# same page live once this has run.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --profile web --lib --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/web/nabemu.wasm web/src/lib/emu/nabemu.wasm
ls -l web/src/lib/emu/nabemu.wasm

# The released C firmware, lapin when it is built, garenne when its
# build is around (NABEMU_GARENNE, or ../clapier beside this repository).
mkdir -p web/public/firmware
cp ../../artifacts/Nab-wpa23-gtk-r3.sim web/public/firmware/
lapin=../../lapin/target/lapin-full.bin
garenne=${NABEMU_GARENNE:-../../../clapier/garenne/build/garenne.bin}
for optional in "$lapin" "$garenne"; do
    if [ -f "$optional" ]; then
        cp "$optional" web/public/firmware/
    else
        echo "not offered: $optional is not built"
    fi
done

cd web
bun install --frozen-lockfile
bun run check
bun run build
