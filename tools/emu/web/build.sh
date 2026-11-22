#!/usr/bin/env bash
# Build the emulator for the browser and put it next to the page.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --profile web --lib --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/web/nabemu.wasm web/nabemu.wasm
ls -l web/nabemu.wasm
