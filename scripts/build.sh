#!/usr/bin/env bash
#
# Build the nabgcc WPA2/WPA3 firmware for Nabaztag/tag V2.
#
# Runs the full pipeline inside Docker (debian:trixie-slim, linux/amd64):
#   1. Compile the Metal boot bytecode with mtl_compiler (32-bit)
#   2. Cross-compile nabgcc with arm-none-eabi-gcc
#   3. Generate the .sim firmware file with tools/mkfirmware
#
# Prerequisites:
#   - Docker (with linux/amd64 emulation if on Apple Silicon)
#   - Rust toolchain (for building tools/mkfirmware on the host)
#
# Usage:
#   scripts/build.sh [--release]
#
#   --release   Disable debug flags (DEBUG_VM, DEBUG_AUDIO, DEBUG_MAIN)
#               for a smaller production firmware.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NABGCC_DIR="."
MTL_DIR="mtl/mtl_linux"
SIM_OUTPUT_DIR="artifacts"
DOCKER_IMAGE="debian:trixie-slim"
DOCKER_PLATFORM="linux/amd64"

RELEASE_MODE=false
for arg in "$@"; do
  case "$arg" in
    --release) RELEASE_MODE=true ;;
    *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 1 ;;
  esac
done

# --- Dependency checks ---

if ! command -v docker >/dev/null 2>&1; then
  printf 'Missing docker. Install Docker Desktop or Docker Engine first.\n' >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  printf 'Missing cargo. Install the Rust toolchain first.\n' >&2
  exit 1
fi

if [ ! -d "${REPO_ROOT}/${NABGCC_DIR}/src" ]; then
  printf 'nabgcc submodule not initialized. Run:\n' >&2
  printf '  git submodule update --init %s\n' "${NABGCC_DIR}" >&2
  exit 1
fi

if [ ! -d "${REPO_ROOT}/${MTL_DIR}/src" ]; then
  printf 'mtl_linux submodule not initialized. Run:\n' >&2
  printf '  git submodule update --init %s\n' "${MTL_DIR}" >&2
  exit 1
fi

# --- Build mkfirmware tool on the host ---

printf '=== Building tools/mkfirmware ===\n'
cargo build --release --manifest-path "${REPO_ROOT}/tools/mkfirmware/Cargo.toml" --quiet

# The binary may land in the workspace target or the crate-local target,
# depending on whether a workspace is configured.
MKFIRMWARE=""
for candidate in \
  "${REPO_ROOT}/target/release/mkfirmware" \
  "${REPO_ROOT}/tools/mkfirmware/target/release/mkfirmware"; do
  if [ -x "${candidate}" ]; then
    MKFIRMWARE="${candidate}"
    break
  fi
done

if [ -z "${MKFIRMWARE}" ]; then
  printf 'Failed to build mkfirmware.\n' >&2
  exit 1
fi

# --- Prepare release mode ---

MAKE_OPTIONS_OVERRIDE=""
if [ "${RELEASE_MODE}" = true ]; then
  printf '=== Release mode: disabling debug flags ===\n'
  # Override the OPTIONS variable at the make command line level,
  # which takes precedence over the Makefile definition.
  MAKE_OPTIONS_OVERRIDE='OPTIONS='
fi
# NABGCC_OPTIONS overrides everything, e.g. OPTIONS='-DDEBUG_WIFI'.
if [ -n "${NABGCC_OPTIONS:-}" ]; then
  printf '=== Custom OPTIONS: %s ===\n' "${NABGCC_OPTIONS}"
  MAKE_OPTIONS_OVERRIDE="OPTIONS=${NABGCC_OPTIONS}"
fi

# --- Stamp the build ---
#
# Eight characters the boot bytecode carries as its BUILD constant: the
# commit, its last character replaced by m when tracked files differ
# from it. The portal shows it, the server and the application get it.

BUILD_ID="$(git -C "${REPO_ROOT}" rev-parse --short=8 HEAD)"
if ! git -C "${REPO_ROOT}" diff --quiet HEAD -- . ':!artifacts'; then
  BUILD_ID="${BUILD_ID:0:7}m"
fi
printf '=== Build %s ===\n' "${BUILD_ID}"

# --- Run the Docker build ---

printf '=== Building nabgcc in Docker (%s on %s) ===\n' "${DOCKER_IMAGE}" "${DOCKER_PLATFORM}"

docker run --rm --platform "${DOCKER_PLATFORM}" \
  -v "${REPO_ROOT}":/work \
  -w "/work/${NABGCC_DIR}" \
  "${DOCKER_IMAGE}" \
  bash -c '
    apt-get update -qq >/dev/null 2>&1 && \
    apt-get install -y -qq --no-install-recommends gcc-arm-none-eabi libnewlib-arm-none-eabi g++-multilib make >/dev/null 2>&1 && \
    echo "--- Building mtl_compiler ---" && \
    make -C /work/'"${MTL_DIR}"' clean comp && \
    echo "--- Cleaning nabgcc ---" && \
    make clean && \
    mkdir -p obj bin && \
    echo "--- Compiling Metal bytecode ---" && \
    cd obj && \
    sed -e "s/^const BUILD=\"[^\"]*\";;/const BUILD=\"'"${BUILD_ID}"'\";;/" \
      ../mtl/boot/boot.0.0.0.13.mtl > boot.stamped.mtl && \
    grep -q "^const BUILD=\"'"${BUILD_ID}"'\";;" boot.stamped.mtl && \
    /work/'"${MTL_DIR}"'/mtl_compiler boot.stamped.mtl ../bin/boot.0.0.0.13.bin && \
    cd /work/'"${NABGCC_DIR}"' && \
    echo "--- Converting bytecode to bc.c ---" && \
    BIN_FILE=bin/boot.0.0.0.13.bin && \
    BIN_SIZE=$(wc -c < "$BIN_FILE" | tr -d " ") && \
    echo "Bytecode size: $BIN_SIZE bytes" && \
    # src/bc.c is a tracked link to this file: write through to it, so
    # a build leaves the tree as it found it.
    printf "const unsigned char dumpbc[%d]={\n" "$BIN_SIZE" > obj/dumpbc.c && \
    od -An -v -tx1 "$BIN_FILE" | sed -e "s/ \([0-9a-f][0-9a-f]\)/0x\1,/g" >> obj/dumpbc.c && \
    printf "};\n" >> obj/dumpbc.c && \
    arm-none-eabi-gcc --version | head -1 && \
    echo "--- Building nabgcc ---" && \
    make -j$(nproc) '"${MAKE_OPTIONS_OVERRIDE:+\"${MAKE_OPTIONS_OVERRIDE}\"}"' && \
    echo "--- Checking the flash routines never leave RAM ---" && \
    # They erase the flash under their own feet: one call back into it
    # (a memcpy the optimizer made out of a copy loop, say) is a brick.
    RAM_START=$(arm-none-eabi-nm bin/Nab.elf | sed -n "s/ . init_uc_flash$//p") && \
    RAM_END=$(arm-none-eabi-nm bin/Nab.elf | sed -n "s/ . _edata$//p") && \
    test -n "$RAM_START" && test -n "$RAM_END" && \
    if arm-none-eabi-objdump -d --start-address=0x$RAM_START --stop-address=0x$RAM_END bin/Nab.elf \
        | grep -E "[[:space:]]bl?x?[a-z]*[[:space:]]+0?8[0-9a-f]{6}[[:space:]]|veneer|_from_(thumb|arm)"; then \
      echo "A RAM flash routine branches into the flash: refusing this build." >&2; exit 1; \
    else echo "ok: $RAM_START..$RAM_END"; fi
  '

BUILD_STATUS=$?
if [ "${BUILD_STATUS}" -ne 0 ]; then
  printf 'nabgcc build failed (exit %d).\n' "${BUILD_STATUS}" >&2
  exit 1
fi

NAB_BIN="${REPO_ROOT}/${NABGCC_DIR}/bin/Nab.bin"
if [ ! -f "${NAB_BIN}" ]; then
  printf 'Build produced no Nab.bin — something went wrong.\n' >&2
  exit 1
fi

NAB_SIZE=$(wc -c < "${NAB_BIN}" | tr -d ' ')
printf '=== nabgcc build complete: Nab.bin = %s bytes ===\n' "${NAB_SIZE}"

# --- Generate .sim firmware ---

mkdir -p "${REPO_ROOT}/${SIM_OUTPUT_DIR}"

if [ "${RELEASE_MODE}" = true ]; then
  SIM_NAME="Nab-wpa23-release.sim"
else
  SIM_NAME="Nab-wpa23.sim"
fi

SIM_PATH="${REPO_ROOT}/${SIM_OUTPUT_DIR}/${SIM_NAME}"

printf '=== Generating %s ===\n' "${SIM_NAME}"
"${MKFIRMWARE}" "${NAB_BIN}" "${SIM_PATH}"

SIM_SIZE=$(wc -c < "${SIM_PATH}" | tr -d ' ')
printf '=== Done: %s = %s bytes ===\n' "${SIM_PATH}" "${SIM_SIZE}"
printf '\nTo flash the rabbit:\n'
printf '  1. Put the rabbit in config mode (hold button + power on)\n'
printf '  2. Connect to the NabaztagXX WiFi AP\n'
printf '  3. Upload %s at http://192.168.0.1/u.htm\n' "${SIM_NAME}"
