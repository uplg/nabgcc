#!/usr/bin/env bash
#
# Build the nabgcc WPA2/WPA3 firmware for Nabaztag/tag V2.
#
# Runs the full pipeline inside Docker (debian:bullseye-slim, linux/amd64):
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
DOCKER_IMAGE="debian:bullseye-slim"
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
  # Debug flags stay off; the deafness-campaign counters stay on
  # (cheap, silent, and the whole point of the soak build).
  MAKE_OPTIONS_OVERRIDE='OPTIONS=-DDIAG_COUNTERS'
fi
# NABGCC_OPTIONS overrides everything: the association-diagnosis image
# wants OPTIONS='-DDIAG_RING -DDEBUG_WIFI -DDIAG_COUNTERS'.
if [ -n "${NABGCC_OPTIONS:-}" ]; then
  printf '=== Custom OPTIONS: %s ===\n' "${NABGCC_OPTIONS}"
  MAKE_OPTIONS_OVERRIDE="OPTIONS=${NABGCC_OPTIONS}"
fi

# --- Run the Docker build ---

printf '=== Building nabgcc in Docker (%s on %s) ===\n' "${DOCKER_IMAGE}" "${DOCKER_PLATFORM}"

docker run --rm --platform "${DOCKER_PLATFORM}" \
  -v "${REPO_ROOT}":/work \
  -w "/work/${NABGCC_DIR}" \
  "${DOCKER_IMAGE}" \
  bash -c '
    apt-get update -qq >/dev/null 2>&1 && \
    apt-get install -y -qq gcc-arm-none-eabi g++-multilib make libnewlib-arm-none-eabi xxd >/dev/null 2>&1 && \
    echo "--- Building mtl_compiler ---" && \
    make -C /work/'"${MTL_DIR}"' clean comp && \
    echo "--- Cleaning nabgcc ---" && \
    make clean && \
    mkdir -p obj bin && \
    echo "--- Compiling Metal bytecode ---" && \
    cd obj && \
    /work/'"${MTL_DIR}"'/mtl_compiler ../mtl/boot/boot.0.0.0.13.mtl ../bin/boot.0.0.0.13.bin && \
    cd /work/'"${NABGCC_DIR}"' && \
    echo "--- Converting bytecode to bc.c ---" && \
    BIN_FILE=bin/boot.0.0.0.13.bin && \
    BIN_SIZE=$(wc -c < "$BIN_FILE" | tr -d " ") && \
    echo "Bytecode size: $BIN_SIZE bytes" && \
    rm -f src/bc.c && \
    printf "const unsigned char dumpbc[%d]={\n" "$BIN_SIZE" > src/bc.c && \
    xxd -i < "$BIN_FILE" >> src/bc.c && \
    printf "};\n" >> src/bc.c && \
    echo "--- Building nabgcc ---" && \
    make -j$(nproc) '"${MAKE_OPTIONS_OVERRIDE:+\"${MAKE_OPTIONS_OVERRIDE}\"}"'
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
