# NabGCC

This a port of the Nabaztag's firmware sources for ARM GCC (and OSS tools).

# Improvements

- Cleanup
  - Fixed all types to use fixed size types from stdint.h
  - Removed lot of useless/debug/dead code
- **WPA2 support** (very experimental)

## Howto
### Requirements

Docker (with linux/amd64 emulation on Apple Silicon) and a Rust toolchain.

### Get the sources

    git clone https://github.com/uplg/nabgcc.git
    cd nabgcc
    git submodule update --init

### Build

    scripts/build.sh --release

The whole pipeline runs in a debian:trixie container: the Metal boot
bytecode, the firmware (arm-none-eabi-gcc), then the `.sim` image in
`artifacts/`. Every image carries the commit it was built from; the
config page shows it. Without `--release` the UART debug output is on,
which is too slow to associate: flash release images.

### Flash

Put the Nabaztag in config mode (head button held while powering on, blue
leds), join its `NabaztagXX` access point, then either run clapier's
`flash-nabaztag artifacts/Nab-wpa23-release.sim` or upload the file at
http://192.168.0.1/u.htm.

Flashing rewrites the whole firmware and there is no bootloader: keep the
power steady. `docs/jtag-debrick.md` is the way back from a bad flash.
