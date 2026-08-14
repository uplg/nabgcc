# Nabaztag V2 — JTAG debrick with a Raspberry Pi 1/Zero and stock OpenOCD

Companion to `vendor/nabgcc/JTAG-RECOVERY.md`. That guide relied on RedoX's
patched OpenOCD 0.8.0 (`ml67q40xx` flash driver), whose source archives
(`wk.redox.ws/_media/dev/nab/v2/jtag/*`) are now offline and were never
archived. The x86-64 binary vendored at `vendor/nabgcc/openocd/openocd`
cannot run on a Raspberry Pi.

This guide replaces the custom driver with a **RAM stub** (`tools/jtag/`):
stock OpenOCD ≥ 0.12 loads `stub.bin` into the ML67Q4051's internal RAM over
JTAG and drives it sector by sector. The stub replicates the exact SPD
flash-programming sequences from the firmware's own self-update code
(`vendor/nabgcc/src/utils/mem.c`). The config sector (0x1F000, WiFi
config/serial) is protected by the stub and never erased.

## Files

| File | Role |
|---|---|
| `tools/jtag/stub.c` / `stub.ld` | RAM flash stub (source) |
| `tools/jtag/build-stub.sh` | builds `stub.bin` via Docker (arm-none-eabi) |
| `tools/jtag/nabaztag-pi1.cfg` | OpenOCD 0.12 config, Pi 1/Zero GPIO bit-bang |
| `tools/jtag/flash-jtag.tcl` | `backup_flash` + `flash_rabbit` procs |
| `vendor/nabgcc-latest/Nab0013-original.bin` | original Violet firmware, decrypted from `Nab0013.01ca89.sim` (105,128 bytes, round-trip verified) |

## Wiring (6 Dupont wires, no soldering if J29 is populated)

J29 is the 8-pin inline header near the MCU (top-left, facing the rabbit).
**Pin 1 = square pad = 3.3 V — leave it unconnected.** Pin 3 (nTRST) is also
left unconnected (on-board 10k pull-up). Wire with everything powered off;
the rabbit keeps its own power supply, only GND is shared.

| Signal | J29 pin | Pi BCM GPIO | Pi physical pin |
|---|---|---|---|
| GND    | 2 | —      | 25 |
| TDI    | 4 | GPIO10 | 19 |
| TMS    | 5 | GPIO25 | 22 |
| TCK    | 6 | GPIO11 | 23 |
| TDO    | 7 | GPIO9  | 21 |
| RESETN | 8 | GPIO8  | 24 |

Before wiring, sanity-check pin 1 with a multimeter: rabbit powered on,
pin 1 → GND must read ~3.3 V; pin 2 must be continuous with power-jack
ground (rabbit off).

## Procedure

```bash
# 1. On the Mac: build the stub
tools/jtag/build-stub.sh

# 2. Copy everything to the Pi (Raspberry Pi OS Bookworm, openocd 0.12 via apt)
scp tools/jtag/{stub.bin,nabaztag-pi1.cfg,flash-jtag.tcl} \
    vendor/nabgcc-latest/Nab0013-original.bin pi@<pi-ip>:~/jtag/

# 3. On the Pi
sudo apt-get install -y openocd
openocd --version          # must be >= 0.12 (adapter gpio / read_memory syntax)
cd ~/jtag
split -b 4096 -d -a 3 Nab0013-original.bin chunk_

# 4. Power on the rabbit, then check the JTAG link
sudo openocd -f nabaztag-pi1.cfg
#   -> must print: tap/device found: 0x3f0f0f0f
#   Ctrl+C once confirmed. If scan fails: recheck wiring, drop adapter speed.

# 5. Backup the bricked flash, then flash + verify + reboot
sudo openocd -f nabaztag-pi1.cfg -f flash-jtag.tcl \
  -c "init; backup_flash bricked-backup.bin; flash_rabbit Nab0013-original.bin; shutdown"
```

`flash_rabbit` errors out if any sector fails or if `verify_image`
mismatches; it is safe to re-run from scratch (each sector is erased before
programming).

After `reset run` the rabbit should boot normally; holding the head button
during power-on must give solid blue LEDs (config mode) again. From there,
the WiFi/HTTP flashing path (`scripts/flash-nabaztag.py`) works again.

## Alpine Linux on the Pi

The procedure works on Alpine (armhf covers the Pi 1/Zero); adjust:

```sh
apk add openocd coreutils        # openocd 0.12 is in community; coreutils for GNU split -d
openocd --version                # must be >= 0.12
```

- Run OpenOCD as **root** (`su -` or `doas`) — Alpine has no sudo by default.
- BusyBox `split` has no `-d`; either use coreutils (above) or drop `-d`
  (alphabetic suffixes `chunk_aaa…` sort correctly too; `flash-jtag.tcl`
  only needs lexical order).
- If `bcm2835gpio` fails to open `/dev/mem` (STRICT_DEVMEM kernels), use the
  drop-in fallback config `nabaztag-pi1-gpiod.cfg` (linuxgpiod via
  `/dev/gpiochip0`) — same wiring, same commands, just slower.

## Notes

- The stub refuses to touch anything past 0x1EFFF, so the config sector
  (serial, WiFi params) survives. If the bricked firmware corrupted it, the
  rabbit still boots — you just reconfigure WiFi in config mode.
- Once the rabbit is alive again, do **not** re-flash
  `Nab-wpa23-release.sim` (the bytecode that caused the brick, per
  `JTAG-RECOVERY.md`). Rebuild per that guide's "Build Command" section
  first.
- Fallback if the stub path misbehaves: RedoX (mem.c author,
  `dev@redox.ws`) may still have `openocd_0.8.0_oki.patch.gz`; the build
  recipe for it is in `rngtng/NabaztagHackKit`
  `lua/tools/openocd/README.md`, whose rig also validated this exact Pi
  wiring.
