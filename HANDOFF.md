# Handoff

State of the `modern` branch on 2026-11-22. Two new things live here,
both untouched by the C firmware build:

- `tools/emu` — **nabemu**, an emulator of the rabbit and the world
  around it. Its README says what is modelled and how far to trust it.
- `lapin` — a firmware for the rabbit in Rust, developed against the
  emulator. Its README says where it stands and gives the timings.

Nothing here has been on a real rabbit.

## Running it

    cd tools/emu && cargo test --release          # 112 tests, about 40 s
    cd lapin && ./build.sh                        # needs the nightly toolchain
    cd tools/emu && cargo run --release -- --ap Terrier ../../lapin/target/thumbv4t-none-eabi/release/lapin
    cd tools/emu && web/build.sh && node web/test.mjs

The emulator tests that run the Rust firmware (`tests/lapin.rs`) and
garenne (`tests/garenne.rs`) skip themselves when their image is not
there, so build `lapin` first. The CPU test ROMs go in
`tools/emu/tests/roms` (see the emulator's README).

## The plan, and where it is

The decision: a complete firmware in Rust, flashed once, after it
passes in the emulator everything the C firmware passes there.

| Step | State |
|---|---|
| 0. Emulator | done, with the gaps listed below |
| 1. Board drivers (clock, interrupts, timer, watchdog, leds, button, ears, audio codec, tag reader, flash) | done, checked by `selftest` |
| 2. USB host, RT2573 Wi-Fi stick | done: finds the stick, scans the channels |
| 3. 802.11 station and access point: WEP, WPA, WPA2, WPA3 | next |
| 4. Metal virtual machine, to run the boot bytecode and garenne as they are | not started |
| 5. Resident loader, so a failed update no longer kills the rabbit | not started |
| 6. Size, soak, then a real rabbit | not started |

The tests in `tools/emu/tests` (`join`, `link`, `network`, `setup`,
`flash`, `board`, `factory`, `rfid`) run the C firmware today. They are
the acceptance tests for steps 3 to 5: point them at the Rust image.

## Things worth knowing before continuing

**Flash budget.** 124 KB below the settings sector. The boot bytecode
takes 27.6 KB of it. `lapin` is at 10.6 KB after step 2; SAE with its
curve adds about 9 KB. Track it at every step.

**WPA3.** `lapin/core` and `lapin/p256` hold SAE (both password element
methods) and reproduce the IEEE 802.11-2020 J.10 vector on the emulated
ARM7: 1.35 to 1.9 s per connection. The watchdog bites at 2.09 s, so
these computations must feed it. The stick's hardware cannot protect
management frames (Linux's driver says so and falls back to software
encryption): on a WPA3 link the firmware has to do CCMP itself and load
no key in the stick. `tools/emu/src/supplicant.rs` is a WPA3 station
written from the standard, to port from.

**Defects found in the C firmware (r3).** Not to be fixed in C; the
rewrite fixes them. Each is pinned by a test marked "Known defect":
mixed-mode handshake names the wrong group cipher (`eapol.c:496`);
104-bit WEP keys are cut to 40 bits (`ieee80211.c:1932`); the first
CCMP frame is numbered 0 and dropped by Linux access points
(`eapol.c:545`). Probe requests without a network name element is the
fourth; the Rust firmware already sends it.

**Unverified assumptions.** In the emulator: flash erase and program
times (from a comment in the C code, within the manual's maxima), ear
speed, the stick's power-on beacon interval, what the stick reports
for a frame it has no key for, the ring oscillator's frequency (the
first milliseconds of boot), one clock for internal memory and
peripheral registers (the manual gives no wait for them). The external
bus is timed from the manual: the C firmware spends about 8 % of its
time waiting on the SRAM and the USB controller. The rabbit's Wi-Fi module is an MSI MS-6877
(RT2571WF; USB id 0db0:6877), which exists as "VER:1.0, made in
Taiwan" (the one in Léonard's rabbit) and "Ver:A, made in China". The
FCC photos of an MS-6877 without its shield show an RT2528L radio. No
type has been read from a rabbit's own stick yet: the Rust driver
tunes the two 2.4 GHz chips (RT2528, RT2527, words as in Linux's
rt73usb), prints the type at boot (`wifi <address> radio NN`) and
refuses the two 5 GHz ones. The watchdog can be paused (WDHLT in
TBGCON, after the 5AH unlock); the C code sets the bit without the
unlock, which the chip ignores, so its flash routines run under the
watchdog. A full image takes 1.76 s by the modelled timings, against
2.09 s.

**Not done in the emulator.** MP3 decoding to samples (the browser
does it); MIDI is rendered with a plain synthesiser, not the chip's
instruments.

**WPA3 on a real network.** A rabbit that restarts while associated
with protected management frames (a watchdog reset, say) finds the
access point still holding its old association: hostapd refuses the
new one with status 30 and a comeback time of about a second while it
asks the old keys whether they are still there (SA Query). The
firmware has to wait and try again. `tests/wpa3.rs` shows the whole
sequence with the reference station. The browser page was only looked at
through two screenshots.

**Not exercised by any test yet, in the Rust firmware.** Transmit power
calibration, key loading, beacon generation.
