# Handoff

State of the `modern` branch on 2026-11-27. Two new things live here,
both untouched by the C firmware build:

- `tools/emu` — **nabemu**, an emulator of the rabbit and the world
  around it. Its README says what is modelled and how far to trust it.
- `lapin` — a firmware for the rabbit in Rust, developed against the
  emulator. Its README says where it stands and gives the timings.

Nothing here has been on a real rabbit.

## Running it

    cd tools/emu && cargo test --release          # the C firmware (r3), about a minute
    cd lapin && ./build.sh                        # needs the nightly toolchain
    cd tools/emu && NABEMU_FIRMWARE=lapin cargo test --release --test boot --test board \
        --test join --test link --test network --test setup --test rfid --test factory \
        --test flash --test garenne               # the same acceptance tests, on lapin
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
| 3. 802.11 station and access point: WEP, WPA, WPA2, WPA3 | done, in `lapin/core/src/wifi.rs` |
| 4. Metal virtual machine, to run the boot bytecode and garenne as they are | done, `lapin/metal`, checked word for word against the C machine (`lapin/cref`) |
| 5. Resident loader, so a failed update no longer kills the rabbit | not started: needs a decision, see below |
| 6. Size, soak, then a real rabbit | size 89.5 KB, 30 minutes of garenne soaked in the emulator; the real rabbit waits for Léonard's go |

Every acceptance test written for the C firmware (`boot`, `board`,
`join`, `link`, `network`, `setup`, `rfid`, `factory`, `flash`,
`garenne`) passes on lapin, and CI runs them on both images.

## Things worth knowing before continuing

**Flash budget.** 124 KB below the settings sector. lapin takes 89.5
KB, the boot bytecode's 27.6 KB included, packed to 16 KB: 34.5 KB left. The curve and the
machine are built at opt-level 2 for speed (about 7 KB between them).

**Speed.** The interpreter outruns the C one: 1.0 s against 1.7 s on a
loop of 500 000 opcodes, 0.68 s against 1.26 s on `fib 20`
(`tests/lapin.rs` fails past 70 % of the C's time). Its hot loop is ARM
code (`#[instruction_set(arm::a32)]`): Thumb's eight registers could
not hold the machine's state.

**Limits.** `tools/emu/tests/limits.rs` measures, under the heaviest
work (WPA3 with garenne and rekeys, the setup page deriving a key, the
factory test, a collection over an 85 % full heap): the program stack
at most 6.8 KB of its 12 KB (asserted by the linker against the data),
the interrupt stack 196 bytes of 1 KB, the watchdog at most 664 ms
unfed (an SAE step) against a budget of half its 2.09 s. The first
measurement found 12.8 KB of stack, 5.4 KB of it a scan array built on
the stack, and a collection three times slower than the C one's.

**A real hostapd.** `scripts/hostapd-interop.sh`, in a Linux VM (Lima
here: Docker's kernels lack `mac80211_hwsim`), puts hostapd 2.11 on a
simulated radio with dnsmasq and a web server, and
`tools/emu/tests/hostapd.rs` carries frames between that radio and the
emulated rabbit over generic netlink, as wmediumd does. Open, WPA TKIP,
WPA2, WPA2/WPA3 transition and WPA3 only all pass: the boot bytecode
gets its address, fetches the served bytecode and runs it. The access
point's ciphers there are the kernel's. Not in CI (it needs root and
the module); run it by hand after touching the station.

**Randomness.** The chip has no generator. SAE's numbers come from a
pool (`lapin/core/src/rng.rs`) stirred with the volume wheel's noise,
the arrival times, strengths and first bytes of received frames, and
the main loop's rhythm. Unmeasured on a real rabbit.

**Resident loader, the decision to take.** Two full images do not fit
in the flash, so surviving a power cut during an update means a part
that is never rewritten and can fetch the firmware again by itself:
drivers, USB, Wi-Fi with its handshakes, and its own small IP stack
(DHCP, DNS, TCP, HTTP), with the Metal machine and the bytecode in the
part that updates. It costs a stable interface between the two parts,
a URL from which the server serves the image to fetch again (a clapier
change), and about 10 KB of the 17 left; an update that touches the
resident part keeps today's risk.

**WPA3.** The bytecode knows nothing of it: an RSN network offering
SAE is reported as WPA2, and the station uses SAE when the settings
hold the passphrase (the setup page stores it next to the derived key).
The stick cannot protect management frames, so on a WPA3 link it holds
no key and the firmware does CCMP itself. On the emulated ARM7 a join
takes 1.6 s after the scan; after a power cut the access point's SA
Query is waited out (status 30) and the rabbit is back in 9 s.

**Defects found in the C firmware (r3).** Not to be fixed in C; lapin
fixes them, and each test marked "Known defect" checks the fix when it
runs lapin:
mixed-mode handshake names the wrong group cipher (`eapol.c:496`);
a pairwise rekey on a running link is ignored (`eapol.c:383`);
104-bit WEP keys are cut to 40 bits (`ieee80211.c:1932`); the first
CCMP frame is numbered 0 and dropped by Linux access points
(`eapol.c:545`). Probe requests without a network name element is the
fourth.

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
2.09 s. lapin's routine feeds the watchdog after every word instead.

**Not done in the emulator.** MP3 decoding to samples (the browser
does it); MIDI is rendered with a plain synthesiser, not the chip's
instruments.

The browser page was only looked at through two screenshots.

**Not exercised by any test yet, in the Rust firmware.** Transmit power
calibration (it runs, nothing checks its effect).
