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
| 5. Resident loader, so a failed update no longer kills the rabbit | done: the rescue core (see below) |
| 6. Size, soak, then a real rabbit | size 111.2 KB (rescue core included), two hours of garenne soaked, an independent review's findings fixed, in the emulator; the real rabbit waits for Léonard's go |

Every acceptance test written for the C firmware (`boot`, `board`,
`join`, `link`, `network`, `setup`, `rfid`, `factory`, `flash`,
`garenne`) passes on lapin, and CI runs them on both images.

## Things worth knowing before continuing

**Flash budget.** 124 KB below the settings sector. lapin takes 111.2
KB (113 840 bytes), the boot bytecode's 27.6 KB included, packed to 16
KB, and the rescue core's 20 KB (19 232 bytes used): 12.8 KB left. The curve and the
machine are built at opt-level 2 for speed (about 7 KB between them).

**Speed.** The interpreter outruns the C one: 1.0 s against 1.7 s on a
loop of 500 000 opcodes, 0.68 s against 1.26 s on `fib 20`
(`tests/lapin.rs` fails past 70 % of the C's time). Its hot loop is ARM
code (`#[instruction_set(arm::a32)]`): Thumb's eight registers could
not hold the machine's state.

**Limits.** `tools/emu/tests/limits.rs` measures, under the heaviest
work (WPA3 with garenne and rekeys, the setup page deriving a key, the
factory test, a collection over an 85 % full heap): the program stack
at most 6.5 KB of its 12 KB (asserted by the linker against the data),
the interrupt stack 196 bytes of 1 KB, the watchdog at most 157 ms
unfed under WPA3 (126 ms by hunting and pecking, which
`wpa3_by_hunting_and_pecking` checks) against a budget of half its
2.09 s: the password exchange runs in steps of at most about 60 ms
across the main loop's turns, which feed the sound between them
(`tests/wpa3_sound.rs`). Before, one step left it 664 ms unfed and a
WPA3 rejoin cut a playing sound for 0.6 s. The first
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

**Fuzzing.** `lapin/fuzz` (cargo-fuzz, its own workspace) drives the
station into every state through a scripted access point and feeds it
frames, and runs the machine on arbitrary bytecode and against the C
one. About 10 CPU-hours found seven station bugs (a short EAPOL frame
halting the rabbit, clear text accepted on a keyed link, a forged
rekey message locking it out until power-off, among them), all fixed
with regression tests; the machine showed no panic and no divergence,
only hangs the C one has too on hostile bytecode.

**Soak.** Two hours of garenne with sound on command, dances, ears,
tags, group rekeys every 30 s, pairwise rekeys every 10 minutes and an
access point restart every quarter of an hour: no reset, 23 sounds
asked, 23 played. The first run, before the fuzzing's fixes, rebooted
three times: a rekey cut by an access point restart left its key
pending and every rejoin failed, the bug the fuzzer had found too.

**Randomness.** The chip has no generator. SAE's numbers come from a
pool (`lapin/core/src/rng.rs`) stirred with the volume wheel's noise,
the arrival times, strengths and first bytes of received frames, and
the main loop's rhythm. Unmeasured on a real rabbit.

**The rescue core.** The first 20 KB of the flash (`lapin/fw/src/bin/rescue.rs`,
`boot.rs`, `rescue.rs`, 18.9 KB) hold the vectors and a core that
the application's updates never write: the firmware proper is an
application after it, with a header (length, CRC-32, entry) the core
checks at every start; the core itself ends on a trailer (magic,
CRC-32). An update that brings the same core (`lapin-full.bin`
from `lapin/build.sh`, as clapier sends it) rewrites the application
alone. When the application is missing or damaged, or has restarted
three times without running a minute, the core raises an open network
"Nabaztag-secours-XXXX" (192.168.0.1, DHCP) with a page to send it
`lapin-full.bin` from a phone; with an application in place it gives
it another try after ten minutes without a request, or at once from
the page. The button held 20 seconds from power-on (setup takes 2, the
factory test 8) asks a running application for the rescue core.
Léonard chose this over a download from clapier: no server change.
`tools/emu/tests/rescue.rs` cuts the power at 17 points of an update:
the rabbit always comes back. An image with a new core is written
whole only when both its parts check (a power cut in its first 20 KB
still kills the rabbit: there is one core); one that starts as lapin
but is damaged or cut is refused. The C firmware's images are still
written whole, unchecked, with the old risk (Léonard to decide whether
to keep that way back).

**The review.** Three independent reviews (station and crypto, the
machine against the C, the firmware and rescue core) found about forty
problems, fixed with a test each: among them a WPA3 link that never
noticed its access point had forgotten it (SA Query now), no replay
check on frames the stick decrypts, a transition network forced down
to WPA2, a group key reinstalled (KRACK), the curve arithmetic not
constant-time, a collector that could loop, a USB timeout that froze
the rabbit with the watchdog fed, and an image cut short that rewrote
the rescue core. `tools/emu/tests/hardening.rs`, `wifi_review.rs`,
`odd_audio.rs` and `lapin/cref/tests/ops.rs` hold the tests. A WPA
(TKIP) link now reports itself up after its group key, not at
message 3: timing only for the bytecode.

**WPA3.** The bytecode knows nothing of it: an RSN network offering
SAE is reported as WPA2, and the station uses SAE when the settings
hold the passphrase (the setup page stores it next to the derived key).
The stick cannot protect management frames, so on a WPA3 link it holds
no key and the firmware does CCMP itself. On the emulated ARM7 a join
takes 2.0 s after the scan; after a power cut the access point's SA
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

## Deliberate differences from r3

lapin behaves as r3 wherever the bytecode or the outside can see it,
except where r3 is wrong or unsafe. Each difference below is checked
by a test that runs on both firmwares; a "Known defect" test checks
r3's misbehaviour where the emulator shows it.

What the bytecode sees:

- **Scan results**: one entry per network (BSSID and name), the
  strongest frame heard, up to 256 networks; r3 lists every frame it
  hears, as many as its heap holds, and loses some neighbours in a
  crowded band (175 of 201 listed, `tests/crowded.rs`). The boot keeps
  the strongest per name anyway (`filterscan`).
- **Scan codes**: a WPA element whose group cipher is WEP is reported
  0xFF (cannot join: neither handshake installs a WEP group key); r3
  says WPA. An RSN network offering SAE alone is WPA2 to lapin, which
  joins it with WPA3; r3 says 0xFF (`tests/scan.rs`).
- **netAuth** on an open or WPA network with a non-zero mode: lapin
  authenticates as open system; r3 sends a shared-key request, then
  reads the answer as open system's, and stays off the network. On WEP
  both take any mode but 0 for a shared key.
- **netSetmode** to master with a nil name: an empty name; r3 copies
  from address 0.
- **netState** says broken (0) while the stick fails every receive, and
  no longer once it works; r3 never says it (its host controller driver
  hands a failed transfer over as a short packet) and sees the link
  lost when its wait runs out.
- **Environment** across a change of bytecode: up to 32 KB, as r3
  effectively keeps (its 4 KB audio buffer and what follows, up to its
  USB heap); past that r3 corrupts its USB heap and restarts, lapin
  carries the first 32 KB.
- **netSend** during the first handshake is refused (r3 sent the
  bytecode's frames in clear before the keys); a frame over about 2360
  bytes is refused (0), where r3 copies it past the stick's buffer and
  restarts.
- **netPmk** and **netScan** take at most 32 bytes of a network name;
  r3 copies a longer one over what follows its buffer (netPmk then
  hangs).
- **Frames**: EAPOL never reaches the bytecode, in any mode, and is
  acted on only on a WPA link (lapin used to answer message 1 on open
  and WEP links, and hand EAPOL up in master mode: fixed, as r3 does).
  Protected frames the stick could not open are dropped; r3 hands them
  up as they came.
- **Reboot** asked by the bytecode does not count as a failed start for
  the rescue core.
- The audio converters: an ADPCM step index past 88 reads a step of 0
  where r3 reads past its table; a negative length to `alaw2wav` or
  `wav2alaw` does nothing where r3 loops until the watchdog bites. A
  codec that never asks for data is waited for 500 ms, not for ever.
  The tag reader's "Error" (8 bytes, padded) and a jammed I2C bus are
  handled as `tests/odd_audio.rs`, `tests/rfid.rs` and
  `tests/hardening.rs` describe.

What the access point and the air see:

- **Rates**: lapin sends at 12 and 18 Mb/s when the access point's
  rates and the signal call for them; r3 has no case for those two
  rates and sends at 1 Mb/s, with a duration computed for the faster
  rate (its DHCP retries go out at 1 Mb/s, lapin's at 18). The signal
  average is fed by the same frames in both (management frames from
  the access point once associated, data frames from it).
- **EAPOL bodies**: messages 2 and 4 and the group key answer have
  their exact length; r3 adds 24 zero bytes.
- **The handshake**: a message 1 sent again keeps the nonce and does
  not commit the replay counter (as wpa_supplicant); a message 3
  without a group key is not answered; the group key is installed
  before message 4 or the group answer goes out; a WPA (TKIP era)
  association names the access point's own pairwise cipher, where r3
  always says TKIP; all four key slots are cleared on a join; a pairwise
  rekey on a running link is taken (r3 ignored it); 104-bit WEP keys
  are kept whole; the first CCMP frame is numbered 1; probe requests
  carry a network name element. WPA2 with TKIP alone joins (r3 never
  installs its group key, `tests/join.rs`).
- **Shared-key authentication** with a challenge that is not 128 bytes
  ends the attempt at once and uses the first challenge element; r3
  waits for its timeout and uses the last.
- **Elements**: the first RSN element is read and a truncated one is
  ignored; a deauthentication during a scan is ignored (the scan runs
  its course, as in r3).
- **A scan** listens 120 ms per channel (r3 350) and sends no probe on
  channel 14.
- **Replay check**: frames the stick decrypts are checked against their
  packet numbers from the receive descriptor; if the stick gives none
  (IV words without the extended IV bit) the check is left out for
  them and the console says so once (`tests/observable.rs`). r3 never
  checked.

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
