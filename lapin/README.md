# lapin

A firmware for the Nabaztag:tag written in Rust, to replace the C one
in this repository. It is developed against the emulator in
`../tools/emu`: nothing goes to a real rabbit before it passes there.

    ./build.sh                                      # needs a nightly toolchain
    (cd ../tools/emu && cargo run --release -- ../../lapin/target/thumbv4t-none-eabi/release/lapin)

| Crate | What it is |
|---|---|
| `p256` | the NIST P-256 curve: field, points, constant-time scalar multiplication |
| `core` | everything portable: SHA-256, HMAC, key derivation, the WPA3 password exchange (SAE) |
| `fw` | the firmware itself, for the ARM7TDMI (`thumbv4t-none-eabi`) |

`p256` and `core` have no dependency and no allocation, and are tested
on the machine that builds them (`cargo test` in each).

## Where it stands

`lapin`, the firmware, brings the board up (clock, pins, interrupts, a
millisecond tick, the watchdog, leds, button), starts the USB host,
finds the Wi-Fi stick, loads its firmware, reads its address and
calibration, then goes through the channels asking who is there and
names the networks it hears. 10.6 KB so far, the stick's own 1.6 KB
firmware included.

`selftest` exercises the other drivers one by one: both ears (it
counts the teeth of a full turn), the tag reader, the settings sector
of the flash (rewritten by a routine that runs from RAM), the
loudspeaker and the microphone.

`bench` replays the SAE test vector of IEEE 802.11-2020 on the rabbit's
processor. On the emulated rabbit, 32 MHz and real ARM7TDMI cycle
counts:

| Step | Time |
|---|---|
| Password element, hunting and pecking (forty uniform rounds) | 930 ms |
| Password point, hash-to-element (once per network) | 125 ms |
| Password element from the point | 340 ms |
| Commit (one scalar multiplication) | 335 ms |
| Shared key (two scalar multiplications) | 666 ms |

So a WPA3 connection costs about 1.9 s of computation by hunting and
pecking, 1.35 s by hash-to-element, in 15 KB with everything it needs.
`tools/emu/tests/lapin.rs` checks all of the above on every run and
fails if the timings drift.

The watchdog bites after 2.09 s: these computations will have to feed
it as they go.

## What is left

In order: the 802.11 station and access point with WEP, WPA, WPA2 and
WPA3, the Metal virtual machine that runs the existing bytecode, then
a resident loader so that a failed update no longer kills the rabbit.
Each step has its tests waiting in `tools/emu/tests`, which today run
the C firmware.
