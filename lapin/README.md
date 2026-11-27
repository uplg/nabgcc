# lapin

A firmware for the Nabaztag:tag written in Rust, to replace the C one
in this repository. It is developed against the emulator in
`../tools/emu`: nothing goes to a real rabbit before it passes there.

    ./build.sh                                      # needs a nightly toolchain
    (cd ../tools/emu && cargo run --release -- ../../lapin/target/thumbv4t-none-eabi/release/lapin)

| Crate | What it is |
|---|---|
| `p256` | the NIST P-256 curve: field, points, constant-time scalar multiplication |
| `core` | everything portable: the hashes and ciphers 802.11 uses (SHA-1, SHA-256, MD5, RC4, AES with CCM, CMAC and key wrap), CCMP and BIP, the WPA3 password exchange (SAE), and the 802.11 station and setup access point |
| `metal` | the Metal virtual machine that runs the bytecode, as the C firmware runs it |
| `cref` | tests only: the C firmware's machine built for the host, to check `metal` against word for word |
| `fw` | the firmware itself, for the ARM7TDMI (`thumbv4t-none-eabi`) |

`p256`, `core` and `metal` have no dependency and no allocation, and
are tested on the machine that builds them (`cargo test` in each).
`core/tests/station.rs` runs the station against the emulator's access
point, on the host.

## Where it stands

`lapin`, the firmware, does what the C firmware does: it brings the
board up, starts the USB host and the Wi-Fi stick, then runs the boot
bytecode (the one the r3 release carries, `fw/src/boot.bc`) on the
Metal machine, whose calls to the board (`fw/src/host.rs`) go to this
firmware's drivers and its 802.11 station. 115.4 KB of the 124 KB, rescue core included, the
boot bytecode's 27.6 KB included.

It passes the emulator's acceptance tests, the ones written for the C
firmware (`NABEMU_FIRMWARE=lapin`, see `tools/emu/README.md`): boot,
setup mode and its page, joining every kind of network, the boot over
the network, the link through rekeys and restarts, the tag reader, the
factory test, a firmware update over the air, and garenne itself, for
minutes. Where the C firmware has a known defect, lapin does it right:
the handshake of a mixed-mode network, 104-bit WEP keys, the first
encrypted frame's number, probe requests without a network name.

It adds WPA3, without a change to the bytecode: a network that offers
SAE is still "WPA2" to the bytecode, which hands over the derived key;
the firmware reads the passphrase where the setup page saved it and
runs SAE (hash to element when offered), with protected management
frames, CCMP done in software (the stick may hold no key on such a
link), BIP on broadcast deauthentications, SA Query answered, and the
wait an access point asks for after a restart. Coming back to the same
network it reuses the key of the last exchange (PMKSA caching), and
falls back to the full exchange if the access point forgot it.

On every kind of network it also takes a new pairwise key on a running
link (the access point's periodic rekey), which the C firmware ignored
until the access point gave up on it. Its scan listens 120 ms on each
channel instead of 350 (one beacon interval is 102.4 ms) and sends no
probe on channel 14, which only Japan allows: garenne is awake 5 s
after power-on on the emulated rabbit, against 12 s for the C firmware.

What differs from the C on purpose: a new image is written by a RAM
routine that feeds the watchdog after every word (the C counted on the
whole rewrite fitting in 2.09 s), and the interpreter is faster: its
hot loop, in ARM code, keeps the machine's stack and memory in
registers, runs the frequent opcodes itself and sends the others to a
cold side that follows the C step by step; the watchdog is fed every
256 opcodes. On the emulated rabbit a loop of 500 000 opcodes takes
1.0 s against the C's 1.7 s, `fib 20` 0.68 s against 1.26 s
(`tools/emu/tests/lapin.rs` fails past 70 % of the C's time).

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

The watchdog bites after 2.09 s: the station feeds it between these
steps. Joining a WPA3 network takes 1.6 s after the scan on the
emulated rabbit.

A rescue core holds the first 20 KB of the flash, which updates never
rewrite: a power cut during an update, or an image that keeps
crashing, leaves a rabbit that raises "Nabaztag-secours" and takes a
new image from a phone (`src/boot.rs`, `src/rescue.rs`); the button
held 20 seconds from power-on asks for it too. `build.sh`
makes `target/lapin-full.bin`, the image to flash or to send.

## What is left

The real rabbit.
