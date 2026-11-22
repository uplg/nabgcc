# nabemu

An emulator for the Nabaztag:tag main board and the world around it,
to run the real firmware image without a rabbit: in tests, in CI, and
before any flash.

    cargo run --release -- --ms 30000 --ap Terrier ../../artifacts/Nab-wpa23-gtk-r3.sim

It takes an ELF (function names come for free), a raw `.bin` or a
Violet `.sim`. The firmware's serial output goes to stdout. `--calls`
lists every function entered, `--profile` says where the time went.

Two examples show both sides of a link:

    cargo run --release --example join -- <firmware> open|wep|wepshared|wpa|wpa2|mixed
    cargo run --release --example garenne -- <firmware> <bc.jsp content>

## What is modelled

| Part | State |
|---|---|
| ARM7TDMI, ARM and Thumb | complete; passes jsmolka's `arm.gba` and `thumb.gba` |
| Interrupt controller, system timer, watchdog | as the firmware uses them |
| Internal flash: erase and program command sequences, timing, power cuts | yes |
| Internal and external RAM | yes |
| UART0 | transmit only |
| ML60842 USB host controller (OHCI) | control and bulk lists, one port |
| RT2573 Wi-Fi stick | enumeration, firmware upload, registers, EEPROM, shared key table, WEP/TKIP/CCMP encryption and decryption, beacon generation |
| Leds, head button, volume wheel (`board`) | yes |
| Ears: motors and encoders | yes, with an estimated speed |
| Audio codec (`vs1003`) | control registers, the stream sent to the decoder split into tracks and drained at its own pace, the microphone recorded as IMA ADPCM; no decoding of MP3 or MIDI |
| RFID reader and tags (`rfid`), I2C master | identifiers, anticollision slots, memory blocks read and written |
| Access points (`air`) | beacons, probes, open and shared-key authentication, association, WPA and WPA2 pre-shared-key handshakes, group key renewal, replay checks, hidden networks, WPA3 (SAE by hunting and pecking or hash-to-element, key management 8, protected management frames), WPA2/WPA3 transition |
| A phone joining the rabbit in setup mode (`visitor`) | open association, DHCP client, HTTP client |
| A WPA3 station written from the standard (`supplicant`) | what the next firmware has to do; the access point's opposite number in tests |
| Wired network (`lan`) | DHCP, DNS, HTTP server, UDP capture and injection |

Not there yet: protected broadcast management frames (BIP) and the SA
query procedure, SAE anti-clogging tokens, the pairwise key table of
the stick, cycle-exact timing.

## In a browser

    web/build.sh                       # builds web/nabemu.wasm (about 260 KB)
    python3 -m http.server             # from the repository root
    # then open http://localhost:8000/tools/emu/web/

The page shows the rabbit with its leds and ears, its serial console,
and lets you press its button, hear what it plays, talk to its
microphone, hold a tag at its nose, choose the network around it and
the firmware and bytecode it runs. `?warp=20000` skips ahead. The module
has a plain C interface (`src/web.rs`), wrapped by `web/nabemu.mjs`;
`node web/test.mjs` runs the same module without a browser.

## What the numbers are worth

Time is counted in clock cycles at 32 MHz, each instruction costing
what the ARM7TDMI data sheet says (wait states on the bus are not
modelled), so a run is exactly reproducible. Flash
timings (22 ms per sector erase, 40 µs per word) are derived from the
"63 ms per sector" in the firmware's comments, not measured. An ear
is given about three seconds for a full turn (the factory test bounds
it from below). The stick's power-on beacon
interval (100 time units) is inferred from the firmware never
setting one.

The frames on the emulated air are real 802.11 frames. The cipher
code is checked against the IEEE and RFC test vectors (`crypto`).

When the stick has no valid key for a protected frame, the model hands
the frame over undecrypted with the "key not valid" error; what the
real chip reports in that case has not been checked.

## Tests

    cargo test --release

| File | What it covers |
|---|---|
| `src/crypto.rs` | hashes, PSK, PRF, KDF, HKDF, AES key wrap, AES-CMAC, RC4, Michael, TKIP mixing, CCMP against published vectors |
| `src/p256.rs`, `src/sae.rs` | the curve against published points; SAE against the IEEE 802.11-2020 J.10 vectors, both methods |
| `src/rfid.rs`, `src/vs1003.rs`, `src/board.rs` | the tag reader, the codec, leds and ears on their own |
| `tests/cpu_roms.rs` | the instruction test ROMs |
| `tests/boot.rs` | boot, Wi-Fi stick bring-up, scan, settings in flash, reproducibility |
| `tests/join.rs` | joining every kind of network, wrong passphrase |
| `tests/network.rs` | the whole boot: DHCP, DNS, bytecode over HTTP, on each cipher |
| `tests/link.rs` | group key renewals, being thrown out, access point restart |
| `tests/flash.rs` | firmware update over the air, power cut during the flash |
| `tests/board.rs` | leds, button, setup mode, factory test mode |
| `tests/factory.rs` | the firmware's own factory test: ears, tag reader, playing a tone, recording and playing back |
| `tests/rfid.rs` | the firmware reading and writing a tag |
| `tests/wpa3.rs` | WPA3 between the access point and the reference station, forged and genuine deauthentications, replays |
| `tests/setup.rs` | a phone on the rabbit's own network: setup page, saving settings, firmware upload |
| `web/test.mjs` | the WebAssembly build, under Node |
| `tests/garenne.rs` | the real application bytecode, when a build is around |
| `tests/lapin.rs` | the Rust firmware in `../../lapin`, when it is built: WPA3 on the ARM7, timed |

All of them run the released image in `artifacts/`. Three of them pin
down defects of that image (search the tests for "Known defect").

The instruction test ROMs are fetched in CI, not kept here:

    curl -L -o tests/roms/arm.gba   https://github.com/jsmolka/gba-tests/raw/master/arm/arm.gba
    curl -L -o tests/roms/thumb.gba https://github.com/jsmolka/gba-tests/raw/master/thumb/thumb.gba
