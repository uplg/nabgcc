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

## Where we stopped (2026-11-28), and what comes next

Three independent audits (bytecode-visible behaviour, the C firmware
function by function, the emulator against the real hardware) found
critical problems the green emulator suite never exercised; all are
fixed or documented, with tests (`tools/emu/tests/c_audit.rs`,
`observable.rs`, `crowded.rs`, `scan.rs`, `scan_connected.rs`,
`first_flash.rs`, `wpa3_sound.rs`, ...). lapin is NOT ready for Garen.
Léonard rules out a first flash by JTAG: the C to lapin migration must
be safe over the air by construction.

Done since:

- **A packed first image.** The server sends an r3 rabbit
  `lapin-first.bin`, once (see "The first flash" below and
  `docs/first-flash.md`): 1931 ms unfed at the manual's slowest flash,
  166 ms to spare, where `lapin-full.bin` is bitten. A power cut in the
  first ~0.35 s, while r3 writes the rescue core itself, stays fatal
  (pinned as a Known defect): nothing on the lapin side can change
  that.
- **INTST.RSTSTATUS** tells a power-on from a watchdog restart.
- **The flash rules of the manual's 20.5.5** written out in the RAM
  routines and checked by the emulator; no erase of an erased sector
  (the flash is guaranteed for 100 rewrites).
- **Every audit test can fail**: M11, A14, I1, the data toggle after a
  take-back, the I2C STOP after a timeout, the receive overflow path
  (each seen failing on the code before its fix). A lost receive packet
  now drops what is left of its own frame only, from the descriptor's
  length.
- **nose**: no family left anywhere (lapin, tools/emu, scripts,
  .github), even on its full surface; `nose.ignore.json` gives the
  reason for each one that must stay; `scripts/nose.sh` gates it in
  ci-local.sh and in the CI.
- **The CI** splits the tests on lapin over three runners (about 4 min
  end to end on GitHub); the suites that pick their own images run
  once.
- **The last global of a served bytecode** is kept (it was open item
  1, `7737b92`): lapin's `OPbytecode` leaves the new main's result for
  its caller's pull, where r3 pulls it itself and its caller then
  takes the new bytecode's last global off the stack. Harmless to
  every bytecode served today, by the accident of where their last
  string sits; see "Deliberate differences from r3".
- **Receive throughput in a crowded band.** The OHCI controller hands
  its done descriptors over once a frame (1 ms), so the transfers in
  flight bound what comes off the stick: lapin had four of one packet
  (two frames a millisecond), r3 has one (half a frame). It now keeps
  eight of two packets in flight (eight frames a millisecond, 1 KB of
  the controller's RAM, taken from a control buffer and a transmit
  buffer larger than any frame); a failed descriptor hands over the
  packets that went through, then the loss. The scan could not read
  eight frames a millisecond: an open network's beacon is no longer
  hashed, and once the queue is half full a second announcement of a
  network already queued during the scan is dropped in the interrupt.
  A pump of the queue stops after 20 ms (frames coming faster than they
  are handled starved the watchdog). With 200 neighbours beaconing
  every 20 ms (`crowded.rs`, every phase of their round, a millisecond
  at a time) lapin lists all 201 networks, where it listed 120 to 201
  and r3 lists 168 to 177; the scan is unchanged (1.92 s from the
  first probe to channel 14's end, r3 5.24 s). The emulator now gives
  a full-speed frame its bus time (19 bulk packets of 64 bytes at
  most, USB 2.0 table 5-10) and leaves a failed descriptor's buffer
  pointer after the packets that went through, as the controller does.
  Its air carries more than a real channel could (ten beacons a
  millisecond, at 1 Mb/s one takes 0.7 ms): `crowded.rs` is a stress
  test, not a building.

Open:

1. **cargo-mutants** only on Léonard's go; nose gates the code it adds.

## Things worth knowing before continuing

**Flash budget.** 124 KB below the settings sector. lapin takes 113.0
KB (115 692 bytes), the boot bytecode's 27.6 KB included, packed to 16
KB, and the rescue core's 20 KB (19 884 bytes used of its 20 472, the
first image's unpacker in them): 11.0 KB left. `lapin-first.bin` is
81 499 bytes, 20 sectors and 421 bytes short of a 21st. The curve and the
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
to keep that way back). The first image (`lapin-first.bin`, below) is
for r3 only: lapin refuses it. The core tells a power-on from a
watchdog restart by INTST.RSTSTATUS (manual table 11-2), read before
its watchdog's start clears it: a power-on counts no failed start even
if the RAM kept the counting words, a watchdog restart counts even if
they were lost (a "start afresh" is now a word of its own, not a
cleared one).

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

- **The last global of a bytecode started by `OPbytecode`** stays its
  own once its main function returned. r3's `OPbytecode` pulls the new
  main's result, then leaves the interpreter, and its caller (the main
  loop or a callback's wrapper in `main.c`, `vnet.c`, `vaudio.c`) pulls
  once more, off the new stack: the last global then lies above the
  top, the collector no longer marks it, and the outermost callback's
  frame lands on it (its first argument, its first local, or its saved
  program counter, -1). Reading the global then reads that slot of the
  frame, writing it writes the frame; r3's string natives take an
  integer n found there for the object at heap word n and write into
  it (the -1 happens to read as nil). Nested loads
  lose one global more each. No dangling pointer is read: every entry
  into the interpreter pushes over the slot before any bytecode runs.
  The Metal compiler lays the globals out in the order it first meets
  them, `var`s and string literals alike, each literal its own global,
  nothing added at the end; the last is the last literal or `var` in
  the source. Harmless today by accident: garenne's is `" ip="`,
  read only in `garenne_init`, which runs inside main (its console and
  calls to the board are the same either way; only the collector's
  own counts move); the boot bytecode is never served. A `var`
  declared last, or a literal in a function placed after
  `garenne_init` and called later, would break on r3. lapin leaves the
  new main's result for its caller's pull. `tests/observable.rs`
  (`the_last_global_of_a_served_bytecode_is_kept`, a Known defect on
  r3), and `lapin/cref`, whose C machine is built with that one pull
  cut out of `vinterp.c` (`build.rs`), so that the differential tests
  and `vm_diff` compare everything else against the C as it is.
- **Scan results**: one entry per network (BSSID and name), the
  strongest frame heard, up to 256 networks; r3 lists every frame it
  hears, as many as its heap holds, and loses some neighbours in a
  crowded band (175 of 201 listed, `tests/crowded.rs`). lapin loses
  some too there: it takes about two frames a millisecond off the
  stick, 240 of the 1400 that 200 neighbours beaconing every 20 ms send
  in its 120 ms on a channel, and lists 119 to 201 of them depending on
  where the beacons' rounds stand when it starts (the emulator's
  beacons keep in step; it listed 201 until the rescue core's start got
  15 ms faster). The boot keeps the strongest per name anyway
  (`filterscan`).
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
- **netState** says idle (1) about two and a half seconds after the
  access point vanished (switched off, out of range), where r3 says
  connected (4) for two minutes, its timeout refreshed by beacons,
  unless the bytecode sends and the restarted access point throws it
  out (Known defect, `tests/link.rs`,
  `notices_the_access_point_switched_off`). Beacon loss as mac80211
  has it (`net/mac80211/mlme.c`: seven beacons missed, then probe the
  access point before the disconnection): five ticks of the main loop
  (200 ms each) without a frame from the access point, about ten of
  its beacons, then three unicast probe requests a tick apart, and the
  link is given up if none is answered (any frame from the access
  point, a beacon, a probe response, data, counts). Counted in ticks,
  not on the clock: a scan, or a bytecode that keeps the loop from
  turning, is not taken for silence; a band too busy to hear every
  beacon still lets one through in a second (the scorecard's crowded,
  WPA3 and two-minute scenarios keep their link). While the program
  joins again, its authentication goes out once more as soon as the
  access point's beacon is heard again, rather than at the end of the
  two-second wait for an answer (open, WEP open system and WPA/WPA2
  only; WPA3's exchange and shared keys keep their own retries): back
  on the network 156 ms after the access point is on again (r3, thrown
  out at its next frame, 221).
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

**Drivers and sound.** An
audit of the drivers and the sound against r3 (`tools/emu/tests/c_audit.rs`,
`first_flash.rs`, `lapin/metal/tests/audio.rs`). lapin does what the C
does where the outside world can see it, except here, where the C is
wrong:

- Wi-Fi receive: the C goes deaf for good after a receive transfer longer
  than its buffer (Known defect). lapin holds the longest transfer the
  stick hands over (4095 bytes) and drops what follows an overrun or a
  lost USB packet up to the end of its transfer (it used to read it as
  a new frame, whose descriptor the sender chose: frames in clear
  passed as decrypted).
- The stick unplugged and plugged back: the C gets back through a
  watchdog restart (Known defect); lapin brings it up again in place,
  the station back to idle. A bring-up that fails on the way gets two
  more tries with the USB controller reset. The request that starts
  the stick's firmware may fail, as in the C (whose result it ignores);
  control transfers get the C's second.
- Tuning: a failed request leaves the receiver on, as the C (which
  ignores every error); a failed key write leaves the key slot invalid
  and a failed beacon write sends no beacon (the C marks a half-written
  key valid and beacons a half-written frame). BBP R94 is put back on
  the next channel (the C leaves it raised). Beacons and their slots
  are cleared at start, as Linux's rt73usb does (the C never cleared
  them: the rescue network kept beaconing after a restart). Radio types
  other than RT2528 and RT2527 are refused by name. (This used to say
  the C has no table for the others: it has, `rt2501usb.c:153` and
  `:173`, the RT5226's and the RT5225's, which the RT2527 shares; a
  rabbit with one of the two 5 GHz radios would work on r3 and not on
  lapin, see `docs/first-flash.md` item 14.) The IVs
  the replay check reads (descriptor words 2 and 3, as rt73usb reads
  them; the C never did) go to the serial port for the first frames.
- USB wire: the root hub is served in the interrupt, as the C; the
  rest of the C's sequence too (three tries of the first descriptor,
  the descriptor again at the new address, the configuration in two
  reads, reset at once then 40 ms). Left different: control
  descriptors all interrupt (the C's no-interrupt ones are not needed),
  HcControl is written once, the done list is walked at most 16 deep.
- Sound: a byte taken from the ring while DREQ fell is held for the
  codec (lapin dropped it; the C writes it anyway, which the VS1003
  takes). At the end of a stream lapin sends the 2048 zeros the data
  sheet asks for after a file and switches the amplifier off (the C
  sends nothing and leaves it on, Known defect B40); SM_OUTOFWAV is for
  stopping in the middle (data sheet 9.3) and is not needed at an end.
  The refill asks the bytecode once (the C asks twice and drops the
  second answer, B41). recVol from a negative start is 0 (the C reads
  before the string, B38); an ADPCM step index past the table is its
  last entry (the C reads past it); a negative length to wav2alaw or
  alaw2wav converts nothing (the C restarts, Known defect B36).
- Codec: given up after half a second without DREQ, and then not
  waited for until it raises DREQ again (the C waits for ever: a dead
  codec keeps it from starting, Known defect). The reset pulse is the
  C's DelayMs(1), which can be close to nothing: not a defect, the data
  sheet asks two of the chip's clock cycles, and DREQ is waited for.
  A command takes 8 us against the C's 5 (lapin reads every SPI byte
  back); harmless.
- Tag reader: the C's sequence and pauses, within 10 % of its time
  (rfidGet 5 ms, rfidRead 12 ms). Left different: the field is closed
  once after a scan that found nothing (the C twice); a tag write leaves
  the tag its 5 ms of programming before the field goes off or another
  frame goes out (the C turns the field off at once and may cut the
  write short, Known defect in `tests/rfid.rs`, which the emulator's
  reader counts): the bytecode has its answer at once, as from the C
  (6 ms), and the reader's next operation waits out what remains, or
  the main loop turns the field off once it is over; writes in a row
  take 11 ms each where the C's take 6; the C retries a refused
  write for ever, lapin a thousand times; a bus that does not come
  free is tried again for 300 ms with interrupts let through (the C
  polls a million times with them off) and a timed-out transfer sends
  its stop (the C leaves the bus held). A field that reads back wrong
  is told on the serial port, the scan goes on, as the C. I2C: status
  cleared before the stop, as the C; a read of nothing reads nothing
  (the C clocks two bytes into no buffer; nobody asks for none).
- Flash: after an update the watchdog bites in 256 us, as the C (lapin
  waited 2.1 s). A sector that already holds what it would be given is
  not rewritten (the manual guarantees a hundred rewrites). The rest of
  the image's last sector is erased (the C keeps the old bytes there;
  the header's length and CRC make them meaningless). A sector that
  reads all ones is written without an erase: the manual forbids
  erasing one twice with nothing written between (20.5.5), which the C
  does to the blank settings sector at first boot (Known defect) and
  to the free sectors past its own image when it writes lapin as the
  first flash. The commands' timing (an instruction after FLWE, 8
  clocks free of the flash around each) is written out as four dummy
  loads, as the manual's example; the C's NOPs keep it too. The
  emulator checks all of it (`Soc::flash_rules`).
- Board: the volume wheel at 1 MHz as the C (lapin had 2). The rescue
  core starts the watchdog first and sets the pins before checking the
  application (they were set 76 ms later than the C's). An interrupt
  that names the system timer when its source went away (manual 6.5.6)
  is no millisecond. The UART's receiver is not wired: the C takes
  its bytes in an interrupt for an XMODEM loader its main never calls.
- Self-test: what it writes (the settings' first bytes, a tag block) it
  puts back.

**The first flash, measured.** `tests/first_flash.rs`. r3 writes
the flash unfed by its own routine: `lapin-full.bin` takes 1951 ms of
the watchdog's 2097 with the flash's typical timings, and with the
manual's slowest (50 ms an erase, 40 µs a word) it is bitten after
21577 of 28558 operations. So the first image, which the server sends
an r3 rabbit once, is `lapin-first.bin` (81.7 KB, from `lapin/build.sh`
through `lapin/pack`): the same rescue core, then the application
packed to 64.6 % (`lapin/core/src/pack.rs`: LZ77 and an adaptive binary
coder, rANS with 12-bit probabilities, after a filter that makes
Thumb's BL offsets targets; copies reach back into the rescue core,
which the application shares much code with; LZMA at its best does
59.4 KB against these 61.2) behind a header "LAPP" (packed length,
unpacked length, CRC-32 of each). r3 writes it with the watchdog unfed
1371 ms typically, 1931 ms at the slowest: 166 ms to spare. That is
thin: a sector more costs about 97 ms, the image is 211 bytes short of
one, and `build.sh` prints that number. At its first start the rescue
core finds no application but the packed one, unpacks it into the
external RAM behind a copy of itself (2.5 s), checks its CRC and
header, writes the 9 sectors past the packed ones (which leaves those
whole), restarts, unpacks again, writes the rest over them, restarts
into lapin: 6.4 s, the watchdog fed (54 ms unfed at most). Cuts at
every 32nd of that: while the packed application is whole (the first
5.2 s) the rabbit unpacks again and comes back on lapin; in the last
step (it cannot keep the packed application: 92.6 KB and 60 KB do not
both fit in 104) it comes back on the rescue network. Cuts at every
16th of r3's write: past the rescue core's 20 KB, the rescue network;
during them (the first 0.35 s) a dead rabbit, the one window left, a
Known defect nothing on lapin's side can close. `docs/first-flash.md`
is the checklist.

**Harsher hardware.** The emulator can make the root hub's interrupt
a level (`NABEMU_RHSC_LEVEL`), the USB interrupt line slow to fall
(`NABEMU_IRQ_LAG`), the stick refuse or delay requests, lose a packet,
be unplugged; the flash slowest. Every suite passes with the first two
on, both firmwares.

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
