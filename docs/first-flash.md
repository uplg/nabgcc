# The first flash of lapin on a rabbit

Over the air, from the C firmware (r3) the rabbit runs, as any update
clapier sends: no JTAG anywhere. Nothing here happens without Léonard's
go. Measurements on Garen, if any are wanted, are made from the running
C firmware with a bytecode, and only with his yes.

## What is settled in the emulator

Each line names the test that shows it.

1. **A power cut during the first write.** r3 writes `lapin-full.bin`
   from its first byte, the rescue core first. A cut once the rescue
   core's 20 KB are written (after the first sixth of the write, about
   0.35 s) leaves the rabbit on its rescue network; a cut during them
   leaves a dead one (`first_flash::a_power_cut_during_the_first_flash`).
   **Open**: a packed first image (rescue core plus the application
   compressed, unpacked by the core on its first start) is being
   designed separately to close that window. Until it lands, the first
   flash is the one moment a rabbit can be lost.
2. **The watchdog during r3's write.** r3's routine does not feed it
   (it sets the pause bit without the unlock). With the flash's typical
   timings the write takes 1907 ms of the 2097 (`first_flash::r3_writes_lapin_whole_with_typical_flash_timings`);
   with the manual's slowest (50 ms an erase) it bites after the rescue
   core is whole, and the rescue core takes over (`first_flash::with_the_slowest_flash_r3_is_bitten_mid_write_and_the_rescue_core_takes_over`).
   Either way a rabbit comes back.
3. **The rescue core against harsher hardware than the emulator's
   default**: a root hub interrupt that stays up while a change bit is
   set (`NABEMU_RHSC_LEVEL`), a USB interrupt line slow to fall, which
   makes illegal interrupts (`NABEMU_IRQ_LAG`), a stick that refuses
   its first requests, answers its firmware's start late, fails a
   bring-up once, loses a packet, is unplugged (`c_audit`). Every suite
   passes with the first two on, r3's and lapin's.
4. **The watchdog from the rescue core's first instruction**, through
   the clock's switch and the application's check; the pins at rest
   before that check, at 11 ms as in the C (`c_audit::pins_and_watchdog_are_set_up_before_the_application_is_checked`).
5. **The rescue core never restarts in a loop on one failed transfer**:
   a failed bring-up gets two more tries; without a stick it hands back
   to the application, or tries again in five seconds.
6. **A restart with the stick powered** (a watchdog restart, RSTOUT_N):
   the stick's beacon registers are cleared at start, so the rescue
   network does not go on beaconing under the application (`c_audit::the_rescue_networks_beacons_stop_with_the_application`).
7. **The settings sector** (the server's address, the network) is left
   alone by r3's write: `lapin-full.bin` ends below it. lapin reads the
   C's settings as they are (`setup`, `join`).
8. **Flash wear**: an update rewrites only the sectors that change.
9. **Sound, tag reader, volume wheel**: as the C, or better where the
   C is wrong (HANDOFF.md, deliberate differences).

## What only the rabbit can tell

10. **The stick's radio chip.** lapin tunes the RT2528 and the RT2527;
    a stick with another one is refused, by the application and by
    the rescue core alike: no network at all, so no way back over the
    air. Garen's module is an MSI MS-6877, whose FCC photos show an
    RT2528L; its type has never been read from a rabbit. No bytecode
    of r3 can read it. This is the largest open risk.
11. **The receive descriptor's IV words** (2 and 3, read as rt73usb
    reads them; r3 never did). If the chip leaves them zero, the replay
    check must fail safe (the station's side). lapin prints the first
    four on the serial port (`wifi rx iv ...`).
12. **The root hub's interrupt**, edge or level: both are handled.
13. **The flash's real erase time**: between the typical and the
    manual's maximum, both covered by item 2.
14. **The watchdog's pause bit**: if the real chip does pause the
    watchdog under r3's write (the manual says it should not without
    the unlock), the write simply takes its time.
15. **The ring oscillator's frequency** before the clock's switch: the
    watchdog only runs slower on it.
16. **Whether the stick keeps its power across a watchdog restart**:
    handled either way (item 6).
17. **The VS1003's end of stream**: lapin sends the 2048 zeros the data
    sheet asks for; heard on a real speaker only.
18. **The tag reader's timings** follow the C's; the CRX14 waits are
    ridden out by retrying, as the C does.

## The procedure

1. Léonard's go, then Garen on mains power, on a stable supply, its
   network up, clapier reachable.
2. clapier sends `lapin-full.bin` (from `lapin/build.sh`) as it sends
   any firmware: the bytecode's `flashFirmware`. r3 writes it and
   restarts (about two seconds).
3. Expected: lapin starts (its bytecode, then the network), within a
   minute the rabbit is on its network and asks clapier for garenne.
4. If instead the network "Nabaztag-secours-XXXX" appears (a write cut
   short, or bitten): from a phone, join it (open, DHCP), open
   http://192.168.0.1 and send `lapin-full.bin`. The core writes the
   application and starts it.
5. If neither within five minutes: power off, on again once. If still
   nothing, the rabbit waits for the bench; do not retry blindly.

## Going back to the C

From lapin's application, as any update: clapier sends the C
firmware's image (r3's, as the rabbit ran it) by `flashFirmware`.
lapin writes another firmware's image whole, unchecked, from the first
byte: the same window as item 1, the other way (a cut in its first
moments leaves no firmware at all). The rescue core's page takes lapin
images only: from the rescue network, the way back is lapin first,
then the C from lapin.
