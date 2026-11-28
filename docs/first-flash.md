# The first flash of lapin on a rabbit

Over the air, from the C firmware (r3) the rabbit runs, as any update
clapier sends: no JTAG anywhere. Nothing here happens without Léonard's
go. Measurements on Garen, if any are wanted, are made from the running
C firmware with a bytecode, and only with his yes.

## What is settled in the emulator

Each line names the test that shows it.

1. **The first image is `lapin-first.bin`**, not `lapin-full.bin`.
   `lapin/build.sh` makes both. `lapin-first.bin` (81.7 KB) is the rescue
   core as in `lapin-full.bin` (its 20 KB, trailer included), then the
   application packed to 64.6 % (`lapin/pack`, `lapin/core/src/pack.rs`:
   LZ77 with an adaptive binary coder, after a filter on Thumb's calls,
   the copies reaching into the rescue core too), behind a header of
   five words: "LAPP", the packed length, the unpacked length, the CRC-32
   of the unpacked application, the CRC-32 of the packed bytes. The
   server sends it once, to a rabbit that runs r3. A lapin rabbit is
   sent `lapin-full.bin`, as before, and refuses `lapin-first.bin`
   (`rescue::the_first_image_sent_to_a_lapin_rabbit_is_refused`).
2. **The watchdog during r3's write.** r3's routine does not feed it
   (it sets the pause bit without the unlock). For `lapin-first.bin`,
   20 sectors where `lapin-full.bin` takes 29, the watchdog goes
   unfed 1371 ms of its 2097 with the flash's typical timings (726 ms to
   spare) and 1931 ms with the manual's slowest, 50 ms an erase and 40
   µs a word (166 ms to spare) (`first_flash::r3_writes_the_first_image_within_the_watchdog_even_at_the_slowest_flash`,
   which fails under 100 ms to spare). The margin is thin at the slowest:
   one sector more costs about 97 ms, and the image is 211 bytes short
   of one (`build.sh` prints that number; the application must not grow
   past it unnoticed). `lapin-full.bin` takes 1951 ms typically and is
   bitten at the slowest (`first_flash::with_the_slowest_flash_r3_is_bitten_mid_write_and_the_rescue_core_takes_over`).
   r3's sysFlash checks (a length from 4 KB to 124 KB, five `ldr pc`
   vectors) take it: it opens on the same vectors.
3. **The first start.** The rescue core finds no application but a
   packed one whose CRC checks. It unpacks it into the external RAM
   behind a copy of itself, checks the unpacked CRC and the
   application's header, and writes it with lapin's own routine, which
   feeds the watchdog (54 ms unfed at most). In two steps, each ending
   in a restart: first the 9 sectors past the packed application's 15,
   which leave it whole; then the rest, over it. Each time a sector
   already right is skipped. About 6.4 s from the first start to lapin
   (`first_flash::the_rescue_core_unpacks_the_first_image_and_writes_the_application`).
   A packed application that does not check is not installed: the
   rescue network (`first_flash::a_damaged_first_image_is_not_installed`).
4. **A power cut during the first start**, at every 32nd of it
   (`first_flash::a_power_cut_anywhere_in_the_first_start_leaves_a_rabbit_that_comes_back`):
   while the packed application is whole (the unpacking, the first
   step, 5.2 s of the 6.4) the rabbit unpacks it again and comes back
   on lapin; during the second step (the last second) it comes back on
   the rescue network, from where a phone sends `lapin-full.bin`. Never
   dead. The application (92.6 KB) and the packed one (60 KB) do not
   both fit in the 104 KB they share, so the last step cannot keep the
   packed one; it is short. The application's CRC covers all of it, so
   whatever the order of its sectors, it runs only once whole.
5. **A power cut during r3's write**, at every 16th of it
   (`first_flash::a_power_cut_during_r3s_write_of_the_first_image`): once
   the rescue core's 20 KB are written (the first quarter of the write,
   about 0.35 s), the rescue network; at the end, lapin. **Still fatal,
   and pinned as a Known defect: a cut during those first 0.35 s,
   while r3 writes the rescue core itself, leaves a dead rabbit.**
   Nothing on lapin's side can change that: r3 writes from the first
   byte, and there is one rescue core. The same holds for
   `lapin-full.bin` (`first_flash::a_power_cut_during_the_first_flash`).
6. **A power-on is told from a watchdog restart** by INTST.RSTSTATUS
   (manual table 11-2: set by the watchdog's overflow, cleared by a
   power-on), read before the watchdog's start clears it: a power-on
   never counts as a failed start even if the RAM kept the counting
   words, and a watchdog restart counts even if they were lost
   (`rescue::a_power_on_is_no_failed_start_even_if_the_ram_kept_its_words`,
   `rescue::a_watchdog_restart_counts_even_if_the_ram_lost_its_words`).
7. **The rescue core against harsher hardware than the emulator's
   default**: a root hub interrupt that stays up while a change bit is
   set (`NABEMU_RHSC_LEVEL`), a USB interrupt line slow to fall, which
   makes illegal interrupts (`NABEMU_IRQ_LAG`), a stick that refuses
   its first requests, answers its firmware's start late, fails a
   bring-up once, loses a packet, is unplugged (`c_audit`). Every suite
   passes with the first two on, r3's and lapin's.
8. **The watchdog from the rescue core's first instruction**, through
   the clock's switch and the application's check; the pins at rest
   before that check, at 11 ms as in the C (`c_audit::pins_and_watchdog_are_set_up_before_the_application_is_checked`).
9. **The rescue core never restarts in a loop on one failed transfer**:
   a failed bring-up gets two more tries; without a stick it hands back
   to the application, or tries again in five seconds.
10. **A restart with the stick powered** (a watchdog restart, RSTOUT_N):
   the stick's beacon registers are cleared at start, so the rescue
   network does not go on beaconing under the application (`c_audit::the_rescue_networks_beacons_stop_with_the_application`).
11. **The settings sector** (the server's address, the network) is left
   alone by r3's write: `lapin-first.bin` ends below it. lapin reads the
   C's settings as they are (`setup`, `join`).
12. **Flash wear**: an update rewrites only the sectors that change.
13. **Sound, tag reader, volume wheel**: as the C, or better where the
   C is wrong (HANDOFF.md, deliberate differences).
14. **The stick's radio chip.** The radio types were researched and
    named: Garen's module is an MSI MS-6877 (RT2571WF), whose FCC photos
    show an RT2528L, and r3's own driver marks the RT2528 "notre carte"
    (`src/usb/rt2501usb.c:466`). lapin tunes the RT2528 and the RT2527
    (their synthesiser words as Linux's rt73usb has them; r3 tunes
    both too, the RT2527 on its RT5225 table); the emulator's stick tunes
    only on each chip's own words, and lapin joins with both
    (`lapin::a_stick_with_the_rt2527_radio_joins_too`, and every join
    test on the default RT2528), refusing the others by name before
    writing to the radio (`lapin::a_stick_with_a_radio_it_cannot_tune_is_refused`).
    Garen runs r3 with working Wi-Fi, so its radio is one r3 tunes.
    One difference remains: r3 also carries tables for the two radios
    that do 5 GHz too, the RT5226 and the RT5225 (`rt2501usb.c:153`,
    `:173`, tuned at `:610` and `:628`), which lapin refuses (no network,
    not even the rescue one). A rabbit with one of those would work on
    r3 and not on lapin; nothing found says a rabbit ever carried one.
    lapin prints the type at boot (`wifi <address> radio NN`).

## What only the rabbit can tell

15. **The receive descriptor's IV words** (2 and 3, read as rt73usb
    reads them; r3 never did). If the chip leaves them zero, the replay
    check must fail safe (the station's side). lapin prints the first
    four on the serial port (`wifi rx iv ...`).
16. **The root hub's interrupt**, edge or level: both are handled.
17. **The flash's real erase time**: between the typical and the
    manual's maximum, both covered by item 2.
18. **The watchdog's pause bit**: if the real chip does pause the
    watchdog under r3's write (the manual says it should not without
    the unlock), the write simply takes its time.
19. **The ring oscillator's frequency** before the clock's switch: the
    watchdog only runs slower on it.
20. **Whether the stick keeps its power across a watchdog restart**:
    handled either way (item 10).
21. **The VS1003's end of stream**: lapin sends the 2048 zeros the data
    sheet asks for; heard on a real speaker only.
22. **The tag reader's timings** follow the C's; the CRX14 waits are
    ridden out by retrying, as the C does.

## The procedure

1. Léonard's go, then Garen on mains power, on a stable supply, its
   network up, clapier reachable.
2. `cd lapin && ./build.sh`: it makes `target/lapin-first.bin` and
   `target/lapin-full.bin`, and prints how many bytes the first image
   is short of a sector more (item 2). Run
   `tools/emu/tests/first_flash.rs` on that build.
3. clapier sends `lapin-first.bin`, once, as it sends any firmware: the
   bytecode's `flashFirmware`. r3 writes it (1.4 s, 1.9 s at the
   slowest flash) and restarts. **Do not touch the power in those
   first seconds** (item 5).
4. Expected: the rescue core unpacks and writes the application (the
   console says `secours: unpacked` twice, about 6.4 s, with two
   restarts), then lapin starts (its bytecode, then the network);
   within a minute the rabbit is on its network and asks clapier for
   garenne. From then on clapier sends lapin `lapin-full.bin`, never
   `lapin-first.bin` again.
5. If instead the network "Nabaztag-secours-XXXX" appears (a write cut
   short, the packed application damaged): from a phone, join it (open,
   DHCP), open http://192.168.0.1 and send `lapin-full.bin`. The core
   writes the application and starts it.
6. If neither within five minutes: power off, on again once. If still
   nothing, the rabbit waits for the bench; do not retry blindly.

## Going back to the C

From lapin's application, as any update: clapier sends the C
firmware's image (r3's, as the rabbit ran it) by `flashFirmware`.
lapin writes another firmware's image whole, unchecked, from the first
byte: the same window as item 5, the other way (a cut in its first
moments leaves no firmware at all). The rescue core's page takes lapin
images only: from the rescue network, the way back is lapin first,
then the C from lapin.
