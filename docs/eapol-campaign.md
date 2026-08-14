# The EAPOL campaign: why the rabbit's radio goes deaf

Written 2026-07-31 (Fable), after garenne reached G7 and the wedge had
struck four times in one night. This is the plan for the firmware side
of the problem, to be executed in a fresh session.

Ground rules carry over: code and comments in English, no commit or
push without Leonard's explicit go, every reflash is a risk to be
earned (one brick already paid for that lesson - see
`docs/nabaztag-jtag-debrick.md`).

## The symptom, measured

Four occurrences on the night of 2026-07-30/31, under three different
garenne versions, so the fault is below the VM:

- the rabbit keeps **transmitting** perfectly (UDP pulses arrive every
  2 s, `link=4`, RSSI healthy);
- it stops **receiving** anything useful: no ICMP echo, no UDP control
  command, not even an IP broadcast;
- `netState` still reports 4 (connected), which is why the first
  watchdog never fired;
- intervals between boot and deafness: roughly 58, 25, 29 minutes -
  **variable**, which rules out a fixed timer and points at a
  key-rotation or cache-expiry event;
- a power cycle always heals it; a long button press (garenne's local
  lever) heals it too, because it reboots.

## The smoking gun in the source

`vendor/nabgcc/src/net/aes128.c` - the whole file:

```c
void aes128_init(struct aes128_context *aes, const uint8_t *key, uint16_t length)
{
}
void aes128_crypt(struct aes128_context *aes, uint8_t *out, const uint8_t *in, uint16_t length)
{
}
void aes128_decrypt(struct aes128_context *aes, uint8_t *out, const uint8_t *in, uint16_t length)
{
}
```

**Three empty function bodies.** Nothing is written to `out`.

Now `src/net/eapol.c`, `eapol_input_group_msg1` (the group-key
message, i.e. every rekey the AP performs), CCMP branch:

```c
case IEEE80211_CIPHER_CCMP: // Decrypt CCMP/AES
  {
    // FIXME Actually do something...
    memcpy(&key[0], ptk.s.kek, 16);
    aes128_init(&aes, key, 16);           // no-op
    aes128_decrypt(&aes, gtk.b, ..., EAPOL_MICK_LENGTH+EAPOL_EK_LENGTH);  // no-op
    // FIXME
    if(fr_in->key_frame.key_info.key_index != 0)
        rt2501_set_key(..., gtk.s.ek, ..., RT2501_CIPHER_AES);
  }
```

So on a WPA2/CCMP network - exactly ours (`crypt=64`, confirmed by
reading the EEPROM with garenne's `ctl conf`) - the group key is never
actually decrypted. `gtk` keeps whatever it held before. The function
then unconditionally declares success:

```c
eapol_state = EAPOL_S_RUN;
ieee80211_state = IEEE80211_S_RUN;
```

which is precisely why the driver keeps claiming a healthy link while
the hardware can no longer decrypt what the AP sends. The MIC of the
incoming rekey message *is* verified properly (`hmac_sha1` is real, in
`hash.c`), so the frame is accepted as genuine - and then mishandled.

Note also that the AES key-unwrap for CCMP is not raw AES-ECB at all:
RFC 3394 AES Key Wrap is required (WPA2 uses it for the Key Data
field). So even a correct AES-128 block function would not be enough
on its own.

## Two candidate mechanisms (the instrumentation must decide)

1. **Broadcast/multicast deafness after a GTK rotation.** The AP
   rotates its group key every so often; our supplicant installs
   garbage (or nothing) and can no longer decrypt broadcast frames.
   Unicast keeps working *while* peers still have the rabbit in their
   ARP cache; when the Mac's ARP entry expires it re-ARPs by
   **broadcast**, gets no answer, and from then on nothing reaches the
   rabbit at all. This fits the variable interval (rekey period AND
   ARP-cache lifetime both vary) and it fits "TX fine, RX dead".
2. **A pairwise-key or hardware slot wedge.** A failed rekey leaves
   `RT2501_SEC_CSR0`/`CSR1` (key-valid bits and per-slot cipher
   selectors, written in `rt2501_set_key`, `usb/rt2501usb.c:1078`)
   inconsistent, so the hardware drops even unicast.

The discriminator is cheap: **count beacons and per-class RX frames**.
Beacons are unencrypted management frames. If beacons keep arriving
while encrypted data stops, it is a key problem (1). If everything
stops, it is a radio/slot wedge (2).

## Plan

**E1. Instrument, do not fix yet.** Extend `src/utils/diag.c` (the
wireless diagnostic channel already written and proven) with a
counter block, and have it emitted over the air on a timer - TX
survives the wedge, which is what makes this possible at all:
beacons seen, encrypted data frames seen, decrypt failures, EAPOL
messages by type (1/4, 3/4, group), `eapol_state`, `ieee80211_state`,
`SEC_CSR0`/`SEC_CSR1`, and the time of the last EAPOL exchange.
Build with `-DDIAG_RING`, keep `DEBUG_WIFI` **off** (it logs every
beacon to the UART and once froze the rabbit for minutes - see the
traps list in memory). Ship it, wait for the wedge, read the truth.
*Proof: one wedge captured with counters, mechanism (1) or (2) named.*

**E2. Implement AES-128 and RFC 3394 key unwrap.** A real AES-128
block cipher (decrypt direction plus the key schedule) and the Key
Wrap unwrap on top, used by the CCMP branches of both
`eapol_input_group_msg1` and (for the GTK carried in message 3/4)
`eapol_input_msg3`. Budget: roughly 3-4 KB of flash for AES with
tables trimmed; about 19.5 KB were free at the end of the WPA2/3
campaign, so it fits. Unit-test the primitive **on the Mac first**
against FIPS-197 and RFC 3394 test vectors, in a tiny host harness -
never debug a cipher on the device.
*Proof: vectors pass on the host; on the device, a captured rekey
installs a plausible GTK and broadcast RX survives it.*

**E3. Make failure loud instead of silent.** `EAPOL_S_RUN` must not be
asserted when the key handling failed; a failed rekey should mark the
link as broken so `netState` stops lying and the existing
reassociation path takes over. This alone would have let garenne's
first watchdog do its job.
*Proof: a deliberately corrupted rekey leads to a reassociation, not
to silent deafness.*

**E4. Belt and braces in garenne (no reflash needed, do it first).**
A periodic gratuitous ARP announce (every few minutes) keeps peers'
ARP caches warm, so unicast reachability no longer depends on the
rabbit hearing a broadcast ARP request. Cheap, entirely in MTL, and it
buys comfort while E1-E3 proceed. It also sharpens the diagnosis: if
the rabbit stays reachable by unicast for much longer with announces
on, mechanism (1) is confirmed from the outside.

**E5. Upstream.** Whatever comes out of E2/E3 is a real fix for
anyone running nabgcc on WPA2. RedoXyde/nabgcc#10 (the cipher fix) is
already open in French; a second PR follows the same route.

## Status (2026-07-31, second session)

- **E4 done.** `garenne/net/link.mtl`: a `garp` task announces every 3
  minutes while the link is up (`LINK_GARP_MS`). Garenne bumped to
  0.8.1, 208 golden tests green, `build/garenne.bin` rebuilt. No
  reflash needed: serve it as bc.jsp.
- **E1 built, soak pending.** New `-DDIAG_COUNTERS` flag (kept
  *separate* from `-DDIAG_RING`, whose boot probe + AP export would add
  ~5 minutes to every boot). Counters live in `src/utils/diag.c`:
  beacons (all/MyBss), encrypted data OK, CipherErr by class
  (ICV/MIC/KEY), CRC, EAPOL by type + drops + MIC failures, age of last
  EAPOL event, `eapol_state`, `ieee80211_state`, SEC_CSR0/1/2 read from
  the RT2573. Hooks: `rt2501_rx_callback` (every frame, at the RXD),
  the `eapol_input` dispatch, and the MIC/ANonce failure paths. One
  ASCII datagram (`NDC1 ...`) broadcast on UDP 9999 every 2 s from the
  main loop; `scripts/diag-listen.py` now timestamps and prints them.
  `--release` build keeps the flag on (`scripts/build-nabgcc.sh`).
  Image: `vendor/nabgcc-latest/Nab-wpa23-release.sim`, 116108 bytes of
  text (+2.8 KB over the frozen image). **To do: flash it, run the
  listener, wait for the wedge, read the verdict.**
- **E2 host-side done, wiring deliberately deferred.** Real AES-128
  (decrypt direction) and RFC 3394 unwrap in `src/net/aes128.c` under
  new names (`aes128_dec_*`, `aes_key_unwrap`); the legacy no-op API is
  untouched and still what eapol.c calls, so the E1 image's behaviour
  is unchanged — instrument first, fix later. FIPS-197 C.1 and RFC
  3394 4.1 vectors plus negative cases pass on the Mac
  (`utils/test_aeskw.c`, build line in its header).
- **E3 not started** — it changes rekey behaviour, so it waits for the
  E1 verdict like the E2 wiring does.

### First flash, first verdicts (same night, ~02:30)

The first E1 image booted into orange association-roulette and garbage
counter values. Both had the same cause, and it was not the campaign
code: **the linker script never collected `.bss.*` subsections**
(`-fdata-sections` puts every variable in its own), so 56 sections —
the whole EAPOL state, the scan cache, `usbhost_init_status`, the
counters — sat past `__bss_end__` and were *never zeroed at boot*.
Association success depended on power-on SRAM garbage; every replug
rolled the dice. This is almost certainly the historic "boot C flaky"
behaviour. Leonard had already found and tested the fix on the
never-merged `diag-usb-hunt-20260730` branch (commit 364c761); the
linker part was cherry-picked from it, plus its two `.extbss`
relocations (`audioFifoPlay`, `buffer_temp`, 4 KB each — needed
because a properly-collected BSS no longer fits IntRAM next to the
stack), and the counters packet moved into `.extbss` too. Verified in
the map: zero orphans, `__bss_end__` 0x10001350, stack floor clear.

And the garbage build still delivered a verdict, because `es`, `is`
and `csr0/1/2` are live reads, not counters: **`es=2`
(EAPOL_S_GROUP) with `csr0=00000001`** — only the pairwise key slot
is ever valid. On WPA2 the GTK is delivered inside message 3/4,
AES-Key-Wrapped — which this firmware never decrypts. So the group
key is not lost on a rekey: **it is never installed at all**, and
broadcast RX is dead from the first second of every association.
Mechanism (1), with an earlier onset than hypothesised: the
25-60 min "wedge" is just the moment the Mac's ARP cache gives up on
unicast refresh and re-ARPs by broadcast. E4's gratuitous ARP should
therefore mask the symptom entirely, and the E2 wiring (unwrap the
GTK from msg3 key data + group rekey path) is the real fix. The
clean-counter soak remains worth running to confirm with sane
numbers (expected: `bcn` rising, `denc` rising, `eg=0` forever,
`es` stuck at 2, `dpl` near-zero).

Two follow-ups from the same night, both worth remembering:

- The `.extbss` output section, taken as-is from 364c761, silently
  moved `__heap_start__` into ExtRAM (an output section in another
  region carries the location counter with it) while `__heap_end__`
  stayed in IntRAM. `_sbrk` compares the two, so malloc would have
  handed out memory without ever reaching its limit. Fixed by saving
  the counter in `_intram_end` before the section and restoring it
  after. **Any future output section in a second region needs the
  same treatment.**
- Whether a given image is actually in flash cost the whole night to
  establish by inference. The counters datagram now carries
  `bld=HH:MM:SS` (`__TIME__` of the build), so one glance at the
  listener answers it. Images worth keeping are copied to
  `Nab-eapol-<phase>-bld<HHMMSS>.sim` rather than overwriting
  `Nab-wpa23-release.sim`.

### E2 + E3 wired, proven on hardware (same night, 03:52)

With clean counters the verdict took ninety seconds: `es=2` forever,
`eg=0`, `csr0=00000001` — GTK never installed, exactly as read off the
garbage build. So E2 was wired in that same session instead of
waiting:

- `eapol_install_msg3_gtk()` (eapol.c): bounds-checks Key Data against
  the delivered frame, unwraps it (RFC 3394 under the KEK), picks the
  GTK KDE (`rsn_find_gtk` in aes128.c), refuses key id 0 (the pairwise
  slot), installs via `rt2501_set_key`. Called from msg 3/4 *and* from
  the group-rekey handler, where — E3 — failure now drops the link to
  IDLE instead of asserting RUN, handing recovery to garenne's
  watchdog. New counters `gok`/`gko` report installs/failures.
- **Bug caught between the two flashes:** the KDE length arithmetic
  first read `elen - 8` instead of `elen - 6`; the installed GTK was 2
  bytes short and the hardware *tried* to decrypt broadcast and failed
  ICV on every frame — visible as `cerr` climbing ~90/min while
  `csr0=3` looked healthy. The first test vector encoded the same
  wrong arithmetic, which is why it passed: a lesson in deriving
  vectors from the spec (802.11-2016 fig. 12-34), not from the code.

Proof, image `Nab-eapol-e2b-bld014830.sim` (232704 bytes):
`gok=1 csr0=00000003 cerr=0/0/0` frozen; at up=73 s the AP ran a
**live PTK+GTK rekey** (`e14/e34/gok` → 2) with zero disruption; and a
UDP `grn1 ping` sent to **255.255.255.255 was answered** —
`ok garenne 0.8.1`. First broadcast frame heard by a Nabaztag on
WPA2/CCMP since the 2006 firmware shipped.

E5 status: the upstream branch **`wpa23-gtk`** is ready in the fork -
base `wpa23` (the PR #10 branch) plus the linker-script fix and the
GTK fix, with every diag reference stripped. Host vectors ALL PASS on
the merged code, GCC 5.4 container build clean (text 109064), map
clean (zero orphan `.bss.*`, `__bss_end__` 0x10001458 under the
0x10002988 stack floor). Flashed and proven on hardware as
`Nab-wpa23-gtk-release-bld051859.sim`: association, unicast, and ctl
pings answered on both 192.168.1.255 and 255.255.255.255. The PR
itself waits for RedoXyde's answer on #10.

Two flashes of the branch failed first, each with its own lesson:

- The raw Makefile builds with `-DDEBUG_VM -DDEBUG_AUDIO -DDEBUG_MAIN`,
  and on this lineage the console still goes through the blocking
  UART FIFO (~87 us per character, the diag branch had cut that in
  diag v4). The VM crawls, association almost never completes, and
  the one boot that got through died before its first datagram.
  Flash images must be built with `OPTIONS=` (empty), like
  build-nabgcc.sh --release does.
- This lineage kept `key_data` as a fixed 24-byte struct field where
  the diag branch had made it flexible, so the ported GTK bounds
  check was 24 bytes too strict and rejected every message 3/4:
  association fine, unicast fine, broadcast deaf - the original 2006
  symptom, reintroduced by the port. The frame-header size on this
  branch is `sizeof(struct eapol_frame) - EAPOL_RSN_LENGTH`.

Directed broadcast is no longer filtered: garenne 0.8.2 accepts the
subnet's directed address (`NET_BCAST`, computed from the inherited
mask) in `ipv4_valid`, and a `grn1 ping` to 192.168.1.255 was answered
on hardware.

Remaining, in no hurry: a naturally failed rekey showing `gko>0`
followed by a clean reassociation (E3's negative path, observational);
deleting the no-op aes128 legacy API once soak time accumulates.

## Reflash discipline

Every image goes through the reproducible container build (byte
identical to the RedoX release, recipe in the setup doc and in
memory), gets packed with `tools/mkfirmware`, and is flashed **over
the air through config mode** whenever possible. The JTAG rig
(`tools/jtag/`, Alpine Pi at 192.168.1.103) is the recovery path, not
the daily one. Keep the head-button-at-boot escape hatch working: it
is what makes a bad image survivable.
