//! What an audit of the C firmware (r3) against lapin found in the
//! drivers and the sound, and the harsher-than-real hardware the
//! rescue core must survive. Each test runs on the firmware under test
//! (`nabemu::testing`); those marked "Known defect" check r3's bug on
//! r3 and lapin's fix on lapin (HANDOFF.md lists the differences).

mod common;

use common::{
    BSSID, ap_count, authorized, machine, on_network, open, under_test, until, wait, wpa2,
};
use nabemu::air::ApEvent;
use nabemu::config::Wifi;
use nabemu::lan::{GATEWAY_MAC, Lan};
use nabemu::rt2573::RxFrame;
use nabemu::testing::is_lapin;
use nabemu::{DEFAULT_MAC, Machine, metal};

// ---- the network ---------------------------------------------------

/// An ARP request for the rabbit's address, after its LLC header.
fn arp_request() -> Vec<u8> {
    let mut b = vec![0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x06];
    b.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    b.extend_from_slice(&GATEWAY_MAC);
    b.extend_from_slice(&[192, 168, 1, 1]);
    b.extend_from_slice(&[0; 6]);
    b.extend_from_slice(&[192, 168, 1, 100]);
    b
}

/// The same as an Ethernet frame, for the access point to send on.
fn eth_arp() -> Vec<u8> {
    let mut e = DEFAULT_MAC.to_vec();
    e.extend_from_slice(&GATEWAY_MAC);
    e.extend_from_slice(&[0x08, 0x06]);
    e.extend_from_slice(&arp_request()[8..]);
    e
}

/// A data frame's header from the access point, `fc1` its flags.
fn header(fc1: u8, seq: u16) -> Vec<u8> {
    let mut h = vec![0x08, fc1, 0, 0];
    h.extend_from_slice(&DEFAULT_MAC);
    h.extend_from_slice(&BSSID);
    h.extend_from_slice(&GATEWAY_MAC);
    h.extend_from_slice(&(seq << 4).to_le_bytes());
    h
}

fn arp_replies(m: &Machine) -> usize {
    m.air[0]
        .uplink
        .iter()
        .filter(|e| e.len() >= 22 && e[12..14] == [0x08, 0x06] && e[20..22] == [0, 2])
        .count()
}

/// The rabbit on the home network (WPA2, or open), with an address.
fn with_an_address(wifi: (Wifi, nabemu::air::Security)) -> Machine {
    let mut m = on_network(&nabemu::testing::image(), wifi);
    m.lan = Some(Lan::new());
    until(&mut m, 60_000, "an address", |m| {
        m.lan.as_ref().unwrap().leased_to.is_some()
    });
    wait(&mut m, 3000);
    m.lan = None;
    m.air[0].uplink.clear();
    m
}

/// The access point asks the rabbit for its address, properly: how
/// many answers came within two seconds.
fn answers_arp(m: &mut Machine) -> usize {
    m.air[0].uplink.clear();
    let eth = eth_arp();
    m.air[0].send(&mut m.radio.borrow_mut(), &eth);
    wait(m, 2000);
    arp_replies(m)
}

/// A frame from a sender in radio range, in clear, `len` bytes long,
/// that carries at `inner_at` of the stick's transfer (its 24-byte
/// descriptor, then the frame) what would read as a descriptor saying
/// "decrypted with CCMP, no error", then an ARP request.
fn oversized(len: usize, inner_at: usize) -> Vec<u8> {
    let mut inner = header(0x02, 101);
    inner.extend_from_slice(&arp_request());
    let w0: u32 = 1 << 2 | 1 << 5 | (inner.len() as u32) << 16 | 4 << 29;
    let w1: u32 = (0x79 + 50) << 8;
    let mut fake = Vec::new();
    for w in [w0, w1, 0x2000_FFFF, 0x0100_0000, 0, 0] {
        fake.extend_from_slice(&w.to_le_bytes());
    }
    fake.extend_from_slice(&inner);
    let mut outer = header(0x02, 102);
    outer.extend_from_slice(&[0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00]);
    while 24 + outer.len() < inner_at {
        outer.push(0x55);
    }
    outer.extend_from_slice(&fake);
    while outer.len() < len {
        outer.push(0x55);
    }
    outer
}

/// Known defect (B1/B2 of the audit): r3 goes deaf for good after a
/// receive transfer longer than its buffer. lapin took the rest of an
/// over-long transfer for a new one, whose "descriptor" the sender
/// wrote: a frame in clear passed as decrypted (A1). Now it receives
/// every frame the stick passes (4095 bytes) whole, drops what follows
/// an overrun up to the end of the transfer, and keeps hearing.
#[test]
fn a_frame_longer_than_2_kb_slips_nothing_in_and_deafens_nobody() {
    let mut m = with_an_address(wpa2());
    for (len, at) in [(2172, 2112), (4095, 2112), (4095, 4032)] {
        m.air[0].uplink.clear();
        m.radio
            .borrow_mut()
            .rx
            .push_back(RxFrame::new(oversized(len, at)));
        wait(&mut m, 2000);
        assert_eq!(arp_replies(&m), 0, "{len} bytes: the forged frame went in");
    }
    let replies = answers_arp(&mut m);
    if is_lapin() {
        assert_eq!(replies, 1, "lapin still hears");
    } else {
        assert_eq!(replies, 0, "Known defect: r3 deaf after an overrun");
    }
}

/// A stick that hands over a transfer longer than any frame it should
/// pass (4500 bytes, past MAC_CSR6's 4095): lapin's reassembly buffer,
/// which holds the longest transfer, overflows; what follows is dropped
/// up to the transfer's end, so a descriptor forged past the buffer
/// slips nothing in, and the next frame is heard (r3: deaf, as above).
#[test]
fn a_transfer_past_the_reassembly_buffer_is_dropped_to_its_end() {
    let mut m = with_an_address(wpa2());
    m.radio.borrow_mut().rx_any_length = true;
    // lapin's buffer ends at 4160, a whole packet: the forged
    // descriptor starts the packet after the one that overflows.
    m.radio
        .borrow_mut()
        .rx
        .push_back(RxFrame::new(oversized(4500, 4224)));
    wait(&mut m, 2000);
    assert_eq!(arp_replies(&m), 0, "the forged frame went in");
    let replies = answers_arp(&mut m);
    if is_lapin() {
        assert_eq!(replies, 1, "lapin still hears");
    } else {
        assert_eq!(replies, 0, "Known defect: r3 deaf after an overrun");
    }
}

/// A receive packet the USB controller gives up on: lapin glued what
/// followed to the frame it lost a packet of (M11); now it drops the
/// rest of that transfer, and hears the next frames as r3 does.
#[test]
fn a_lost_usb_packet_merges_no_frames() {
    let mut m = with_an_address(wpa2());
    // The ARP request arrives in two packets: its second is lost.
    m.radio.borrow_mut().lose_rx_packet = Some(1);
    m.air[0].uplink.clear();
    let eth = eth_arp();
    // The same again right behind it: the very next frame the stick
    // hands over. Glued to the packet before the lost one, it would be
    // the tail of a broken frame, and lost too.
    m.air[0].send(&mut m.radio.borrow_mut(), &eth);
    m.air[0].send(&mut m.radio.borrow_mut(), &eth);
    wait(&mut m, 1000);
    assert_eq!(arp_replies(&m), 1, "the next frame merged");
}

// ---- the stick on its port ---------------------------------------------

/// A stick that does not answer its first requests after its reset: the
/// C asks for its descriptor three times, 20 ms apart (A11); lapin gave
/// up at once and had no network.
#[test]
fn a_stick_slow_to_answer_is_still_brought_up() {
    let mut m = on_network(&nabemu::testing::image(), open());
    m.radio.borrow_mut().refuse_requests = 2;
    until(&mut m, 40_000, "on the network", authorized);
}

/// The request that starts the stick's own firmware answering late (K2):
/// Linux gives it a second, the C ignores how it ends; lapin gave it
/// half a second and gave the stick up.
#[test]
fn a_stick_slow_to_start_its_firmware_is_still_brought_up() {
    let mut m = on_network(&nabemu::testing::image(), open());
    m.radio.borrow_mut().firmware_start_nak_ms = 800;
    until(&mut m, 40_000, "on the network", authorized);
}

/// A stick that refuses requests for a while, longer than the
/// descriptor's three tries cover: lapin starts the controller over
/// and tries again (K2), and comes up.
#[test]
fn a_stick_that_fails_its_bring_up_once_gets_another_try() {
    if !is_lapin() {
        return;
    }
    let mut m = on_network(&nabemu::testing::image(), open());
    m.radio.borrow_mut().refuse_requests = 5;
    until(&mut m, 40_000, "on the network", authorized);
}

/// The stick unplugged and plugged back (a loose contact, A11): the C
/// enumerates it again and the bytecode joins anew (Known defect: after
/// a watchdog restart the unplugging causes); lapin brought it up once
/// only, at boot.
#[test]
fn a_stick_plugged_back_in_is_brought_up_again() {
    let mut m = with_an_address(open());
    let associations = ap_count(&m, &ApEvent::Associated { sta: DEFAULT_MAC });
    let stick = m.soc.ohci.unplug().expect("a stick");
    wait(&mut m, 3000);
    m.soc.ohci.plug(stick);
    m.lan = Some(Lan::new());
    until(&mut m, 60_000, "a new association", |m| {
        ap_count(m, &ApEvent::Associated { sta: DEFAULT_MAC }) > associations
    });
    until(&mut m, 60_000, "an address again", |m| {
        m.lan.as_ref().unwrap().leased_to.is_some()
    });
    wait(&mut m, 3000);
    m.lan = None;
    assert!(answers_arp(&mut m) >= 1, "on the network again");
    if is_lapin() {
        assert_eq!(m.events, []);
    } else {
        // Known defect: r3 gets there through a watchdog restart.
        assert_eq!(
            m.events,
            [nabemu::Event::Reset(nabemu::soc::ResetCause::Watchdog)]
        );
    }
}

/// A root hub that keeps its status change interrupt up while a change
/// bit is set, as some OHCI controllers do (K1): the C clears the bits
/// in its interrupt; lapin cleared them later, in its main program, so
/// it interrupted for ever and the watchdog bit.
#[test]
fn a_level_root_hub_interrupt_is_served() {
    let mut m = on_network(&nabemu::testing::image(), wpa2());
    m.soc.ohci.rhsc_level = true;
    until(&mut m, 40_000, "on the network", authorized);
    wait(&mut m, 5000);
    assert_eq!(m.events, []);
}

/// The same for the rescue core, the safety net: with the level
/// interrupt it still raises its network.
#[test]
fn the_rescue_core_serves_a_level_root_hub_interrupt() {
    if !is_lapin() {
        return;
    }
    let mut m = machine(&nabemu::testing::image());
    m.soc.ohci.rhsc_level = true;
    m.soc.flash[common::RESCUE..common::RESCUE + 4096].fill(0xFF);
    common::rescue_network_up(&mut m);
    assert_eq!(m.events, []);
}

// ---- the radio --------------------------------------------------------

/// The fraction of `ms` milliseconds, looked at every 5, the receiver
/// was on.
fn receiver_on(m: &mut Machine, ms: u64) -> f64 {
    let (mut on, mut all) = (0, 0);
    for _ in 0..ms / 5 {
        wait(m, 5);
        all += 1;
        on += m.radio.borrow().rx_enabled as u32;
    }
    on as f64 / all as f64
}

/// A request that fails while the radio changes channel (A12): the C
/// ignores it and always ends with the receiver on; lapin returned at
/// the error, with the receiver off.
#[test]
fn a_failed_request_while_tuning_leaves_the_receiver_on() {
    let mut m = under_test();
    until(&mut m, 20_000, "the stick up", |m| {
        m.radio.borrow().rx_enabled
    });
    m.radio.borrow_mut().refuse_bbp = true;
    let on = receiver_on(&mut m, 4000);
    assert!(on > 0.6, "the receiver on {:.0} % of the time", on * 100.0);
}

/// The RT2528's baseband R3: the C leaves its "smart mode" bit clear
/// (0x80) on every channel; lapin set it (A13).
#[test]
fn the_rt2528s_smart_mode_bit_is_left_as_the_c_leaves_it() {
    let mut m = under_test();
    wait(&mut m, 8000);
    let r3: Vec<u8> = m
        .radio
        .borrow()
        .bbp_writes
        .iter()
        .filter(|w| w.0 == 3)
        .map(|w| w.1)
        .collect();
    assert!(!r3.is_empty());
    assert!(r3.iter().all(|v| v & 1 == 0), "R3 written {r3:02x?}");
}

// ---- the board ----------------------------------------------------------

const ADCON2: u32 = 0xB600_0008;

/// The volume wheel's conversion clock: the C sets CPUCLK/32, 1 MHz
/// (ADCON2 4); lapin wrote 3, 2 MHz, said 1 MHz (A4).
#[test]
fn the_volume_wheel_is_converted_at_1_mhz() {
    let mut m = under_test();
    m.soc.trace = Some((vec![ADCON2], Vec::new()));
    wait(&mut m, 1000);
    let log = &m.soc.trace.as_ref().unwrap().1;
    assert_eq!(log.last().map(|w| w.2 & 7), Some(4), "{log:x?}");
}

const PO4: u32 = 0xB7A0_4000;
const WDTCON: u32 = 0xB7E0_0000;

/// After a power-on, how soon the pins are at rest and the watchdog
/// running (M7, K4): the C's are at 11 ms; lapin's rescue core checked
/// the application's CRC first, 76 ms more with floating pins and no
/// watchdog.
#[test]
fn pins_and_watchdog_are_set_up_before_the_application_is_checked() {
    let mut m = under_test();
    m.soc.trace = Some((vec![PO4, WDTCON], Vec::new()));
    wait(&mut m, 300);
    let log = &m.soc.trace.as_ref().unwrap().1;
    let first = |addr| {
        log.iter()
            .find(|w| w.1 == addr)
            .map(|w| common::ms(w.0))
            .unwrap_or(u64::MAX)
    };
    assert!(first(PO4) <= 15, "pins at {} ms", first(PO4));
    assert!(first(WDTCON) <= 15, "watchdog at {} ms", first(WDTCON));
}

// ---- sound ----------------------------------------------------------------

fn fun(narg: u8, nloc: u16, code: &[u8]) -> Vec<u8> {
    let mut out = vec![narg];
    out.extend(nloc.to_le_bytes());
    out.extend_from_slice(code);
    out
}

/// A bytecode with globals (an empty one is the integer 0) and several
/// functions, the first run when loaded.
fn bytecode(globals: &[&[u8]], funs: &[Vec<u8>]) -> Vec<u8> {
    let mut g = Vec::new();
    for s in globals {
        if s.is_empty() {
            g.extend(0u32.to_le_bytes());
            continue;
        }
        g.extend(((s.len() as u32) << 2 | 1).to_le_bytes());
        g.extend_from_slice(s);
    }
    let mut bc = (g.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(g);
    let mut code: Vec<u8> = Vec::new();
    let mut starts = Vec::new();
    for f in funs {
        starts.push(code.len() as u32);
        code.extend(f);
    }
    bc.extend((code.len() as u32).to_le_bytes());
    bc.extend(code);
    bc.extend((funs.len() as u16).to_le_bytes());
    for s in starts {
        bc.extend(s.to_le_bytes());
    }
    bc
}

const NIL: u8 = 4;
const DROP: u8 = 5;
const ADD: u8 = 9;
const AND: u8 = 14;
const SUB: u8 = 10;
const NEG: u8 = 19;
const GOTO: u8 = 28;
const ELSE: u8 = 29;
const GETGLOBALB: u8 = 36;
const SETGLOBAL: u8 = 42;
const PLAYSTART: u8 = 79;
const PLAYFEED: u8 = 80;
const GC: u8 = 87;
const IECHOLN: u8 = 95;
const RET: u8 = 1;

/// A WAV header for 16-bit sound at `rate` hertz on `channels`, of
/// `len` bytes of samples.
fn wav_header_at(rate: u32, channels: u16, len: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(b"RIFF");
    h.extend((len + 36).to_le_bytes());
    h.extend(b"WAVEfmt ");
    h.extend(16u32.to_le_bytes());
    h.extend(1u16.to_le_bytes());
    h.extend(channels.to_le_bytes());
    h.extend(rate.to_le_bytes());
    h.extend((rate * 2 * channels as u32).to_le_bytes());
    h.extend((2 * channels).to_le_bytes());
    h.extend(16u16.to_le_bytes());
    h.extend(b"data");
    h.extend(len.to_le_bytes());
    h
}

/// The same for 16-bit mono at 8 kHz.
fn wav_header(len: u32) -> Vec<u8> {
    wav_header_at(8000, 1, len)
}

/// Bytes the play callback hands over at a time.
const CHUNK: usize = 1000;

/// A bytecode that plays `stream` (a whole number of chunks) from its
/// play callback, which every other call feeds the next chunk and then
/// runs a collection, as garenne does every few seconds (the other
/// calls give nothing, so the ring runs dry); with `eof`, the end of
/// the stream is said once it is all in.
fn player(stream: &[u8], eof: bool) -> Vec<u8> {
    assert_eq!(stream.len() % CHUNK, 0);
    let mut main = metal::int(7770);
    main.extend([IECHOLN, DROP]);
    main.extend(metal::int(1));
    main.extend(metal::int(1));
    main.extend([PLAYSTART, DROP, NIL, RET]);
    // callback(free): global 2 counts the calls; on the odd ones,
    // global 1 += playFeed stream (global 1) CHUNK, then gc.
    let mut cb = metal::int(2);
    cb.extend([GETGLOBALB, 2]);
    cb.extend(metal::int(1));
    cb.extend([ADD, SETGLOBAL]);
    cb.extend(metal::int(1));
    cb.extend([AND, ELSE, 0, 0]);
    let to_skip = cb.len() - 2;
    cb.extend(feed(CHUNK));
    cb.extend([GC, DROP]);
    if eof {
        // Once it is all in (position minus length is 0, on which ELSE
        // jumps): playFeed nil, the C's play_eof.
        cb.extend([GETGLOBALB, 1]);
        cb.extend(metal::int(stream.len() as i32));
        cb.extend([SUB, ELSE, 0, 0]);
        let to_eof = cb.len() - 2;
        cb.extend([GOTO, 0, 0]);
        let to_end = cb.len() - 2;
        let eof_at = cb.len() as u16;
        cb[to_eof..to_eof + 2].copy_from_slice(&eof_at.to_le_bytes());
        cb.extend([NIL, NIL, NIL, PLAYFEED, DROP]);
        let end = cb.len() as u16;
        cb[to_end..to_end + 2].copy_from_slice(&end.to_le_bytes());
    }
    let skip = cb.len() as u16;
    cb[to_skip..to_skip + 2].copy_from_slice(&skip.to_le_bytes());
    cb.extend([NIL, RET]);
    let spare = [0u8; 4];
    bytecode(
        &[stream, &[], &[], &spare, &spare, &spare, &spare],
        &[fun(0, 4, &main), fun(1, 0, &cb)],
    )
}

/// Global 1 += playFeed stream (global 0) from global 1, `chunk` bytes.
fn feed(chunk: usize) -> Vec<u8> {
    let mut f = metal::int(1);
    f.extend([GETGLOBALB, 0, GETGLOBALB, 1]);
    f.extend(metal::int(chunk as i32));
    f.extend([PLAYFEED, GETGLOBALB, 1, ADD, SETGLOBAL, DROP]);
    f
}

/// Global 2 += 1.
fn next_phase() -> Vec<u8> {
    let mut f = metal::int(2);
    f.extend([GETGLOBALB, 2]);
    f.extend(metal::int(1));
    f.extend([ADD, SETGLOBAL]);
    f
}

/// A bytecode that plays `stream` as it would come from the network:
/// two `chunk`s every `period_ms`, the first when due, the second at the
/// next call but one (a call that gives nothing ends the machine's
/// refill, and sits between), and the call after it, the last of that
/// refill, sets the volume. Global 2 is the phase of the four calls,
/// global 3 when the next two are due.
fn streamer(stream: &[u8], chunk: usize, period_ms: i32) -> Vec<u8> {
    let mut main = metal::int(7770);
    main.extend([IECHOLN, DROP]);
    main.extend(metal::int(1));
    main.extend(metal::int(1));
    main.extend([PLAYSTART, DROP, NIL, RET]);
    let label = |cb: &mut Vec<u8>, at: usize| {
        let here = cb.len() as u16;
        cb[at..at + 2].copy_from_slice(&here.to_le_bytes());
    };
    // Phase 0 (global 2 & 3 is 0) to P0, phase 2 to P2.
    let mut cb = vec![GETGLOBALB, 2];
    cb.extend(metal::int(3));
    cb.extend([AND, ELSE, 0, 0]);
    let to_p0 = cb.len() - 2;
    cb.extend([GETGLOBALB, 2]);
    cb.extend(metal::int(1));
    cb.extend([AND, ELSE, 0, 0]);
    let to_p2 = cb.len() - 2;
    // Phases 1 and 3 give nothing; after 3, the next two are due a
    // period on.
    cb.extend(next_phase());
    cb.extend(metal::int(3));
    cb.extend([AND, ELSE, 0, 0]);
    let to_due = cb.len() - 2;
    cb.extend([NIL, RET]);
    label(&mut cb, to_due);
    cb.extend(metal::int(3));
    cb.push(TIME_MS);
    cb.extend(metal::int(period_ms));
    cb.extend([ADD, SETGLOBAL, DROP]);
    // Then the volume set (again), last: the codec carries the write
    // out with DREQ down, as the machine's refill ends.
    cb.extend(metal::int(40));
    cb.extend([SNDVOL, DROP, NIL, RET]);
    // P0: the first chunk once due.
    label(&mut cb, to_p0);
    cb.extend([TIME_MS, GETGLOBALB, 3, LT, ELSE, 0, 0]);
    let to_give = cb.len() - 2;
    cb.extend([NIL, RET]);
    label(&mut cb, to_give);
    cb.extend(feed(chunk));
    cb.extend(next_phase());
    cb.extend([DROP, NIL, RET]);
    // P2: the second chunk.
    label(&mut cb, to_p2);
    cb.extend(feed(chunk));
    cb.extend(next_phase());
    cb.extend([DROP, NIL, RET]);
    let spare = [0u8; 4];
    bytecode(
        &[stream, &[], &[], &[], &spare, &spare, &spare, &spare],
        &[fun(0, 4, &main), fun(1, 0, &cb)],
    )
}

/// What the codec received of the last stream played.
fn played(m: &Machine) -> Vec<u8> {
    let codec = &m.soc.board.codec;
    let tracks = codec.all_tracks();
    tracks.last().map(|t| t.data.clone()).unwrap_or_default()
}

/// A 16-bit tone at 8 kHz, about `samples` long: whole chunks, and no
/// zero byte in it.
fn a_pcm_stream(samples: usize) -> Vec<u8> {
    let len = (44 + 2 * samples).div_ceil(CHUNK) * CHUNK - 44;
    let mut s = wav_header(len as u32);
    for i in 0..len {
        let v = common::note(i / 2).to_le_bytes()[i % 2];
        s.push(v.max(1));
    }
    s
}

/// A mono WAV stream of format `tag` (1 PCM, 0x11 IMA ADPCM), `bits`
/// a sample at `rate` hertz, `byte_rate` bytes a second: whole `chunk`s
/// of about `len` bytes, the samples a sweep with no zero byte in it.
fn a_wav_stream(
    tag: u16,
    bits: u16,
    rate: u32,
    byte_rate: u32,
    len: usize,
    chunk: usize,
) -> Vec<u8> {
    let len = (44 + len).div_ceil(chunk) * chunk - 44;
    let mut s = Vec::new();
    s.extend(b"RIFF");
    s.extend((len as u32 + 36).to_le_bytes());
    s.extend(b"WAVEfmt ");
    s.extend(16u32.to_le_bytes());
    s.extend(tag.to_le_bytes());
    s.extend(1u16.to_le_bytes());
    s.extend(rate.to_le_bytes());
    s.extend(byte_rate.to_le_bytes());
    s.extend(1u16.to_le_bytes());
    s.extend(bits.to_le_bytes());
    s.extend(b"data");
    s.extend((len as u32).to_le_bytes());
    s.extend((0..len).map(|i| (i % 251) as u8 + 1));
    s
}

/// The C writes the byte it took from the ring whatever happened in the
/// bytecode's refill; lapin re-checked the codec's DREQ and dropped the
/// byte when a collection in the callback had filled the codec meanwhile
/// (A14): in 16-bit PCM one byte lost swaps every sample after it.
#[test]
fn no_byte_of_a_stream_is_lost_to_a_slow_play_callback() {
    let stream = a_pcm_stream(24_000);
    let mut m = common::serving(&nabemu::testing::image(), &player(&stream, false));
    until(&mut m, 60_000, "the sound", |m| played(m).len() > 1000);
    wait(&mut m, 6000);
    let got = played(&m);
    assert!(got.len() > stream.len() / 2, "{} bytes played", got.len());
    let n = got.len().min(stream.len());
    let first_wrong = (0..n).find(|&i| got[i] != stream[i]);
    assert_eq!(first_wrong, None, "{} bytes played", got.len());
}

/// The same end to end with a codec that is slow to take its last
/// register write (A14): a stream that comes as from the network, two
/// chunks at a time, the codec run dry in between, whose callback sets
/// the volume as it ends the machine's refill. DREQ is down while the
/// codec carries the write out (its data sheet's worst case, 43 µs
/// here), when the machine has the byte it took after the refill:
/// lapin dropped it, here at the second chunk's first byte, and every
/// 16-bit sample after it was swapped. It now waits in the ring.
#[test]
fn no_byte_of_a_stream_is_lost_to_a_codec_still_busy_after_the_refill() {
    // 16-bit mono at 8 kHz, 16 bytes a millisecond: the two chunks play
    // in 150 ms of the 200.
    let chunk = 1200;
    let stream = a_wav_stream(1, 16, 8000, 16_000, 4 * chunk, chunk);
    let mut m = common::serving(&nabemu::testing::image(), &streamer(&stream, chunk, 200));
    until(&mut m, 60_000, "the sound", |m| played(m).len() > 1000);
    wait(&mut m, 500);
    let got = played(&m);
    assert!(got.len() >= 3 * chunk, "{} bytes played", got.len());
    let n = got.len().min(stream.len());
    let first_wrong = (0..n).find(|&i| got[i] != stream[i]);
    assert_eq!(first_wrong, None, "{} bytes played", got.len());
}

/// Known defect (B40): at the end of a stream r3 sends the codec nothing
/// more and leaves the amplifier on. The VS1003 wants 2048 zeros after a
/// file or it may cut its end (data sheet 9.3); lapin sends them, then
/// switches the amplifier off.
#[test]
fn the_end_of_a_stream_is_flushed_and_the_amplifier_switched_off() {
    let stream = a_pcm_stream(4000);
    let mut m = common::serving(&nabemu::testing::image(), &player(&stream, true));
    until(&mut m, 60_000, "the sound", |m| played(m).len() > 1000);
    wait(&mut m, 3000);
    let got = played(&m);
    assert!(got.len() >= stream.len());
    assert_eq!(got[..stream.len()], stream[..]);
    let tail = &got[stream.len()..];
    if is_lapin() {
        assert!(
            tail.len() >= 2048 && tail.iter().all(|b| *b == 0),
            "{} bytes after",
            tail.len()
        );
        assert!(!m.soc.board.amplifier, "amplifier off");
    } else {
        assert_eq!(tail.len(), 0, "Known defect: nothing after the stream");
        assert!(m.soc.board.amplifier, "Known defect: amplifier left on");
    }
}

// ---- the tag reader -------------------------------------------------------

const TIME_MS: u8 = 53;

/// Milliseconds `calls` of `call` take on `image` with a tag in front
/// of the nose, as the bytecode times them.
fn rfid_ms(image: &[u8], call: &[u8], calls: usize) -> u64 {
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.push(TIME_MS);
    for _ in 0..calls {
        f.extend_from_slice(call);
    }
    f.extend([TIME_MS, SUB, IECHOLN, RET]);
    let mut m = common::serving(image, &metal::bytecode(&[], &f));
    m.soc.board.rfid.tags = vec![nabemu::rfid::Tag::new(common::UID)];
    until(&mut m, 60_000, "the timing", |m| {
        common::time_printed(m).is_some()
    });
    common::time_printed(&m).unwrap()
}

/// The tag reader's calls take as long as r3's, within 10 % (A15): the
/// C's pauses, as long as its own, and no more of them. lapin took two
/// and a half times as long.
#[test]
fn the_tag_reader_is_as_quick_as_r3s() {
    let Some(lapin) = common::lapin() else { return };
    let get = [metal::OP_RFID_GET, DROP];
    let mut read = vec![metal::OP_RFID_GET];
    read.extend(metal::int(1));
    read.extend([metal::OP_RFID_READ, DROP]);
    for (name, call) in [("rfidGet", &get[..]), ("rfidRead", &read[..])] {
        let r3 = rfid_ms(&common::r3(), call, 40) as f64 / 40.0;
        let ours = rfid_ms(&lapin, call, 40) as f64 / 40.0;
        eprintln!("{name}: r3 {r3:.2} ms, lapin {ours:.2} ms");
        assert!(
            ours <= r3 * 1.1,
            "{name}: r3 {r3:.2} ms, lapin {ours:.2} ms"
        );
    }
}

/// The reader holds the clock low a second in the middle of a transfer:
/// the wait for its end times out. lapin left I2CMSTA set then, and the
/// controller kept the bus (I2CMBB, from a start to its stop): every
/// transfer after found it busy, and no tag was read again until a
/// restart. It now sends the stop. Known defect: r3 still does as
/// lapin did.
#[test]
fn a_transfer_that_timed_out_leaves_the_bus_free() {
    // Ask for a tag, print what came, again and again.
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.extend([metal::OP_RFID_GET, metal::OP_SECHOLN, DROP, GOTO, 0, 0]);
    let mut m = common::serving(&nabemu::testing::image(), &metal::bytecode(&[], &f));
    until(&mut m, 60_000, "the polling", |m| {
        m.soc.board.rfid.exchanges > 0
    });
    m.soc.i2c_stretch_ms = Some(1000);
    wait(&mut m, 2000);
    let mark = m.soc.uart_tx.len();
    m.soc.board.rfid.tags = vec![nabemu::rfid::Tag::new(common::UID)];
    wait(&mut m, 1000);
    let seen = common::find(&m.soc.uart_tx[mark..], &common::UID).is_some();
    if is_lapin() {
        assert!(seen, "the reader dead after a timeout");
    } else {
        assert!(!seen, "Known defect: r3's reader dead until a restart");
    }
}

// ---- more of r3's defects --------------------------------------------------

const WAV2ALAW: u8 = 141;
const SNDVOL: u8 = 100;
const LT: u8 = 24;

/// Known defect (B36): wav2alaw with a negative length writes over the
/// heap and r3 restarts, and restarts again as the server gives it the
/// same bytecode. lapin converts nothing and carries on.
#[test]
fn a_negative_length_to_wav2alaw_is_nothing_to_convert() {
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.extend([GETGLOBALB, 0]);
    f.extend(metal::int(0));
    f.extend([GETGLOBALB, 1]);
    f.extend(metal::int(0));
    f.extend(metal::int(-200));
    f.extend(metal::int(0));
    f.extend([WAV2ALAW, DROP]);
    f.extend(metal::int(8880));
    f.extend([IECHOLN, RET]);
    let bytecode = metal::bytecode(&[&[0; 64], &[0x55; 64]], &f);
    let mut m = common::serving(&nabemu::testing::image(), &bytecode);
    wait(&mut m, 30_000);
    if is_lapin() {
        assert!(m.console().contains("8880"), "{}", m.console());
        assert_eq!(m.events, []);
    } else {
        assert!(!m.events.is_empty(), "Known defect: r3 restarts");
    }
}

/// A codec that never raises DREQ (M8). Known defect: r3 waits for it
/// for ever, at its start, feeding the watchdog: no bytecode, no
/// network. lapin gives up after half a second once, then no longer
/// waits: ten volume changes take no time.
#[test]
fn a_dead_codec_costs_half_a_second_once() {
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.push(TIME_MS);
    for _ in 0..10 {
        f.extend(metal::int(40));
        f.extend([SNDVOL, DROP]);
    }
    // end - start, after a marker line: it can be 0, which has no sign
    // to tell it from the boot's own output.
    f.extend([TIME_MS, SUB, NEG]);
    f.extend(metal::int(7770));
    f.extend([IECHOLN, DROP, IECHOLN, RET]);
    let mut m = common::serving(&nabemu::testing::image(), &metal::bytecode(&[], &f));
    m.soc.board.codec.dead = true;
    if !is_lapin() {
        wait(&mut m, 30_000);
        assert!(
            m.lan.as_ref().unwrap().requests.is_empty(),
            "Known defect: r3 never gets as far as its server"
        );
        return;
    }
    let after_marker = |m: &Machine| -> Option<u64> {
        let console = m.console();
        let mut lines = console.lines().skip_while(|l| *l != "7770");
        lines.next()?;
        lines.next()?.parse().ok()
    };
    until(&mut m, 60_000, "the timing", |m| after_marker(m).is_some());
    let ms = after_marker(&m).unwrap();
    assert!(ms < 20, "ten volume changes took {ms} ms");
}

/// The rescue core's network, then the application, with the stick
/// powered throughout (I3): the C never cleared the stick's beacon
/// registers, lapin did not either, and the application kept sending the
/// rescue network's beacons. They stop at the application's start.
#[test]
fn the_rescue_networks_beacons_stop_with_the_application() {
    if !is_lapin() {
        return;
    }
    let image = nabemu::testing::image();
    let app = image[common::RESCUE..common::RESCUE + 4096].to_vec();
    let mut m = common::without_application(&image);
    wait(&mut m, 2000);
    let beacons = |m: &Machine| {
        m.radio
            .borrow()
            .tx
            .iter()
            .filter(|f| f.data[0] == 0x80 && common::find(&f.data, b"Nabaztag-secours").is_some())
            .count()
    };
    assert!(beacons(&m) > 0, "the rescue network beacons");
    // The application back in its place, and a restart (the watchdog's,
    // the stick keeps its power and its registers).
    m.soc.flash[common::RESCUE..common::RESCUE + 4096].copy_from_slice(&app);
    m.soc.pending_reset = Some(nabemu::soc::ResetCause::Watchdog);
    until(&mut m, 20_000, "the application", |m| {
        m.console().contains("lapin 0.1")
    });
    wait(&mut m, 3000);
    m.radio.borrow_mut().tx.clear();
    wait(&mut m, 3000);
    assert_eq!(beacons(&m), 0, "still beaconing for the rescue core");
}

/// The processor seeing the interrupt line late (I1): an interrupt whose
/// source went away is taken, and the controller names source 0, the
/// system timer. lapin counted a millisecond for each: its clock ran
/// ahead of the board's. Now its clock never runs ahead. (r3 counts
/// them too, but its handler returns late enough for the line to be
/// down: the model gives it none.)
#[test]
fn an_illegal_interrupt_is_no_millisecond() {
    // Wait in the bytecode until its clock says 10 s, say so, then
    // until it says 13 s, and say so.
    let mut f = metal::FUNCTION_HEADER.to_vec();
    for (until_ms, say) in [(10_000, 731_731), (13_000, 937_937)] {
        let top = (f.len() - 3) as u16;
        f.push(TIME_MS);
        f.extend(metal::int(until_ms));
        f.extend([LT, ELSE, 0, 0]);
        let to_end = f.len() - 2;
        f.push(GOTO);
        f.extend(top.to_le_bytes());
        let end = (f.len() - 3) as u16;
        f[to_end..to_end + 2].copy_from_slice(&end.to_le_bytes());
        f.extend(metal::int(say));
        f.extend([IECHOLN, DROP]);
    }
    f.extend([NIL, RET]);
    let mut m = common::serving(&nabemu::testing::image(), &metal::bytecode(&[], &f));
    m.soc.irq_lag = true;
    let first = common::until_every(&mut m, 1, 60_000, "10 s", |m| {
        m.console().contains("\n731731")
    });
    let before = m.soc.illegal_irqs;
    // Meanwhile, a frame for the rabbit every 5 ms: USB interrupts.
    let mut eth = DEFAULT_MAC.to_vec();
    eth.extend_from_slice(&[2, 0, 0, 0, 0, 0x55, 0x88, 0xB5]);
    eth.extend_from_slice(&[0x5A; 100]);
    let mut ms = 0;
    while !m.console().contains("\n937937") {
        assert!(ms < 6000, "13 s on the rabbit's clock not by {ms} ms on");
        if ms % 5 == 0 {
            m.air[0].send(&mut m.radio.borrow_mut(), &eth);
        }
        wait(&mut m, 1);
        ms += 1;
    }
    let second = m.soc.millis();
    // The bytecode ran before its clock said 10 s: it waited.
    assert!(first < 11_000, "the bytecode came at {first} ms");
    let board = second - first;
    let illegal = m.soc.illegal_irqs - before;
    eprintln!("{illegal} illegal interrupts, 3 s in {board} ms");
    if is_lapin() {
        // The handler clears the controller's status last, and the
        // CILCL write follows: the line, still up, is taken again.
        assert!(illegal > 10, "{illegal} illegal interrupts");
    }
    assert!(board + 2 >= 3000, "3 s on the rabbit's clock in {board} ms");
}
