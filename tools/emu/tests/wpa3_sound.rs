//! A sound plays on while the rabbit joins a WPA3 network again: the
//! password exchange's arithmetic (more than a second of it on the
//! rabbit's processor) must not starve the codec, whose buffer holds an
//! eighth of a second of this sound. lapin only: r3 has no WPA3.

mod common;

use common::{BSSID, SSID, authorized, lapin, on_wpa3_network, until, wait};
use nabemu::DEFAULT_MAC;
use nabemu::air::ApEvent;
use nabemu::metal::{self, OP_DROP, OP_GETGLOBALB, OP_RET};

const NIL: u8 = 4;
const GETLOCALB: u8 = 7;
const EQ: u8 = 22;
const ELSE: u8 = 29;
const DEFTABB: u8 = 32;
const SETGLOBAL: u8 = 42;
const PLAYSTART: u8 = 79;
const PLAYFEED: u8 = 80;
const LOOPCB: u8 = 94;
const NETSTATE: u8 = 105;
const NETAUTH: u8 = 110;

/// 16-bit samples at 8 kHz, one channel: 16 KB a second.
fn wav_header() -> Vec<u8> {
    let mut h = b"RIFF".to_vec();
    h.extend(u32::MAX.to_le_bytes());
    h.extend(b"WAVEfmt ");
    h.extend(16u32.to_le_bytes());
    h.extend(1u16.to_le_bytes());
    h.extend(1u16.to_le_bytes());
    h.extend(8000u32.to_le_bytes());
    h.extend(16000u32.to_le_bytes());
    h.extend(2u16.to_le_bytes());
    h.extend(16u16.to_le_bytes());
    h.extend(b"data");
    h.extend(u32::MAX.to_le_bytes());
    h
}

/// A string global, as the bytecode's globals hold it.
fn global_str(s: &[u8]) -> Vec<u8> {
    let mut g = ((s.len() as u32) << 2 | 1).to_le_bytes().to_vec();
    g.extend(s);
    g
}

/// A program that starts an endless sound, fed from its loop of
/// samples, and joins the home network again whenever the link is idle,
/// with what a scan of it says written in (a scan would hold the sound
/// up, on both firmwares).
fn program() -> Vec<u8> {
    let mut main = vec![0, 0, 0];
    // set g2 = ["Terrier" bssid bssid -40 6 255 WPA2+CCMP]
    main.extend(metal::int(2));
    main.extend([OP_GETGLOBALB, 3, OP_GETGLOBALB, 4, OP_GETGLOBALB, 4]);
    for v in [-40, 6, 255, 0x4A] {
        main.extend(metal::int(v));
    }
    main.extend([DEFTABB, 7, SETGLOBAL, OP_DROP]);
    // playStart 1 #feed; playFeed g0 0 nil
    main.extend(metal::int(1));
    main.extend(metal::int(1));
    main.extend([PLAYSTART, OP_DROP, OP_GETGLOBALB, 0]);
    main.extend(metal::int(0));
    main.extend([NIL, PLAYFEED, OP_DROP]);
    // loopcb #rejoin
    main.extend(metal::int(2));
    main.extend([LOOPCB, OP_DROP]);
    main.extend(metal::int(0));
    main.push(OP_RET);

    // feed room = playFeed g1 0 room
    let mut feed = vec![1, 0, 0, OP_GETGLOBALB, 1];
    feed.extend(metal::int(0));
    feed.extend([GETLOCALB, 0, PLAYFEED, OP_RET]);

    // rejoin = if netState == IDLE then netAuth g2 0 WPA2 nil
    let mut body = vec![NETSTATE];
    body.extend(metal::int(1));
    body.extend([EQ, ELSE, 0, 0, OP_GETGLOBALB, 2]);
    body.extend(metal::int(0));
    body.extend(metal::int(0x40));
    body.extend([NIL, NETAUTH, OP_DROP]);
    let skip = (body.len() as u16).to_le_bytes();
    let at = body.iter().position(|b| *b == ELSE).unwrap();
    body[at + 1..at + 3].copy_from_slice(&skip);
    body.extend(metal::int(0));
    body.push(OP_RET);
    let mut rejoin = vec![0, 0, 0];
    rejoin.extend(body);

    let samples: Vec<u8> = (0..4096).map(|i| (i * 7) as u8).collect();
    let mut globals = global_str(&wav_header());
    globals.extend(global_str(&samples));
    globals.extend(u32::MAX.to_le_bytes());
    globals.extend(global_str(SSID.as_bytes()));
    globals.extend(global_str(&BSSID));
    let mut bc = (globals.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(globals);
    let starts = [0, main.len(), main.len() + feed.len()];
    let code = [main, feed, rejoin].concat();
    bc.extend((code.len() as u32).to_le_bytes());
    bc.extend(code);
    bc.extend(3u16.to_le_bytes());
    for s in starts {
        bc.extend((s as u32).to_le_bytes());
    }
    bc
}

/// The access point restarts in the middle of the sound: it forgets the
/// rabbit and the key of their last exchange, so the rabbit runs the
/// whole password exchange again, and the sound goes on without a gap.
#[test]
fn a_wpa3_rejoin_does_not_starve_the_sound() {
    let Some(image) = lapin() else { return };
    let mut m = on_wpa3_network(&image);
    common::serve(&mut m, metal::boot_response(&program()));
    until(&mut m, 40_000, "the sound", |m| {
        m.soc.board.codec.current.is_some() && authorized(m)
    });
    wait(&mut m, 2000);
    let exchanges = |m: &nabemu::Machine| {
        m.air[0]
            .events
            .iter()
            .filter(|e| matches!(e, ApEvent::SaeComplete { .. }))
            .count()
    };
    let before = exchanges(&m);
    let since = m.soc.millis();
    m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 3);
    m.air[0].power_cut();
    until(&mut m, 30_000, "the rabbit back on its network", |m| {
        exchanges(m) > before && authorized(m)
    });
    wait(&mut m, 2000);
    let codec = &m.soc.board.codec;
    let gaps: Vec<_> = codec.gaps.iter().filter(|(at, _)| *at >= since).collect();
    assert!(codec.tracks.is_empty(), "one sound all along");
    assert_eq!(gaps, Vec::<&(u64, u64)>::new(), "gaps (at ms, for ms)");
}
