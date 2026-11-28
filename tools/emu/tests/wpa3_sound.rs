//! A sound plays on while the rabbit joins a WPA3 network again: the
//! password exchange's arithmetic (more than a second of it on the
//! rabbit's processor) must not starve the codec, whose buffer holds an
//! eighth of a second of this sound. lapin only: r3 has no WPA3.

mod common;

use common::bc::{self, Global, op::*};
use common::{BSSID, SSID, authorized, lapin, on_wpa3_network, sae_exchanges, until, wait};
use nabemu::DEFAULT_MAC;
use nabemu::metal;

/// A program that starts an endless sound, fed from its loop of
/// samples, and joins the home network again whenever the link is idle,
/// with what a scan of it says written in (a scan would hold the sound
/// up, on both firmwares).
fn program() -> Vec<u8> {
    // set g2 = ["Terrier" bssid bssid -40 6 255 WPA2+CCMP]
    let mut main = bc::main_with_home_network(2, 3, 4);
    // playStart 1 #feed; playFeed g0 0 nil
    main.extend(metal::int(1));
    main.extend(metal::int(1));
    main.extend([PLAYSTART, DROP, GETGLOBALB, 0]);
    main.extend(metal::int(0));
    main.extend([NIL, PLAYFEED, DROP]);
    // loopcb #rejoin
    main.extend(bc::loop_callback(2));

    // feed room = playFeed g1 0 room
    let mut feed = vec![GETGLOBALB, 1];
    feed.extend(metal::int(0));
    feed.extend([GETLOCALB, 0, PLAYFEED, RET]);
    let feed = bc::function(1, 0, &feed);

    // rejoin = if netState == IDLE then netAuth g2 0 WPA2 nil
    let rejoin = bc::rejoin(2, &[NIL]);

    // 16-bit samples at 8 kHz, one channel: 16 KB a second, no end.
    let header = common::pcm_8k_header(u32::MAX);
    let samples: Vec<u8> = (0..4096).map(|i| (i * 7) as u8).collect();
    let globals = [
        Global::Str(&header),
        Global::Str(&samples),
        Global::Word(u32::MAX),
        Global::Str(SSID.as_bytes()),
        Global::Str(&BSSID),
    ];
    bc::assemble(&globals, &[&main, &feed, &rejoin])
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
    let before = sae_exchanges(&m);
    let since = m.soc.millis();
    m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 3);
    m.air[0].power_cut();
    until(&mut m, 30_000, "the rabbit back on its network", |m| {
        sae_exchanges(m) > before && authorized(m)
    });
    wait(&mut m, 2000);
    let codec = &m.soc.board.codec;
    let gaps: Vec<_> = codec.gaps.iter().filter(|(at, _)| *at >= since).collect();
    assert!(codec.tracks.is_empty(), "one sound all along");
    assert_eq!(gaps, Vec::<&(u64, u64)>::new(), "gaps (at ms, for ms)");
}
