//! A long run of garenne, the real application, on the emulated rabbit:
//! minutes of board time with the group key renewed now and then. It
//! takes the time of a real rabbit's first minutes, so its length is
//! `NABEMU_SOAK_MINUTES` (default 3). Skipped without a garenne build.

mod common;

use common::{
    PROGRAM_FLOOR, SYSTEM, WATCHDOG_BUDGET_MS, authorized, garenne, garenne_log as log, ms,
    on_network, serve, terrier, wait, wpa2,
};
use nabemu::air::{ApEvent, Wpa3};
use nabemu::config::Config;
use nabemu::lan::{Lan, Response};

/// How long to run: `NABEMU_SOAK_MINUTES`, 3 by default.
fn minutes() -> u64 {
    std::env::var("NABEMU_SOAK_MINUTES")
        .ok()
        .and_then(|m| m.parse().ok())
        .unwrap_or(3)
}

/// Garenne's pulses among its log lines: one every two seconds while
/// its link is up.
fn pulses(log: &[String]) -> usize {
    log.iter().filter(|l| l.contains("link=4")).count()
}

#[test]
fn garenne_runs_for_minutes_through_group_key_renewals() {
    let Some(bytecode) = garenne() else {
        eprintln!("skipped: no garenne build around");
        return;
    };
    let minutes = minutes();
    let mut m = on_network(&nabemu::testing::image(), wpa2());
    serve(&mut m, bytecode);

    let end = minutes * 60_000;
    let mut next_rekey = 60_000;
    let mut awake = None;
    let mut before_last_minute = 0;
    while m.soc.millis() < end {
        wait(&mut m, 1000);
        if awake.is_none() && log(&m).iter().any(|l| l.contains("awake")) {
            awake = Some(m.soc.millis());
        }
        if m.soc.millis() <= end - 60_000 {
            before_last_minute = log(&m).len();
        }
        if m.soc.millis() >= next_rekey {
            let mut radio = m.radio.borrow_mut();
            m.air[0].rekey_group(&mut radio);
            next_rekey += 30_000;
        }
    }
    let log = log(&m);
    eprintln!(
        "{:?}: awake at {awake:?} ms, {} log lines, {} rekeys",
        nabemu::testing::firmware(),
        log.len(),
        m.air[0]
            .events
            .iter()
            .filter(|e| matches!(e, ApEvent::GroupKeyInstalled { .. }))
            .count()
    );
    assert_eq!(m.events, [], "no reset");
    assert!(awake.is_some(), "{log:#?}");
    // Pulses all along, through the last minute.
    let late = pulses(&log[before_last_minute..]);
    assert!(late >= 20, "{late} pulses in the last minute");
    assert!(authorized(&m));
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}

/// MPEG-1 layer III frames, 128 kb/s at 44.1 kHz, silent: what a
/// streamed sound looks like to the codec.
fn mp3(seconds: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..seconds * 38 {
        let mut frame = vec![0u8; 417];
        frame[..4].copy_from_slice(&[0xFF, 0xFB, 0x90, 0x64]);
        out.extend(frame);
    }
    out
}

/// Everything at once, for `NABEMU_SOAK_MINUTES` (3 by default):
/// garenne told by its control port to stream sound, dance, move its
/// ears and leds, a tag shown and taken away, the group key renewed
/// every 30 s, the pairwise key every 10 minutes, the access point
/// restarted every quarter of an hour. lapin only.
#[test]
fn garenne_lives_through_everything() {
    if !nabemu::testing::is_lapin() {
        return;
    }
    let Some(bytecode) = garenne() else {
        eprintln!("skipped: no garenne build around");
        return;
    };
    let minutes = minutes();
    let mut m = common::under_test();
    let mut config = Config::new(common::SSID, wpa2().0);
    // Garenne's server is the one the settings name.
    config.server = "192.168.1.1/vl".into();
    config.install(&mut m.soc.flash);
    let ap = || {
        let mut ap = terrier(wpa2().1);
        ap.wpa3 = Wpa3::Transition;
        ap
    };
    m.air.push(ap());
    let sound = mp3(4);
    let mut lan = Lan::new();
    lan.handler = Box::new(move |r| {
        if r.target.contains("stream.mp3") {
            Response::ok(sound.clone())
        } else {
            Response::ok(bytecode.clone())
        }
    });
    m.lan = Some(lan);
    let tag = nabemu::rfid::Tag::new([0xD0, 2, 0x1A, 3, 4, 5, 6, 7]);

    let end = minutes * 60_000;
    let mut before_last_minute = 0;
    let mut restarts = 0;
    let mut resets_seen = 0;
    let mut plays = 0;
    let mut unfed_before = 0;
    while m.soc.millis() < end {
        unfed_before = unfed_before.max(m.soc.watchdog_unfed());
        wait(&mut m, 1000);
        if m.events.len() > resets_seen {
            resets_seen = m.events.len();
            let console = m.console();
            let tail: Vec<&str> = console
                .lines()
                .rev()
                .take(25)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let lg = log(&m);
            eprintln!(
                "RESET {:?} at {} ms, watchdog unfed up to {} ms before; log tail {:?}\nconsole tail:\n{}",
                m.events.last(),
                m.soc.millis(),
                ms(unfed_before),
                &lg[lg.len().saturating_sub(5)..],
                tail.join("\n")
            );
        }
        unfed_before = 0;
        let t = m.soc.millis();
        let minute = t / 60_000;
        let second = (t / 1000) % 60;
        if t >= 60_000 && second.is_multiple_of(30) {
            m.air[0].rekey_group(&mut m.radio.borrow_mut());
        }
        if t >= 60_000 && t % 600_000 < 1000 {
            m.air[0].rekey_pairwise(&mut m.radio.borrow_mut(), nabemu::DEFAULT_MAC);
        }
        if t >= 900_000 && t % 900_000 < 1000 {
            // The access point restarts: everyone dropped, keys forgotten.
            m.air[0].kick(&mut m.radio.borrow_mut(), nabemu::DEFAULT_MAC, 3);
            wait(&mut m, 100);
            m.radio.borrow_mut().tx.clear();
            m.air[0] = ap();
            restarts += 1;
        }
        if t >= 30_000 && second == 10 {
            if minute.is_multiple_of(5) {
                plays += 1;
            }
            let command: &[u8] = match minute % 5 {
                0 => b"grn1 play /vl/stream.mp3",
                1 => b"grn1 dance",
                2 => b"grn1 ears 5 10",
                3 => b"grn1 led 2 FF00FF",
                _ => b"grn1 ping",
            };
            m.lan.as_mut().unwrap().send_udp(9998, 9998, command);
        }
        if minute % 5 == 4 {
            if second == 20 {
                m.soc.board.rfid.tags.push(tag.clone());
            } else if second == 40 {
                m.soc.board.rfid.tags.clear();
            }
        }
        if m.soc.millis() <= end - 60_000 {
            before_last_minute = log(&m).len();
        }
    }
    let log = log(&m);
    if std::env::var("SOAK_LOG").is_ok() {
        for l in log.iter().filter(|l| !l.contains("link=4")) {
            eprintln!("LOG {l}");
        }
    }
    let played = log.iter().filter(|l| l.contains("audio: done")).count();
    let tracks = m.soc.board.codec.tracks.len();
    eprintln!(
        "{minutes} minutes: {} log lines, {restarts} access point restarts, {plays} sounds asked, {played} played to the end, {tracks} tracks at the codec",
        log.len()
    );
    assert_eq!(m.events, [], "no reset");
    let late = pulses(&log[before_last_minute..]);
    assert!(
        late >= 20,
        "{late} pulses in the last minute: {:?}",
        &log[before_last_minute..]
    );
    assert_eq!(played, plays, "sounds asked and played: {log:#?}");
    let unfed = ms(m.soc.watchdog_longest);
    assert!(unfed <= WATCHDOG_BUDGET_MS, "watchdog unfed {unfed} ms");
    assert!(m.stack_low[SYSTEM] >= PROGRAM_FLOOR);
}
