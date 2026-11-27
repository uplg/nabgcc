//! A long run of garenne, the real application, on the emulated rabbit:
//! minutes of board time with the group key renewed now and then. It
//! takes the time of a real rabbit's first minutes, so its length is
//! `NABEMU_SOAK_MINUTES` (default 3). Skipped without a garenne build.

use nabemu::Machine;
use nabemu::air::{AccessPoint, ApEvent, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};

fn garenne() -> Option<Vec<u8>> {
    let default = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../clapier/garenne/build/garenne.bin"
    );
    let path = std::env::var("NABEMU_GARENNE").unwrap_or_else(|_| default.into());
    std::fs::read(path).ok()
}

fn log(m: &Machine) -> Vec<String> {
    m.lan
        .as_ref()
        .unwrap()
        .datagrams
        .iter()
        .filter(|d| d.to_port == 9999)
        .map(|d| String::from_utf8_lossy(&d.payload).into_owned())
        .collect()
}

#[test]
fn garenne_runs_for_minutes_through_group_key_renewals() {
    let Some(bytecode) = garenne() else {
        eprintln!("skipped: no garenne build around");
        return;
    };
    let minutes: u64 = std::env::var("NABEMU_SOAK_MINUTES")
        .ok()
        .and_then(|m| m.parse().ok())
        .unwrap_or(3);
    let mut m = Machine::from_file(&nabemu::testing::image()).0;
    let wifi = Wifi::Wpa2 {
        passphrase: "carotte-violette".into(),
    };
    Config::new("Terrier", wifi).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2("carotte-violette"),
    ));
    let mut lan = Lan::new();
    lan.handler = Box::new(move |_| Response::ok(bytecode.clone()));
    m.lan = Some(lan);

    let end = minutes * 60_000;
    let mut next_rekey = 60_000;
    let mut awake = None;
    let mut before_last_minute = 0;
    while m.soc.millis() < end {
        m.run_until_ms(m.soc.millis() + 1000);
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
    let late = log[before_last_minute..]
        .iter()
        .filter(|l| l.contains("link=4"))
        .count();
    assert!(late >= 20, "{late} pulses in the last minute");
    assert!(m.air[0].is_authorized(nabemu::DEFAULT_MAC));
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
    let minutes: u64 = std::env::var("NABEMU_SOAK_MINUTES")
        .ok()
        .and_then(|m| m.parse().ok())
        .unwrap_or(3);
    let mut m = Machine::from_file(&nabemu::testing::image()).0;
    let mut config = Config::new(
        "Terrier",
        Wifi::Wpa2 {
            passphrase: "carotte-violette".into(),
        },
    );
    // Garenne's server is the one the settings name.
    config.server = "192.168.1.1/vl".into();
    config.install(&mut m.soc.flash);
    let ap = || {
        let mut ap = AccessPoint::new(
            "Terrier",
            [2, 0, 0, 0, 0, 0xA1],
            6,
            Security::wpa2("carotte-violette"),
        );
        ap.wpa3 = nabemu::air::Wpa3::Transition;
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
    while m.soc.millis() < end {
        m.run_until_ms(m.soc.millis() + 1000);
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
            m.run_until_ms(m.soc.millis() + 100);
            m.radio.borrow_mut().tx.clear();
            m.air[0] = ap();
            restarts += 1;
        }
        if t >= 30_000 && second == 10 {
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
    let consumed = m.soc.board.codec.consumed;
    eprintln!(
        "{minutes} minutes: {} log lines, {restarts} access point restarts, {consumed} bytes of sound played",
        log.len()
    );
    assert_eq!(m.events, [], "no reset");
    let late = log[before_last_minute..]
        .iter()
        .filter(|l| l.contains("link=4"))
        .count();
    assert!(
        late >= 20,
        "{late} pulses in the last minute: {:?}",
        &log[before_last_minute..]
    );
    assert!(consumed > 0, "no sound was played: {log:#?}");
    let unfed = m.soc.watchdog_longest * 1000 / nabemu::soc::CLOCK_HZ;
    assert!(unfed <= 1045, "watchdog unfed {unfed} ms");
    assert!(m.stack_low[0x1F] >= 0x1000_4000 - 0x400 - 12 * 1024);
}
