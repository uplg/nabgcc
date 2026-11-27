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
