//! Garenne, the rabbit's real application bytecode, on the emulated
//! rabbit. Garenne lives in another repository: the test runs when its
//! build is found (`NABEMU_GARENNE`, or `../clapier` beside this
//! repository) and is skipped otherwise.

use nabemu::Machine;
use nabemu::air::{AccessPoint, Security};
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

#[test]
fn garenne_wakes_up_and_reports_every_two_seconds() {
    let Some(bytecode) = garenne() else {
        eprintln!("skipped: no garenne build around");
        return;
    };
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../artifacts/Nab-wpa23-gtk-r3.sim"
    );
    let mut m = Machine::from_file(&std::fs::read(path).unwrap()).0;
    Config::new(
        "Terrier",
        Wifi::Wpa2 {
            passphrase: "carotte-violette".into(),
        },
    )
    .install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2("carotte-violette"),
    ));
    let mut lan = Lan::new();
    lan.handler = Box::new(move |_| Response::ok(bytecode.clone()));
    m.lan = Some(lan);
    m.run_until_ms(45_000);

    assert_eq!(m.events, [], "no reset");
    let lan = m.lan.as_ref().unwrap();
    // Garenne broadcasts its log lines on UDP port 9999.
    let log: Vec<String> = lan
        .datagrams
        .iter()
        .filter(|d| d.to_port == 9999)
        .map(|d| String::from_utf8_lossy(&d.payload).into_owned())
        .collect();
    assert!(
        log.iter()
            .any(|l| l.contains("awake") && l.contains("ip=192.168.1.100")),
        "{log:#?}"
    );
    let pulses = log
        .iter()
        .filter(|l| l.contains("link=4") && l.contains("mac=0019db000001"))
        .count();
    assert!(pulses >= 5, "{pulses} pulses: {log:#?}");
}
