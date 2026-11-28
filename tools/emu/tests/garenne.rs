//! Garenne, the rabbit's real application bytecode, on the emulated
//! rabbit. Garenne lives in another repository: the test runs when its
//! build is found (`NABEMU_GARENNE`, or `../clapier` beside this
//! repository) and is skipped otherwise.

mod common;

use common::{garenne, garenne_log, on_network, serve, wpa2};

#[test]
fn garenne_wakes_up_and_reports_every_two_seconds() {
    let Some(bytecode) = garenne() else {
        eprintln!("skipped: no garenne build around");
        return;
    };
    let mut m = on_network(&nabemu::testing::image(), wpa2());
    serve(&mut m, bytecode);
    m.run_until_ms(45_000);

    assert_eq!(m.events, [], "no reset");
    let log = garenne_log(&m);
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
