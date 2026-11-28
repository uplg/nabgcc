//! The released firmware, booted on the emulated board.

mod common;

use common::{PASSPHRASE, terrier, under_test, until_every};
use nabemu::DEFAULT_MAC;

#[test]
fn boots_finds_its_wifi_stick_and_scans() {
    let mut m = under_test();
    m.run_until_ms(8000);

    assert_eq!(m.events, [], "no reset, no undefined instruction");
    assert!(
        m.soc.bus_faults.is_empty(),
        "stray accesses: {:08x?}",
        m.soc.bus_faults
    );
    assert_eq!(m.soc.ohci.errors, 0);
    // Every register it touched exists on the chip, with a known value
    // after reset, and it set the clocks the board is modelled at.
    assert!(
        m.soc.unmodelled.is_empty(),
        "registers without a model: {:08x?}",
        m.soc.unmodelled
    );
    assert_eq!(m.soc.cpu_clock_hz(), Some(32_000_000));

    let console = m.console();
    assert!(
        console.contains(":started"),
        "the boot bytecode ran:\n{console}"
    );
    assert!(
        console.contains("00.19.db.00.00.01."),
        "it read the stick's MAC:\n{console}"
    );

    // The receiver is off for a moment at every change of channel:
    // it has to come back within the next step of the scan.
    until_every(&mut m, 10, 500, "the receiver back on", |m| {
        m.radio.borrow().rx_enabled
    });
    let radio = m.radio.borrow();
    assert!(
        radio.firmware_loaded,
        "the 8051 firmware was uploaded and started"
    );
    assert!(radio.rx_enabled);
    assert_eq!(radio.mac, DEFAULT_MAC);

    // It scans: probe requests from its own address, channel after channel.
    assert!(radio.tx.len() >= 10, "{} frames sent", radio.tx.len());
    let mut channels = std::collections::BTreeSet::new();
    for f in &radio.tx {
        assert_eq!(f.data[0], 0x40, "a probe request");
        assert_eq!(f.data[10..16], DEFAULT_MAC);
        assert_eq!(f.data[1] & 0x40, 0, "not encrypted");
        channels.insert(f.channel);
    }
    assert!(channels.len() >= 5, "channels visited: {channels:?}");
    assert!(channels.iter().all(|c| (1..=14).contains(c)));
}

#[test]
fn blank_configuration_is_written_to_the_last_flash_sector() {
    let mut m = under_test();
    assert!(m.soc.flash[0x1F000..].iter().all(|&b| b == 0xFF));
    m.run_until_ms(1000);
    assert_eq!(m.soc.flash_erases, 1);
    assert!(m.soc.flash_programs > 0);
    // The default server URL is the first thing in the configuration.
    assert!(m.soc.flash[0x1F000..].starts_with(b"r.nabaztag.com/vl\0"));
    // Nothing below the configuration sector was touched.
    let fresh = under_test();
    assert_eq!(m.soc.flash[..0x1F000], fresh.soc.flash[..0x1F000]);
}

#[test]
fn runs_are_reproducible() {
    let (mut a, mut b) = (under_test(), under_test());
    a.run_until_ms(1500);
    b.run_until_ms(1500);
    assert_eq!(a.soc.uart_tx, b.soc.uart_tx);
    assert_eq!(a.radio.borrow().tx, b.radio.borrow().tx);
    assert_eq!(a.cpu.r, b.cpu.r);
}

#[test]
fn scan_reports_an_access_point_in_range() {
    let mut m = under_test();
    m.air.push(terrier(nabemu::air::Security::wpa2(PASSPHRASE)));
    m.run_until_ms(12_000);

    assert_eq!(m.events, []);
    let console = m.console();
    let report = console
        .split("## SCAN Terrier")
        .nth(1)
        .expect("the scan listed the network");
    assert!(report.contains("bssid:02.00.00.00.00.a1."), "{report}");
    assert!(report.contains("channel:6"), "{report}");
    // 0x4A: IEEE80211_CRYPT_WPA2 with CCMP as group and pairwise cipher.
    assert!(report.contains("encryption:74"), "{report}");
}
