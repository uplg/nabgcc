//! Life of an established link: group key renewal, being thrown out,
//! the access point going away.

use nabemu::air::{AccessPoint, ApEvent, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{GATEWAY_IP, GATEWAY_MAC, LEASE_IP, Lan};
use nabemu::{DEFAULT_MAC, Machine};

const PASS: &str = "carotte-violette";

/// A rabbit that joined, got its address, and keeps running the boot
/// bytecode (the server has no bytecode for it), so its IP stack is up.
fn connected(wifi: Wifi, security: Security) -> Machine {
    let image = nabemu::testing::image();
    let mut m = Machine::from_file(&image).0;
    Config::new("Terrier", wifi).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        security,
    ));
    m.lan = Some(Lan::new());
    while m.lan.as_ref().unwrap().leased_to.is_none() {
        assert!(
            m.soc.millis() < 30_000,
            "no DHCP lease: {:?}\n{}",
            m.air[0].events,
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 50);
    }
    m.run_until_ms(m.soc.millis() + 500);
    m
}

fn arp_request() -> Vec<u8> {
    let mut f = vec![0xFF; 6];
    f.extend_from_slice(&GATEWAY_MAC);
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    f.extend_from_slice(&GATEWAY_MAC);
    f.extend_from_slice(&GATEWAY_IP);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&LEASE_IP);
    f
}

/// Broadcast an ARP request for the rabbit's address and say whether it
/// answered: proof that group-addressed frames still get through.
fn hears_broadcasts(m: &mut Machine) -> bool {
    // Take the wired side away so the answer stays on the uplink.
    let lan = m.lan.take();
    m.air[0].uplink.clear();
    m.air[0].send(&mut m.radio.borrow_mut(), &arp_request());
    m.run_until_ms(m.soc.millis() + 500);
    let answered = m.air[0]
        .uplink
        .iter()
        .any(|f| f[12..14] == [0x08, 0x06] && f[20..22] == [0, 2]);
    m.lan = lan;
    answered
}

fn count(m: &Machine, wanted: &ApEvent) -> usize {
    m.air[0].events.iter().filter(|e| *e == wanted).count()
}

#[test]
fn answers_arp_once_connected() {
    let mut m = connected(Wifi::Open, Security::Open);
    assert!(hears_broadcasts(&mut m));
}

#[test]
fn survives_wpa2_group_key_renewals() {
    let mut m = connected(
        Wifi::Wpa2 {
            passphrase: PASS.into(),
        },
        Security::wpa2(PASS),
    );
    assert!(hears_broadcasts(&mut m));
    for round in 1..=3 {
        m.air[0].rekey_group(&mut m.radio.borrow_mut());
        m.run_until_ms(m.soc.millis() + 1000);
        assert_eq!(
            count(&m, &ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC }),
            round,
            "renewal {round} acknowledged: {:?}",
            m.air[0].events
        );
        assert!(
            hears_broadcasts(&mut m),
            "deaf to broadcasts after renewal {round}"
        );
    }
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    assert!(m.air[0].is_authorized(DEFAULT_MAC));
}

#[test]
fn survives_wpa_tkip_group_key_renewals() {
    let mut m = connected(
        Wifi::Wpa {
            passphrase: PASS.into(),
        },
        Security::wpa(PASS),
    );
    assert!(hears_broadcasts(&mut m));
    for round in 1..=3 {
        m.air[0].rekey_group(&mut m.radio.borrow_mut());
        m.run_until_ms(m.soc.millis() + 1000);
        // The join itself already installed one group key.
        assert_eq!(
            count(&m, &ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC }),
            round + 1
        );
        assert!(
            hears_broadcasts(&mut m),
            "deaf to broadcasts after renewal {round}"
        );
    }
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}

#[test]
fn comes_back_after_being_thrown_out() {
    let mut m = connected(
        Wifi::Wpa2 {
            passphrase: PASS.into(),
        },
        Security::wpa2(PASS),
    );
    // Reason 2: previous authentication no longer valid.
    m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 2);
    assert!(!m.air[0].is_authorized(DEFAULT_MAC));
    let deadline = m.soc.millis() + 60_000;
    while count(&m, &ApEvent::HandshakeComplete { sta: DEFAULT_MAC }) < 2 {
        assert!(
            m.soc.millis() < deadline,
            "never came back: {:?}\n{}",
            m.air[0].events,
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 50);
    }
    m.run_until_ms(m.soc.millis() + 6000);
    assert!(hears_broadcasts(&mut m));
}

#[test]
fn comes_back_after_the_access_point_restarts() {
    let mut m = connected(
        Wifi::Wpa2 {
            passphrase: PASS.into(),
        },
        Security::wpa2(PASS),
    );
    // The access point loses power: no beacons, no memory of anyone.
    m.air.clear();
    m.run_until_ms(m.soc.millis() + 20_000);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2(PASS),
    ));
    let deadline = m.soc.millis() + 300_000;
    while !m.air[0].is_authorized(DEFAULT_MAC) {
        assert!(
            m.soc.millis() < deadline,
            "never came back: {:?}\n{}",
            m.air[0].events,
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 50);
    }
}

/// An ARP request sent to the rabbit alone: whether it answered, both
/// directions then going under the pairwise key.
fn hears_unicast(m: &mut Machine) -> bool {
    let lan = m.lan.take();
    m.air[0].uplink.clear();
    let mut request = arp_request();
    request[..6].copy_from_slice(&DEFAULT_MAC);
    m.air[0].send(&mut m.radio.borrow_mut(), &request);
    m.run_until_ms(m.soc.millis() + 500);
    let answered = m.air[0]
        .uplink
        .iter()
        .any(|f| f[12..14] == [0x08, 0x06] && f[20..22] == [0, 2]);
    m.lan = lan;
    answered
}

/// The access point renews the pairwise key on a running link
/// (hostapd's `wpa_ptk_rekey`): message 1 under the current key, the
/// new key from message 4 on.
fn survives_pairwise_key_renewals(wifi: Wifi, security: Security) {
    let mut m = connected(wifi, security);
    assert!(hears_unicast(&mut m));
    for round in 1..=3 {
        m.air[0].rekey_pairwise(&mut m.radio.borrow_mut(), DEFAULT_MAC);
        m.run_until_ms(m.soc.millis() + 1000);
        let renewed = count(&m, &ApEvent::PairwiseKeyRenewed { sta: DEFAULT_MAC });
        if !nabemu::testing::is_lapin() {
            // Known defect of r3: message 1 on a running link is
            // ignored (`eapol_input_msg1` only takes it during the
            // handshake), so the access point gives up on the rabbit.
            assert_eq!(renewed, 0, "{:?}", m.air[0].events);
            return;
        }
        assert_eq!(renewed, round, "renewal {round}: {:?}", m.air[0].events);
        assert!(hears_unicast(&mut m), "deaf after renewal {round}");
        assert!(
            hears_broadcasts(&mut m),
            "deaf to broadcasts after renewal {round}"
        );
    }
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    assert!(m.air[0].is_authorized(DEFAULT_MAC));
}

#[test]
fn survives_wpa2_pairwise_key_renewals() {
    survives_pairwise_key_renewals(
        Wifi::Wpa2 {
            passphrase: PASS.into(),
        },
        Security::wpa2(PASS),
    );
}

#[test]
fn survives_wpa_tkip_pairwise_key_renewals() {
    survives_pairwise_key_renewals(
        Wifi::Wpa {
            passphrase: PASS.into(),
        },
        Security::wpa(PASS),
    );
}
