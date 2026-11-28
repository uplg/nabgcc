//! Life of an established link: group key renewal, being thrown out,
//! the access point going away.

mod common;

use common::bc::{self, Global, op::GETGLOBALB};
use common::{
    ap_count, arp_replies, arp_request, authorized, handshakes, on_network, terrier, until_every,
    wait, wpa, wpa2,
};
use nabemu::air::{ApEvent, Security};
use nabemu::config::Wifi;
use nabemu::lan::Lan;
use nabemu::{DEFAULT_MAC, Machine, metal};

/// A rabbit that joined, got its address, and keeps running the boot
/// bytecode (the server has no bytecode for it), so its IP stack is up.
fn connected(network: (Wifi, Security)) -> Machine {
    let mut m = on_network(&nabemu::testing::image(), network);
    m.lan = Some(Lan::new());
    until_every(&mut m, 50, 30_000, "a DHCP lease", |m| {
        m.lan.as_ref().unwrap().leased_to.is_some()
    });
    wait(&mut m, 500);
    m
}

/// Send the rabbit an ARP request to `to` and say whether it answered.
fn answers_arp(m: &mut Machine, to: [u8; 6]) -> bool {
    // Take the wired side away so the answer stays on the uplink.
    let lan = m.lan.take();
    m.air[0].uplink.clear();
    m.air[0].send(&mut m.radio.borrow_mut(), &arp_request(to));
    wait(m, 500);
    let answered = arp_replies(m) > 0;
    m.lan = lan;
    answered
}

/// Broadcast an ARP request for the rabbit's address and say whether it
/// answered: proof that group-addressed frames still get through.
fn hears_broadcasts(m: &mut Machine) -> bool {
    answers_arp(m, [0xFF; 6])
}

/// An ARP request sent to the rabbit alone: whether it answered, both
/// directions then going under the pairwise key.
fn hears_unicast(m: &mut Machine) -> bool {
    answers_arp(m, DEFAULT_MAC)
}

#[test]
fn answers_arp_once_connected() {
    let mut m = connected(common::open());
    assert!(hears_broadcasts(&mut m));
}

/// Three key renewals on a link of `network` that `hears` first:
/// `renew` makes renewal `round` and checks it, or says the link is
/// given up (false); broadcasts are heard after each, and nothing
/// failed to decrypt.
fn survives_renewals(
    network: (Wifi, Security),
    hears: fn(&mut Machine) -> bool,
    renew: impl Fn(&mut Machine, usize) -> bool,
) {
    let mut m = connected(network);
    assert!(hears(&mut m));
    for round in 1..=3 {
        if !renew(&mut m, round) {
            return;
        }
        assert!(
            hears_broadcasts(&mut m),
            "deaf to broadcasts after renewal {round}"
        );
    }
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    assert!(authorized(&m));
}

/// The access point renews the group key three times: each renewal
/// acknowledged, broadcasts heard after each. `joined` is how many
/// group keys the join itself installed.
fn survives_group_key_renewals(network: (Wifi, Security), joined: usize) {
    survives_renewals(network, hears_broadcasts, |m, round| {
        m.air[0].rekey_group(&mut m.radio.borrow_mut());
        wait(m, 1000);
        assert_eq!(
            ap_count(m, &ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC }),
            joined + round,
            "renewal {round} acknowledged: {:?}",
            m.air[0].events
        );
        true
    });
}

#[test]
fn survives_wpa2_group_key_renewals() {
    survives_group_key_renewals(wpa2(), 0);
}

#[test]
fn survives_wpa_tkip_group_key_renewals() {
    // The join itself already installed one group key.
    survives_group_key_renewals(wpa(), 1);
}

#[test]
fn comes_back_after_being_thrown_out() {
    let mut m = connected(wpa2());
    // Reason 2: previous authentication no longer valid.
    m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 2);
    assert!(!authorized(&m));
    until_every(&mut m, 50, 60_000, "back", |m| handshakes(m) >= 2);
    wait(&mut m, 6000);
    assert!(hears_broadcasts(&mut m));
}

#[test]
fn comes_back_after_the_access_point_restarts() {
    let mut m = connected(wpa2());
    // The access point loses power: no beacons, no memory of anyone.
    m.air.clear();
    wait(&mut m, 20_000);
    m.air.push(terrier(wpa2().1));
    until_every(&mut m, 50, 300_000, "back", authorized);
}

/// The access point renews the pairwise key on a running link
/// (hostapd's `wpa_ptk_rekey`): message 1 under the current key, the
/// new key from message 4 on.
fn survives_pairwise_key_renewals(network: (Wifi, Security)) {
    survives_renewals(network, hears_unicast, |m, round| {
        m.air[0].rekey_pairwise(&mut m.radio.borrow_mut(), DEFAULT_MAC);
        wait(m, 1000);
        let renewed = ap_count(m, &ApEvent::PairwiseKeyRenewed { sta: DEFAULT_MAC });
        if !nabemu::testing::is_lapin() {
            // Known defect of r3: message 1 on a running link is
            // ignored (`eapol_input_msg1` only takes it during the
            // handshake), so the access point gives up on the rabbit.
            assert_eq!(renewed, 0, "{:?}", m.air[0].events);
            return false;
        }
        assert_eq!(renewed, round, "renewal {round}: {:?}", m.air[0].events);
        assert!(hears_unicast(m), "deaf after renewal {round}");
        true
    });
}

#[test]
fn survives_wpa2_pairwise_key_renewals() {
    survives_pairwise_key_renewals(wpa2());
}

#[test]
fn survives_wpa_tkip_pairwise_key_renewals() {
    survives_pairwise_key_renewals(wpa());
}

/// The access point switched off, the rabbit sending nothing: lapin
/// notices its beacons are gone, asks it (probe requests), and gives
/// the link up after about two and a half seconds; its program, which
/// joins again whenever the link is idle, starts looking for it. Known
/// defect: r3 stays "connected" to a vanished access point for two
/// minutes (its timeout, refreshed by beacons), unless it sends.
#[test]
fn notices_the_access_point_switched_off() {
    let key = nabemu::crypto::wpa_psk(common::PASSPHRASE, common::SSID);
    let globals = [
        Global::Word(u32::MAX),
        Global::Str(&key),
        Global::Str(common::SSID.as_bytes()),
        Global::Str(&common::BSSID),
    ];
    let mut main = bc::main_with_home_network(0, 2, 3);
    main.extend(bc::loop_callback(1));
    let rejoin = bc::rejoin(0, &[GETGLOBALB, 1]);
    let program = bc::assemble(&globals, &[&main, &rejoin]);
    let mut m = on_network(&nabemu::testing::image(), wpa2());
    common::serve(&mut m, metal::boot_response(&program));
    until_every(&mut m, 50, 60_000, "on the network", authorized);
    wait(&mut m, 2000);
    m.air.clear();
    m.radio.borrow_mut().tx.clear();
    let sent = |m: &Machine, kind: u8| m.radio.borrow().tx.iter().any(|f| f.data[0] == kind);
    let off = m.soc.millis();
    let looking = |m: &Machine| sent(m, 0xB0);
    if nabemu::testing::is_lapin() {
        let at = until_every(&mut m, 10, 5000, "joining again", looking);
        eprintln!("noticed after {} ms", at - off);
        assert!(sent(&m, 0x40), "the access point asked first");
    } else {
        wait(&mut m, 20_000);
        assert!(!looking(&m), "Known defect: r3 never noticed");
    }
}
