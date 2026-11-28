//! Life of an established link: group key renewal, being thrown out,
//! the access point going away.

mod common;

use common::{ap_count, authorized, handshakes, on_network, terrier, until_every, wait, wpa, wpa2};
use nabemu::air::{ApEvent, Security};
use nabemu::config::Wifi;
use nabemu::lan::{GATEWAY_IP, GATEWAY_MAC, LEASE_IP, Lan};
use nabemu::{DEFAULT_MAC, Machine};

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

/// An ARP request from the gateway for the rabbit's address, sent to
/// `to`.
fn arp_request(to: [u8; 6]) -> Vec<u8> {
    let mut f = to.to_vec();
    f.extend_from_slice(&GATEWAY_MAC);
    f.extend_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    f.extend_from_slice(&GATEWAY_MAC);
    f.extend_from_slice(&GATEWAY_IP);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&LEASE_IP);
    f
}

/// Send the rabbit an ARP request to `to` and say whether it answered.
fn answers_arp(m: &mut Machine, to: [u8; 6]) -> bool {
    // Take the wired side away so the answer stays on the uplink.
    let lan = m.lan.take();
    m.air[0].uplink.clear();
    m.air[0].send(&mut m.radio.borrow_mut(), &arp_request(to));
    wait(m, 500);
    let answered = m.air[0]
        .uplink
        .iter()
        .any(|f| f[12..14] == [0x08, 0x06] && f[20..22] == [0, 2]);
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

/// The access point renews the group key three times: each renewal
/// acknowledged, broadcasts heard after each. `joined` is how many
/// group keys the join itself installed.
fn survives_group_key_renewals(network: (Wifi, Security), joined: usize) {
    let mut m = connected(network);
    assert!(hears_broadcasts(&mut m));
    for round in 1..=3 {
        m.air[0].rekey_group(&mut m.radio.borrow_mut());
        wait(&mut m, 1000);
        assert_eq!(
            ap_count(&m, &ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC }),
            joined + round,
            "renewal {round} acknowledged: {:?}",
            m.air[0].events
        );
        assert!(
            hears_broadcasts(&mut m),
            "deaf to broadcasts after renewal {round}"
        );
    }
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    assert!(authorized(&m));
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
    let mut m = connected(network);
    assert!(hears_unicast(&mut m));
    for round in 1..=3 {
        m.air[0].rekey_pairwise(&mut m.radio.borrow_mut(), DEFAULT_MAC);
        wait(&mut m, 1000);
        let renewed = ap_count(&m, &ApEvent::PairwiseKeyRenewed { sta: DEFAULT_MAC });
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
    assert!(authorized(&m));
}

#[test]
fn survives_wpa2_pairwise_key_renewals() {
    survives_pairwise_key_renewals(wpa2());
}

#[test]
fn survives_wpa_tkip_pairwise_key_renewals() {
    survives_pairwise_key_renewals(wpa());
}
