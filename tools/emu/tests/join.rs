//! The released firmware joining access points of every kind.

mod common;

use common::{
    PASSPHRASE, ap_saw, authorized, handshakes, ip_on_the_wire, on_network, until, wait, wep, wpa,
    wpa2,
};
use nabemu::air::{ApEvent, Security, Wpa3};
use nabemu::config::Wifi;
use nabemu::{DEFAULT_MAC, Machine};

fn rabbit(network: (Wifi, Security)) -> Machine {
    on_network(&nabemu::testing::image(), network)
}

/// Run until the access point has reported `wanted`, or fail showing
/// what happened instead.
fn run_until_event(m: &mut Machine, wanted: &ApEvent, limit_ms: u64) {
    until(m, limit_ms, &format!("{wanted:?}"), |m| ap_saw(m, wanted));
}

#[test]
fn joins_an_open_network() {
    let mut m = rabbit(common::open());
    run_until_event(&mut m, &ApEvent::Associated { sta: DEFAULT_MAC }, 15_000);
    assert!(authorized(&m));
    wait(&mut m, 500);
    assert!(m.console().contains("-------------dhcp"), "{}", m.console());
}

/// Everything the access point saw, minus what a clean join produces.
fn trouble(m: &Machine) -> Vec<&ApEvent> {
    m.air[0]
        .events
        .iter()
        .filter(|e| {
            !matches!(
                e,
                ApEvent::Authenticated { .. }
                    | ApEvent::Associated { .. }
                    | ApEvent::HandshakeComplete { .. }
                    | ApEvent::GroupKeyInstalled { .. }
                    | ApEvent::SaeComplete { .. }
            )
        })
        .collect()
}

/// r3 numbers its first CCMP frame 0, where the standard starts at 1:
/// an access point that follows the standard drops that frame as a
/// replay. Known defect of r3; lapin starts at 1.
fn first_frame_replay() -> Vec<ApEvent> {
    if nabemu::testing::is_lapin() {
        vec![]
    } else {
        vec![ApEvent::Replay { sta: DEFAULT_MAC }]
    }
}

fn join(network: (Wifi, Security)) -> Machine {
    let psk = matches!(network.1, Security::Psk { .. });
    let mut m = rabbit(network);
    let done = if psk {
        ApEvent::HandshakeComplete { sta: DEFAULT_MAC }
    } else {
        ApEvent::Associated { sta: DEFAULT_MAC }
    };
    run_until_event(&mut m, &done, 15_000);
    // Its DHCP request must reach the wire: encryption works both ways.
    until(&mut m, 8000, "an IP frame through", ip_on_the_wire);
    assert!(authorized(&m), "{:?}", m.air[0].events);
    assert!(m.console().contains("-------------dhcp"), "{}", m.console());
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    m
}

#[test]
fn joins_a_wpa2_network() {
    let m = join(wpa2());
    assert_eq!(trouble(&m), first_frame_replay().iter().collect::<Vec<_>>());
}

#[test]
fn joins_a_wpa_tkip_network() {
    let m = join(wpa());
    assert!(ap_saw(&m, &ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC }));
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

/// WPA2 settings, and an access point whose group cipher is TKIP.
fn mixed_mode() -> (Wifi, Security) {
    (wpa2().0, Security::wpa2_tkip_group(PASSPHRASE))
}

/// Known defect of r3: on a network whose group cipher is TKIP and
/// pairwise cipher CCMP ("mixed mode"), message 2 of the handshake names
/// CCMP for both, while the association request said TKIP and CCMP. An
/// access point that compares the two, as hostapd does, throws it out.
/// lapin names the same ciphers in both, and gets in.
#[test]
fn mixed_mode_is_refused_because_message_2_misnames_the_group_cipher() {
    if nabemu::testing::is_lapin() {
        let m = join(mixed_mode());
        assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
        return;
    }
    let mut m = rabbit(mixed_mode());
    let thrown_out = ApEvent::Deauthenticated {
        sta: DEFAULT_MAC,
        reason: 17,
        by_ap: true,
    };
    run_until_event(&mut m, &thrown_out, 15_000);
    assert!(
        !ap_saw(&m, &ApEvent::EapolMicFailure { sta: DEFAULT_MAC }),
        "the keys were right"
    );
    assert_eq!(handshakes(&m), 0);
}

#[test]
fn joins_a_wep_network_with_open_authentication() {
    let m = join(wep("abcde", false));
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

/// Known defect of r3: `rt2501_auth` picks the WEP key size from
/// `strlen((char*)&key)`, the length of the pointer's own bytes, so a
/// 13-character key is installed as its first 5 characters. The rabbit
/// cannot talk to a 104-bit WEP network, and does talk to a 40-bit one
/// keyed with the first five characters. lapin keeps the whole key.
#[test]
fn a_104_bit_wep_key_is_cut_down_to_40_bits() {
    let (typed, real) = wep("thirteenchars", false);
    if nabemu::testing::is_lapin() {
        let m = join((typed, real));
        assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
        return;
    }

    let mut m = rabbit((typed.clone(), real));
    let garbled = ApEvent::DecryptFailure {
        sta: DEFAULT_MAC,
        error: nabemu::crypto::CipherError::Icv,
    };
    run_until_event(&mut m, &garbled, 15_000);
    assert!(m.air[0].uplink.is_empty());

    let m = join((typed, wep("thirt", false).1));
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

#[test]
fn joins_a_wep_network_with_shared_key_authentication() {
    let m = join(wep("abcde", true));
    assert!(ap_saw(
        &m,
        &ApEvent::Authenticated {
            sta: DEFAULT_MAC,
            shared_key: true
        }
    ));
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

#[test]
fn a_wrong_passphrase_never_gets_in() {
    let wrong = Wifi::Wpa2 {
        passphrase: "pas-la-bonne".into(),
    };
    let mut m = rabbit((wrong, Security::wpa2(PASSPHRASE)));
    run_until_event(
        &mut m,
        &ApEvent::EapolMicFailure { sta: DEFAULT_MAC },
        15_000,
    );
    wait(&mut m, 10_000);
    assert!(!authorized(&m));
    assert_eq!(handshakes(&m), 0);
    assert!(m.air[0].uplink.is_empty());
    assert!(!m.console().contains("-------------dhcp"));
}

/// A rabbit set up for WPA2 at an access point that offers WPA3:
/// in within `limit_ms`, and its DHCP request through.
fn joins_offering_wpa3(wpa3: Wpa3, limit_ms: u64) -> Machine {
    let mut m = rabbit(wpa2());
    m.air[0].wpa3 = wpa3;
    run_until_event(
        &mut m,
        &ApEvent::HandshakeComplete { sta: DEFAULT_MAC },
        limit_ms,
    );
    wait(&mut m, 6000);
    assert!(authorized(&m));
    assert!(ip_on_the_wire(&m), "its DHCP request came through");
    m
}

/// The kind of network most home routers offer today: WPA2 and WPA3
/// side by side. r3 gets in as a WPA2 station, lapin with WPA3.
#[test]
fn joins_a_wpa2_wpa3_transition_network_as_a_wpa2_station() {
    let m = joins_offering_wpa3(Wpa3::Transition, 15_000);
    assert_eq!(trouble(&m), first_frame_replay().iter().collect::<Vec<_>>());
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}

/// r3 has no WPA3: a network that offers nothing else turns it away.
/// lapin joins it.
#[test]
fn a_wpa3_only_network_turns_it_away() {
    if nabemu::testing::is_lapin() {
        let m = joins_offering_wpa3(Wpa3::Only, 20_000);
        assert!(m.console().contains("-------------dhcp"));
        assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
        return;
    }
    let mut m = rabbit(wpa2());
    m.air[0].wpa3 = Wpa3::Only;
    m.run_until_ms(20_000);
    assert!(!authorized(&m));
    assert_eq!(handshakes(&m), 0);
    assert!(m.air[0].uplink.is_empty());
}
