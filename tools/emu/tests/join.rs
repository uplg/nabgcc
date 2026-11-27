//! The released firmware joining access points of every kind.

use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
use nabemu::config::{Config, Wifi};
use nabemu::{DEFAULT_MAC, Machine};

const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 0xA1];

fn rabbit(ssid: &str, wifi: Wifi, security: Security) -> Machine {
    let image = nabemu::testing::image();
    let mut m = Machine::from_file(&image).0;
    Config::new(ssid, wifi).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(ssid, BSSID, 6, security));
    m
}

/// Run until the access point has reported `wanted`, or fail showing
/// what happened instead.
fn run_until_event(m: &mut Machine, wanted: &ApEvent, limit_ms: u64) {
    while m.soc.millis() < limit_ms {
        m.run_until_ms(m.soc.millis() + 20);
        if m.air[0].events.contains(wanted) {
            return;
        }
    }
    panic!(
        "no {wanted:?} within {limit_ms} ms.\nevents: {:#?}\nconsole:\n{}",
        m.air[0].events,
        m.console()
    );
}

#[test]
fn joins_an_open_network() {
    let mut m = rabbit("Terrier", Wifi::Open, Security::Open);
    run_until_event(&mut m, &ApEvent::Associated { sta: DEFAULT_MAC }, 15_000);
    assert!(m.air[0].is_authorized(DEFAULT_MAC));
    m.run_until_ms(m.soc.millis() + 500);
    assert!(m.console().contains("-------------dhcp"), "{}", m.console());
}

const PASSPHRASE: &str = "carotte-violette";

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

fn join(wifi: Wifi, security: Security) -> Machine {
    let psk = matches!(security, Security::Psk { .. });
    let mut m = rabbit("Terrier", wifi, security);
    let done = if psk {
        ApEvent::HandshakeComplete { sta: DEFAULT_MAC }
    } else {
        ApEvent::Associated { sta: DEFAULT_MAC }
    };
    run_until_event(&mut m, &done, 15_000);
    // Its DHCP request must reach the wire: encryption works both ways.
    let deadline = m.soc.millis() + 8000;
    while !m.air[0].uplink.iter().any(|f| f[12..14] == [0x08, 0x00]) {
        assert!(
            m.soc.millis() < deadline,
            "no IP frame came through: {:?}\n{}",
            m.air[0].events,
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 20);
    }
    assert!(m.air[0].is_authorized(DEFAULT_MAC), "{:?}", m.air[0].events);
    assert!(m.console().contains("-------------dhcp"), "{}", m.console());
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    m
}

#[test]
fn joins_a_wpa2_network() {
    let m = join(
        Wifi::Wpa2 {
            passphrase: PASSPHRASE.into(),
        },
        Security::wpa2(PASSPHRASE),
    );
    assert_eq!(trouble(&m), first_frame_replay().iter().collect::<Vec<_>>());
}

#[test]
fn joins_a_wpa_tkip_network() {
    let m = join(
        Wifi::Wpa {
            passphrase: PASSPHRASE.into(),
        },
        Security::wpa(PASSPHRASE),
    );
    assert!(
        m.air[0]
            .events
            .contains(&ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC })
    );
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

/// Known defect of r3: on a network whose group cipher is TKIP and
/// pairwise cipher CCMP ("mixed mode"), message 2 of the handshake names
/// CCMP for both, while the association request said TKIP and CCMP. An
/// access point that compares the two, as hostapd does, throws it out.
/// lapin names the same ciphers in both, and gets in.
#[test]
fn mixed_mode_is_refused_because_message_2_misnames_the_group_cipher() {
    if nabemu::testing::is_lapin() {
        let m = join(
            Wifi::Wpa2 {
                passphrase: PASSPHRASE.into(),
            },
            Security::wpa2_tkip_group(PASSPHRASE),
        );
        assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
        return;
    }
    let mut m = rabbit(
        "Terrier",
        Wifi::Wpa2 {
            passphrase: PASSPHRASE.into(),
        },
        Security::wpa2_tkip_group(PASSPHRASE),
    );
    let thrown_out = ApEvent::Deauthenticated {
        sta: DEFAULT_MAC,
        reason: 17,
        by_ap: true,
    };
    run_until_event(&mut m, &thrown_out, 15_000);
    assert!(
        !m.air[0]
            .events
            .contains(&ApEvent::EapolMicFailure { sta: DEFAULT_MAC }),
        "the keys were right"
    );
    assert!(
        !m.air[0]
            .events
            .contains(&ApEvent::HandshakeComplete { sta: DEFAULT_MAC })
    );
}

#[test]
fn joins_a_wep_network_with_open_authentication() {
    let m = join(
        Wifi::Wep {
            key: "abcde".into(),
            shared_auth: false,
        },
        Security::Wep {
            key: b"abcde".to_vec(),
            shared_auth: false,
        },
    );
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

/// Known defect of r3: `rt2501_auth` picks the WEP key size from
/// `strlen((char*)&key)`, the length of the pointer's own bytes, so a
/// 13-character key is installed as its first 5 characters. The rabbit
/// cannot talk to a 104-bit WEP network, and does talk to a 40-bit one
/// keyed with the first five characters. lapin keeps the whole key.
#[test]
fn a_104_bit_wep_key_is_cut_down_to_40_bits() {
    let typed = Wifi::Wep {
        key: "thirteenchars".into(),
        shared_auth: false,
    };
    if nabemu::testing::is_lapin() {
        let m = join(
            typed,
            Security::Wep {
                key: b"thirteenchars".to_vec(),
                shared_auth: false,
            },
        );
        assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
        return;
    }

    let real = Security::Wep {
        key: b"thirteenchars".to_vec(),
        shared_auth: false,
    };
    let mut m = rabbit("Terrier", typed.clone(), real);
    let garbled = ApEvent::DecryptFailure {
        sta: DEFAULT_MAC,
        error: nabemu::crypto::CipherError::Icv,
    };
    run_until_event(&mut m, &garbled, 15_000);
    assert!(m.air[0].uplink.is_empty());

    let m = join(
        typed,
        Security::Wep {
            key: b"thirt".to_vec(),
            shared_auth: false,
        },
    );
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

#[test]
fn joins_a_wep_network_with_shared_key_authentication() {
    let m = join(
        Wifi::Wep {
            key: "abcde".into(),
            shared_auth: true,
        },
        Security::Wep {
            key: b"abcde".to_vec(),
            shared_auth: true,
        },
    );
    assert!(m.air[0].events.contains(&ApEvent::Authenticated {
        sta: DEFAULT_MAC,
        shared_key: true
    }));
    assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
}

#[test]
fn a_wrong_passphrase_never_gets_in() {
    let mut m = rabbit(
        "Terrier",
        Wifi::Wpa2 {
            passphrase: "pas-la-bonne".into(),
        },
        Security::wpa2(PASSPHRASE),
    );
    run_until_event(
        &mut m,
        &ApEvent::EapolMicFailure { sta: DEFAULT_MAC },
        15_000,
    );
    m.run_until_ms(m.soc.millis() + 10_000);
    assert!(!m.air[0].is_authorized(DEFAULT_MAC));
    assert!(
        !m.air[0]
            .events
            .contains(&ApEvent::HandshakeComplete { sta: DEFAULT_MAC })
    );
    assert!(m.air[0].uplink.is_empty());
    assert!(!m.console().contains("-------------dhcp"));
}

/// The kind of network most home routers offer today: WPA2 and WPA3
/// side by side. r3 gets in as a WPA2 station, lapin with WPA3.
#[test]
fn joins_a_wpa2_wpa3_transition_network_as_a_wpa2_station() {
    let mut m = rabbit(
        "Terrier",
        Wifi::Wpa2 {
            passphrase: PASSPHRASE.into(),
        },
        Security::wpa2(PASSPHRASE),
    );
    m.air[0].wpa3 = Wpa3::Transition;
    run_until_event(
        &mut m,
        &ApEvent::HandshakeComplete { sta: DEFAULT_MAC },
        15_000,
    );
    m.run_until_ms(m.soc.millis() + 6000);
    assert!(m.air[0].is_authorized(DEFAULT_MAC));
    assert!(
        m.air[0].uplink.iter().any(|f| f[12..14] == [0x08, 0x00]),
        "its DHCP request came through"
    );
    assert_eq!(trouble(&m), first_frame_replay().iter().collect::<Vec<_>>());
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}

/// r3 has no WPA3: a network that offers nothing else turns it away.
/// lapin joins it.
#[test]
fn a_wpa3_only_network_turns_it_away() {
    if nabemu::testing::is_lapin() {
        let mut m = rabbit(
            "Terrier",
            Wifi::Wpa2 {
                passphrase: PASSPHRASE.into(),
            },
            Security::wpa2(PASSPHRASE),
        );
        m.air[0].wpa3 = Wpa3::Only;
        run_until_event(
            &mut m,
            &ApEvent::HandshakeComplete { sta: DEFAULT_MAC },
            20_000,
        );
        m.run_until_ms(m.soc.millis() + 6000);
        assert!(m.air[0].is_authorized(DEFAULT_MAC));
        assert!(m.air[0].uplink.iter().any(|f| f[12..14] == [0x08, 0x00]));
        assert!(m.console().contains("-------------dhcp"));
        assert_eq!(trouble(&m), Vec::<&ApEvent>::new());
        return;
    }
    let mut m = rabbit(
        "Terrier",
        Wifi::Wpa2 {
            passphrase: PASSPHRASE.into(),
        },
        Security::wpa2(PASSPHRASE),
    );
    m.air[0].wpa3 = Wpa3::Only;
    m.run_until_ms(20_000);
    assert!(!m.air[0].is_authorized(DEFAULT_MAC));
    assert!(
        !m.air[0]
            .events
            .contains(&ApEvent::HandshakeComplete { sta: DEFAULT_MAC })
    );
    assert!(m.air[0].uplink.is_empty());
}
