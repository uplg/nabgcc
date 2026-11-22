//! WPA3 between the emulated access point and the reference station:
//! the password exchange, the handshake that follows, protected
//! management frames. No rabbit here: r3 has no WPA3; this is the
//! behaviour its successor has to reach.

use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
use nabemu::rt2573::{Radio, RxFrame, TxFrame};
use nabemu::supplicant::{Method, Notice, State, Supplicant};

const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 0xA1];
const STA: [u8; 6] = [0x02, 0, 0, 0, 0, 0xC3];
const PASSWORD: &str = "carotte-violette";

struct World {
    radio: Radio,
    ap: AccessPoint,
    sta: Supplicant,
    now: u64,
}

impl World {
    fn new(wpa3: Wpa3, password: &str) -> World {
        let mut ap = AccessPoint::new("Terrier", BSSID, 6, Security::wpa2(PASSWORD));
        ap.wpa3 = wpa3;
        let radio = Radio {
            channel: 6,
            ..Radio::default()
        };
        World {
            radio,
            ap,
            sta: Supplicant::new(STA, "Terrier", password),
            now: 0,
        }
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.now += 1;
            self.ap.poll(&mut self.radio, self.now);
            // Beacons are not for the station's state machine.
            self.radio.rx.retain(|f| f.data[0] != 0x80);
            self.sta.poll(&mut self.radio);
        }
    }

    fn join(&mut self) {
        self.sta.connect(&mut self.radio, BSSID, 6);
        self.run(50);
    }
}

fn ethernet(dst: [u8; 6], src: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(payload);
    f
}

fn joins_and_talks(wpa3: Wpa3, method: Method) {
    let mut w = World::new(wpa3, PASSWORD);
    w.sta.method = method;
    w.join();
    assert_eq!(w.sta.state, State::Connected, "{:?}", w.ap.events);
    assert!(w.ap.is_authorized(STA));
    let hash_to_element = method == Method::HashToElement;
    assert!(w.ap.events.contains(&ApEvent::SaeComplete {
        sta: STA,
        hash_to_element
    }));
    assert!(
        w.ap.events
            .contains(&ApEvent::HandshakeComplete { sta: STA })
    );
    assert!(w.sta.has_integrity_group_key());

    // Traffic both ways, to the station alone and to everyone.
    let up = ethernet([2, 0, 0, 0, 0, 1], STA, b"bonjour");
    w.sta.send(&mut w.radio, &up);
    w.ap.send(&mut w.radio, &ethernet(STA, [2, 0, 0, 0, 0, 1], b"salut"));
    w.ap.send(
        &mut w.radio,
        &ethernet([0xFF; 6], [2, 0, 0, 0, 0, 1], b"a tous"),
    );
    w.run(5);
    assert_eq!(w.ap.uplink.pop_front(), Some(up));
    assert_eq!(w.sta.received.len(), 2);
    assert!(w.sta.received[0].ends_with(b"salut"));
    assert!(w.sta.received[1].ends_with(b"a tous"));
    assert_eq!(w.sta.notices, []);
    // Nothing readable went over the air.
    assert!(
        !w.radio
            .tx
            .iter()
            .any(|f| f.data.windows(7).any(|x| x == b"bonjour"))
    );
}

#[test]
fn joins_a_wpa3_network_by_hashing_to_the_curve() {
    joins_and_talks(Wpa3::Only, Method::HashToElement);
}

#[test]
fn joins_a_wpa3_network_by_hunting_and_pecking() {
    joins_and_talks(Wpa3::Only, Method::HuntingAndPecking);
}

#[test]
fn joins_a_transition_network_as_a_wpa3_station() {
    joins_and_talks(Wpa3::Transition, Method::HashToElement);
}

#[test]
fn a_network_can_insist_on_hashing_to_the_curve() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.ap.require_h2e = true;
    w.sta.method = Method::HuntingAndPecking;
    w.join();
    assert_eq!(
        w.sta.state,
        State::Failed("the access point refused the commit")
    );
    assert!(!w.ap.is_authorized(STA));
}

#[test]
fn a_wrong_password_gets_no_further_than_the_confirm() {
    let mut w = World::new(Wpa3::Only, "pas-la-bonne");
    w.join();
    assert_eq!(
        w.sta.state,
        State::Confirmed,
        "left waiting: the access point says nothing"
    );
    assert!(w.ap.events.contains(&ApEvent::SaeRejected {
        sta: STA,
        why: "confirm does not match"
    }));
    assert!(
        !w.ap
            .events
            .iter()
            .any(|e| matches!(e, ApEvent::SaeComplete { .. } | ApEvent::Associated { .. }))
    );
}

#[test]
fn a_network_without_wpa3_refuses_the_exchange() {
    let mut w = World::new(Wpa3::Off, PASSWORD);
    w.join();
    assert_eq!(
        w.sta.state,
        State::Failed("the access point refused the commit")
    );
    assert!(w.ap.events.contains(&ApEvent::AuthRejected {
        sta: STA,
        status: 13
    }));
}

#[test]
fn a_station_that_will_not_protect_management_frames_is_refused() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.sta.protect_management = false;
    w.join();
    assert_eq!(
        w.sta.state,
        State::Failed("refused: management frame protection policy")
    );
    assert!(w.ap.events.contains(&ApEvent::AssocRejected {
        sta: STA,
        status: 31
    }));
}

#[test]
fn skipping_the_password_exchange_does_not_get_in() {
    // Open authentication, then an association claiming WPA3 keys.
    let mut w = World::new(Wpa3::Transition, PASSWORD);
    let mut auth = vec![0xB0, 0, 0, 0];
    auth.extend_from_slice(&BSSID);
    auth.extend_from_slice(&STA);
    auth.extend_from_slice(&BSSID);
    auth.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
    w.radio.tx.push_back(TxFrame {
        data: auth,
        channel: 6,
    });
    let mut assoc = vec![0x00, 0, 0, 0];
    assoc.extend_from_slice(&BSSID);
    assoc.extend_from_slice(&STA);
    assoc.extend_from_slice(&BSSID);
    assoc.extend_from_slice(&[0x10, 0, 0x31, 0x04, 10, 0, 0, 7]);
    assoc.extend_from_slice(b"Terrier");
    assoc.extend_from_slice(&[
        48, 20, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 8, 0xC0, 0,
    ]);
    w.radio.tx.push_back(TxFrame {
        data: assoc,
        channel: 6,
    });
    w.run(10);
    assert!(
        w.ap.events.contains(&ApEvent::AssocRejected {
            sta: STA,
            status: 43
        }),
        "{:?}",
        w.ap.events
    );
}

#[test]
fn forged_deauthentications_are_ignored_by_both_ends() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    assert!(w.sta.is_connected());

    // Somebody else pretends to be the access point...
    let mut forged = vec![0xC0, 0, 0, 0];
    forged.extend_from_slice(&STA);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&[0, 0, 7, 0]);
    w.radio.rx.push_back(RxFrame::new(forged));
    // ...and to be the station.
    let mut forged = vec![0xC0, 0, 0, 0];
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&STA);
    forged.extend_from_slice(&BSSID);
    forged.extend_from_slice(&[0, 0, 3, 0]);
    w.radio.tx.push_back(TxFrame {
        data: forged,
        channel: 6,
    });
    w.run(5);

    assert!(w.sta.is_connected());
    assert_eq!(w.sta.notices, [Notice::ForgedDeauthIgnored]);
    assert!(w.ap.is_authorized(STA));
    assert!(
        w.ap.events
            .contains(&ApEvent::UnprotectedDeauthIgnored { sta: STA })
    );
}

#[test]
fn genuine_deauthentications_get_through_in_both_directions() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    w.ap.kick(&mut w.radio, STA, 2);
    w.run(5);
    assert_eq!(w.sta.state, State::Idle);
    assert_eq!(w.sta.notices, [Notice::Deauthenticated { reason: 2 }]);

    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    w.sta.disconnect(&mut w.radio);
    w.run(5);
    assert!(!w.ap.is_authorized(STA));
    assert!(w.ap.events.contains(&ApEvent::Deauthenticated {
        sta: STA,
        reason: 3,
        by_ap: false
    }));
}

#[test]
fn group_key_renewals_reach_a_wpa3_station() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    for round in 1..=3 {
        w.ap.rekey_group(&mut w.radio);
        w.run(10);
        assert_eq!(w.sta.notices.len(), round, "{:?}", w.ap.events);
        w.ap.send(
            &mut w.radio,
            &ethernet([0xFF; 6], [2, 0, 0, 0, 0, 1], b"encore"),
        );
        w.run(5);
        assert_eq!(w.sta.received.len(), round);
    }
    assert!(
        w.sta
            .notices
            .iter()
            .all(|n| matches!(n, Notice::GroupKeyRenewed { .. }))
    );
}

#[test]
fn replayed_frames_are_dropped() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    w.ap.send(
        &mut w.radio,
        &ethernet(STA, [2, 0, 0, 0, 0, 1], b"une fois"),
    );
    let recorded = w.radio.rx.back().unwrap().clone();
    w.run(5);
    w.radio.rx.push_back(recorded);
    w.run(5);
    assert_eq!(w.sta.received.len(), 1);
    assert_eq!(w.sta.notices, [Notice::Dropped]);

    w.sta.send(
        &mut w.radio,
        &ethernet([2, 0, 0, 0, 0, 1], STA, b"une fois"),
    );
    let recorded = w.radio.tx.back().unwrap().clone();
    w.run(5);
    w.radio.tx.push_back(recorded);
    w.run(5);
    assert_eq!(w.ap.uplink.len(), 1);
    assert!(w.ap.events.contains(&ApEvent::Replay { sta: STA }));
}
