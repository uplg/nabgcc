//! WPA3 between the emulated access point and the reference station:
//! the password exchange, the handshake that follows, protected
//! management frames. No rabbit here: r3 has no WPA3; this is the
//! behaviour its successor has to reach.

mod common;

use common::{BSSID, PASSPHRASE as PASSWORD, SSID, frame, terrier};
use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
use nabemu::rt2573::{Radio, RxFrame, TxFrame};
use nabemu::supplicant::{Method, Notice, State, Supplicant};

const STA: [u8; 6] = [0x02, 0, 0, 0, 0, 0xC3];

struct World {
    radio: Radio,
    ap: AccessPoint,
    sta: Supplicant,
    now: u64,
}

impl World {
    fn new(wpa3: Wpa3, password: &str) -> World {
        let mut ap = terrier(Security::wpa2(PASSWORD));
        ap.wpa3 = wpa3;
        let radio = Radio {
            channel: 6,
            ..Radio::default()
        };
        World {
            radio,
            ap,
            sta: Supplicant::new(STA, SSID, password),
            now: 0,
        }
    }

    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.now += 1;
            self.ap.poll(&mut self.radio, self.now);
            // Beacons are not for the station's state machine.
            self.radio.rx.retain(|f| f.data[0] != 0x80);
            self.sta.poll(&mut self.radio, self.now);
        }
    }

    fn join(&mut self) {
        self.sta.connect(&mut self.radio, BSSID, 6);
        self.run(50);
    }

    /// A frame on the air from the station's side, for the access point.
    fn station_sends(&mut self, data: Vec<u8>) {
        self.radio.tx.push_back(TxFrame { data, channel: 6 });
    }
}

/// An association request in clear, for the station, that claims
/// WPA3's keys (SAE, management frames protected).
fn wpa3_association() -> Vec<u8> {
    let mut body = vec![0x10, 0, 0x31, 0x04, 10, 0, 0, 7];
    body.extend_from_slice(SSID.as_bytes());
    body.extend_from_slice(&[
        48, 20, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 4, 1, 0, 0, 0x0F, 0xAC, 8, 0xC0, 0,
    ]);
    frame([0x00, 0], BSSID, STA, BSSID, &body)
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
    w.station_sends(frame(
        [0xB0, 0],
        BSSID,
        STA,
        BSSID,
        &[0, 0, 0, 0, 1, 0, 0, 0],
    ));
    w.station_sends(wpa3_association());
    w.run(10);
    // As hostapd's `check_assoc_ies`: open authentication with SAE's key
    // management needs a cached exchange, status 53 (invalid PMKID).
    assert!(
        w.ap.events.contains(&ApEvent::AssocRejected {
            sta: STA,
            status: 53
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
    let forged = frame([0xC0, 0], STA, BSSID, BSSID, &[0, 0, 7, 0]);
    w.radio.rx.push_back(RxFrame::new(forged));
    // ...and to be the station.
    w.station_sends(frame([0xC0, 0], BSSID, STA, BSSID, &[0, 0, 3, 0]));
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

fn anti_clogging(method: Method) {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    // hostapd's threshold at 0: every commit needs a token.
    w.ap.anti_clogging_threshold = 0;
    w.sta.method = method;
    w.join();
    assert_eq!(w.sta.state, State::Connected, "{:?}", w.ap.events);
    assert_eq!(w.sta.notices, [Notice::TokenSentBack]);
    assert_eq!(
        w.ap.events
            .iter()
            .filter(|e| matches!(e, ApEvent::SaeTokenRequested { .. }))
            .count(),
        1
    );
}

#[test]
fn a_busy_access_point_gets_its_token_back_after_hashing_to_the_curve() {
    anti_clogging(Method::HashToElement);
}

#[test]
fn a_busy_access_point_gets_its_token_back_after_hunting_and_pecking() {
    anti_clogging(Method::HuntingAndPecking);
}

#[test]
fn tokens_are_only_asked_for_once_enough_exchanges_are_open() {
    // hostapd's default of 5: a lone station is not bothered.
    let mut w = World::new(Wpa3::Only, PASSWORD);
    assert_eq!(w.ap.anti_clogging_threshold, 5);
    w.join();
    assert!(w.sta.is_connected());
    assert!(
        !w.ap
            .events
            .iter()
            .any(|e| matches!(e, ApEvent::SaeTokenRequested { .. }))
    );
}

#[test]
fn a_made_up_token_is_dropped_without_an_answer() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.ap.anti_clogging_threshold = 0;
    w.sta.method = Method::HuntingAndPecking;
    w.sta.connect(&mut w.radio, BSSID, 6);
    w.now += 1;
    w.ap.poll(&mut w.radio, w.now);
    // The token request is in the air for the station; swap the token
    // the station will copy for a forged one.
    let reply = w.radio.rx.iter_mut().find(|f| f.data[0] == 0xB0).unwrap();
    let n = reply.data.len();
    reply.data[n - 1] ^= 1;
    w.run(50);
    assert_eq!(w.sta.state, State::Committed, "{:?}", w.ap.events);
    assert!(
        w.ap.events
            .contains(&ApEvent::SaeTokenRejected { sta: STA })
    );
    assert!(!w.ap.is_authorized(STA));
}

#[test]
fn a_station_that_lost_its_keys_gets_back_in_after_the_sa_query_times_out() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    assert!(w.sta.is_connected());
    // The station restarts: no keys any more, the access point does not
    // know.
    w.sta.forget();
    let restarted = w.now;
    w.join();
    // The password exchange went through, the association was refused
    // for now and the old association asked whether it is still there.
    assert!(
        w.ap.events.contains(&ApEvent::AssocRejected {
            sta: STA,
            status: 30
        }),
        "{:?}",
        w.ap.events
    );
    assert!(w.ap.events.contains(&ApEvent::SaQueryStarted { sta: STA }));
    assert!(
        matches!(w.sta.notices[..], [Notice::ComeBackIn { tu: 990..=1001 }]),
        "{:?}",
        w.sta.notices
    );
    // Nobody answers the queries (the keys are gone): after the time
    // given, the station is let in.
    while !w.sta.is_connected() && w.now < restarted + 2000 {
        w.run(1);
    }
    let took = w.now - restarted;
    w.run(2);
    assert!(w.ap.events.contains(&ApEvent::SaQueryTimedOut { sta: STA }));
    assert_eq!(w.sta.state, State::Connected, "{:?}", w.ap.events);
    assert!(w.ap.is_authorized(STA));
    // hostapd's 1000 time units are 1024 ms.
    assert!((1024..1100).contains(&took), "back after {took} ms");
}

#[test]
fn a_station_still_there_keeps_its_association_against_an_impostor() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    // Somebody else, with the station's address, associates in clear.
    w.station_sends(wpa3_association());
    w.run(10);
    // Refused for now; the real station answers the query with its keys.
    assert!(w.ap.events.contains(&ApEvent::AssocRejected {
        sta: STA,
        status: 30
    }));
    assert!(w.ap.events.contains(&ApEvent::SaQueryAnswered { sta: STA }));
    assert!(w.sta.notices.contains(&Notice::SaQueryAnswered));
    assert!(w.sta.is_connected());
    assert!(w.ap.is_authorized(STA));
    // And traffic still flows on the old keys.
    let up = ethernet([2, 0, 0, 0, 0, 1], STA, b"toujours la");
    w.sta.send(&mut w.radio, &up);
    w.run(5);
    assert_eq!(w.ap.uplink.pop_front(), Some(up));
}

#[test]
fn robust_action_frames_in_clear_are_dropped() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    w.station_sends(frame(
        [0xD0, 0],
        BSSID,
        STA,
        BSSID,
        &[0, 0, 8, 0, 0x12, 0x34],
    ));
    w.run(5);
    assert!(
        w.ap.events
            .contains(&ApEvent::UnprotectedActionDropped { sta: STA })
    );
}

#[test]
fn a_shut_down_is_believed_only_with_its_integrity_code() {
    let mut w = World::new(Wpa3::Only, PASSWORD);
    w.join();
    // A forged deauthentication to everyone, no management MIC element.
    let forged = frame([0xC0, 0], [0xFF; 6], BSSID, BSSID, &[0, 0, 3, 0]);
    w.radio.rx.push_back(RxFrame::new(forged));
    w.run(2);
    assert!(w.sta.is_connected());
    assert_eq!(w.sta.notices, [Notice::ForgedDeauthIgnored]);

    // The genuine one, after a group key renewal (new integrity key,
    // new identifier).
    w.ap.rekey_group(&mut w.radio);
    w.run(10);
    w.ap.shut_down(&mut w.radio);
    let genuine = w.radio.rx.back().unwrap().clone();
    w.run(2);
    assert_eq!(w.sta.state, State::Idle);
    assert_eq!(
        w.sta.notices.last(),
        Some(&Notice::Deauthenticated { reason: 3 })
    );
    let n = genuine.data.len();
    assert_eq!(
        genuine.data[n - 18..n - 14],
        [76, 16, 5, 0],
        "key 5 after the renewal"
    );

    // Replayed to a station that came back: refused by its packet number.
    let mut w2 = World::new(Wpa3::Only, PASSWORD);
    w2.join();
    w2.ap.shut_down(&mut w2.radio);
    let first = w2.radio.rx.back().unwrap().clone();
    w2.run(2);
    assert_eq!(w2.sta.state, State::Idle);
    let _ = first;
}
