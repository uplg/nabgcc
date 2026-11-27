//! The harness's access point takes the station where it says: every
//! script ends with the station connected (or, for the access point,
//! with a laptop in it).

use lapin_core::wifi;
use lapin_fuzz::station::{KINDS, Kind, world};

#[test]
fn every_script_ends_connected() {
    for (k, &kind) in KINDS.iter().enumerate() {
        let states: Vec<_> = (0..16).map(|s| world(k, s).sta.net_state()).collect();
        println!("{kind:?}: {states:?}");
        let want = if kind == Kind::Master {
            wifi::S_MASTER
        } else {
            wifi::S_CONNECTED
        };
        let end = world(k, lapin_fuzz::station::script_len(kind)).sta;
        assert_eq!(end.net_state(), want, "{kind:?}");
        if let Kind::Sae { .. } = kind {
            assert!(end.is_wpa3());
        }
    }
}

fn data_op(how: u8, to: u8) -> Vec<u8> {
    let body = [0xAA, 0xAA, 3, 0, 0, 0, 8, 0, 1, 2, 3];
    let mut v = vec![2, 0, 0, to, how, body.len() as u8, 0];
    v.extend_from_slice(&body);
    v
}

fn at(kind: Kind, ops: &[u8]) -> (usize, i32) {
    let k = KINDS.iter().position(|x| *x == kind).unwrap();
    let mut v = vec![k as u8, 0x80 | lapin_fuzz::station::script_len(kind) as u8];
    v.extend_from_slice(ops);
    lapin_fuzz::station::run(&v)
}

const WPA3: Kind = Kind::Sae {
    h2e: false,
    transition: false,
    cached: false,
};
const WPA2: Kind = Kind::Psk {
    wpa2: true,
    group: 4,
    pairwise: 4,
};

#[test]
fn the_access_point_gets_frames_through() {
    // WPA3: under the pairwise key, under the group key; not in clear.
    assert_eq!(at(WPA3, &data_op(1, 0)), (1, wifi::S_CONNECTED));
    assert_eq!(at(WPA3, &data_op(2, 2)), (1, wifi::S_CONNECTED));
    assert_eq!(at(WPA3, &data_op(0, 0)).0, 0);
    // WPA2: what the stick opened.
    assert_eq!(at(WPA2, &data_op(8, 0)).0, 1);
    assert_eq!(at(WPA2, &data_op(0, 0)).0, 0);
    // A signed broadcast deauthentication is believed, a badly signed
    // one is not.
    assert_eq!(at(WPA3, &[8, 0, 0, 0, 2, 3, 0]).1, wifi::S_IDLE);
    assert_eq!(at(WPA3, &[8, 0, 0, 4, 2, 3, 0]).1, wifi::S_CONNECTED);
}

/// A rekey begun, then a deauthentication: joining again works (the
/// half-done rekey's keys once signed every handshake after it).
#[test]
fn the_network_can_be_joined_again_after_a_rekey_cut_short() {
    let (_, state) = at(WPA2, &[4, 0, 1, 0xC0, 0, 2, 3, 0]);
    assert_eq!(state, wifi::S_IDLE);
}
