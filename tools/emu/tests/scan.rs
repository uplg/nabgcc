//! What a scan tells the bytecode of each kind of network: the same
//! code on both firmwares, r3 being the reference, except where r3
//! calls joinable a network it cannot join.

mod common;

use common::until;
use nabemu::Machine;
use nabemu::air::{AccessPoint, Security};

const RSN: [u8; 3] = [0x00, 0x0F, 0xAC];
const WPA: [u8; 3] = [0x00, 0x50, 0xF2];
const TKIP: u8 = 2;
const CCMP: u8 = 4;
const WEP40: u8 = 1;
const IEEE8021X: u8 = 1;
const PSK: u8 = 2;
const SAE: u8 = 8;

/// The suites of an RSN or WPA element: group, pairwise, key managements.
fn suites(oui: [u8; 3], group: (&[u8; 3], u8), pairwise: &[u8], akms: &[u8]) -> Vec<u8> {
    let mut e = vec![1, 0];
    e.extend_from_slice(group.0);
    e.push(group.1);
    e.extend_from_slice(&[pairwise.len() as u8, 0]);
    for p in pairwise {
        e.extend_from_slice(&oui);
        e.push(*p);
    }
    e.extend_from_slice(&[akms.len() as u8, 0]);
    for a in akms {
        e.extend_from_slice(&oui);
        e.push(*a);
    }
    e
}

fn rsn(group: u8, pairwise: &[u8], akms: &[u8]) -> Vec<u8> {
    let mut body = suites(RSN, (&RSN, group), pairwise, akms);
    body.extend_from_slice(&[0, 0]);
    element(48, &body)
}

fn wpa(group: u8, pairwise: &[u8], akms: &[u8]) -> Vec<u8> {
    let mut body = vec![0x00, 0x50, 0xF2, 1];
    body.extend(suites(WPA, (&WPA, group), pairwise, akms));
    element(221, &body)
}

fn element(id: u8, body: &[u8]) -> Vec<u8> {
    let mut e = vec![id, body.len() as u8];
    e.extend_from_slice(body);
    e
}

/// Each network's name and the code the setup mode's scan printed.
fn codes(networks: &[(&str, Vec<u8>)]) -> Vec<(String, i64)> {
    let mut m = common::under_test();
    for (i, (name, elements)) in networks.iter().enumerate() {
        let mut ap = AccessPoint::new(
            name,
            [2, 0, 0, 2, 0, i as u8],
            1 + i as u8 % 11,
            Security::wpa2("ignore-pas-ca"),
        );
        ap.announced = Some(elements.clone());
        m.air.push(ap);
    }
    common::scan_in_setup_mode(&mut m);
    dumped(&m)
}

/// The boot's scan dump: names and encryption codes.
fn dumped(m: &Machine) -> Vec<(String, i64)> {
    let console = m.console();
    let mut out = Vec::new();
    let mut name = None;
    for line in console.lines() {
        if let Some(s) = line.strip_prefix("## SCAN ") {
            name = Some(s.trim_end().to_owned());
        } else if let Some(code) = line.strip_prefix("encryption:")
            && let (Some(n), Ok(c)) = (name.take(), code.trim().parse())
        {
            out.push((n, c));
        }
    }
    out.sort();
    out
}

#[test]
fn the_code_of_each_kind_of_network() {
    let wpa_psk = wpa(TKIP, &[TKIP], &[PSK]);
    let both = |r: Vec<u8>| [r, wpa_psk.clone()].concat();
    let mut vendor_group = rsn(CCMP, &[CCMP], &[PSK]);
    vendor_group[4..7].copy_from_slice(&WPA);
    let networks = [
        ("Rsn-psk", rsn(CCMP, &[CCMP], &[PSK])),
        ("Rsn-mixed", rsn(TKIP, &[TKIP, CCMP], &[PSK])),
        ("Wpa-psk", wpa_psk.clone()),
        ("Wpa-ccmp", wpa(CCMP, &[CCMP], &[PSK])),
        // Joinable only with a key server: none of them.
        ("Wpa-8021x", wpa(TKIP, &[TKIP], &[IEEE8021X])),
        ("Rsn-8021x", rsn(CCMP, &[CCMP], &[IEEE8021X])),
        ("Rsn-vendor-group", vendor_group),
        // RSN out of reach, WPA with PSK beside it: joined as WPA.
        ("Rsn-8021x+wpa", both(rsn(CCMP, &[CCMP], &[IEEE8021X]))),
        ("Rsn-wep-group+wpa", both(rsn(WEP40, &[TKIP], &[PSK]))),
        ("Wpa-wep-group", wpa(WEP40, &[TKIP], &[PSK])),
        ("Rsn-sae", rsn(CCMP, &[CCMP], &[SAE])),
    ];
    let lapin = nabemu::testing::is_lapin();
    let mut expected = vec![
        ("Rsn-psk", 0x4A),
        ("Rsn-mixed", 0x47),
        ("Wpa-psk", 0x20),
        ("Wpa-ccmp", 0x20),
        ("Wpa-8021x", 0xFF),
        ("Rsn-8021x", 0xFF),
        ("Rsn-vendor-group", 0xFF),
        ("Rsn-8021x+wpa", 0x20),
        ("Rsn-wep-group+wpa", 0x20),
        // Known defect of r3: a WPA element is taken for WPA whatever
        // its group cipher, and a WEP group key is one its handshake
        // cannot install. lapin says it cannot join.
        ("Wpa-wep-group", if lapin { 0xFF } else { 0x20 }),
        // WPA3, which lapin joins and r3 does not.
        ("Rsn-sae", if lapin { 0x4A } else { 0xFF }),
    ];
    expected.sort();
    let expected: Vec<(String, i64)> = expected
        .into_iter()
        .map(|(n, c)| (n.to_owned(), c))
        .collect();
    assert_eq!(codes(&networks), expected);
}

/// A network whose RSN element offers only a key server and whose WPA
/// element offers a passphrase: both firmwares join it with WPA.
#[test]
fn joins_with_wpa_where_rsn_is_out_of_reach() {
    let mut m = common::on_network(&nabemu::testing::image(), common::wpa());
    let announced = [rsn(CCMP, &[CCMP], &[IEEE8021X]), wpa(TKIP, &[TKIP], &[PSK])].concat();
    m.air[0].announced = Some(announced);
    until(&mut m, 20_000, "the handshake", |m| {
        common::handshakes(m) > 0
    });
    until(&mut m, 8000, "an IP frame through", common::ip_on_the_wire);
}
