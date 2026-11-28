//! A scan the bytecode asks for while the rabbit is on its network: the
//! station leaves the channel for a while, then comes back to the link
//! it held, keys and all; and a rabbit that did lose its link joins
//! again a WPA3 network whose access point still holds the old
//! protected association.

mod common;

use common::{
    BSSID, PASSPHRASE, SSID, ap_count, authorized, find, handshakes, on_network, until, wait, wpa2,
};
use nabemu::air::{ApEvent, Wpa3};
use nabemu::metal::{OP_DROP, OP_GETGLOBALB, OP_IECHOLN, OP_RET};
use nabemu::{DEFAULT_MAC, Machine, metal};

const NIL: u8 = 4;
const EQ: u8 = 22;
const ELSE: u8 = 29;
const DEFTABB: u8 = 32;
const SETGLOBAL: u8 = 42;
const LOOPCB: u8 = 94;
const NETSTATE: u8 = 105;
const NETSCAN: u8 = 109;
const NETAUTH: u8 = 110;

/// A string global, as the bytecode's globals hold it.
fn global_str(s: &[u8]) -> Vec<u8> {
    let mut g = ((s.len() as u32) << 2 | 1).to_le_bytes().to_vec();
    g.extend(s);
    g
}

/// A program that prints 7770, scans, prints the network's state, then
/// 8880; and from then on joins the home network again whenever the
/// link is idle, as the rabbit's bytecode does.
fn program() -> Vec<u8> {
    let mut main = vec![0, 0, 0];
    // set g0 = ["Terrier" bssid bssid -40 6 255 WPA2+CCMP]
    main.extend(metal::int(0));
    main.extend([OP_GETGLOBALB, 2, OP_GETGLOBALB, 3, OP_GETGLOBALB, 3]);
    for v in [-40, 6, 255, 0x4A] {
        main.extend(metal::int(v));
    }
    main.extend([DEFTABB, 7, SETGLOBAL, OP_DROP]);
    main.extend(metal::int(7770));
    main.extend([OP_IECHOLN, OP_DROP, NIL, NETSCAN, OP_DROP]);
    main.extend([NETSTATE, OP_IECHOLN, OP_DROP]);
    main.extend(metal::int(8880));
    main.extend([OP_IECHOLN, OP_DROP]);
    // loopcb #rejoin
    main.extend(metal::int(1));
    main.extend([LOOPCB, OP_DROP]);
    main.extend(metal::int(0));
    main.push(OP_RET);

    // rejoin = if netState == IDLE then netAuth g0 0 WPA2 g1
    let mut body = vec![NETSTATE];
    body.extend(metal::int(1));
    body.extend([EQ, ELSE, 0, 0, OP_GETGLOBALB, 0]);
    body.extend(metal::int(0));
    body.extend(metal::int(0x40));
    body.extend([OP_GETGLOBALB, 1, NETAUTH, OP_DROP]);
    let skip = (body.len() as u16).to_le_bytes();
    let at = body.iter().position(|b| *b == ELSE).unwrap();
    body[at + 1..at + 3].copy_from_slice(&skip);
    body.extend(metal::int(0));
    body.push(OP_RET);
    let mut rejoin = vec![0, 0, 0];
    rejoin.extend(body);

    let mut globals = u32::MAX.to_le_bytes().to_vec();
    // The key the setup page derived from the passphrase. (Not last:
    // on both machines the last global of this bytecode reads empty by
    // the time the callback runs.)
    globals.extend(global_str(&nabemu::crypto::wpa_psk(PASSPHRASE, SSID)));
    globals.extend(global_str(SSID.as_bytes()));
    globals.extend(global_str(&BSSID));
    let mut bc = (globals.len() as u32 + 4).to_le_bytes().to_vec();
    bc.extend(globals);
    let starts = [0, main.len()];
    let code = [main, rejoin].concat();
    bc.extend((code.len() as u32).to_le_bytes());
    bc.extend(code);
    bc.extend(2u16.to_le_bytes());
    for s in starts {
        bc.extend((s as u32).to_le_bytes());
    }
    bc
}

/// The numbers the program printed between 7770 and 8880.
fn printed(m: &Machine) -> Vec<i64> {
    let c = m.console();
    let from = c.rfind("7770").expect("the program ran") + 4;
    let to = c[from..].find("8880").map_or(c.len(), |i| from + i);
    c[from..to]
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect()
}

/// The rabbit on the home network, `wpa3` or not, running the program
/// until it printed 8880.
fn scanned(image: &[u8], wpa3: bool) -> Machine {
    let mut m = on_network(image, wpa2());
    if wpa3 {
        m.air[0].wpa3 = Wpa3::Only;
    }
    common::serve(&mut m, metal::boot_response(&program()));
    until(&mut m, 60_000, "the program's end", |m| {
        find(&m.soc.uart_tx, b"8880").is_some()
    });
    m
}

/// After the scan the link is the one held before: the state says
/// connected, the access point never saw the rabbit leave or come
/// again, and a new group key, sent under the pairwise key of the
/// first handshake, is taken.
fn keeps_its_link(m: &mut Machine) {
    assert_eq!(printed(m), [4], "the state after the scan");
    wait(m, 3000);
    let events = &m.air[0].events;
    assert!(authorized(m), "{events:?}");
    assert_eq!(handshakes(m), 1, "{events:?}");
    assert_eq!(
        ap_count(m, &ApEvent::Associated { sta: DEFAULT_MAC }),
        1,
        "{events:?}"
    );
    let installed = |m: &Machine| ap_count(m, &ApEvent::GroupKeyInstalled { sta: DEFAULT_MAC });
    let before = installed(m);
    m.air[0].rekey_group(&mut m.radio.borrow_mut());
    until(m, 5000, "the new group key taken", |m| {
        installed(m) > before
    });
}

/// lapin keeps its link across the scan, on WPA2.
#[test]
fn a_scan_keeps_the_wpa2_link() {
    let Some(image) = common::lapin() else { return };
    let mut m = scanned(&image, false);
    keeps_its_link(&mut m);
}

/// And on WPA3, where a station that left could not come back at once:
/// the access point holds its protected association.
#[test]
fn a_scan_keeps_the_wpa3_link() {
    let Some(image) = common::lapin() else { return };
    let mut m = scanned(&image, true);
    keeps_its_link(&mut m);
}

/// r3, the reference, on WPA2: `rt2501_scan` leaves the state idle
/// when it is done, whatever it was, and the bytecode joins again, a
/// second handshake (the access point, without protected management
/// frames, takes the fresh authentication). r3 has no WPA3.
#[test]
fn r3_drops_its_link_for_a_scan() {
    let mut m = scanned(&common::r3(), false);
    assert_eq!(printed(&m), [1], "the state after the scan");
    until(&mut m, 30_000, "back on the network", |m| {
        handshakes(m) == 2 && authorized(m)
    });
}

/// The access point out of range for two minutes and more: the rabbit
/// gives the link up (no beacon for 120 s), the access point, which
/// heard nothing, still holds the protected association (hostapd lets
/// an inactive station be for five minutes). Back in range, the
/// rabbit's fresh association is turned away (status 30, come back) and
/// the access point asks the holder of the old keys (SA Query); no one
/// answers under them, and the rabbit, coming back as told, is let in.
#[test]
fn after_a_drop_it_rejoins_a_wpa3_network_that_held_it() {
    let Some(image) = common::lapin() else { return };
    let mut m = scanned(&image, true);
    wait(&mut m, 1000);
    assert_eq!(handshakes(&m), 1);
    // Out of range: neither end hears the other.
    m.air[0].channel = 11;
    wait(&mut m, 130_000);
    m.air[0].channel = 6;
    until(&mut m, 40_000, "back on the network", |m| {
        handshakes(m) == 2 && authorized(m)
    });
    let events = &m.air[0].events;
    for e in [
        ApEvent::SaQueryStarted { sta: DEFAULT_MAC },
        ApEvent::AssocRejected {
            sta: DEFAULT_MAC,
            status: 30,
        },
        ApEvent::SaQueryTimedOut { sta: DEFAULT_MAC },
    ] {
        assert!(events.contains(&e), "{e:?}: {events:?}");
    }
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ApEvent::Deauthenticated { .. })),
        "{events:?}"
    );
}
