//! A scan the bytecode asks for while the rabbit is on its network: the
//! station leaves the channel for a while, then comes back to the link
//! it held, keys and all; and a rabbit that did lose its link joins
//! again a WPA3 network whose access point still holds the old
//! protected association.

mod common;

use common::bc::{self, Global, op::*};
use common::{
    BSSID, PASSPHRASE, SSID, ap_count, authorized, handshakes, on_network, printed, program_ended,
    until, wait, wpa2,
};
use nabemu::air::{ApEvent, Wpa3};
use nabemu::{DEFAULT_MAC, Machine, metal};

/// A program that prints 7770, scans, prints the network's state, then
/// 8880; and from then on joins the home network again whenever the
/// link is idle, as the rabbit's bytecode does.
fn program() -> Vec<u8> {
    // set g0 = ["Terrier" bssid bssid -40 6 255 WPA2+CCMP]
    let mut main = bc::main_with_home_network(0, 2, 3);
    main.extend(metal::int(7770));
    main.extend([IECHOLN, DROP, NIL, NETSCAN, DROP]);
    main.extend([NETSTATE, IECHOLN, DROP]);
    main.extend(metal::int(8880));
    main.extend([IECHOLN, DROP]);
    // loopcb #rejoin
    main.extend(bc::loop_callback(1));
    // rejoin = if netState == IDLE then netAuth g0 0 WPA2 g1
    let rejoin = bc::rejoin(0, &[GETGLOBALB, 1]);
    // The key the setup page derived from the passphrase. (Not last:
    // the last global of a served bytecode lies above the stack once
    // its main function returned, and the callback's frame writes over
    // it, on both machines: `tests/observable.rs`,
    // `the_last_global_lies_above_the_stack_once_main_returned`.)
    let key = nabemu::crypto::wpa_psk(PASSPHRASE, SSID);
    let globals = [
        Global::Word(u32::MAX),
        Global::Str(&key),
        Global::Str(SSID.as_bytes()),
        Global::Str(&BSSID),
    ];
    bc::assemble(&globals, &[&main, &rejoin])
}

/// The rabbit on the home network, `wpa3` or not, running the program
/// until it printed 8880.
fn scanned(image: &[u8], wpa3: bool) -> Machine {
    let mut m = on_network(image, wpa2());
    if wpa3 {
        m.air[0].wpa3 = Wpa3::Only;
    }
    common::serve(&mut m, metal::boot_response(&program()));
    until(&mut m, 60_000, "the program's end", program_ended);
    m
}

/// After the scan the link is the one held before: the state says
/// connected, the access point never saw the rabbit leave or come
/// again, and a new group key, sent under the pairwise key of the
/// first handshake, is taken. lapin on the home network, `wpa3` or not.
fn keeps_its_link(wpa3: bool) {
    let Some(image) = common::lapin() else { return };
    let m = &mut scanned(&image, wpa3);
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
    keeps_its_link(false);
}

/// And on WPA3, where a station that left could not come back at once:
/// the access point holds its protected association.
#[test]
fn a_scan_keeps_the_wpa3_link() {
    keeps_its_link(true);
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
