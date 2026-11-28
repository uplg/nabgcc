//! A crowded 2.4 GHz band: many access points around the rabbit's
//! own. The same scenarios on both firmwares, r3 being the reference:
//! the rabbit still finds and joins its network.

mod common;

use common::{SSID, ap_saw, handshakes, until, wait, wpa2};
use nabemu::air::{AccessPoint, ApEvent, Security};
use nabemu::config::{Config, Wifi};
use nabemu::{DEFAULT_MAC, Machine};

/// The home network, open, on channel 11, and `n` open neighbours on
/// channel 1 beaconing five times as often as usual.
fn crowded(n: usize) -> Machine {
    let mut m = common::under_test();
    Config::new(SSID, Wifi::Open).install(&mut m.soc.flash);
    m.air
        .push(AccessPoint::new(SSID, common::BSSID, 11, Security::Open));
    for i in 0..n {
        let name = format!("Voisin{i:03}");
        let bssid = [2, 0, 0, 1, (i >> 8) as u8, i as u8];
        let mut ap = AccessPoint::new(&name, bssid, 1, Security::Open);
        ap.beacon_interval = 20;
        m.air.push(ap);
    }
    m
}

/// Two hundred neighbours heard before the home network: the C
/// firmware lists every frame heard, and still finds its network
/// among them; lapin lists every network once.
#[test]
fn joins_its_network_among_two_hundred_neighbours() {
    let mut m = crowded(200);
    until(&mut m, 40_000, "associated", |m| {
        ap_saw(m, &ApEvent::Associated { sta: DEFAULT_MAC })
    });
}

/// The networks the boot printed in its last scan dump.
fn listed(m: &Machine) -> Vec<String> {
    let console = m.console();
    let last = console.rfind("## DUMPSCAN").unwrap_or(0);
    console[last..]
        .lines()
        .filter_map(|l| l.strip_prefix("## SCAN "))
        .map(|l| l.trim_end().to_owned())
        .collect()
}

/// In setup mode the page lists the networks around: the home
/// network among them, each network once.
fn setup_mode_lists(neighbours: usize) -> Vec<String> {
    let mut m = crowded(neighbours);
    common::scan_in_setup_mode(&mut m);
    listed(&m)
}

#[test]
fn setup_mode_lists_its_network_among_a_hundred_neighbours() {
    let listed = setup_mode_lists(100);
    assert!(listed.iter().any(|s| s == SSID), "{listed:?}");
    assert_eq!(listed.len(), 101, "{listed:?}");
}

#[test]
fn setup_mode_lists_its_network_among_two_hundred_neighbours() {
    let listed = setup_mode_lists(200);
    assert!(listed.iter().any(|s| s == SSID), "{} listed", listed.len());
    if nabemu::testing::is_lapin() {
        // Each network once. Not all of them: two hundred neighbours
        // beaconing every 20 ms send ten thousand frames a second, and
        // lapin takes about two a millisecond off the stick, some 240
        // in its 120 ms on channel 1. Which 200 of the 1400 those are
        // depends on where the beacons' rounds stand when it starts
        // listening: this listed 201 with the rabbit started 15 ms
        // later, 119 as it starts now (the rescue core, rebuilt with the
        // first image's unpacker, hands over 15 ms sooner). On the air
        // the beacons do not keep in step, and some are lost the same
        // way.
        let mut names = listed.clone();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), listed.len(), "a network twice: {listed:?}");
        assert!(listed.len() > 100, "{listed:?}");
    } else {
        // Known defect of r3: so many frames in its 350 ms on channel 1
        // that some neighbours are lost (175 listed of 201).
        assert!(listed.len() < 201, "{listed:?}");
    }
}

/// Twenty WPA2 neighbours on the other channels: more secured networks
/// than lapin remembered the offers of. The join completes at the first
/// try, as on r3 (lapin took the boot's 20 s retry: the home network's
/// offer had been pushed out, and message 3 was judged a downgrade).
#[test]
fn joins_wpa2_at_once_among_twenty_secured_neighbours() {
    let mut m = common::on_network(&nabemu::testing::image(), wpa2());
    m.air[0].channel = 1;
    for i in 0..20u8 {
        let bssid = [2, 0, 0, 0, 1, i];
        let security = Security::wpa2("autre-passe-123");
        m.air.push(AccessPoint::new(
            &format!("Voisin{i:02}"),
            bssid,
            2 + i % 12,
            security,
        ));
    }
    until(&mut m, 15_000, "the handshake", |m| handshakes(m) > 0);
    wait(&mut m, 1000);
    assert!(
        !m.air[0].events.iter().any(|e| matches!(
            e,
            ApEvent::Deauthenticated { .. } | ApEvent::EapolRejected { .. }
        )),
        "{:?}",
        m.air[0].events
    );
}
