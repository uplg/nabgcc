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
    neighbours(&mut m, n);
    m
}

/// `n` open neighbours on channel 1, beaconing every 20 ms, all at once
/// from now on.
fn neighbours(m: &mut Machine, n: usize) {
    for i in 0..n {
        let name = format!("Voisin{i:03}");
        let bssid = [2, 0, 0, 1, (i >> 8) as u8, i as u8];
        let mut ap = AccessPoint::new(&name, bssid, 1, Security::Open);
        ap.beacon_interval = 20;
        m.air.push(ap);
    }
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
/// network among them, each network once. The neighbours come on
/// `phase_ms` after power-on: where their beacons' rounds stand when
/// the scan begins.
fn setup_mode_lists(neighbours_n: usize, phase_ms: u64) -> Vec<String> {
    let mut m = crowded(0);
    m.soc.board.button = true;
    wait(&mut m, phase_ms);
    neighbours(&mut m, neighbours_n);
    common::scan_in_setup_mode(&mut m);
    listed(&m)
}

#[test]
fn setup_mode_lists_its_network_among_a_hundred_neighbours() {
    let listed = setup_mode_lists(100, 0);
    assert!(listed.iter().any(|s| s == SSID), "{listed:?}");
    assert_eq!(listed.len(), 101, "{listed:?}");
}

/// Two hundred neighbours beaconing every 20 ms send ten thousand
/// frames a second on channel 1, and the rabbit's probe as many answers
/// again. lapin took two frames a millisecond off the stick (four
/// receive transfers of a packet in flight), and its scan read fewer:
/// it listed from 120 to 201 networks, by phase, r3 from 169 to 177.
/// Now it takes eight a millisecond (eight transfers of two packets),
/// and once its queue is half full keeps no second announcement of a
/// network: every one of them listed, once, whatever the phase (the
/// whole 20 ms round, a millisecond at a time).
fn lists_every_network_among_two_hundred(phases: std::ops::Range<u64>) {
    for phase in phases {
        let listed = setup_mode_lists(200, phase);
        assert!(listed.iter().any(|s| s == SSID), "{} listed", listed.len());
        if !nabemu::testing::is_lapin() {
            // Known defect of r3: one packet a millisecond off the stick
            // in its 350 ms on channel 1 (175 listed of 201). Once only:
            // r3 is slow to run.
            assert!(listed.len() < 201, "{listed:?}");
            return;
        }
        let mut names = listed.clone();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), listed.len(), "a network twice: {listed:?}");
        assert_eq!(listed.len(), 201, "phase {phase} ms: {listed:?}");
    }
}

#[test]
fn setup_mode_lists_every_network_among_two_hundred_neighbours() {
    lists_every_network_among_two_hundred(0..5);
}

#[test]
fn whatever_the_phase_5_to_9() {
    if nabemu::testing::is_lapin() {
        lists_every_network_among_two_hundred(5..10);
    }
}

#[test]
fn whatever_the_phase_10_to_14() {
    if nabemu::testing::is_lapin() {
        lists_every_network_among_two_hundred(10..15);
    }
}

#[test]
fn whatever_the_phase_15_to_19() {
    if nabemu::testing::is_lapin() {
        lists_every_network_among_two_hundred(15..20);
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
