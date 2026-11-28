//! The released firmware booting all the way: join, DHCP, DNS, fetch a
//! bytecode over HTTP, run it.

mod common;

use common::{ap_saw, on_network, until_every, wep, wpa, wpa2};
use nabemu::air::{ApEvent, Security};
use nabemu::config::Wifi;
use nabemu::lan::{Lan, Response};
use nabemu::{DEFAULT_MAC, Machine, metal};

fn rabbit_on(network: (Wifi, Security)) -> Machine {
    let mut m = on_network(&nabemu::testing::image(), network);
    let mut lan = Lan::new();
    lan.handler = Box::new(|request| {
        if request.target.starts_with("/vl/bc.jsp?") {
            Response::ok(metal::boot_response(&metal::print_number(20061225)))
        } else {
            Response::not_found()
        }
    });
    m.lan = Some(lan);
    m
}

fn run_until_console(m: &mut Machine, wanted: &str, limit_ms: u64) {
    until_every(m, 50, limit_ms, &format!("{wanted:?} printed"), |m| {
        m.console().contains(wanted)
    });
}

fn boots_its_bytecode(network: (Wifi, Security)) -> Machine {
    let mut m = rabbit_on(network);
    run_until_console(&mut m, "BOOT DONE", 40_000);
    run_until_console(&mut m, "20061225", 2000);
    assert_eq!(m.events, [], "no reset on the way");

    let lan = m.lan.as_ref().unwrap();
    // Discover until an offer gets through, then request. With WPA the
    // first discover can leave while the group key handshake is still
    // on (the port is open, as on hostapd): the broadcast offer is then
    // lost to a rabbit that has no group key yet, and it asks again.
    let request = lan.dhcp_messages.iter().position(|m| *m == 3);
    assert!(
        request.is_some_and(|i| i >= 1 && lan.dhcp_messages[..i].iter().all(|m| *m == 1)),
        "discover, then request: {:?}",
        lan.dhcp_messages
    );
    assert_eq!(lan.leased_to, Some(DEFAULT_MAC));
    assert_eq!(lan.dns_queries[0], "r.nabaztag.com");
    let request = &lan.requests[0];
    assert_eq!(request.method, "GET");
    assert!(
        request
            .target
            .starts_with("/vl/bc.jsp?v=0.0.0.13&m=00:19:db:00:00:01&"),
        "{}",
        request.target
    );
    assert_eq!(request.header("host"), Some("r.nabaztag.com"));
    m
}

#[test]
fn boots_its_bytecode_from_an_open_network() {
    boots_its_bytecode(common::open());
}

#[test]
fn boots_its_bytecode_from_a_wpa2_network() {
    let m = boots_its_bytecode(wpa2());
    // The DHCP answers are broadcast: they came through the group key.
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    assert!(ap_saw(&m, &ApEvent::HandshakeComplete { sta: DEFAULT_MAC }));
}

#[test]
fn boots_its_bytecode_from_a_wpa_tkip_network() {
    let m = boots_its_bytecode(wpa());
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}

#[test]
fn boots_its_bytecode_from_a_wep_network() {
    let m = boots_its_bytecode(wep("abcde", false));
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}
