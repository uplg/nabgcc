//! The released firmware booting all the way: join, DHCP, DNS, fetch a
//! bytecode over HTTP, run it.

use nabemu::air::{AccessPoint, ApEvent, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};
use nabemu::{DEFAULT_MAC, Machine, metal};

fn rabbit_on(wifi: Wifi, security: Security) -> Machine {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../artifacts/Nab-wpa23-gtk-r3.sim"
    );
    let image = std::fs::read(path).expect("the r3 release image is in artifacts/");
    let mut m = Machine::from_file(&image).0;
    Config::new("Terrier", wifi).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        security,
    ));
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
    while !m.console().contains(wanted) {
        assert!(
            m.soc.millis() < limit_ms,
            "{wanted:?} never printed.\nap: {:?}\nconsole:\n{}",
            m.air[0].events,
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 50);
    }
}

fn boots_its_bytecode(wifi: Wifi, security: Security) -> Machine {
    let mut m = rabbit_on(wifi, security);
    run_until_console(&mut m, "BOOT DONE", 40_000);
    let limit = m.soc.millis() + 2000;
    run_until_console(&mut m, "20061225", limit);
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
    boots_its_bytecode(Wifi::Open, Security::Open);
}

#[test]
fn boots_its_bytecode_from_a_wpa2_network() {
    let pass = "carotte-violette";
    let m = boots_its_bytecode(
        Wifi::Wpa2 {
            passphrase: pass.into(),
        },
        Security::wpa2(pass),
    );
    // The DHCP answers are broadcast: they came through the group key.
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    assert!(
        m.air[0]
            .events
            .contains(&ApEvent::HandshakeComplete { sta: DEFAULT_MAC })
    );
}

#[test]
fn boots_its_bytecode_from_a_wpa_tkip_network() {
    let pass = "carotte-violette";
    let m = boots_its_bytecode(
        Wifi::Wpa {
            passphrase: pass.into(),
        },
        Security::wpa(pass),
    );
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}

#[test]
fn boots_its_bytecode_from_a_wep_network() {
    let key = "abcde";
    let m = boots_its_bytecode(
        Wifi::Wep {
            key: key.into(),
            shared_auth: false,
        },
        Security::Wep {
            key: key.as_bytes().to_vec(),
            shared_auth: false,
        },
    );
    assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
}
