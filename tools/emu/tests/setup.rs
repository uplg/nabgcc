//! Setup mode from the outside: someone joins the rabbit's own network
//! with a phone and uses its configuration pages.

use nabemu::air::{AccessPoint, ApEvent, Security};
use nabemu::config;
use nabemu::crypto::wpa_psk;
use nabemu::elf::decode_sim;
use nabemu::soc::ResetCause;
use nabemu::visitor::{Link, Visitor};
use nabemu::{DEFAULT_MAC, Event, Machine};

const PHONE: [u8; 6] = [0x02, 0, 0, 0, 0, 0xB2];

fn artifact(name: &str) -> Vec<u8> {
    let path = format!("{}/../../artifacts/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A rabbit started with its button held, and a phone looking for it.
fn in_setup_mode() -> Machine {
    let mut m = Machine::from_file(&artifact("Nab-wpa23-gtk-r3.sim")).0;
    m.soc.board.button = true;
    m.run_until_ms(2000);
    m.soc.board.button = false;
    m.visitor = Some(Visitor::new(PHONE, "Nabaztag"));
    m
}

fn run_until(m: &mut Machine, limit_ms: u64, what: &str, done: impl Fn(&Machine) -> bool) {
    while !done(m) {
        assert!(
            m.soc.millis() < limit_ms,
            "{what}: not within {limit_ms} ms\n{}",
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 20);
    }
}

fn phone(m: &Machine) -> &Visitor {
    m.visitor.as_ref().unwrap()
}

fn fetch(m: &mut Machine, target: &str) -> String {
    let before = phone(m).pages.len();
    m.visitor.as_mut().unwrap().get(target);
    let limit = m.soc.millis() + 30_000;
    run_until(m, limit, target, |m| phone(m).pages.len() > before);
    phone(m).pages[before].text()
}

#[test]
fn a_phone_joins_the_rabbit_and_reads_its_setup_page() {
    let mut m = in_setup_mode();
    run_until(&mut m, 30_000, "an address for the phone", |m| {
        phone(m).address.is_some()
    });
    let v = phone(&m);
    assert_eq!(v.link, Link::Associated);
    assert_eq!(v.network, Some(("Nabaztag01".to_string(), DEFAULT_MAC)));
    assert_eq!(v.server, Some([192, 168, 0, 1]));
    assert_eq!(v.address.unwrap()[..3], [192, 168, 0]);

    let page = fetch(&mut m, "/");
    assert!(page.starts_with("HTTP/1."), "{page}");
    assert!(page.contains("Save and start"), "{page}");
    assert!(
        page.contains("00:19:db:00:00:01") || page.contains("0019db000001"),
        "its address is on the page"
    );
    assert_eq!(m.events, []);
}

/// The whole first-time setup: fill in the page, and the rabbit leaves
/// setup mode and joins the network it was told about.
#[test]
fn settings_typed_in_the_page_take_the_rabbit_to_its_network() {
    let mut m = in_setup_mode();
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2("carotte-violette"),
    ));
    run_until(&mut m, 30_000, "an address for the phone", |m| {
        phone(m).address.is_some()
    });

    let page = fetch(&mut m, "/b?k=Terrier&m=64&n=carotte-violette&z=1");
    assert!(page.starts_with("HTTP/1."), "{page}");

    let joined = ApEvent::HandshakeComplete { sta: DEFAULT_MAC };
    run_until(&mut m, 120_000, "the rabbit on its network", |m| {
        m.air[0].events.contains(&joined)
    });

    let saved = &m.soc.flash[config::OFFSET..config::OFFSET + config::LENGTH];
    assert_eq!(saved[58..66], *b"Terrier\0");
    assert_eq!(saved[91], 64, "WPA2");
    assert_eq!(
        saved[175..207],
        wpa_psk("carotte-violette", "Terrier"),
        "the key was derived on the rabbit"
    );
    assert_eq!(m.events, []);
}

/// The firmware update page: post a `.sim`, the rabbit flashes itself
/// and restarts on the new image.
#[test]
fn a_firmware_posted_to_the_update_page_is_flashed() {
    let mut m = in_setup_mode();
    run_until(&mut m, 30_000, "an address for the phone", |m| {
        phone(m).address.is_some()
    });
    let page = fetch(&mut m, "/u.htm");
    assert!(page.contains("Firmware update"), "{page}");

    let sim = artifact("Nab0013.01ca89.sim");
    let image = decode_sim(&sim).unwrap();
    m.visitor.as_mut().unwrap().post("/c", &sim);
    run_until(&mut m, 300_000, "the reboot after the flash", |m| {
        !m.events.is_empty()
    });
    assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
    assert_eq!(m.soc.flash[..image.len()], image[..]);
}
