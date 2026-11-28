//! Setup mode from the outside: someone joins the rabbit's own network
//! with a phone and uses its configuration pages.

mod common;

use common::{PASSPHRASE, artifact, page, phone, phone_gets_an_address, until_by};
use nabemu::config;
use nabemu::crypto::wpa_psk;
use nabemu::elf::decode_sim;
use nabemu::soc::ResetCause;
use nabemu::visitor::Link;
use nabemu::{DEFAULT_MAC, Event, Machine};

/// A rabbit started with its button held, and a phone looking for it.
fn in_setup_mode() -> Machine {
    common::in_setup_mode(&nabemu::testing::image())
}

fn fetch(m: &mut Machine, target: &str) -> String {
    page(m, 30_000, |v| v.get(target))
}

#[test]
fn a_phone_joins_the_rabbit_and_reads_its_setup_page() {
    let mut m = in_setup_mode();
    phone_gets_an_address(&mut m);
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
    let (m, page) = common::set_up_from_the_page(&nabemu::testing::image());
    assert!(page.starts_with("HTTP/1."), "{page}");

    let saved = &m.soc.flash[config::OFFSET..config::OFFSET + config::LENGTH];
    assert_eq!(saved[58..66], *b"Terrier\0");
    assert_eq!(saved[91], 64, "WPA2");
    assert_eq!(
        saved[175..207],
        wpa_psk(PASSPHRASE, "Terrier"),
        "the key was derived on the rabbit"
    );
    assert_eq!(m.events, []);
}

/// The firmware update page: post a `.sim`, the rabbit flashes itself
/// and restarts on the new image.
#[test]
fn a_firmware_posted_to_the_update_page_is_flashed() {
    let mut m = in_setup_mode();
    phone_gets_an_address(&mut m);
    let page = fetch(&mut m, "/u.htm");
    assert!(page.contains("Firmware update"), "{page}");

    let sim = artifact("Nab0013.01ca89.sim");
    let image = decode_sim(&sim).unwrap();
    m.visitor.as_mut().unwrap().post("/c", &sim);
    until_by(&mut m, 300_000, 20, "the reboot after the flash", |m| {
        !m.events.is_empty()
    });
    assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
    assert_eq!(m.soc.flash[..image.len()], image[..]);
}
