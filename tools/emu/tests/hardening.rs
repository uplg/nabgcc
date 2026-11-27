//! lapin against what a review found could stop it for good: a Wi-Fi
//! stick that stops answering, a hostile visitor on the rescue network,
//! an image cut short. lapin only; skipped when it is not built.

use nabemu::Machine;
use nabemu::air::{AccessPoint, Security};
use nabemu::config::{Config, Wifi};
use nabemu::metal;
use nabemu::soc::ResetCause;
use nabemu::{Event, lan::Lan, lan::Response};

const RESCUE: usize = 20 * 1024;

fn image() -> Option<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../lapin/target/lapin-full.bin"
    );
    std::fs::read(path).ok().or_else(|| {
        eprintln!("skipped: lapin is not built");
        None
    })
}

fn until(m: &mut Machine, limit_ms: u64, what: &str, done: impl Fn(&Machine) -> bool) {
    let limit = m.soc.millis() + limit_ms;
    while !done(m) {
        assert!(
            m.soc.millis() < limit,
            "{what}: not within {limit_ms} ms\n{}",
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 20);
    }
}

fn on_open_network(image: &[u8]) -> Machine {
    let mut m = Machine::from_file(image).0;
    Config::new("Terrier", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::Open,
    ));
    m
}

/// The stick gone from under a running rabbit: its control transfers
/// time out, and taking one back waits 2 ms with interrupts held back.
/// That wait must end (it used to count on the tick it held back, and
/// fed the watchdog for ever).
#[test]
fn a_stick_that_stops_answering_never_freezes_the_rabbit() {
    let Some(image) = image() else { return };
    let mut m = on_open_network(&image);
    until(&mut m, 30_000, "the stick up", |m| {
        m.console().contains("wifi ")
    });
    m.run_until_ms(m.soc.millis() + 3000);
    m.soc.ohci.device = None;
    for second in 0..20 {
        let mut open = false;
        for _ in 0..100 {
            m.run_until_ms(m.soc.millis() + 10);
            open |= m.cpu.cpsr & 0x80 == 0;
        }
        assert!(
            open || !m.events.is_empty(),
            "second {second} after the stick went: interrupts held back all along"
        );
    }
}

/// A file cut inside the rescue core, sent as a firmware: refused with
/// nothing erased (it used to rewrite the whole flash from sector 0).
#[test]
fn an_image_cut_short_is_refused_with_nothing_erased() {
    let Some(image) = image() else { return };
    for cut in [8192, RESCUE, RESCUE + 4096] {
        let mut m = on_open_network(&image);
        let mut lan = Lan::new();
        let flasher = metal::boot_response(&metal::flash_firmware(&image[..cut]));
        lan.handler = Box::new(move |_| Response::ok(flasher.clone()));
        m.lan = Some(lan);
        let before = m.soc.flash.clone();
        until(&mut m, 60_000, "the restart", |m| !m.events.is_empty());
        assert_eq!(
            m.events[0],
            Event::Reset(ResetCause::Watchdog),
            "cut at {cut}"
        );
        assert_eq!(m.soc.flash_erases, 0, "cut at {cut}: something erased");
        assert!(m.soc.flash == before, "cut at {cut}: the flash changed");
    }
}

/// A whole image with a rescue core other than the one in place, its
/// trailer damaged: refused too.
#[test]
fn a_new_rescue_core_that_is_damaged_is_refused() {
    let Some(image) = image() else { return };
    let mut other = image.clone();
    // Another core: a byte changed in its padding (the trailer's CRC no
    // longer holds, and it is not the core in place).
    other[RESCUE - 100] ^= 0x55;
    let mut m = on_open_network(&image);
    let mut lan = Lan::new();
    let flasher = metal::boot_response(&metal::flash_firmware(&other));
    lan.handler = Box::new(move |_| Response::ok(flasher.clone()));
    m.lan = Some(lan);
    until(&mut m, 60_000, "the restart", |m| !m.events.is_empty());
    assert_eq!(m.soc.flash_erases, 0, "something erased");
}

/// The same, with the trailer right: the whole flash rewritten (a new
/// rescue core is allowed in when it is whole).
#[test]
fn a_new_rescue_core_that_is_whole_is_written() {
    let Some(image) = image() else { return };
    let mut other = image.clone();
    other[RESCUE - 100] ^= 0x55;
    let crc = crc32(&other[..RESCUE - 8]);
    other[RESCUE - 4..RESCUE].copy_from_slice(&crc.to_le_bytes());
    let mut m = on_open_network(&image);
    let mut lan = Lan::new();
    let flasher = metal::boot_response(&metal::flash_firmware(&other));
    lan.handler = Box::new(move |_| Response::ok(flasher.clone()));
    m.lan = Some(lan);
    until(&mut m, 60_000, "the restart", |m| !m.events.is_empty());
    assert!(
        m.soc.flash[..other.len()] == other[..],
        "the new image in place"
    );
    assert!(
        m.soc.flash_erases > (RESCUE / 4096) as u64,
        "the core rewritten too"
    );
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

mod rescue_network {
    use super::*;
    use nabemu::rt2573::RxFrame;
    use nabemu::visitor::Visitor;

    const PHONE: [u8; 6] = [2, 0, 0, 0, 0, 0xB2];

    fn phone(m: &Machine) -> &Visitor {
        m.visitor.as_ref().unwrap()
    }

    /// A rabbit whose application is gone, on its rescue network, a
    /// phone on it with an address.
    fn rescued(image: &[u8]) -> Machine {
        let mut m = Machine::from_file(image).0;
        m.soc.flash[RESCUE..RESCUE + 4096].fill(0xFF);
        until(&mut m, 20_000, "the rescue network", |m| {
            m.console().contains("secours: network up")
        });
        m.visitor = Some(Visitor::new(PHONE, "Nabaztag-secours"));
        until(&mut m, 60_000, "an address", |m| phone(m).address.is_some());
        m
    }

    /// A length that wraps past the end of the request: refused, where
    /// it used to panic the rescue core into a restart.
    #[test]
    fn a_wrapping_content_length_is_refused() {
        let Some(image) = image() else { return };
        let mut m = rescued(&image);
        m.visitor
            .as_mut()
            .unwrap()
            .post("/flash HTTP/1.0\r\nContent-Length: 4294967295\r\nX:", b"");
        until(&mut m, 30_000, "the answer", |m| !phone(m).pages.is_empty());
        let page = phone(&m).pages[0].text();
        assert!(page.contains("400"), "{page}");
        assert_eq!(m.events, [], "{}", m.console());
    }

    /// Larger than the rescue core can hold: refused at once.
    #[test]
    fn an_upload_too_big_is_refused_at_once() {
        let Some(image) = image() else { return };
        let mut m = rescued(&image);
        m.visitor
            .as_mut()
            .unwrap()
            .post("/flash HTTP/1.0\r\nContent-Length: 200000\r\nX:", b"");
        until(&mut m, 30_000, "the answer", |m| !phone(m).pages.is_empty());
        assert!(phone(&m).pages[0].text().contains("400"));
    }

    /// A SYN from another port of the same phone in the middle of an
    /// upload (a browser's spare connection) leaves the upload alone.
    #[test]
    fn a_second_connection_does_not_drop_an_upload() {
        let Some(image) = image() else { return };
        let mut m = rescued(&image);
        m.visitor.as_mut().unwrap().post("/flash", &image);
        m.run_until_ms(m.soc.millis() + 200);
        assert!(phone(&m).pages.is_empty(), "the upload is already over");
        let ip = phone(&m).address.unwrap();
        let bssid = phone(&m).network.as_ref().unwrap().1;
        m.radio
            .borrow_mut()
            .rx
            .push_back(RxFrame::new(syn(bssid, ip, 50_000)));
        until(&mut m, 60_000, "the upload's answer", |m| {
            !phone(m).pages.is_empty()
        });
        let page = phone(&m).pages[0].text();
        assert!(page.contains("200 OK"), "{page}");
    }

    /// A TCP SYN to port 80 from `port`, as an 802.11 data frame.
    fn syn(bssid: [u8; 6], ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut f = vec![0x08, 0x01, 0, 0];
        f.extend(bssid);
        f.extend(PHONE);
        f.extend(bssid);
        f.extend([0x10, 0x00]);
        f.extend([0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00]);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&port.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02;
        tcp[14..16].copy_from_slice(&8192u16.to_be_bytes());
        let mut ipv4 = vec![0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0];
        ipv4.extend(ip);
        ipv4.extend([192, 168, 0, 1]);
        let sum = checksum(&ipv4);
        ipv4[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut pseudo = ipv4[12..20].to_vec();
        pseudo.extend([0, 6, 0, 20]);
        pseudo.extend(&tcp);
        let sum = checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        f.extend(ipv4);
        f.extend(tcp);
        f
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut s = 0u32;
        for c in data.chunks(2) {
            s += (c[0] as u32) << 8 | *c.get(1).unwrap_or(&0) as u32;
        }
        while s > 0xFFFF {
            s = (s & 0xFFFF) + (s >> 16);
        }
        !(s as u16)
    }

    /// The button held for 20 seconds from the start asks a working
    /// application for the rescue core; a phone that joins and goes
    /// without a word does not keep the rabbit there: ten minutes
    /// later it is back on its application.
    #[test]
    fn the_button_asks_for_the_rescue_core_and_a_vanished_phone_does_not_keep_it() {
        let Some(image) = image() else { return };
        let mut m = on_open_network(&image);
        m.soc.board.button = true;
        until(&mut m, 40_000, "the rescue core asked for", |m| {
            m.console().contains("secours: asked for")
        });
        m.soc.board.button = false;
        assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
        until(&mut m, 20_000, "the rescue network", |m| {
            m.console().contains("secours: network up")
        });
        m.visitor = Some(Visitor::new(PHONE, "Nabaztag-secours"));
        until(&mut m, 60_000, "an address", |m| phone(m).address.is_some());
        m.visitor.as_mut().unwrap().get("/");
        until(&mut m, 30_000, "the page", |m| !phone(m).pages.is_empty());
        // Gone, without a deauthentication.
        m.visitor = None;
        until(&mut m, 11 * 60_000, "back to the application", |m| {
            m.console().contains("secours: back to the application")
        });
        until(&mut m, 30_000, "the application", |m| {
            let c = m.console();
            c[c.rfind("secours: back").unwrap()..].contains("lapin 0.1")
        });
    }
}
