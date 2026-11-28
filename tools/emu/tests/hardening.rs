//! lapin against what a review found could stop it for good: a Wi-Fi
//! stick that stops answering, a hostile visitor on the rescue network,
//! an image cut short. lapin only; skipped when it is not built.

mod common;

use common::{RESCUE, lapin, ms, on_network, open, restarted, serving, until, wait};
use nabemu::crypto::crc32;
use nabemu::metal;
use nabemu::soc::ResetCause;
use nabemu::{Event, Machine};

/// A rabbit on the open network, no server behind it.
fn on_open_network(image: &[u8]) -> Machine {
    on_network(image, open())
}

fn stick_up(m: &mut Machine) {
    until(m, 30_000, "the stick up", |m| m.console().contains("wifi "));
}

/// A whole image with a rescue core other than the one in place: a
/// byte changed in its padding (the trailer's CRC no longer holds, and
/// it is not the core in place).
fn with_another_core(image: &[u8]) -> Vec<u8> {
    let mut other = image.to_vec();
    other[RESCUE - 100] ^= 0x55;
    other
}

/// `image` served a bytecode that flashes `new`, run to its restart;
/// and its flash before.
fn flashed(image: &[u8], new: &[u8]) -> (Machine, Vec<u8>) {
    let mut m = serving(image, &metal::flash_firmware(new));
    let before = m.soc.flash.clone();
    until(&mut m, 60_000, "the restart", restarted);
    (m, before)
}

/// The stick gone from under a running rabbit: its control transfers
/// time out, and taking one back waits 2 ms with interrupts held back.
/// That wait must end (it used to count on the tick it held back, and
/// fed the watchdog for ever).
#[test]
fn a_stick_that_stops_answering_never_freezes_the_rabbit() {
    let Some(image) = lapin() else { return };
    let mut m = on_open_network(&image);
    stick_up(&mut m);
    wait(&mut m, 3000);
    m.soc.ohci.device = None;
    for second in 0..20 {
        let mut open = false;
        for _ in 0..100 {
            wait(&mut m, 10);
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
    let Some(image) = lapin() else { return };
    for cut in [8192, RESCUE, RESCUE + 4096] {
        let (m, before) = flashed(&image, &image[..cut]);
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
    let Some(image) = lapin() else { return };
    let (m, _) = flashed(&image, &with_another_core(&image));
    assert_eq!(m.soc.flash_erases, 0, "something erased");
}

/// The same, with the trailer right: the whole flash rewritten (a new
/// rescue core is allowed in when it is whole).
#[test]
fn a_new_rescue_core_that_is_whole_is_written() {
    let Some(image) = lapin() else { return };
    let mut other = with_another_core(&image);
    let crc = crc32(&other[..RESCUE - 8]);
    other[RESCUE - 4..RESCUE].copy_from_slice(&crc.to_le_bytes());
    let (m, _) = flashed(&image, &other);
    assert!(
        m.soc.flash[..other.len()] == other[..],
        "the new image in place"
    );
    assert!(m.soc.flash_erases > 0, "the core rewritten too");
}

mod rescue_network {
    use super::*;
    use common::{
        PHONE, frame, page, phone, phone_on_the_rescue_network, rescue_network_up,
        without_application,
    };
    use nabemu::rt2573::RxFrame;

    /// A rabbit whose application is gone, on its rescue network, a
    /// phone on it with an address.
    fn rescued(image: &[u8]) -> Machine {
        let mut m = without_application(image);
        phone_on_the_rescue_network(&mut m);
        m
    }

    /// The rescue network's beacons as phones expect them: the rates of
    /// 802.11b, the channel, and a TIM (the standard requires one in a
    /// beacon; it had none).
    #[test]
    fn the_rescue_beacon_carries_rates_and_a_tim() {
        let Some(image) = lapin() else { return };
        let mut m = without_application(&image);
        wait(&mut m, 500);
        let radio = m.radio.borrow();
        let beacon = radio
            .tx
            .iter()
            .map(|t| t.data.clone())
            .find(|f| f.first() == Some(&0x80))
            .expect("a beacon");
        let mut ies = std::collections::BTreeMap::new();
        let mut at = 36;
        while at + 2 <= beacon.len() {
            let (id, len) = (beacon[at], beacon[at + 1] as usize);
            ies.insert(id, beacon[at + 2..at + 2 + len].to_vec());
            at += 2 + len;
        }
        assert_eq!(ies[&1], [0x82, 0x04, 0x0B, 0x16], "rates");
        assert_eq!(ies[&3], [1], "channel");
        assert_eq!(ies[&5], [0, 1, 0, 0], "TIM");
    }

    /// A length that wraps past the end of the request: refused, where
    /// it used to panic the rescue core into a restart.
    #[test]
    fn a_wrapping_content_length_is_refused() {
        let Some(image) = lapin() else { return };
        let mut m = rescued(&image);
        let page = page(&mut m, 30_000, |v| {
            v.post("/flash HTTP/1.0\r\nContent-Length: 4294967295\r\nX:", b"")
        });
        assert!(page.contains("400"), "{page}");
        assert_eq!(m.events, [], "{}", m.console());
    }

    /// Larger than the rescue core can hold: refused at once.
    #[test]
    fn an_upload_too_big_is_refused_at_once() {
        let Some(image) = lapin() else { return };
        let mut m = rescued(&image);
        let page = page(&mut m, 30_000, |v| {
            v.post("/flash HTTP/1.0\r\nContent-Length: 200000\r\nX:", b"")
        });
        assert!(page.contains("400"), "{page}");
    }

    /// A SYN from another port of the same phone in the middle of an
    /// upload (a browser's spare connection) leaves the upload alone.
    #[test]
    fn a_second_connection_does_not_drop_an_upload() {
        let Some(image) = lapin() else { return };
        let mut m = rescued(&image);
        m.visitor.as_mut().unwrap().post("/flash", &image);
        wait(&mut m, 200);
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
        let mut f = frame(
            [0x08, 0x01],
            bssid,
            PHONE,
            bssid,
            &[0x10, 0x00, 0xAA, 0xAA, 3, 0, 0, 0, 0x08, 0x00],
        );
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
        let sum = nabemu::lan::checksum(&ipv4);
        ipv4[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut pseudo = ipv4[12..20].to_vec();
        pseudo.extend([0, 6, 0, 20]);
        pseudo.extend(&tcp);
        let sum = nabemu::lan::checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        f.extend(ipv4);
        f.extend(tcp);
        f
    }

    /// The button held for 20 seconds from the start asks a working
    /// application for the rescue core; a phone that joins and goes
    /// without a word does not keep the rabbit there: ten minutes
    /// later it is back on its application.
    #[test]
    fn the_button_asks_for_the_rescue_core_and_a_vanished_phone_does_not_keep_it() {
        let Some(image) = lapin() else { return };
        let mut m = on_open_network(&image);
        m.soc.board.button = true;
        until(&mut m, 40_000, "the rescue core asked for", |m| {
            m.console().contains("secours: asked for")
        });
        m.soc.board.button = false;
        assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
        rescue_network_up(&mut m);
        phone_on_the_rescue_network(&mut m);
        page(&mut m, 30_000, |v| v.get("/"));
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

/// A stick that stops taking frames to send: for a few seconds, the
/// frames caught in it are dropped and the rabbit sends again once it
/// takes them; for good, the rabbit starts again from scratch, which
/// brings the stick up anew. Before, one transfer that never went left
/// the rabbit mute for good.
#[test]
fn a_stick_that_stops_sending_is_got_going_again() {
    let Some(image) = lapin() else { return };
    let mut m = on_open_network(&image);
    stick_up(&mut m);
    wait(&mut m, 5000);

    // A while.
    m.radio.borrow_mut().tx_stuck = true;
    wait(&mut m, 3000);
    m.radio.borrow_mut().tx_stuck = false;
    let sent = m.radio.borrow().tx.len();
    until(&mut m, 20_000, "a frame sent again", |m| {
        m.radio.borrow().tx.len() > sent
    });
    assert_eq!(m.events, [], "a short stall needs no restart");

    // For good.
    m.radio.borrow_mut().tx_stuck = true;
    until(&mut m, 40_000, "the restart", restarted);
    assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
}

/// The routines that write the flash sit in the internal RAM from the
/// start: overwritten there since (a stray write), an update still
/// goes through, as they are copied afresh from the flash first.
#[test]
fn flash_routines_overwritten_in_ram_still_write_the_update() {
    let Some(image) = lapin() else { return };
    // Another application than the one in place (the same one would
    // leave every sector as it is).
    let Some(image_after) = common::lapin_target("selftest-full.bin") else {
        return;
    };
    let mut m = serving(&image, &metal::flash_firmware(&image_after));
    let image = image_after;
    stick_up(&mut m);
    // Both routines, from the first word of the RAM after the slots.
    m.soc.iram[0x10..0x150].fill(0xA5);
    until(&mut m, 60_000, "the restart", restarted);
    assert_eq!(m.events[0], Event::Reset(ResetCause::Watchdog));
    assert!(m.soc.flash_erases > 0, "nothing written");
    assert!(
        m.soc.flash[..image.len()] == image[..],
        "the image in place"
    );
}

/// A tag reader that holds the I2C bus, under a bytecode asking for
/// tags all the time: each wait on it gives up within milliseconds and
/// is not tried again, so interrupts are never held back long and the
/// rabbit keeps running (the C hangs on it; lapin used to restart over
/// and over, the watchdog starved by a thousand tries of each).
#[test]
fn a_jammed_i2c_bus_never_holds_interrupts_back_long() {
    let Some(image) = lapin() else { return };
    // A bytecode that asks the reader for a tag, again and again.
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.extend([metal::OP_RFID_GET, metal::OP_DROP, 28, 0, 0]);
    let mut m = serving(&image, &metal::bytecode(&[], &f));
    until(&mut m, 60_000, "the polling bytecode", |m| {
        !m.lan.as_ref().unwrap().requests.is_empty()
    });
    wait(&mut m, 2000);
    m.masked_longest = 0;
    let exchanges = m.soc.board.rfid.exchanges;
    m.soc.i2c_jammed = true;
    wait(&mut m, 20_000);
    assert!(exchanges > 0, "the reader was never asked");
    assert_eq!(m.events, []);
    let ms = ms(m.masked_longest);
    eprintln!("interrupts held back {ms} ms at most");
    assert!(ms < 20, "interrupts held back {ms} ms");
}
