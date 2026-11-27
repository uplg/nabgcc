//! Replacing the firmware over the air, the way clapier does it: the
//! server hands the rabbit a bytecode that carries the new image.

use std::cell::Cell;
use std::rc::Rc;

use nabemu::air::{AccessPoint, Security};
use nabemu::config::{self, Config, Wifi};
use nabemu::elf::decode_sim;
use nabemu::lan::{Lan, Response};
use nabemu::soc::ResetCause;
use nabemu::{Event, Machine, metal};

fn artifact(name: &str) -> Vec<u8> {
    let path = format!("{}/../../artifacts/{name}", env!("CARGO_MANIFEST_DIR"));
    decode_sim(&std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}")))
        .expect("a .sim file")
}

/// A rabbit running r3 whose server answers its first request with a
/// bytecode that flashes `new_image`, and the following ones with a
/// program that prints 4242.
fn rabbit_about_to_flash(new_image: &[u8]) -> Machine {
    let mut m = Machine::from_file(&nabemu::testing::image()).0;
    Config::new("Terrier", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::Open,
    ));
    let mut lan = Lan::new();
    let flasher = metal::boot_response(&metal::flash_firmware(new_image));
    let served = Rc::new(Cell::new(false));
    lan.handler = Box::new(move |_| {
        if served.replace(true) {
            Response::ok(metal::boot_response(&metal::print_number(4242)))
        } else {
            Response::ok(flasher.clone())
        }
    });
    m.lan = Some(lan);
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

#[test]
fn flashes_a_new_firmware_over_the_air_and_boots_it() {
    let new_image = artifact("Nab0013.01ca89.sim");
    let mut m = rabbit_about_to_flash(&new_image);
    let settings = m.soc.flash[config::OFFSET..].to_vec();

    run_until(&mut m, 90_000, "reboot after the flash", |m| {
        !m.events.is_empty()
    });
    assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
    assert_eq!(
        m.soc.flash[..new_image.len()],
        new_image[..],
        "the new image is in flash"
    );
    assert_eq!(
        m.soc.flash[config::OFFSET..],
        settings[..],
        "the settings survived"
    );
    assert_eq!(
        m.soc.flash_reads_while_busy, 0,
        "nothing ran from the flash while it was busy"
    );

    // The whole rewrite has to fit in one watchdog period (2.09 s): the
    // firmware does not feed the watchdog while it erases itself.
    let took = m.soc.flash_last_op - m.soc.flash_first_op.unwrap();
    eprintln!(
        "flash: {} erases, {} words, {took} ms",
        m.soc.flash_erases, m.soc.flash_programs
    );
    assert!(took < 2090, "the flash took {took} ms");

    // The new firmware comes up, joins, and asks the server again.
    run_until(&mut m, 180_000, "second boot", |m| {
        m.console().contains("4242")
    });
    assert_eq!(m.lan.as_ref().unwrap().requests.len(), 2);
    assert_eq!(m.resets, 1);
}

/// There is no bootloader: the firmware erases itself from the first
/// sector on, so a power cut during the rewrite leaves a rabbit that
/// cannot start. This test states that fact; it is the one to turn
/// around when a resident loader exists.
#[test]
fn a_power_cut_during_the_flash_leaves_a_dead_rabbit() {
    let new_image = artifact("Nab0013.01ca89.sim");
    let mut m = rabbit_about_to_flash(&new_image);
    // A third of the way through: sectors erased, the image half written.
    m.soc.cut_power_after_flash_ops = Some(8000);
    run_until(&mut m, 90_000, "the power cut", |m| !m.events.is_empty());
    // What the half-written image does next varies: it may never run,
    // or run into an undefined instruction. It never comes back.
    assert_eq!(m.events[0], Event::Reset(ResetCause::PowerLoss));

    let said = m.soc.uart_tx.len();
    let asked = m.lan.as_ref().unwrap().requests.len();
    m.run_until_ms(m.soc.millis() + 60_000);
    assert_eq!(m.soc.uart_tx.len(), said, "it never spoke again");
    assert_eq!(m.lan.as_ref().unwrap().requests.len(), asked);
    assert!(
        !m.radio.borrow().firmware_loaded,
        "it never woke its Wi-Fi stick"
    );
}
