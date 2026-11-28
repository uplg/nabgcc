//! Replacing the firmware over the air, the way clapier does it: the
//! server hands the rabbit a bytecode that carries the new image.

mod common;

use common::{artifact, on_network, open, serve_first, until, until_by, wait};
use nabemu::config;
use nabemu::elf::decode_sim;
use nabemu::soc::ResetCause;
use nabemu::{Event, Machine, metal};

fn sim(name: &str) -> Vec<u8> {
    decode_sim(&artifact(name)).expect("a .sim file")
}

/// A rabbit running the firmware under test whose server answers its
/// first request with a bytecode that flashes `new_image`, and the
/// following ones with a program that prints 4242.
fn rabbit_about_to_flash(new_image: &[u8]) -> Machine {
    let mut m = on_network(&nabemu::testing::image(), open());
    serve_first(&mut m, &metal::flash_firmware(new_image));
    m
}

#[test]
fn flashes_a_new_firmware_over_the_air_and_boots_it() {
    let new_image = sim("Nab0013.01ca89.sim");
    let mut m = rabbit_about_to_flash(&new_image);
    let settings = m.soc.flash[config::OFFSET..].to_vec();

    until(&mut m, 90_000, "reboot after the flash", |m| {
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
    until_by(&mut m, 180_000, 20, "second boot", |m| {
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
    let new_image = sim("Nab0013.01ca89.sim");
    let mut m = rabbit_about_to_flash(&new_image);
    // A third of the way through: sectors erased, the image half written.
    m.soc.cut_power_after_flash_ops = Some(8000);
    until(&mut m, 90_000, "the power cut", |m| !m.events.is_empty());
    // What the half-written image does next varies with the old image
    // left past the cut: it may never run, run into an undefined
    // instruction, or put a few stray bytes on the serial port. It
    // never comes back.
    assert_eq!(m.events[0], Event::Reset(ResetCause::PowerLoss));

    let said = m.soc.uart_tx.len();
    let asked = m.lan.as_ref().unwrap().requests.len();
    wait(&mut m, 60_000);
    let stray = &m.soc.uart_tx[said..];
    assert!(stray.len() < 16, "it spoke again: {stray:?}");
    assert_eq!(m.lan.as_ref().unwrap().requests.len(), asked);
    assert!(
        !m.radio.borrow().firmware_loaded,
        "it never woke its Wi-Fi stick"
    );
}
