//! The released firmware driving the board: leds, button, setup mode.

use nabemu::board::{LED_BOTTOM, LED_NOSE};
use nabemu::{DEFAULT_MAC, Machine};

fn released() -> Machine {
    Machine::from_file(&nabemu::testing::image()).0
}

const AMBER: [u8; 3] = [126, 16, 0];
const BLUE: [u8; 3] = [0, 0, 126];
const WHITE: [u8; 3] = [126, 126, 126];

#[test]
fn leds_are_amber_while_it_looks_for_a_network() {
    let mut m = released();
    m.run_until_ms(3000);
    assert_eq!(m.soc.board.leds, [AMBER; 5]);
    assert!(m.soc.board.led_updates > 0);
}

/// Head button held while plugging in, then released: setup mode. The
/// rabbit turns blue and becomes an open access point named after the
/// last byte of its address.
#[test]
fn button_at_power_on_starts_setup_mode() {
    let mut m = released();
    m.soc.board.button = true;
    m.run_until_ms(2000);
    assert_eq!(m.soc.board.leds[LED_NOSE], BLUE);
    m.soc.board.button = false;
    m.run_until_ms(12_000);

    assert!(
        m.console().contains("-------------master"),
        "{}",
        m.console()
    );
    assert_eq!(m.soc.board.leds, [BLUE; 5]);
    let radio = m.radio.borrow();
    let beacons: Vec<_> = radio.tx.iter().filter(|f| f.data[0] == 0x80).collect();
    // One every 100 time units of 1.024 ms.
    let per_second = beacons.len() as f64 / 4.0;
    assert!(
        (5.0..=11.0).contains(&per_second),
        "{} beacons",
        beacons.len()
    );
    let beacon = &beacons.last().unwrap().data;
    assert_eq!(beacon[10..16], DEFAULT_MAC);
    assert_eq!(beacon[36..48], *b"\x00\x0aNabaztag01");
    assert_eq!(beacon[34] & 0x10, 0, "no encryption announced");
}

/// Held for more than seven seconds, the button starts the factory
/// test instead: everything white.
#[test]
fn button_held_seven_seconds_starts_the_factory_test() {
    let mut m = released();
    m.soc.board.button = true;
    m.run_until_ms(9000);
    assert_eq!(m.soc.board.leds, [WHITE; 5]);
    assert_eq!(m.soc.board.leds[LED_BOTTOM], WHITE);
    assert!(!m.console().contains("gomaster"));
}
