//! The five RGB leds, behind a 16-channel constant-current driver.
//!
//! Each led takes three 7-bit current settings; all fifteen are
//! shifted to the driver in one go, most significant bit first.

use core::cell::Cell;

use crate::{board, irq, spi};

/// The leds as the bytecode numbers them.
pub const NOSE: usize = 0;
pub const LEFT: usize = 1;
pub const MIDDLE: usize = 2;
pub const RIGHT: usize = 3;
pub const BOTTOM: usize = 4;

/// The led at each place of the driver's chain (the nose is last).
const LED_AT: [usize; 5] = [MIDDLE, BOTTOM, LEFT, RIGHT, NOSE];

/// From an 8-bit colour component to a current setting: eyes do not
/// see brightness linearly.
const CURRENT: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 6, 6,
    6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 11, 11, 11, 11, 12, 12, 13, 13, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 17, 17, 18, 18, 19, 19, 19, 20, 20, 20, 21, 21, 22, 23, 23,
    24, 24, 25, 25, 25, 26, 26, 27, 27, 28, 29, 29, 30, 31, 31, 32, 32, 33, 34, 34, 35, 36, 36, 37,
    38, 38, 39, 40, 40, 41, 42, 42, 43, 44, 44, 45, 46, 47, 47, 48, 49, 50, 50, 51, 52, 54, 54, 55,
    56, 57, 57, 58, 59, 60, 61, 62, 63, 64, 65, 65, 67, 68, 69, 70, 70, 72, 73, 74, 75, 76, 77, 78,
    79, 80, 82, 83, 84, 85, 86, 87, 88, 89, 91, 92, 93, 95, 96, 96, 98, 99, 100, 102, 103, 105,
    106, 107, 109, 110, 111, 113, 114, 116, 117, 119, 120, 122, 123, 125, 126,
];

struct Settings(Cell<[[u8; 3]; 5]>);
// SAFETY: only touched with interrupts held back.
unsafe impl Sync for Settings {}
static SETTINGS: Settings = Settings(Cell::new([[0; 3]; 5]));

fn latch() {
    board::port4_set(board::LED_LATCH);
    board::port4_clear(board::LED_LATCH);
}

/// Switch every output on and every current to zero.
pub fn init() {
    board::port2_clear(board::LED_MODE);
    board::port4_clear(board::LED_LATCH);
    spi::LEDS.transfer(0xFF);
    spi::LEDS.transfer(0xFF);
    latch();
    board::port2_set(board::LED_MODE);
    board::port4_clear(board::LED_LATCH);
    for _ in 0..14 {
        spi::LEDS.transfer(0);
    }
    latch();
}

/// Set one led to a colour given as 0xRRGGBB.
pub fn set(led: usize, colour: u32) {
    let rgb =
        [(colour >> 16) as u8, (colour >> 8) as u8, colour as u8].map(|c| CURRENT[c as usize]);
    irq::free(|| {
        let mut all = SETTINGS.0.get();
        all[led % 5] = rgb;
        SETTINGS.0.set(all);
        board::port2_set(board::LED_MODE);
        board::port4_clear(board::LED_LATCH);
        // Fifteen 7-bit fields in fourteen bytes, in the chain's order,
        // the last seven bits zero.
        let mut bits = 0u32;
        let mut held = 0;
        for led in LED_AT {
            for value in all[led] {
                bits = bits << 7 | value as u32;
                held += 7;
                if held >= 8 {
                    held -= 8;
                    spi::LEDS.transfer((bits >> held) as u8);
                }
            }
        }
        spi::LEDS.transfer((bits << (8 - held)) as u8);
        latch();
    });
}

/// Set all five leds to the same colour.
pub fn set_all(colour: u32) {
    for led in 0..5 {
        set(led, colour);
    }
}
