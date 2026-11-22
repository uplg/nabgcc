//! Firmware for the Nabaztag:tag.

#![no_std]
#![no_main]

use lapin_fw::wifi::rt2573::{self, Stick, TxOptions};
use lapin_fw::{board, clock, halt, irq, led, spi, timer, uart, usb, watchdog};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    uart::write(b"PANIC\n");
    halt()
}

const AMBER: u32 = 0xFF8000;
const BLUE: u32 = 0x0000FF;

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    clock::init();
    board::init();
    irq::init();
    watchdog::start();
    timer::init();
    irq_enable_checked();
    spi::init();
    led::init();
    uart::init();
    uart::write(b"lapin 0.1\n");

    // The button at power-on asks for setup mode, as it always did.
    let setup = board::button();
    led::set_all(if setup { BLUE } else { AMBER });
    uart::write(if setup { b"setup\n" } else { b"run\n" });

    let stick = usb::init()
        .and_then(|()| usb::attach(3000))
        .and_then(|()| usb::enumerate())
        .map_err(rt2573::Error::Usb)
        .and_then(Stick::start);
    let mut stick = match stick {
        Ok(stick) => {
            uart::write(b"wifi ");
            for (i, byte) in stick.mac.iter().enumerate() {
                if i > 0 {
                    uart::write(b":");
                }
                uart::hex8(*byte);
            }
            uart::write(b" radio ");
            uart::hex8(stick.radio());
            uart::write(b"\n");
            Some(stick)
        }
        Err(rt2573::Error::Radio(radio)) => {
            // Not the radio chip this firmware knows how to tune.
            uart::write(b"wifi: radio ");
            uart::hex8(radio);
            uart::write(b"\n");
            None
        }
        Err(_) => {
            uart::write(b"wifi: no stick\n");
            None
        }
    };
    if let Some(stick) = &mut stick {
        look_around(stick);
    }

    let mut beat = 0u32;
    loop {
        watchdog::feed();
        let now = timer::millis();
        if now / 1000 != beat {
            beat = now / 1000;
            uart::write(b".");
            // A press of more than a second stops the feeding: a way to
            // watch the watchdog do its job.
            if !setup && board::button() {
                uart::write(b"\nhang\n");
                halt();
            }
        }
    }
}

/// Go through the channels once: ask who is there, and name every
/// network heard, with its channel.
fn look_around(stick: &mut Stick) {
    let mut probe = [0u8; 42];
    probe[0] = 0x40;
    probe[4..10].fill(0xFF);
    probe[10..16].copy_from_slice(&stick.mac);
    probe[16..22].fill(0xFF);
    // Any network; the rates we take.
    probe[24..].copy_from_slice(&[
        0, 0, 1, 8, 0x02, 0x04, 0x0B, 0x16, 0x24, 0x30, 0x48, 0x6C, 50, 4, 0x0C, 0x12, 0x18, 0x60,
    ]);
    let mut frame = [0u8; 512];
    for channel in 1..=13 {
        if stick.set_channel(channel).is_err() {
            return;
        }
        stick.transmit(&probe, &TxOptions::PLAIN);
        let start = timer::millis();
        while timer::millis().wrapping_sub(start) < 120 {
            watchdog::feed();
            let Some(got) = stick.receive(&mut frame) else {
                continue;
            };
            // Beacons and probe responses carry the name after 36 bytes.
            if got.len < 38 || (frame[0] != 0x80 && frame[0] != 0x50) || frame[36] != 0 {
                continue;
            }
            let name = &frame[38..got.len.min(38 + frame[37] as usize)];
            uart::write(if frame[0] == 0x80 {
                b"beacon "
            } else {
                b"answer "
            });
            uart::write(name);
            uart::write(b" channel ");
            uart::hex8(channel);
            uart::write(b"\n");
        }
    }
}

fn irq_enable_checked() {
    irq::irq_enable();
}
