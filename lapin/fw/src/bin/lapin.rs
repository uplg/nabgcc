//! Firmware for the Nabaztag:tag: the board, the Wi-Fi stick, and the
//! Metal machine running the boot bytecode, as the C firmware did.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use lapin_core::rng::Pool;
use lapin_core::wifi::Station;
use lapin_fw::host::{Board, SCAN_RESULTS};
use lapin_fw::wifi::rt2573::{self, Stick};
use lapin_fw::{board, clock, codec, ears, i2c, irq, led, spi, timer, uart, usb, watchdog};
use lapin_metal::{Memory, ScanResult, Vm};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    lapin_fw::panicked()
}

/// The bytecode every rabbit starts with, as the r3 firmware carries it.
static BOOT: &[u8] = include_bytes!("../boot.bc");

#[unsafe(link_section = ".vmem")]
static mut MEMORY: Memory = Memory::new();
#[unsafe(link_section = ".xram.station")]
static mut STATION: MaybeUninit<Station> = MaybeUninit::uninit();
#[unsafe(link_section = ".xram.stick")]
static mut STICK: MaybeUninit<Stick> = MaybeUninit::uninit();
#[unsafe(link_section = ".xram.frame")]
static mut FRAME: [u8; 2400] = [0; 2400];
#[unsafe(link_section = ".xram.scan")]
static mut SCAN: MaybeUninit<[ScanResult; SCAN_RESULTS]> = MaybeUninit::uninit();

// `&mut *&raw mut` is how a static is borrowed once, by hand.
#[allow(clippy::deref_addrof)]
#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    clock::init();
    board::init();
    irq::init();
    watchdog::start();
    timer::init();
    irq::irq_enable();
    spi::init();
    led::init();
    i2c::init();
    codec::init();
    ears::init();
    uart::init();
    uart::write(b"lapin 0.1\n");

    // SAFETY: each of these is taken once, here, before anything else
    // can reach it.
    let (station, frame, scan, stick_slot, memory) = unsafe {
        (
            (*(&raw mut STATION)).write(Station::new()),
            &mut *(&raw mut FRAME),
            (*(&raw mut SCAN)).write([lapin_fw::host::SCAN_NONE; SCAN_RESULTS]),
            &mut *(&raw mut STICK),
            &mut *(&raw mut MEMORY),
        )
    };

    let stick = usb::init()
        .and_then(|()| usb::attach(3000))
        .and_then(|()| usb::enumerate())
        .map_err(rt2573::Error::Usb)
        .and_then(Stick::start);
    let stick = match stick {
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
            Some(&mut *stick_slot.write(stick))
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

    let mut pool = Pool::new();
    // The volume wheel's last bits wander: a first handful of noise.
    for _ in 0..64 {
        pool.mix(board::volume() as u32 ^ timer::millis() << 8);
    }
    if let Some(stick) = &stick {
        pool.mix(u32::from_le_bytes([
            stick.mac[2],
            stick.mac[3],
            stick.mac[4],
            stick.mac[5],
        ]));
    }

    let host = Board::new(stick, station, pool, frame, scan);
    let mut vm = Vm::new(host, memory);
    vm.boot(BOOT);
    loop {
        vm.main_loop_once();
    }
}
