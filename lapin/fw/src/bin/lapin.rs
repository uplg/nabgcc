//! Firmware for the Nabaztag:tag: the board, the Wi-Fi stick, and the
//! Metal machine running the boot bytecode, as the C firmware did.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use lapin_core::rng::Pool;
use lapin_core::wifi::Station;
use lapin_fw::host::{Board, SCAN_RESULTS};
use lapin_fw::wifi::rt2573::Stick;
use lapin_fw::{board, clock, codec, ears, i2c, timer, uart, watchdog};
use lapin_metal::{Memory, ScanResult, Vm};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    lapin_fw::panicked()
}

/// The bytecode every rabbit starts with, as the r3 firmware carries it,
/// packed (`build.rs`): unpacked at power-on straight into the
/// machine's memory, where it runs.
static BOOT_PACKED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/boot.lz"));
const BOOT_LEN: usize = 28279;

#[unsafe(link_section = ".vmem")]
static mut MEMORY: Memory = Memory::ZEROED;
#[unsafe(link_section = ".xram.station")]
static mut STATION: MaybeUninit<Station> = MaybeUninit::uninit();
#[unsafe(link_section = ".xram.stick")]
static mut STICK: MaybeUninit<Stick> = MaybeUninit::uninit();
#[unsafe(link_section = ".xram.frame")]
static mut FRAME: [u8; 2400] = [0; 2400];
#[unsafe(link_section = ".xram_high.scan")]
static mut SCAN: [ScanResult; SCAN_RESULTS] = [lapin_fw::host::SCAN_NONE; SCAN_RESULTS];
#[unsafe(link_section = ".xram_high.inbox")]
static mut INBOX: [u8; lapin_fw::inbox::SIZE] = [0; lapin_fw::inbox::SIZE];

#[unsafe(no_mangle)]
extern "C" fn main() -> ! {
    lapin_fw::start::link();
    clock::init();
    lapin_fw::init();
    i2c::init();
    codec::init();
    ears::init();
    uart::init();
    uart::write(b"lapin 0.1\n");

    let mut vm = machine();
    // All of it comes out: build.rs unpacks it once to be sure.
    vm.boot_with(|memory| {
        lapin_core::lz::unpack(BOOT_PACKED, &mut memory[..BOOT_LEN]);
    });
    let mut confirmed = false;
    // The button held from the start for 20 seconds asks for the rescue
    // core (longer than the setup's 2 and the factory test's 8): the way
    // in for an application that starts but cannot take an update.
    let mut held = board::button();
    loop {
        vm.main_loop_once();
        held &= board::button();
        if held && timer::millis() > 20_000 {
            lapin_fw::boot::Slots::ask_rescue();
            watchdog::reset_now();
        }
        // A minute up: the application is well, the rescue core can
        // forget the restarts before (lapin_fw::boot).
        if !confirmed && timer::millis() > 60_000 {
            lapin_fw::boot::Slots::confirm();
            confirmed = true;
        }
    }
}

/// The machine on its board. Out of line: what building it takes on
/// the stack is given back before the bytecode runs, the machine alone
/// stays (in the internal RAM, where the collector wants it).
// `&mut *&raw mut` is how a static is borrowed once, by hand.
#[allow(clippy::deref_addrof)]
#[inline(never)]
fn machine() -> Vm<'static, Board> {
    // SAFETY: each of these is taken once, here, before anything else
    // can reach it.
    let (station, frame, scan, stick_slot, memory, inbox) = unsafe {
        (
            (*(&raw mut STATION)).write(Station::new()),
            &mut *(&raw mut FRAME),
            // Read only where a scan wrote it (`Board`): not cleared.
            &mut *(&raw mut SCAN),
            &mut *(&raw mut STICK),
            &mut *(&raw mut MEMORY),
            &mut *(&raw mut INBOX),
        )
    };

    let mut pool = Pool::new();
    // The volume wheel's last bits wander: a first handful of noise.
    for _ in 0..64 {
        pool.mix(board::volume() as u32 ^ timer::millis() << 8);
    }
    // The Wi-Fi stick comes up in the first turn of the main loop, as
    // in the C firmware: the bytecode starts at once, and sees the
    // network broken until then.
    let host = Board::new(stick_slot, station, pool, frame, scan, inbox);
    Vm::new(host, memory)
}
