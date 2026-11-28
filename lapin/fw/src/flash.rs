//! The processor's own flash: 128 KB in 4 KB sectors. The last sector
//! holds the rabbit's settings; the rest is the firmware.
//!
//! While the flash erases or programs it cannot be read, so the code
//! that does it cannot live there: it is linked into the initialised
//! data and so copied to RAM at reset, and it runs with interrupts off
//! since their handlers are in the flash too.

use core::cell::UnsafeCell;

use crate::{irq, watchdog};

pub const BASE: usize = 0x0800_0000;
pub const SECTOR: usize = 4096;
/// Where the settings sector starts.
pub const SETTINGS: usize = BASE + 0x1_F000;

const FLACON: *mut u8 = 0xB700_0100 as *mut u8;
const COMMAND_1: *mut u8 = 0x0801_5554 as *mut u8;
const COMMAND_2: *mut u8 = 0x0800_AAA8 as *mut u8;
const WDTCON: *mut u8 = 0xB7E0_0000 as *mut u8;
const TBGCON: *mut u8 = 0xB7E0_0004 as *mut u8;
const INTST: *mut u8 = 0xB7E0_0008 as *mut u8;
const OVFAST: *mut u8 = 0xB7E0_000C as *mut u8;
const WDTCNT: *mut u16 = 0xB7E0_0010 as *mut u16;

// What follows runs from RAM while the flash is busy: it is placed in
// the initialised data (copied to RAM at reset), and must reach nothing
// in the flash, no call at all, not even a bounds check's panic or a
// `memcpy`. Hence raw pointers, volatile accesses, and functions forced
// inline into their two callers. `lapin/build.sh` checks the result:
// no branch out of the RAM code.

/// Wait for the flash's command to complete.
///
/// # Safety
/// Only from code running in RAM, interrupts off.
#[inline(always)]
unsafe fn flash_wait() {
    // SAFETY: a register of the processor.
    while unsafe { FLACON.read_volatile() } & 0x0E != 0x02 {}
}

/// The unlock sequence of a flash command, then the command.
///
/// # Safety
/// As [`flash_wait`]; the flash then runs the command.
#[inline(always)]
unsafe fn flash_command(command: u8) {
    // SAFETY: the command registers of the flash, the routine in RAM.
    unsafe {
        FLACON.write_volatile(0x03);
        COMMAND_1.write_volatile(0xAA);
        COMMAND_2.write_volatile(0x55);
        COMMAND_1.write_volatile(command);
    }
}

/// # Safety
/// As [`flash_wait`]; `at` is a sector of the flash, which is erased.
#[inline(always)]
unsafe fn erase_sector(at: *mut u8) {
    // SAFETY: as above; `at` is a sector of the flash.
    unsafe {
        flash_command(0x80);
        COMMAND_1.write_volatile(0xAA);
        COMMAND_2.write_volatile(0x55);
        at.write_volatile(0x30);
        flash_wait();
    }
}

/// Program one word (skipped when all ones, the erased value).
///
/// # Safety
/// As [`flash_wait`]; `at` is a word of the flash, erased.
#[inline(always)]
unsafe fn program_word(at: *mut u8, word: u32) {
    if word == u32::MAX {
        return;
    }
    // SAFETY: as above; `at` is word aligned in the flash.
    unsafe {
        flash_command(0xA0);
        at.write_volatile(word as u8);
        at.add(1).write_volatile((word >> 8) as u8);
        at.add(2).write_volatile((word >> 16) as u8);
        at.add(3).write_volatile((word >> 24) as u8);
        flash_wait();
    }
}

/// Erase the sector at `address` and program it with the 4096 bytes at
/// `data` (word aligned, outside the flash).
///
/// # Safety
/// Interrupts off; `address` is a sector of the flash other than the
/// running code's, `data` 4096 readable bytes outside the flash.
#[unsafe(link_section = ".data.ramcode")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn flash_sector_from_ram(address: usize, data: *const u32) {
    let at = address as *mut u8;
    // SAFETY: interrupts are off (the caller's duty), this runs from RAM.
    unsafe {
        erase_sector(at);
        let mut i = 0;
        while i < SECTOR / 4 {
            program_word(at.add(4 * i), data.add(i).read_volatile());
            i += 1;
        }
        FLACON.write_volatile(0x02);
    }
}

/// The word of `image` (`len` bytes) at `offset` as it goes in the
/// flash: past the image's end, erased.
///
/// # Safety
/// `image` is readable up to `len` rounded up to a word.
#[inline(always)]
unsafe fn image_word(image: *const u32, len: usize, offset: usize) -> u32 {
    if offset >= len {
        return u32::MAX;
    }
    // SAFETY: inside the image, as the caller says.
    let mut word = unsafe { image.add(offset / 4).read_volatile() };
    if len - offset < 4 {
        // The rest of the last word stays erased.
        word |= u32::MAX << (8 * (len - offset));
    }
    word
}

/// Rewrite the flash from the sector at `to` with the `len` bytes at
/// `image`, feeding the watchdog after every word, then restart on the
/// new image at once: the watchdog set to bite in a quarter of a
/// millisecond, as the C's `flash_uc` does.
///
/// A sector that already holds what it would be given is left alone
/// (the manual guarantees a hundred rewrites); the rest of the last
/// sector past the image is erased (the C keeps the old bytes there;
/// the header's length and CRC make them meaningless either way).
///
/// # Safety
/// Interrupts off for good; `image` is `len` readable bytes outside the
/// flash, word aligned; `to` a sector boundary, `to + len` at most the
/// start of the settings sector.
#[unsafe(link_section = ".data.ramcode")]
#[unsafe(no_mangle)]
#[inline(never)]
unsafe extern "C" fn flash_image_from_ram(image: *const u32, len: usize, to: usize) -> ! {
    // SAFETY: interrupts are off for good, this runs from RAM.
    unsafe {
        let mut sector = 0;
        while sector < len {
            let at = (to + sector) as *mut u8;
            let mut same = true;
            let mut offset = sector;
            while offset < sector + SECTOR {
                let now = (at.add(offset - sector) as *const u32).read_volatile();
                if now != image_word(image, len, offset) {
                    same = false;
                }
                offset += 4;
            }
            if !same {
                erase_sector(at);
                let mut offset = sector;
                while offset < sector + SECTOR && offset < len {
                    program_word(at.add(offset - sector), image_word(image, len, offset));
                    WDTCON.write_volatile(0xC3);
                    WDTCON.write_volatile(0x3C);
                    offset += 4;
                }
            }
            WDTCON.write_volatile(0xC3);
            WDTCON.write_volatile(0x3C);
            sector += SECTOR;
        }
        FLACON.write_volatile(0x02);
        // Restart now (watchdog::reset_now, which lives in the flash):
        // each register's key, then a microsecond a count, the counter
        // 256 counts from its end.
        INTST.write_volatile(0x3C);
        INTST.write_volatile(0x00);
        TBGCON.write_volatile(0x5A);
        TBGCON.write_volatile(0x40);
        OVFAST.write_volatile(0x63);
        WDTCON.write_volatile(0x3C);
        WDTCNT.write_volatile(0x5A5A);
        WDTCNT.write_volatile(0xFF00);
        // Nothing else may run: anything (even a spin hint) could be a
        // call into the flash just rewritten.
        #[allow(clippy::empty_loop)]
        loop {}
    }
}

unsafe extern "C" {
    static mut __ramcode_start: u32;
    static mut __ramcode_end: u32;
    static __ramcode_load: u32;
}

/// Copy the routines that run from RAM afresh from the flash, right
/// before they run: whatever wrote over the RAM since the start (a stray
/// write, an overflowing stack) never runs with the flash busy.
fn refresh_ramcode() {
    // SAFETY: the linker's bounds of the RAM routines and of their
    // copy in the flash, word aligned; nothing runs them meanwhile (the
    // callers hold interrupts back, and only they call them).
    unsafe {
        let mut to = &raw mut __ramcode_start;
        let end = &raw mut __ramcode_end;
        let mut from = &raw const __ramcode_load;
        while to < end {
            to.write_volatile(from.read_volatile());
            to = to.add(1);
            from = from.add(1);
        }
    }
    crate::sync::barrier();
}

/// Before the flash is rewritten for good: interrupts off, never to
/// come back, the watchdog's whole period ahead, the RAM routines
/// fresh.
#[inline(always)]
fn stop_for_rewrite() {
    irq::irq_disable();
    watchdog::feed();
    refresh_ramcode();
}

/// Replace the firmware with `image` and restart on it: the end of
/// this firmware. `image` must be word aligned and lie outside the
/// flash. An image that brings the rescue core in place rewrites the
/// application alone (see `boot::update_plan`); a damaged application
/// is refused, and the board restarts on what it had.
pub fn write_firmware(image: &[u8]) -> ! {
    let Some((to, part)) = crate::boot::update_plan(image) else {
        crate::watchdog::reset_now()
    };
    let len = part.len().min(SETTINGS - to);
    stop_for_rewrite();
    // SAFETY: interrupts are off for good, the routine runs from RAM
    // and never returns into the flash it rewrites; `to` is a sector
    // boundary and the length stops below the settings.
    unsafe { flash_image_from_ram(part.as_ptr().cast(), len, to) }
}

/// Write an application image after the rescue core (from the rescue
/// core itself), then restart on it. A damaged image is refused, and
/// the board restarts on what it had.
pub fn write_app(app: &[u8]) -> ! {
    let Some(len) = crate::boot::check_app(app) else {
        crate::watchdog::reset_now()
    };
    stop_for_rewrite();
    // SAFETY: as in `write_firmware`; the application's place starts on
    // a sector boundary and ends below the settings (checked).
    unsafe { flash_image_from_ram(app.as_ptr().cast(), len, crate::boot::APP_BASE) }
}

/// One sector's worth of scratch space, in the external RAM.
struct Scratch(UnsafeCell<[u32; SECTOR / 4]>);
// SAFETY: only used with interrupts off, by one caller at a time.
unsafe impl Sync for Scratch {}
#[unsafe(link_section = ".xram.flash")]
static SCRATCH: Scratch = Scratch(UnsafeCell::new([0; SECTOR / 4]));

/// The settings sector as it is now.
pub fn settings() -> &'static [u8; SECTOR] {
    // SAFETY: the sector is mapped, readable, and only changes inside
    // `write_settings`, which holds no such reference across the write.
    unsafe { &*(SETTINGS as *const [u8; SECTOR]) }
}

/// Replace the first bytes of the settings sector, keeping the rest.
/// Takes about 65 ms with interrupts off.
pub fn write_settings(data: &[u8]) {
    write_settings_at(0, data);
}

/// Replace bytes of the settings sector from `offset` on, keeping the
/// rest.
pub fn write_settings_at(offset: usize, data: &[u8]) {
    let offset = offset.min(SECTOR);
    let len = data.len().min(SECTOR - offset);
    irq::free(|| {
        watchdog::feed();
        refresh_ramcode();
        // SAFETY: interrupts are off, so nobody else is in the scratch
        // buffer; it is in RAM and word aligned, the address is the
        // settings sector, and the routine itself runs from RAM.
        unsafe {
            let scratch = SCRATCH.0.get().cast::<u8>();
            core::ptr::copy_nonoverlapping(SETTINGS as *const u8, scratch, SECTOR);
            core::ptr::copy_nonoverlapping(data.as_ptr(), scratch.add(offset), len);
            flash_sector_from_ram(SETTINGS, scratch.cast());
        }
        watchdog::feed();
    });
}
