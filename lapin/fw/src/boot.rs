//! How the flash is shared between the rescue core and the application.
//!
//! The rescue core (`bin/rescue.rs`) holds the first 20 KB: the
//! processor's vectors, and a mode that raises a Wi-Fi network of its
//! own to take a new image when the application is missing, damaged,
//! or keeps restarting. An update that brings the same rescue core
//! rewrites the application alone, so a power cut in the middle no
//! longer kills the rabbit.
//!
//! The application (the firmware proper: `bin/lapin.rs`, and the bench
//! and self-test) starts at [`APP_BASE`] with a header the rescue core
//! checks before handing over:
//!
//! | Word | |
//! |---|---|
//! | 0 | [`MAGIC`] |
//! | 1 | length in bytes, header included |
//! | 2 | CRC-32 of word 3 and everything after it (filled in by `build.sh`) |
//! | 3 | address of its reset code, inside the application |
//!
//! A whole image (`lapin-full.bin`) is the rescue core, padded to
//! [`RESCUE_SIZE`] and ending on a trailer of its own ([`RESCUE_MAGIC`],
//! then the CRC-32 of the bytes before it), then the application.
//!
//! The first image, which the C firmware writes once (`lapin-first.bin`,
//! from `lapin/pack`), is the same rescue core followed by the
//! application packed (`lapin_core::pack`, about two thirds of its
//! size), so that the C firmware's write, with the watchdog unfed, is
//! short. At its first start the rescue core finds no application but
//! the packed one ([`packed_app`]), unpacks it into the external RAM,
//! checks it, and writes it (`rescue::install_packed`).
//!
//! The two share four words at the bottom of the internal RAM, which
//! neither one's startup clears: see [`Slots`].

use crate::flash;

/// The application's first byte.
pub const APP_BASE: usize = flash::BASE + RESCUE_SIZE;
/// What the rescue core takes.
pub const RESCUE_SIZE: usize = 20 * 1024;
/// Where the application must end: the settings sector follows.
pub const APP_END: usize = flash::SETTINGS;
pub const HEADER_LEN: usize = 16;
/// "LAPA", little-endian.
pub const MAGIC: u32 = 0x4150_414C;
/// "LAPR", little-endian: the rescue core's trailer.
pub const RESCUE_MAGIC: u32 = 0x5250_414C;
/// The bytes at the start of an image that say it is lapin's (the
/// vectors and the first of the rescue core).
const SIGNATURE: usize = 64;

/// Restarts in a row without the application saying it is well, after
/// which the rescue core takes over.
pub const MAX_FAILED_BOOTS: u32 = 3;
/// What [`Slots::count_boot`] gives when the rescue core was asked for.
pub const ASKED: u32 = u32::MAX;

/// The words at the bottom of the internal RAM, kept across a restart
/// (not always across a power cut, which INTST's RSTSTATUS tells apart:
/// [`Slots::count_boot`]): `SLOT_MAGIC` there when the rest is
/// meaningful (`FRESH` when the next start counts 0), the restarts since the application last said it was
/// well, and where the vectors of the rescue core send interrupts and
/// undefined instructions.
pub struct Slots;

const SLOTS: usize = 0x1000_0000;
const SLOT_MAGIC: u32 = 0x5A17_B007;
/// In the first word instead: the next start counts 0.
const FRESH: u32 = 0xF2E5_B007;

fn slot(i: usize) -> crate::reg::Reg<u32> {
    // SAFETY: the four words below the linker's RAM, reserved for this
    // (see common.x); like a register, they are only ever accessed
    // volatile.
    unsafe { crate::reg::Reg::at(SLOTS + 4 * i) }
}

/// The words meaningful, with `restarts` counted.
fn mark(restarts: u32) {
    slot(0).write(SLOT_MAGIC);
    slot(1).write(restarts);
}

impl Slots {
    /// Count one more start; returns how many in a row the application
    /// has had without saying it was well. `bitten`: the watchdog made
    /// this reset ([`crate::watchdog::bit_last`]). A power-on counts 0,
    /// whatever the RAM kept; a watchdog reset whose words were lost
    /// counts 1.
    pub fn count_boot(bitten: bool) -> u32 {
        let n = match slot(0).read() {
            _ if !bitten => 0,
            SLOT_MAGIC => slot(1).read().saturating_add(1),
            FRESH => 0,
            _ => 1,
        };
        mark(n);
        n
    }

    /// Start afresh, as after a power cut: the next start counts 0 (the
    /// rescue core handing back to the application gives it its three
    /// tries again).
    pub fn fresh() {
        slot(0).write(FRESH);
    }

    /// Have the rescue core take over at the next start (the gesture
    /// that asks for it, in the application).
    pub fn ask_rescue() {
        mark(ASKED);
    }

    /// The application runs well: forget the restarts.
    pub fn confirm() {
        mark(0);
    }
}

/// CRC-32 (`lapin_core::pack::crc32`), the watchdog fed every 4 KB: the
/// words of `data` a load each (the flash and the RAM take an aligned
/// word in one access), the odd bytes at its ends one by one.
pub fn crc32(data: &[u8]) -> u32 {
    use lapin_core::pack::{crc_bytes, crc_table, crc_words};
    let table = crc_table();
    // SAFETY: any four bytes are a `u32`; `align_to` gives the words
    // only where they are aligned.
    let (head, words, tail) = unsafe { data.align_to::<u32>() };
    let mut c = crc_bytes(&table, !0, head);
    for chunk in words.chunks(1024) {
        crate::watchdog::feed();
        c = crc_words(&table, c, chunk);
    }
    !crc_bytes(&table, c, tail)
}

fn word(image: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(image.get(at..at + 4)?.try_into().ok()?))
}

/// An application image, from its header: its length if it is whole,
/// its reset address inside it.
pub fn check_app(image: &[u8]) -> Option<usize> {
    if word(image, 0)? != MAGIC {
        return None;
    }
    let len = word(image, 4)? as usize;
    if !(HEADER_LEN..=APP_END - APP_BASE).contains(&len) || len > image.len() {
        return None;
    }
    let entry = (word(image, 12)? as usize).wrapping_sub(APP_BASE);
    if !(HEADER_LEN..len).contains(&entry) || entry % 4 != 0 {
        return None;
    }
    (crc32(&image[12..len]) == word(image, 8)?).then_some(len)
}

/// A rescue core, padded and with its trailer: whether it is whole.
pub fn check_rescue(core: &[u8]) -> bool {
    let Some(core) = core.get(..RESCUE_SIZE) else {
        return false;
    };
    let end = RESCUE_SIZE - 8;
    word(core, end) == Some(RESCUE_MAGIC) && word(core, end + 4) == Some(crc32(&core[..end]))
}

/// The application in the flash, if it is whole: its reset address.
pub fn installed_app() -> Option<u32> {
    let flash = installed_area();
    check_app(flash)?;
    word(flash, 12)
}

/// The packed application of a first image (`lapin-first.bin`), in the
/// application's place, if its header and its CRC check: the stream,
/// the unpacked length and CRC-32.
pub fn packed_app() -> Option<(&'static [u8], usize, u32)> {
    use lapin_core::pack::{HEADER_LEN, MAGIC};
    let flash = installed_area();
    if word(flash, 0)? != MAGIC {
        return None;
    }
    let stream = flash.get(HEADER_LEN..HEADER_LEN.checked_add(word(flash, 4)? as usize)?)?;
    let len = word(flash, 8)? as usize;
    if !(HEADER_LEN..=APP_END - APP_BASE).contains(&len) || crc32(stream) != word(flash, 16)? {
        return None;
    }
    Some((stream, len, word(flash, 12)?))
}

/// The application's place in the flash, as it is.
pub fn installed_area() -> &'static [u8] {
    // SAFETY: the flash is mapped and readable; only the rewrite
    // routines change it, which never come back.
    unsafe { core::slice::from_raw_parts(APP_BASE as *const u8, APP_END - APP_BASE) }
}

/// The rescue core as it is in the flash.
pub fn installed_rescue() -> &'static [u8] {
    // SAFETY: as above; the rescue core is never written by the
    // application's updates.
    unsafe { core::slice::from_raw_parts(flash::BASE as *const u8, RESCUE_SIZE) }
}

/// What part of `image` an update writes, from where; `None`: refused,
/// nothing written.
///
/// - A whole image whose rescue core is the one in place, or an
///   application image alone: the application, if it is whole.
/// - A whole image with another rescue core: the whole flash, only if
///   both parts are whole (a power cut in the first 20 KB of that
///   write still kills the rabbit: there is one rescue core).
/// - Anything else that starts as lapin does: a damaged or cut image,
///   refused.
/// - An image of another firmware (the C one): the whole flash, as
///   before there was a rescue core, with the same risk.
pub fn update_plan(image: &[u8]) -> Option<(usize, &[u8])> {
    let installed = installed_rescue();
    if image.len() > RESCUE_SIZE && image[..RESCUE_SIZE] == *installed {
        let app = &image[RESCUE_SIZE..];
        let len = check_app(app)?;
        return Some((APP_BASE, &app[..len]));
    }
    if let Some(len) = check_app(image) {
        return Some((APP_BASE, &image[..len]));
    }
    if word(image, RESCUE_SIZE - 8) == Some(RESCUE_MAGIC) {
        if !check_rescue(image) {
            return None;
        }
        let len = check_app(&image[RESCUE_SIZE..])?;
        return Some((flash::BASE, &image[..RESCUE_SIZE + len]));
    }
    if image.get(..SIGNATURE) == Some(&installed[..SIGNATURE]) {
        return None;
    }
    Some((flash::BASE, image))
}
