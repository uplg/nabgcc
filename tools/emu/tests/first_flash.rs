//! The first flash of lapin over the air: r3 (the C firmware a rabbit
//! runs) writes the image it is sent with its own routine (`flash_uc`),
//! which runs under the watchdog unfed; then lapin's rescue core takes
//! over. `lapin-full.bin`, the image lapin updates itself with, is too
//! long for that (r3 is bitten at the manual's slowest flash, and a cut
//! early in it is fatal); `lapin-first.bin`, the rescue core then the
//! application packed, is what the server sends an r3 rabbit, once: r3
//! writes it well within the watchdog even at the manual's slowest, and
//! the rescue core unpacks and writes the application at its first
//! start. With the power cut at points all along both: what comes back.
//! Skipped when lapin is not built.

mod common;

use common::{
    RESCUE, in_parallel, lapin, lapin_first as first_image, on_network, open, r3, serve_first,
};
use nabemu::soc::{CLOCK_HZ, FLASH_ERASE_MAX_MS, FLASH_PROGRAM_US, ResetCause};
use nabemu::{Event, Machine, metal};

/// What the rabbit is once the write is over (or cut).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// lapin's application runs and fetched its next bytecode.
    Lapin,
    /// lapin's rescue core raised its network.
    Rescue,
    /// Neither, within a minute: a rabbit for the bench.
    Dead,
}

/// The watchdog's period, in ms (lapin/fw/src/watchdog.rs).
const WATCHDOG_MS: u64 = 2097;

/// Where the packed application's stream ends, from its header (five
/// words: magic, stream length, ...).
fn packed_end(first: &[u8]) -> usize {
    let len = u32::from_le_bytes(first[RESCUE + 4..RESCUE + 8].try_into().unwrap());
    RESCUE + 20 + len as usize
}

/// Wait at most a minute for the rabbit to come back after `from` bytes
/// of console: lapin running, or its rescue network.
fn comes_back(m: &mut Machine, from: usize) -> After {
    let by = m.soc.millis() + 60_000;
    loop {
        let console = String::from_utf8_lossy(&m.soc.uart_tx[from..]).into_owned();
        if console.contains("4242") {
            return After::Lapin;
        }
        if console.contains("secours: network up") {
            return After::Rescue;
        }
        if m.soc.millis() > by {
            return After::Dead;
        }
        m.run_until_ms(m.soc.millis() + 50);
    }
}

/// r3 on its network, served the update to `image` first; `erase_ms`
/// the flash's erase time, the power cut after `cut` flash operations.
/// Also what r3's write was.
fn first_flash(image: &[u8], erase_ms: u64, cut: Option<u64>) -> (Machine, After, R3) {
    let mut m = on_network(&r3(), open());
    serve_first(&mut m, &metal::flash_firmware(image));
    m.soc.flash_erase_ms = erase_ms;
    m.soc.flash_program_us = FLASH_PROGRAM_US;
    m.soc.cut_power_after_flash_ops = cut;
    let by = 90_000;
    let mut unfed_ms = 0;
    while m.events.is_empty() && m.soc.millis() < by {
        let step = if m.soc.flash_first_op.is_some() {
            1
        } else {
            50
        };
        m.run_until_ms(m.soc.millis() + step);
        if m.soc.flash_first_op.is_some() {
            unfed_ms = unfed_ms.max(m.soc.watchdog_unfed() * 1000 / CLOCK_HZ);
        }
    }
    assert!(!m.events.is_empty(), "the update never ended");
    let r3 = R3 {
        unfed_ms,
        write_ms: write_ms(&m),
        ops: m.soc.flash_programs + m.soc.flash_erases,
    };
    let restarted = m.soc.uart_tx.len();
    let after = comes_back(&mut m, restarted);
    (m, after, r3)
}

/// r3's write, up to its restart (or the bite, or the cut).
struct R3 {
    /// The longest the watchdog went unfed once the write began, to the
    /// millisecond.
    unfed_ms: u64,
    write_ms: u64,
    ops: u64,
}

/// How long the write took on the board's clock.
fn write_ms(m: &Machine) -> u64 {
    m.soc.flash_last_op - m.soc.flash_first_op.unwrap()
}

/// The flash's word programs and erases r3 makes for `image`: a word
/// of all ones is skipped.
fn ops(image: &[u8]) -> u64 {
    let sectors = image.len().div_ceil(4096) as u64;
    let words = image
        .chunks(4)
        .filter(|w| w.iter().any(|b| *b != 0xFF))
        .count() as u64;
    sectors + words
}

/// The power cut at sixteen points of r3 writing `image` (typical
/// timings), all at once: after the first `i` of `parts` of its flash
/// operations, `i` from 1 to 16. Once the rescue core (its first 20 KB)
/// is whole, every cut leaves a rabbit on its rescue network; a cut
/// after the last operation, lapin; one in the rescue core, a rabbit
/// that never runs lapin. Known defect (K3): the earliest cut kills
/// the rabbit.
fn cut_during_r3s_write(image: &[u8], parts: u64) {
    let total = ops(image);
    let core = ops(&image[..RESCUE]);
    let results = in_parallel(1..=16, |i| {
        let cut = total * i / parts;
        let (_, after, _) = first_flash(image, nabemu::soc::FLASH_ERASE_MS, Some(cut));
        (cut, after)
    });
    eprintln!("rescue core: the first {core} of {total} operations");
    for (cut, after) in &results {
        eprintln!("cut after {cut:6}: {after:?}");
    }
    for &(cut, after) in &results {
        if cut == total {
            assert_eq!(after, After::Lapin, "cut after {cut}");
        } else if cut > core {
            assert_eq!(after, After::Rescue, "cut after {cut}");
        } else {
            assert_ne!(after, After::Lapin, "cut after {cut}");
        }
    }
    // The defect pinned: the early cuts kill the rabbit.
    assert_eq!(results[0].1, After::Dead, "Known defect: a cut in the core");
}

/// With the timings the emulator takes by default (22 ms an erase):
/// the whole image goes in within the watchdog's 2.1 s, and lapin runs.
#[test]
fn r3_writes_lapin_whole_with_typical_flash_timings() {
    let Some(image) = lapin() else { return };
    let (m, after, _) = first_flash(&image, nabemu::soc::FLASH_ERASE_MS, None);
    eprintln!("written in {} ms, {:?}", write_ms(&m), m.events);
    assert_eq!(after, After::Lapin);
}

/// With the manual's maximum erase time (50 ms, and 40 µs a word): r3's
/// routine does not feed the watchdog (its pause bit is set without the
/// unlock), and 2.097 s is not enough for the whole image. The bite
/// comes once the rescue core is written: the rabbit comes back on the
/// rescue network, from where a phone finishes the job. Why the first
/// image is not this one.
#[test]
fn with_the_slowest_flash_r3_is_bitten_mid_write_and_the_rescue_core_takes_over() {
    let Some(image) = lapin() else { return };
    let (m, after, _) = first_flash(&image, FLASH_ERASE_MAX_MS, None);
    let written = m.soc.flash_programs + m.soc.flash_erases;
    eprintln!(
        "{} ms of writing, {written} of {} operations, {:?}, then {after:?}",
        write_ms(&m),
        ops(&image),
        m.events
    );
    assert_eq!(m.events[0], Event::Reset(ResetCause::Watchdog));
    assert!(written < ops(&image), "the whole image went in");
    assert_eq!(after, After::Rescue);
}

/// The power cut at sixteen points of r3 writing `lapin-full.bin`. Once
/// the rescue core is whole, every cut leaves a rabbit on its rescue
/// network. Known defect (K3) of any way in: a cut while r3 writes the
/// rescue core itself, its first 20 KB (a third of a second), leaves a
/// rabbit that never comes back.
#[test]
fn a_power_cut_during_the_first_flash() {
    let Some(image) = lapin() else { return };
    // Seventeenths: none after the last operation.
    cut_during_r3s_write(&image, 17);
}

/// The first image, with the typical flash timings and with the
/// manual's slowest (50 ms an erase, 40 µs a word): r3 writes it whole
/// with the watchdog unfed, within its 2097 ms; then the rescue core
/// unpacks the application, writes it, and lapin runs. r3's sysFlash
/// checks (its length, the five vectors) took it.
#[test]
fn r3_writes_the_first_image_within_the_watchdog_even_at_the_slowest_flash() {
    let (Some(first), Some(full)) = (first_image(), lapin()) else {
        return;
    };
    let erase = [nabemu::soc::FLASH_ERASE_MS, FLASH_ERASE_MAX_MS];
    let runs = in_parallel(erase, |erase_ms| {
        let (m, after, r3) = first_flash(&first, erase_ms, None);
        eprintln!(
            "lapin-first.bin ({} bytes), {erase_ms} ms an erase: r3 writes it in \
             {} ms, {} operations, the watchdog unfed {} ms at most: {} ms to \
             spare of {WATCHDOG_MS}; then {after:?} after {:?}",
            first.len(),
            r3.write_ms,
            r3.ops,
            r3.unfed_ms,
            WATCHDOG_MS.saturating_sub(r3.unfed_ms),
            m.events
        );
        // r3 wrote it all and restarted itself, then the rescue
        // core's two steps restarted twice.
        assert!(r3.ops >= ops(&first), "r3 did not write it all");
        assert_eq!(m.events.len(), 3, "{:?}", m.events);
        assert_eq!(after, After::Lapin);
        assert_eq!(
            m.soc.flash[..full.len()],
            full[..],
            "the flash is lapin-full.bin"
        );
        r3
    });
    // At the slowest, 100 ms to spare at least (the application packed
    // into a sector more would take about 90 of them); typically, more
    // than a third of the period.
    let (typical, slowest) = (&runs[0], &runs[1]);
    assert!(
        slowest.unfed_ms + 100 < WATCHDOG_MS,
        "{} ms",
        slowest.unfed_ms
    );
    assert!(
        typical.unfed_ms * 3 < WATCHDOG_MS * 2,
        "{} ms",
        typical.unfed_ms
    );
}

/// The flash as r3 leaves it once it wrote `lapin-first.bin` whole (with
/// the typical timings), on its network: the start of every cut below.
fn after_r3(first: &[u8]) -> Vec<u8> {
    let mut m = on_network(&r3(), open());
    serve_first(&mut m, &metal::flash_firmware(first));
    while m.events.is_empty() {
        assert!(m.soc.millis() < 90_000, "r3 never wrote it");
        m.run_until_ms(m.soc.millis() + 50);
    }
    assert_eq!(m.soc.flash[..first.len()], first[..]);
    m.soc.flash.clone()
}

/// That flash on a board on the network, whose server prints 4242.
fn first_start(flash: &[u8]) -> Machine {
    let mut m = on_network(flash, open());
    serve_first(&mut m, &metal::print_number(4242));
    m
}

/// Run the first start a millisecond at a time, `each` looking at it,
/// to its second restart, into lapin: within 30 s.
fn installed(m: &mut Machine, mut each: impl FnMut(&Machine)) {
    while m.events.len() < 2 {
        assert!(m.soc.millis() < 30_000, "not installed: {}", m.console());
        m.run_until_ms(m.soc.millis() + 1);
        each(m);
    }
}

/// The first start, uncut: the rescue core unpacks, writes the sectors
/// past the packed application, restarts, unpacks again, writes the
/// rest, restarts into lapin. The watchdog is fed all along.
#[test]
fn the_rescue_core_unpacks_the_first_image_and_writes_the_application() {
    let (Some(first), Some(full)) = (first_image(), lapin()) else {
        return;
    };
    let mut m = first_start(&after_r3(&first));
    let mut unfed = 0;
    let mut resets_at = Vec::new();
    let mut unpacked_at = Vec::new();
    installed(&mut m, |m| {
        unfed = unfed.max(m.soc.watchdog_unfed() * 1000 / CLOCK_HZ);
        if m.events.len() > resets_at.len() {
            resets_at.push(m.soc.millis());
        }
        let said = m.console().matches("secours: unpacked").count();
        if said > unpacked_at.len() {
            unpacked_at.push(m.soc.millis());
        }
    });
    eprintln!(
        "unpacked at {unpacked_at:?} ms, restarts at {resets_at:?} ms, {} erases, \
         the watchdog unfed {unfed} ms at most",
        m.soc.flash_erases
    );
    assert_eq!(
        m.events,
        [
            Event::Reset(ResetCause::Watchdog),
            Event::Reset(ResetCause::Watchdog)
        ]
    );
    assert!(unfed < common::WATCHDOG_BUDGET_MS, "unfed {unfed} ms");
    assert_eq!(m.console().matches("secours: unpacked").count(), 2);
    assert_eq!(m.soc.flash[..full.len()], full[..]);
    let said = m.soc.uart_tx.len();
    assert_eq!(comes_back(&mut m, said), After::Lapin);
    // Once whole, it starts as any application: nothing left to unpack.
    assert_eq!(m.console().matches("secours").count(), 2);
}

/// A packed application that does not check (a byte of it changed) is
/// not unpacked, nor anything written: the rescue network.
#[test]
fn a_damaged_first_image_is_not_installed() {
    let Some(first) = first_image() else { return };
    let mut flash = after_r3(&first);
    let at = (RESCUE + packed_end(&first)) / 2;
    flash[at] ^= 0x10;
    let mut m = first_start(&flash);
    assert_eq!(comes_back(&mut m, 0), After::Rescue);
    assert_eq!(m.soc.flash_erases, 0, "something written");
    assert!(m.console().contains("secours: no application"));
}

/// The power cut at every 32nd of the first start's unpacking and
/// writing, by time. While the packed application is whole (the
/// unpacking, the first step's writing of the sectors past it), the
/// rabbit unpacks it again and comes back on lapin; once the second
/// step writes over it, on the rescue network; never dead.
#[test]
fn a_power_cut_anywhere_in_the_first_start_leaves_a_rabbit_that_comes_back() {
    let Some(first) = first_image() else { return };
    let flash = after_r3(&first);
    // The uncut first start, to time it.
    let mut m = first_start(&flash);
    installed(&mut m, |_| {});
    let span = m.soc.millis();
    let blob = RESCUE..packed_end(&first);
    let results = in_parallel(1..=32, |i| {
        let at = span * i / 32;
        let mut m = first_start(&flash);
        m.run_until_ms(at);
        let whole = m.soc.flash[blob.clone()] == first[blob.clone()];
        m.power_cycle();
        let said = m.soc.uart_tx.len();
        let after = comes_back(&mut m, said);
        (at, whole, after)
    });
    eprintln!("the first start takes {span} ms");
    for (at, whole, after) in &results {
        eprintln!("cut at {at:5} ms, packed application whole: {whole:5}: {after:?}");
    }
    for &(at, whole, after) in &results {
        assert_ne!(after, After::Dead, "cut at {at} ms");
        if whole {
            assert_eq!(after, After::Lapin, "cut at {at} ms");
        }
    }
    // Both kinds were cut into.
    assert!(results.iter().any(|r| r.1) && results.iter().any(|r| !r.1));
}

/// The power cut at every 16th of r3's write of the first image. Known
/// defect (K3), unchanged: a cut while r3 writes the rescue core (its
/// first 20 KB, the first 0.35 s) leaves a dead rabbit. Past it, the
/// rescue network (the packed application cut short does not check);
/// at the end, lapin.
#[test]
fn a_power_cut_during_r3s_write_of_the_first_image() {
    let Some(first) = first_image() else { return };
    cut_during_r3s_write(&first, 16);
}
