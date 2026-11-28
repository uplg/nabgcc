//! The first flash of lapin over the air: r3 (the C firmware a rabbit
//! runs) writes `lapin-full.bin`, rescue core first, with its own
//! routine (`flash_uc`), which runs under the watchdog unfed. With the
//! flash's typical timings and with the manual's maximum ones, and with
//! the power cut at points all along that write: what comes back.
//! Skipped when lapin is not built.

mod common;

use common::{lapin, on_network, open, r3, serve_first};
use nabemu::soc::{FLASH_ERASE_MAX_MS, ResetCause};
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

/// r3 on its network, served the update to lapin first; `erase_ms` the
/// flash's erase time, the power cut after `cut` flash operations.
fn first_flash(erase_ms: u64, cut: Option<u64>) -> (Machine, After) {
    let image = lapin().unwrap();
    let mut m = on_network(&r3(), open());
    serve_first(&mut m, &metal::flash_firmware(&image));
    m.soc.flash_erase_ms = erase_ms;
    m.soc.cut_power_after_flash_ops = cut;
    let by = 90_000;
    while m.events.is_empty() && m.soc.millis() < by {
        m.run_until_ms(m.soc.millis() + 50);
    }
    assert!(!m.events.is_empty(), "the update never ended");
    let restarted = m.soc.uart_tx.len();
    let by = m.soc.millis() + 60_000;
    let after = loop {
        let console = String::from_utf8_lossy(&m.soc.uart_tx[restarted..]).into_owned();
        if console.contains("4242") {
            break After::Lapin;
        }
        if console.contains("secours: network up") {
            break After::Rescue;
        }
        if m.soc.millis() > by {
            break After::Dead;
        }
        m.run_until_ms(m.soc.millis() + 50);
    };
    (m, after)
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

/// With the timings the emulator takes by default (22 ms an erase):
/// the whole image goes in within the watchdog's 2.1 s, and lapin runs.
#[test]
fn r3_writes_lapin_whole_with_typical_flash_timings() {
    if lapin().is_none() {
        return;
    }
    let (m, after) = first_flash(nabemu::soc::FLASH_ERASE_MS, None);
    eprintln!("written in {} ms, {:?}", write_ms(&m), m.events);
    assert_eq!(after, After::Lapin);
}

/// With the manual's maximum erase time (50 ms, and 40 µs a word): r3's
/// routine does not feed the watchdog (its pause bit is set without the
/// unlock), and 2.097 s is not enough for the whole image. The bite
/// comes once the rescue core is written: the rabbit comes back on the
/// rescue network, from where a phone finishes the job.
#[test]
fn with_the_slowest_flash_r3_is_bitten_mid_write_and_the_rescue_core_takes_over() {
    let Some(image) = lapin() else { return };
    let (m, after) = first_flash(FLASH_ERASE_MAX_MS, None);
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

/// The power cut at sixteen points of the write. Once the rescue core
/// is whole, every cut leaves a rabbit on its rescue network. Known
/// defect (K3) of this way in: a cut while r3 writes the rescue core
/// itself, its first 20 KB (the first sixth of the write, a third of a
/// second), leaves a rabbit that never comes back; that is for the
/// first image to solve (a packed one, being designed separately).
#[test]
fn a_power_cut_during_the_first_flash() {
    let Some(image) = lapin() else { return };
    let total = ops(&image);
    let core = ops(&image[..common::RESCUE]);
    let cuts: Vec<u64> = (1..=16).map(|i| total * i / 17).collect();
    let results: Vec<(u64, After)> = std::thread::scope(|s| {
        let runs: Vec<_> = cuts
            .iter()
            .map(|&cut| {
                s.spawn(move || (cut, first_flash(nabemu::soc::FLASH_ERASE_MS, Some(cut)).1))
            })
            .collect();
        runs.into_iter().map(|r| r.join().unwrap()).collect()
    });
    eprintln!("rescue core: the first {core} of {total} operations");
    for (cut, after) in &results {
        eprintln!("cut after {cut:6}: {after:?}");
    }
    for &(cut, after) in &results {
        if cut > core {
            assert_eq!(after, After::Rescue, "cut after {cut}");
        } else {
            assert_ne!(after, After::Lapin, "cut after {cut}");
        }
    }
    // The defect pinned: the early cuts kill the rabbit.
    assert_eq!(results[0].1, After::Dead, "Known defect: a cut in the core");
}
