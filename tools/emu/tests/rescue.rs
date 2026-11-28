//! lapin's rescue core (`lapin/fw/src/boot.rs`, `rescue.rs`): an update
//! that rewrites the application alone, a power cut in the middle of it
//! survived, an application that keeps restarting taken back, and the
//! rabbit put right from a phone on its own rescue network. lapin only;
//! skipped when it is not built.

mod common;

use common::{
    RESCUE, lapin, lapin_target, on_network, open, page, phone_on_the_rescue_network,
    rescue_network_up, serve_first, until, wait, without_application,
};
use nabemu::soc::ResetCause;
use nabemu::{Event, Machine, metal};

/// A rabbit on an open network whose server answers its first request
/// with `first` (a bytecode), and every later one with a program that
/// prints 4242.
fn rabbit(image: &[u8], first: &[u8]) -> Machine {
    let mut m = on_network(image, open());
    serve_first(&mut m, first);
    m
}

/// Join the rescue network from a phone and load a page.
fn visit(m: &mut Machine, target: &str, body: Option<&[u8]>) -> String {
    phone_on_the_rescue_network(m);
    page(m, 60_000, |v| match body {
        Some(b) => v.post(target, b),
        None => v.get(target),
    })
}

#[test]
fn an_update_that_brings_the_same_rescue_core_rewrites_the_application_alone() {
    let Some(image) = lapin() else { return };
    let mut m = rabbit(&image, &metal::flash_firmware(&image));
    let rescue = m.soc.flash[..RESCUE].to_vec();
    until(&mut m, 60_000, "the restart after the update", |m| {
        !m.events.is_empty()
    });
    assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
    assert_eq!(
        m.soc.flash[..RESCUE],
        rescue[..],
        "the rescue core untouched"
    );
    // The same application as in place: not a sector erased (the flash
    // is good for a hundred rewrites, manual 1.2).
    assert_eq!(m.soc.flash_erases, 0, "sectors erased for nothing");
    until(&mut m, 60_000, "the new application running", |m| {
        m.console().contains("4242")
    });
}

/// The first image is for r3 only: sent to a rabbit that runs lapin, it
/// is refused (its application is packed), nothing written, and the
/// rabbit goes on.
#[test]
fn the_first_image_sent_to_a_lapin_rabbit_is_refused() {
    let (Some(image), Some(first)) = (lapin(), lapin_target("lapin-first.bin")) else {
        return;
    };
    let mut m = rabbit(&image, &metal::flash_firmware(&first));
    until(&mut m, 60_000, "the restart", |m| !m.events.is_empty());
    assert_eq!(m.soc.flash_erases, 0, "something written");
    until(&mut m, 60_000, "the application back", |m| {
        m.console().contains("4242")
    });
}

#[test]
fn a_power_cut_during_an_update_is_survived_and_put_right_from_a_phone() {
    let Some(image) = lapin() else { return };
    // An update to another application (the self-test's, behind the
    // same rescue core), cut halfway through.
    let Some(other) = lapin_target("selftest-full.bin") else {
        return;
    };
    let mut m = rabbit(&image, &metal::flash_firmware(&other));
    m.soc.cut_power_after_flash_ops = Some(1000);
    until(&mut m, 60_000, "the power cut", |m| !m.events.is_empty());
    assert_eq!(m.events, [Event::Reset(ResetCause::PowerLoss)]);
    rescue_network_up(&mut m);
    assert!(
        m.console().contains("secours: no application"),
        "{}",
        m.console()
    );

    let page = visit(&mut m, "/", None);
    assert!(page.contains("Lapin en secours"), "{page}");
    let answer = visit(&mut m, "/flash", Some(&image));
    assert!(answer.contains("200 OK"), "{answer}");
    until(&mut m, 30_000, "the restart on the new image", |m| {
        m.events.len() > 1
    });
    assert_eq!(
        m.soc.flash[RESCUE..image.len()],
        image[RESCUE..],
        "the application written"
    );
    m.visitor = None;
    until(&mut m, 60_000, "the application back on its network", |m| {
        m.console().contains("4242")
    });
}

#[test]
fn an_application_that_keeps_restarting_is_taken_back() {
    let Some(image) = lapin() else { return };
    // A stick that takes no frame to send: the application gives up on
    // it and restarts, every time, within its first minute. (A restart
    // the bytecode asks for does not count: tests/observable.rs.)
    let mut m = on_network(&image, open());
    m.radio.borrow_mut().tx_stuck = true;
    until(&mut m, 200_000, "the rescue core taking over", |m| {
        m.console()
            .contains("secours: the application keeps restarting")
    });
    assert_eq!(m.events.len(), 3, "{:?}", m.events);
    m.radio.borrow_mut().tx_stuck = false;
    // From the phone: back to the application, the count forgotten.
    let answer = visit(&mut m, "/restart", None);
    assert!(answer.contains("200 OK"), "{answer}");
    until(&mut m, 20_000, "the restart", |m| m.events.len() == 4);
    m.visitor = None;
    wait(&mut m, 3000);
    let tail = &m.console()[m.console().rfind("secours").unwrap()..];
    assert!(
        tail.contains("lapin 0.1"),
        "the application runs again:\n{tail}"
    );
}

/// The words the rescue core counts restarts in (lapin/fw/src/boot.rs,
/// Slots), at the bottom of the internal RAM.
const SLOT_WORDS: std::ops::Range<usize> = 0..8;

/// Run until the next reset, and stop right on it: the rescue core has
/// not run an instruction yet.
fn to_next_reset(m: &mut Machine, limit_ms: u64) {
    let n = m.events.len();
    let by = m.soc.millis() + limit_ms;
    while m.events.len() == n {
        assert!(m.soc.millis() < by, "no reset: {}", m.console());
        m.step();
    }
}

/// An application that restarts within its first minute, every time
/// (a stick that takes no frame to send).
fn restarting(image: &[u8]) -> Machine {
    let m = on_network(image, open());
    m.radio.borrow_mut().tx_stuck = true;
    m
}

/// A power-on is no failed start, even when the RAM kept the words that
/// count them (a short cut can leave the internal RAM as it was): the
/// rescue core tells it from a restart by the watchdog's RSTSTATUS
/// (manual table 11-2), set by its overflow only, and cleared by a
/// power-on. Two failed starts, then the power cut with the words kept:
/// the application gets its three tries again.
#[test]
fn a_power_on_is_no_failed_start_even_if_the_ram_kept_its_words() {
    let Some(image) = lapin() else { return };
    let mut m = restarting(&image);
    to_next_reset(&mut m, 120_000);
    to_next_reset(&mut m, 120_000);
    let kept = m.soc.iram[SLOT_WORDS].to_vec();
    m.power_cycle();
    m.soc.iram[SLOT_WORDS].copy_from_slice(&kept);
    let said = m.console().len();
    until(&mut m, 20_000, "a start", |m| {
        let after = &m.console()[said..];
        after.contains("lapin 0.1") || after.contains("secours")
    });
    let after = &m.console()[said..];
    assert!(after.contains("lapin 0.1"), "taken back at once:\n{after}");
    // And it is counted from there: three more, then the rescue core.
    until(&mut m, 200_000, "the rescue core taking over", |m| {
        m.console()[said..].contains("secours: the application keeps restarting")
    });
    assert_eq!(m.events.len(), 2 + 3, "{:?}", m.events);
}

/// A restart by the watchdog counts as a failed start even when the RAM
/// lost the words that count them: the first one, its words wiped,
/// counts one, and the rescue core takes over after three as ever (it
/// read a lost count as a power-on, and took four).
#[test]
fn a_watchdog_restart_counts_even_if_the_ram_lost_its_words() {
    let Some(image) = lapin() else { return };
    let mut m = restarting(&image);
    to_next_reset(&mut m, 120_000);
    assert_eq!(m.events, [Event::Reset(ResetCause::Watchdog)]);
    m.soc.iram[SLOT_WORDS].fill(0);
    until(&mut m, 200_000, "the rescue core taking over", |m| {
        m.console()
            .contains("secours: the application keeps restarting")
    });
    assert_eq!(m.events.len(), 3, "{:?}", m.events);
}

#[test]
fn the_rescue_core_refuses_what_is_not_a_rabbit_image() {
    let Some(image) = lapin() else { return };
    let mut m = without_application(&image);
    let erases = m.soc.flash_erases;
    let answer = visit(&mut m, "/flash", Some(&[0x42; 5000]));
    assert!(answer.contains("400"), "{answer}");
    let answer = visit(&mut m, "/restart", None);
    assert!(answer.contains("409"), "{answer}");
    assert_eq!(m.soc.flash_erases, erases, "nothing written");
    assert_eq!(m.events, []);
}

/// Power cut at every point of an update, a step at a time: whatever
/// was written, the rabbit comes back, on an application or on its
/// rescue network, and never stays dark.
#[test]
fn a_power_cut_anywhere_in_an_update_leaves_a_rabbit_that_comes_back() {
    let Some(image) = lapin() else { return };
    // One erase per sector, one program per word: about 25 000 steps.
    let steps = (image.len() - RESCUE).div_ceil(4096) + (image.len() - RESCUE) / 4;
    // Each cut on its own machine, all at once: one test, every core.
    let outcomes: Vec<(u64, &str)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..=16)
            .map(|i| {
                let image = &image;
                scope.spawn(move || {
                    let at = (steps * i / 16).max(1) as u64;
                    let mut m = rabbit(image, &metal::flash_firmware(image));
                    m.soc.cut_power_after_flash_ops = Some(at);
                    until(&mut m, 60_000, "the power cut", |m| !m.events.is_empty());
                    let said = m.console().len();
                    until(&mut m, 20_000, "the rabbit coming back", |m| {
                        let after = &m.console()[said..];
                        after.contains("secours: network up") || after.contains("lapin 0.1")
                    });
                    let rescued = m.console()[said..].contains("secours");
                    (
                        at,
                        if rescued {
                            "rescue network"
                        } else {
                            "application"
                        },
                    )
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (at, how) in outcomes {
        eprintln!("cut after {at} of {steps} steps: {how}");
    }
}
