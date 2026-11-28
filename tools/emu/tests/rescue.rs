//! lapin's rescue core (`lapin/fw/src/boot.rs`, `rescue.rs`): an update
//! that rewrites the application alone, a power cut in the middle of it
//! survived, an application that keeps restarting taken back, and the
//! rabbit put right from a phone on its own rescue network. lapin only;
//! skipped when it is not built.

use nabemu::air::{AccessPoint, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};
use nabemu::soc::ResetCause;
use nabemu::visitor::Visitor;
use nabemu::{Event, Machine, metal};

const RESCUE: usize = 20 * 1024;

fn image() -> Option<Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../lapin/target/lapin-full.bin"
    );
    std::fs::read(path).ok().or_else(|| {
        eprintln!("skipped: lapin is not built");
        None
    })
}

/// A rabbit on an open network whose server answers its first request
/// with `first` (a bytecode), and every later one with a program that
/// prints 4242.
fn rabbit(image: &[u8], first: Vec<u8>) -> Machine {
    let mut m = Machine::from_file(image).0;
    Config::new("Terrier", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::Open,
    ));
    let mut lan = Lan::new();
    let first = metal::boot_response(&first);
    let later = metal::boot_response(&metal::print_number(4242));
    let mut served = false;
    lan.handler = Box::new(move |_| {
        if std::mem::replace(&mut served, true) {
            Response::ok(later.clone())
        } else {
            Response::ok(first.clone())
        }
    });
    m.lan = Some(lan);
    m
}

fn until(m: &mut Machine, limit_ms: u64, what: &str, done: impl Fn(&Machine) -> bool) {
    let limit = m.soc.millis() + limit_ms;
    while !done(m) {
        assert!(
            m.soc.millis() < limit,
            "{what}: not within {limit_ms} ms\n{}",
            m.console()
        );
        m.run_until_ms(m.soc.millis() + 20);
    }
}

fn phone(m: &Machine) -> &Visitor {
    m.visitor.as_ref().unwrap()
}

/// Join the rescue network from a phone and load a page.
fn visit(m: &mut Machine, target: &str, body: Option<&[u8]>) -> String {
    if m.visitor.is_none() {
        m.visitor = Some(Visitor::new([2, 0, 0, 0, 0, 0xB2], "Nabaztag-secours"));
    }
    until(m, 60_000, "an address on the rescue network", |m| {
        phone(m).address.is_some()
    });
    let before = phone(m).pages.len();
    match body {
        Some(b) => m.visitor.as_mut().unwrap().post(target, b),
        None => m.visitor.as_mut().unwrap().get(target),
    }
    until(m, 60_000, target, |m| phone(m).pages.len() > before);
    phone(m).pages[before].text()
}

#[test]
fn an_update_that_brings_the_same_rescue_core_rewrites_the_application_alone() {
    let Some(image) = image() else { return };
    let mut m = rabbit(&image, metal::flash_firmware(&image));
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
    let app_sectors = (image.len() - RESCUE).div_ceil(4096) as u64;
    assert_eq!(
        m.soc.flash_erases, app_sectors,
        "only the application's sectors erased"
    );
    until(&mut m, 60_000, "the new application running", |m| {
        m.console().contains("4242")
    });
}

#[test]
fn a_power_cut_during_an_update_is_survived_and_put_right_from_a_phone() {
    let Some(image) = image() else { return };
    let mut m = rabbit(&image, metal::flash_firmware(&image));
    // Halfway through the application.
    m.soc.cut_power_after_flash_ops = Some(12_000);
    until(&mut m, 60_000, "the power cut", |m| !m.events.is_empty());
    assert_eq!(m.events, [Event::Reset(ResetCause::PowerLoss)]);
    until(&mut m, 20_000, "the rescue network", |m| {
        m.console().contains("secours: network up")
    });
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
    let Some(image) = image() else { return };
    // A bytecode that restarts the rabbit at once, every time.
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.extend(metal::int(0x0407_FE58));
    f.extend(metal::int(0x13FB_6754));
    f.extend([136, 1]);
    let reboot = metal::bytecode(&[], &f);
    let mut m = rabbit(&image, reboot.clone());
    m.lan.as_mut().unwrap().handler =
        Box::new(move |_| Response::ok(metal::boot_response(&reboot)));
    until(&mut m, 120_000, "the rescue core taking over", |m| {
        m.console()
            .contains("secours: the application keeps restarting")
    });
    assert_eq!(m.events.len(), 3, "{:?}", m.events);
    // From the phone: back to the application, the count forgotten.
    let answer = visit(&mut m, "/restart", None);
    assert!(answer.contains("200 OK"), "{answer}");
    until(&mut m, 20_000, "the restart", |m| m.events.len() == 4);
    m.visitor = None;
    m.run_until_ms(m.soc.millis() + 3000);
    let tail = &m.console()[m.console().rfind("secours").unwrap()..];
    assert!(
        tail.contains("lapin 0.1"),
        "the application runs again:\n{tail}"
    );
}

#[test]
fn the_rescue_core_refuses_what_is_not_a_rabbit_image() {
    let Some(image) = image() else { return };
    let mut m = Machine::from_file(&image).0;
    // No application: as after a power cut that took it.
    m.soc.flash[RESCUE..RESCUE + 4096].fill(0xFF);
    until(&mut m, 20_000, "the rescue network", |m| {
        m.console().contains("secours: network up")
    });
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
    let Some(image) = image() else { return };
    // One erase per sector, one program per word: about 25 000 steps.
    let steps = (image.len() - RESCUE).div_ceil(4096) + (image.len() - RESCUE) / 4;
    // Each cut on its own machine, all at once: one test, every core.
    let outcomes: Vec<(u64, &str)> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..=16)
            .map(|i| {
                let image = &image;
                scope.spawn(move || {
                    let at = (steps * i / 16).max(1) as u64;
                    let mut m = rabbit(image, metal::flash_firmware(image));
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
