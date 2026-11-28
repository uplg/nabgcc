//! The firmware's limits, measured on the emulated rabbit under the
//! heaviest things it does: how deep its two stacks go, and the longest
//! the watchdog (2.09 s) goes unfed. Bounds, not observations: each
//! scenario fails if the firmware leaves its budget. The Rust firmware
//! only (`lapin/build.sh` first); skipped when it is not built.

mod common;

use common::{
    IRQ, IRQ_FLOOR, PROGRAM_FLOOR, STACK_TOP, SYSTEM, WATCHDOG_BUDGET_MS, ap_saw, authorized,
    garenne, in_factory_test, lapin, ms, on_wpa3_network, press, serve, serving, time_printed,
    until_every,
};
use nabemu::Machine;
use nabemu::air::ApEvent;
use nabemu::rfid::Tag;

fn check(m: &Machine, scenario: &str) {
    let irq = m.stack_low[IRQ];
    let program = m.stack_low[SYSTEM];
    let unfed = ms(m.soc.watchdog_longest.max(m.soc.watchdog_unfed()));
    eprintln!(
        "{scenario}: program stack {} bytes, interrupt stack {} bytes, watchdog unfed {unfed} ms",
        IRQ_FLOOR.saturating_sub(program),
        STACK_TOP.saturating_sub(irq),
    );
    eprintln!("  deepest at {:#x}", m.stack_low_pc[SYSTEM]);
    if std::env::var("LIMITS_TRACE").is_ok() {
        let sp = m.stack_low[SYSTEM];
        let words: Vec<String> = m
            .stack_low_words
            .iter()
            .enumerate()
            .filter(|(_, w)| (0x0800_0000..0x0801_F000).contains(*w) && *w & 1 == 1)
            .map(|(i, w)| format!("{w:#x}@{}", STACK_TOP - (sp + 4 * i as u32)))
            .collect();
        eprintln!("  return addresses: {}", words.join(" "));
    }
    assert_eq!(m.events, [], "{scenario}: reset or fault");
    assert!(
        program >= PROGRAM_FLOOR,
        "{scenario}: program stack at {program:#x}"
    );
    assert!(irq >= IRQ_FLOOR, "{scenario}: interrupt stack at {irq:#x}");
    assert!(
        unfed <= WATCHDOG_BUDGET_MS,
        "{scenario}: watchdog unfed {unfed} ms"
    );
}

/// WPA3 (the password exchange on the rabbit's processor), then the
/// application with its callbacks, a group rekey and a pairwise rekey.
#[test]
fn wpa3_and_garenne() {
    let Some(image) = lapin() else { return };
    let mut m = on_wpa3_network(&image);
    if let Some(bytecode) = garenne() {
        serve(&mut m, bytecode);
    }
    m.run_until_ms(30_000);
    assert!(authorized(&m));
    m.air[0].rekey_group(&mut m.radio.borrow_mut());
    m.air[0].rekey_pairwise(&mut m.radio.borrow_mut(), nabemu::DEFAULT_MAC);
    m.run_until_ms(60_000);
    assert!(ap_saw(
        &m,
        &ApEvent::PairwiseKeyRenewed {
            sta: nabemu::DEFAULT_MAC
        }
    ));
    check(&m, "WPA3 and garenne");
}

/// The setup page saves a WPA2 network: the key is derived from the
/// passphrase on the rabbit (PBKDF2, seconds of work), then it joins.
#[test]
fn setup_page_and_key_derivation() {
    let Some(image) = lapin() else { return };
    let (m, _) = common::set_up_from_the_page(&image);
    check(&m, "setup page, key derivation, join");
}

/// The factory test: ears, a tag, a tone, a recording played back.
#[test]
fn factory_test() {
    let Some(image) = lapin() else { return };
    let mut m = in_factory_test(&image);
    m.soc
        .board
        .rfid
        .tags
        .push(Tag::new([0xD0, 2, 0x1A, 3, 4, 5, 6, 7]));
    for _ in 1..6 {
        press(&mut m, 200, 3000);
    }
    // Step 6: hold to record, let go to hear it.
    press(&mut m, 3000, 5000);
    check(&m, "factory test");
}

/// A collection with the heap nearly full of small blocks, a third of
/// them garbage between the others: everything left has to move. Then
/// `gc` once more, timed by the bytecode itself.
#[test]
fn collector_on_a_full_heap() {
    use nabemu::metal;
    let Some(image) = lapin() else { return };
    // Function 0, two locals: the list, the count.
    let mut f = vec![0u8, 2, 0];
    f.extend(metal::int(17_000)); // 0
    f.extend([40, 1]); // 5: setlocalb 1
    f.extend([7, 1, 29, 35, 0]); // 7: getlocalb 1; else 35
    f.extend([2, 4, 62, 5]); // 12: a 4-byte string, dropped
    f.extend([2, 4, 62, 7, 0, 32, 2, 40, 0]); // 16: another, consed onto the list
    f.extend([7, 1, 2, 1, 10, 40, 1, 28, 7, 0]); // 25: count - 1; goto 7
    f.extend([53, 87, 5, 53, 10, 95, 1]); // 35: time_ms; gc; drop; time_ms; sub; Iecholn; ret
    let mut m = serving(&image, &metal::bytecode(&[], &f));
    until_every(&mut m, 100, 60_000, "a time printed", |m| {
        time_printed(m).is_some()
    });
    let took = time_printed(&m).unwrap();
    eprintln!("a collection over a full heap takes {took} ms");
    check(&m, "collector on a full heap");
}
