//! The clock bring-up of the C firmware (r3, what the rabbits run) and
//! of lapin, register write for register write: the same writes to the
//! clock tree, in the same order, and the crystal left the same time to
//! settle before the chip runs on it. Skipped when lapin is not built.

use nabemu::Machine;

const PECLKCNT: u32 = 0xB700_0000;
const PLL1: u32 = 0xB700_0008;
const PLL2: u32 = 0xB700_000C;
const CLKCNT: u32 = 0xB700_0010;
const TMEN: u32 = 0xB800_1004;
const TMRLR: u32 = 0xB800_1008;
const TMOVF: u32 = 0xB800_1010;

fn name(a: u32) -> &'static str {
    match a {
        PECLKCNT => "PECLKCNT",
        PLL1 => "PLL1",
        PLL2 => "PLL2",
        CLKCNT => "CLKCNT",
        TMEN => "TMEN",
        TMRLR => "TMRLR",
        TMOVF => "TMOVF",
        _ => "?",
    }
}

/// The writes up to the peripheral clocks' (the end of the bring-up),
/// with their time in microseconds.
fn bring_up(image: &[u8]) -> Vec<(u64, u32, u32)> {
    let mut m = Machine::from_file(image).0;
    m.soc.trace = Some((
        vec![PECLKCNT, PLL1, PLL2, CLKCNT, TMEN, TMRLR, TMOVF],
        Vec::new(),
    ));
    m.run_until_ms(50);
    let log = m.soc.trace.take().unwrap().1;
    let end = log
        .iter()
        .position(|w| w.1 == PECLKCNT)
        .expect("no peripheral clock written");
    log[..=end]
        .iter()
        .map(|&(c, a, v)| (c * 1_000_000 / nabemu::soc::CLOCK_HZ, a, v))
        .collect()
}

#[test]
fn the_clock_comes_up_as_in_the_c_firmware() {
    let root = env!("CARGO_MANIFEST_DIR");
    let Ok(lapin) = std::fs::read(format!("{root}/../../lapin/target/lapin-full.bin")) else {
        eprintln!("skipped: lapin is not built");
        return;
    };
    let r3 = std::fs::read(format!("{root}/../../artifacts/Nab-wpa23-gtk-r3.sim")).unwrap();
    let (c, rust) = (bring_up(&r3), bring_up(&lapin));
    for (who, log) in [("r3", &c), ("lapin", &rust)] {
        eprintln!("{who}:");
        for (us, a, v) in log.iter() {
            eprintln!("  {us:>7} us  {:<8} {v:#010x}", name(*a));
        }
    }
    let clock = |log: &[(u64, u32, u32)]| -> Vec<(u32, u32)> {
        log.iter()
            .filter(|w| [PECLKCNT, PLL1, PLL2, CLKCNT].contains(&w.1))
            .map(|w| (w.1, w.2))
            .collect()
    };
    assert_eq!(clock(&c), clock(&rust), "the writes to the clock tree");
    // Off the ring oscillator: the first CLKCNT whose source is not it.
    let off_ring = |log: &[(u64, u32, u32)]| {
        log.iter()
            .find(|w| w.1 == CLKCNT && (w.2 >> 8) & 3 != 1)
            .expect("never off the ring oscillator")
            .0
    };
    let (tc, tr) = (off_ring(&c), off_ring(&rust));
    assert!(tc >= 10_000 && tr >= 10_000, "{tc} us, {tr} us");
    assert!(tc.abs_diff(tr) < 1000, "{tc} us on r3, {tr} us on lapin");
}
