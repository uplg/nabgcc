//! The Rust firmware against what a review of its Wi-Fi station and
//! its cryptography found: each test here failed on the firmware
//! before the fix it goes with. They need `lapin/build.sh`, and are
//! skipped when the image is not there.

mod common;

use nabemu::Machine;
use nabemu::cpu::Bus;
use nabemu::soc::IRAM_BASE;

/// lapin as built, symbols and all.
fn elf() -> Option<Vec<u8>> {
    common::lapin_target("thumbv4t-none-eabi/release/lapin")
}

/// Where the arguments and the result go, and the address the called
/// function returns to.
const ARGS: u32 = IRAM_BASE + 0x1000;
const RETURN: u32 = IRAM_BASE + 0x3000;

/// Call the firmware's function at `entry` (Thumb when its bit 0 is
/// set) on the emulated ARM7, with pointers to three numbers in the
/// argument registers, after the pointer to a 32-byte result when the
/// function `returns` one; the cycles it took.
fn cycles_of(m: &mut Machine, entry: u32, returns: bool, args: [[u32; 8]; 3]) -> u64 {
    for (i, n) in args.iter().enumerate() {
        for (j, limb) in n.iter().enumerate() {
            m.soc
                .write32(ARGS + 32 * (i as u32 + 1) + 4 * j as u32, *limb);
        }
    }
    let first = if returns { 0 } else { 1 };
    let regs: Vec<u32> = (0..4).map(|i| ARGS + 32 * (i + first)).collect();
    call(m, entry, &regs, &[]).0
}

/// Call the function at `entry` with these argument registers and
/// words on the stack; the cycles it took and what it left in r0.
fn call(m: &mut Machine, entry: u32, regs: &[u32], stack: &[u32]) -> (u64, u32) {
    // A Thumb `b .` where the function returns: the stop.
    m.soc.write16(RETURN, 0xE7FE);
    m.cpu.reset();
    m.cpu.r[..regs.len()].copy_from_slice(regs);
    let sp = IRAM_BASE + 0x2F00;
    for (i, w) in stack.iter().enumerate() {
        m.soc.write32(sp + 4 * i as u32, *w);
    }
    m.cpu.r[13] = sp;
    m.cpu.r[14] = RETURN | 1;
    m.cpu.r[15] = entry & !1;
    if entry & 1 != 0 {
        let cpsr = m.cpu.cpsr | 1 << 5;
        m.cpu.set_cpsr(cpsr);
    }
    let mut total = 0u64;
    while m.cpu.pc() & !1 != RETURN {
        total += m.cpu.step(&mut m.soc) as u64;
        assert!(total < 10_000_000, "never returned");
    }
    (total, m.cpu.r[0])
}

fn write(m: &mut Machine, at: u32, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        m.soc.write8(at + i as u32, *b);
    }
}

/// The one symbol whose mangled name ends with `suffix`.
fn symbol(symbols: &std::collections::BTreeMap<u32, String>, suffix: &str) -> u32 {
    let found: Vec<u32> = symbols
        .iter()
        .filter(|(_, s)| s.ends_with(suffix))
        .map(|(a, _)| *a)
        .collect();
    assert_eq!(found.len(), 1, "{suffix}: {found:x?}");
    found[0]
}

/// The key unwrap of the group keys undid the S-box by searching it,
/// as long as the byte's place in it: the time told the key bytes. And
/// its final check stopped at the first byte that differed. Now the
/// same wrapped length takes the same time whatever it holds, and the
/// comparison of codes too.
#[test]
fn the_key_unwrap_and_the_comparisons_take_the_same_time() {
    let Some(image) = elf() else { return };
    let (mut m, symbols) = Machine::from_file(&image);
    let symbols = symbols.unwrap().symbols;
    let unwrap = symbol(&symbols, "10lapin_core3aes6unwrap");
    let kek = [0x5Au8; 16];
    let mut times = Vec::new();
    for fill in [0x00u8, 0x63, 0xFF, 0xA6] {
        write(&mut m, ARGS, &kek);
        let mut wrapped = [fill; 40];
        wrapped[7] ^= 1;
        write(&mut m, ARGS + 32, &wrapped);
        let (t, ok) = call(&mut m, unwrap | 1, &[ARGS, ARGS + 32, 40, ARGS + 96], &[32]);
        assert_eq!(ok & 0xFF, 0);
        times.push(t);
    }
    assert!(times.iter().all(|t| *t == times[0]), "unwrap: {times:?}");
    let eq = symbol(&symbols, "10lapin_core4ccmp11constant_eq");
    let mut times = Vec::new();
    for at in [0, 15, 31] {
        write(&mut m, ARGS, &[7; 32]);
        let mut other = [7u8; 32];
        other[at] = 8;
        write(&mut m, ARGS + 32, &other);
        times.push(call(&mut m, eq | 1, &[ARGS, 32, ARGS + 32, 32], &[]).0);
    }
    assert!(
        times.iter().all(|t| *t == times[0]),
        "constant_eq: {times:?}"
    );
}

/// The modular additions and subtractions of the curve took a few
/// cycles more when they had to correct their result (a branch over a
/// subtraction), and the comparison stopped at the first limb that
/// differed: the time of SAE's arithmetic told something of the
/// numbers, which hide the password. Now every case takes the same.
#[test]
fn the_curve_arithmetic_takes_the_same_time_whatever_the_numbers() {
    let Some(image) = elf() else { return };
    let (mut m, symbols) = Machine::from_file(&image);
    let symbols = symbols.unwrap().symbols;
    let p: [u32; 8] = [
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0,
        0,
        0,
        1,
        0xFFFF_FFFF,
    ];
    let mut p1 = p;
    p1[0] -= 1;
    let one = [1, 0, 0, 0, 0, 0, 0, 0];
    let small = [5, 0, 0, 7, 0, 0, 0, 0x1234];
    let cases: [(&str, Vec<[[u32; 8]; 3]>); 4] = [
        (
            "add_mod",
            vec![[one, one, p], [p1, p1, p], [p1, one, p], [small, p1, p]],
        ),
        (
            "sub_mod",
            vec![[one, one, p], [one, p1, p], [p1, one, p], [small, p1, p]],
        ),
        (
            "reduce",
            vec![[one, p, p], [p, p, p], [p1, p, p], [p, one, p]],
        ),
        // `less(a, b)`: the first two only.
        (
            "less",
            vec![[one, p, p], [p, one, p], [p1, p, p], [p, p, p]],
        ),
    ];
    for (name, inputs) in cases {
        let suffix = format!("10lapin_p256{}{name}", name.len());
        let entries: Vec<u32> = symbols
            .iter()
            .filter(|(_, s)| s.ends_with(&suffix))
            .map(|(a, _)| *a)
            .collect();
        assert!(!entries.is_empty(), "no {name} in the image");
        for entry in entries {
            // The symbol table lost the Thumb bit: every one of these
            // is Thumb code (only the product is ARM).
            let times: Vec<u64> = inputs
                .iter()
                .map(|args| cycles_of(&mut m, entry | 1, name != "less", *args))
                .collect();
            assert!(
                times.iter().all(|t| *t == times[0]),
                "{name} at {entry:#x}: {times:?} cycles"
            );
        }
    }
}

/// WPA3 on the emulated rabbit, against an access point that loses
/// track of it.
mod wpa3 {
    use super::common::{
        authorized, handshakes, ip_on_the_wire, lapin, on_wpa3_network, until_every,
    };
    use nabemu::Machine;
    use nabemu::air::{AccessPoint, ApEvent};

    fn rabbit(ap: impl FnOnce(&mut AccessPoint)) -> Option<Machine> {
        let mut m = on_wpa3_network(&lapin()?);
        ap(&mut m.air[0]);
        Some(m)
    }

    /// Scenario A of the review: the access point loses power and comes
    /// back without the rabbit, which goes on sending under its keys;
    /// the answer is a deauthentication in clear, reason 7. The rabbit
    /// ignored it and stayed "connected" for ever; it now asks, gets no
    /// answer, and joins again.
    #[test]
    fn after_the_access_point_restarts_the_rabbit_joins_again() {
        let Some(mut m) = rabbit(|_| {}) else { return };
        let first = until_every(&mut m, 5, 30_000, "authorized", authorized);
        m.run_until_ms(first + 2000);
        m.air[0].power_cut();
        let cut = m.soc.millis();
        let back = until_every(&mut m, 5, 40_000, "back", |m| {
            authorized(m) && handshakes(m) == 2
        });
        assert!(
            m.air[0]
                .events
                .iter()
                .any(|e| matches!(e, ApEvent::Deauthenticated { reason: 7, .. })),
            "{:?}",
            m.air[0].events
        );
        eprintln!("back {} ms after the power cut", back - cut);
        assert_eq!(m.events, []);
    }

    /// Scenario B: message 4 lost, message 3 again in clear. Dropped,
    /// the access point gave up (reason 15, in clear, ignored too); now
    /// answered.
    #[test]
    fn a_lost_message_4_does_not_leave_the_rabbit_stranded() {
        let Some(mut m) = rabbit(|ap| ap.lose_message_4 = 1) else {
            return;
        };
        let done = until_every(&mut m, 5, 30_000, "authorized", authorized);
        m.run_until_ms(done + 3000);
        assert!(authorized(&m));
        assert_eq!(handshakes(&m), 1);
        assert!(ip_on_the_wire(&m));
        assert_eq!(m.events, []);
    }
}
