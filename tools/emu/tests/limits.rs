//! The firmware's limits, measured on the emulated rabbit under the
//! heaviest things it does: how deep its two stacks go, and the longest
//! the watchdog (2.09 s) goes unfed. Bounds, not observations: each
//! scenario fails if the firmware leaves its budget. The Rust firmware
//! only (`lapin/build.sh` first); skipped when it is not built.

use nabemu::Machine;
use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};
use nabemu::rfid::Tag;
use nabemu::soc::CLOCK_HZ;
use nabemu::visitor::Visitor;

/// Top of the internal RAM, where both stacks start (`lapin/fw/link.x`).
const STACK_TOP: u32 = 0x1000_4000;
/// The interrupt stack has 1 KB, the program the next 12 KB.
const IRQ_FLOOR: u32 = STACK_TOP - 0x400;
const PROGRAM_FLOOR: u32 = IRQ_FLOOR - 12 * 1024;
/// Half the watchdog's period: room for a real rabbit slower than this one.
const WATCHDOG_BUDGET_MS: u64 = 1045;

const IRQ: usize = 0x12;
const SYSTEM: usize = 0x1F;

fn lapin() -> Option<Machine> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../lapin/target/lapin-full.bin"
    );
    let image = std::fs::read(path).ok().or_else(|| {
        eprintln!("skipped: lapin is not built");
        None
    })?;
    Some(Machine::from_file(&image).0)
}

fn check(m: &Machine, scenario: &str) {
    let irq = m.stack_low[IRQ];
    let program = m.stack_low[SYSTEM];
    let unfed = m.soc.watchdog_longest.max(m.soc.watchdog_unfed()) * 1000 / CLOCK_HZ;
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

fn garenne() -> Option<Vec<u8>> {
    let default = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../clapier/garenne/build/garenne.bin"
    );
    let path = std::env::var("NABEMU_GARENNE").unwrap_or_else(|_| default.into());
    std::fs::read(path).ok()
}

/// WPA3 (the password exchange on the rabbit's processor), then the
/// application with its callbacks, a group rekey and a pairwise rekey.
#[test]
fn wpa3_and_garenne() {
    let Some(mut m) = lapin() else { return };
    let wifi = Wifi::Wpa2 {
        passphrase: "carotte-violette".into(),
    };
    Config::new("Terrier", wifi).install(&mut m.soc.flash);
    let mut ap = AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2("carotte-violette"),
    );
    ap.wpa3 = Wpa3::Only;
    m.air.push(ap);
    if let Some(bytecode) = garenne() {
        let mut lan = Lan::new();
        lan.handler = Box::new(move |_| Response::ok(bytecode.clone()));
        m.lan = Some(lan);
    }
    m.run_until_ms(30_000);
    assert!(m.air[0].is_authorized(nabemu::DEFAULT_MAC));
    m.air[0].rekey_group(&mut m.radio.borrow_mut());
    m.air[0].rekey_pairwise(&mut m.radio.borrow_mut(), nabemu::DEFAULT_MAC);
    m.run_until_ms(60_000);
    assert!(m.air[0].events.contains(&ApEvent::PairwiseKeyRenewed {
        sta: nabemu::DEFAULT_MAC
    }));
    check(&m, "WPA3 and garenne");
}

/// The setup page saves a WPA2 network: the key is derived from the
/// passphrase on the rabbit (PBKDF2, seconds of work), then it joins.
#[test]
fn setup_page_and_key_derivation() {
    let Some(mut m) = lapin() else { return };
    m.soc.board.button = true;
    m.run_until_ms(2000);
    m.soc.board.button = false;
    m.visitor = Some(Visitor::new([2, 0, 0, 0, 0, 0xB2], "Nabaztag"));
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2("carotte-violette"),
    ));
    while m.visitor.as_ref().unwrap().address.is_none() {
        assert!(m.soc.millis() < 30_000, "the phone got no address");
        m.run_until_ms(m.soc.millis() + 20);
    }
    m.visitor
        .as_mut()
        .unwrap()
        .get("/b?k=Terrier&m=64&n=carotte-violette&z=1");
    let joined = ApEvent::HandshakeComplete {
        sta: nabemu::DEFAULT_MAC,
    };
    while !m.air[0].events.contains(&joined) {
        assert!(m.soc.millis() < 120_000, "never joined");
        m.run_until_ms(m.soc.millis() + 20);
    }
    check(&m, "setup page, key derivation, join");
}

/// The factory test: ears, a tag, a tone, a recording played back.
#[test]
fn factory_test() {
    let Some(mut m) = lapin() else { return };
    m.soc.board.button = true;
    m.run_until_ms(8000);
    m.soc.board.button = false;
    m.run_until_ms(8500);
    m.soc
        .board
        .rfid
        .tags
        .push(Tag::new([0xD0, 2, 0x1A, 3, 4, 5, 6, 7]));
    for _ in 1..6 {
        m.soc.board.button = true;
        m.run_until_ms(m.soc.millis() + 200);
        m.soc.board.button = false;
        m.run_until_ms(m.soc.millis() + 3000);
    }
    // Step 6: hold to record, let go to hear it.
    m.soc.board.button = true;
    m.run_until_ms(m.soc.millis() + 3000);
    m.soc.board.button = false;
    m.run_until_ms(m.soc.millis() + 5000);
    check(&m, "factory test");
}

/// A collection with the heap nearly full of small blocks, a third of
/// them garbage between the others: everything left has to move. Then
/// `gc` once more, timed by the bytecode itself.
#[test]
fn collector_on_a_full_heap() {
    use nabemu::metal;
    let Some(mut m) = lapin() else { return };
    // Function 0, two locals: the list, the count.
    let mut f = vec![0u8, 2, 0];
    f.extend(metal::int(17_000)); // 0
    f.extend([40, 1]); // 5: setlocalb 1
    f.extend([7, 1, 29, 35, 0]); // 7: getlocalb 1; else 35
    f.extend([2, 4, 62, 5]); // 12: a 4-byte string, dropped
    f.extend([2, 4, 62, 7, 0, 32, 2, 40, 0]); // 16: another, consed onto the list
    f.extend([7, 1, 2, 1, 10, 40, 1, 28, 7, 0]); // 25: count - 1; goto 7
    f.extend([53, 87, 5, 53, 10, 95, 1]); // 35: time_ms; gc; drop; time_ms; sub; Iecholn; ret
    let served = metal::boot_response(&metal::bytecode(&[], &f));
    Config::new("Terrier", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::Open,
    ));
    let mut lan = Lan::new();
    lan.handler = Box::new(move |_| Response::ok(served.clone()));
    m.lan = Some(lan);
    let took = loop {
        assert!(m.soc.millis() < 60_000, "{}", m.console());
        m.run_until_ms(m.soc.millis() + 100);
        let console = m.console();
        if let Some(t) = console
            .lines()
            .filter_map(|l| l.strip_prefix('-')?.parse::<u64>().ok())
            .next_back()
        {
            break t;
        }
    };
    eprintln!("a collection over a full heap takes {took} ms");
    check(&m, "collector on a full heap");
}
