//! The scorecard: the C firmware the rabbits run (r3) against lapin, on
//! what a person beside the rabbit, or its server, can feel. Each
//! scenario runs the same way on both firmwares, timed on the board's
//! own clock, and gives table rows: the measure, r3, lapin, the unit,
//! and whether lapin does better, worse or the same. Nothing is asserted
//! but that every scenario ran to its end on both: the rows lapin loses
//! are the goals. It picks both images itself, so it runs once (it is
//! in `lapin_fixed`), and skips when lapin is not built.
//!
//! `VERSUS=<part of a scenario's name>` runs only those scenarios. The
//! table goes to the test's output (`--nocapture`) and to `versus.txt`
//! in Cargo's directory for the tests' files.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use common::bc::{self, Global, op::*};
use common::{
    BSSID, PASSPHRASE, SSID, UID, ap_saw, authorized, find, garenne, garenne_log, handshakes,
    in_parallel, in_setup_mode, lapin, machine, note, on_network, on_wpa3_network, open,
    pcm_8k_header, phone, r3, restarted, serve, serve_first, serving, terrier, until, until_every,
    wait, wpa2,
};
use nabemu::air::{AccessPoint, ApEvent, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::Lan;
use nabemu::rfid::Tag;
use nabemu::visitor::Link;
use nabemu::{DEFAULT_MAC, Machine, metal};

#[derive(Clone, Copy, PartialEq)]
enum Fw {
    R3,
    Lapin,
}

/// A firmware and its image.
struct Rabbit {
    fw: Fw,
    image: Vec<u8>,
}

/// Which way a measure is better.
#[derive(Clone, Copy, PartialEq)]
enum Better {
    Lower,
    Higher,
    /// The bytecode sees it: lapin should do as r3 does.
    Same,
    /// Said for what it explains, not judged.
    Info,
}

/// One measure of one scenario on one firmware (`None`: not there).
struct Measure {
    metric: String,
    value: Option<f64>,
    unit: &'static str,
    better: Better,
}

/// The highs every scenario leaves, with the scenario where each was:
/// names and units. The watchdog and the interrupts are watched apart
/// from power-on to the program's start, and from then on.
const PEAKS: [(&str, &str); 6] = [
    ("watchdog: longest unfed, booting", "ms"),
    ("watchdog: longest unfed, running", "ms"),
    ("interrupts held back: longest, booting", "ms"),
    ("interrupts held back: longest, running", "ms"),
    ("program stack: deepest", "bytes"),
    ("interrupt stack: deepest", "bytes"),
];

/// What a scenario measured on one firmware.
struct Card {
    scenario: &'static str,
    rows: Vec<Measure>,
    peaks: [(f64, &'static str); 6],
    /// Past the program's start: the highs go to the running ones.
    running: bool,
}

impl Card {
    fn new(scenario: &'static str) -> Self {
        Card {
            scenario,
            rows: Vec::new(),
            peaks: [(0.0, ""); 6],
            running: false,
        }
    }

    fn put(
        &mut self,
        metric: impl Into<String>,
        value: Option<f64>,
        unit: &'static str,
        better: Better,
    ) {
        self.rows.push(Measure {
            metric: metric.into(),
            value,
            unit,
            better,
        });
    }

    /// A time, less being better.
    fn ms(&mut self, metric: impl Into<String>, value: Option<f64>) {
        self.put(metric, value, "ms", Better::Lower);
    }

    /// Fold in the highs of a machine, so far.
    fn seen(&mut self, m: &Machine) {
        let depth = |modes: &[usize]| {
            modes
                .iter()
                .filter(|&&mode| m.stack_low[mode] != u32::MAX)
                .map(|&mode| m.stack_high[mode] - m.stack_low[mode])
                .max()
                .unwrap_or(0) as f64
        };
        let phase = self.running as usize;
        let mut now = [0.0; 6];
        now[phase] = board_ms(m.soc.watchdog_longest.max(m.soc.watchdog_unfed()));
        now[2 + phase] = board_ms(m.masked_longest);
        // User, supervisor and system: wherever the program runs.
        now[4] = depth(&[0x10, 0x13, 0x1F]);
        now[5] = depth(&[0x12]);
        for (peak, value) in self.peaks.iter_mut().zip(now) {
            if value > peak.0 {
                *peak = (value, self.scenario);
            }
        }
    }

    /// The program is running: the highs of the boot are kept, and the
    /// watch starts again.
    fn started(&mut self, m: &mut Machine) {
        self.seen(m);
        self.running = true;
        m.masked_longest = 0;
        m.soc.watchdog_longest = 0;
    }

    /// The machine starts again (a new one, or the same after a power
    /// cut): what comes next is a boot.
    fn booting(&mut self, m: &mut Machine) {
        self.seen(m);
        self.running = false;
        m.masked_longest = 0;
        m.soc.watchdog_longest = 0;
    }
}

/// Board cycles as milliseconds, to the microsecond.
fn board_ms(cycles: u64) -> f64 {
    cycles as f64 * 1000.0 / nabemu::soc::CLOCK_HZ as f64
}

/// Milliseconds between two moments, when both came.
fn span(from: Option<u64>, to: Option<u64>) -> Option<f64> {
    Some(to? as f64 - from? as f64)
}

fn when(t: Option<u64>) -> Option<f64> {
    t.map(|t| t as f64)
}

// The programs, put together a function at a time.

/// Global 0 of every program here: what `say` prints before a value.
const AT: u8 = 0;
/// The locals of the programs' main functions: a time, a count, two
/// values.
const T0: u8 = 0;
const N: u8 = 1;
const ACC: u8 = 2;
const X: u8 = 3;

/// A function put together a piece at a time, its jumps going to places
/// named before they are reached.
struct Code {
    args: u8,
    locals: u16,
    b: Vec<u8>,
    places: Vec<Option<usize>>,
    jumps: Vec<(usize, usize)>,
}

impl Code {
    fn new(args: u8, locals: u16) -> Self {
        Code {
            args,
            locals,
            b: Vec::new(),
            places: Vec::new(),
            jumps: Vec::new(),
        }
    }

    /// A main function that starts as `whole` (header included) does.
    fn from_main(whole: Vec<u8>, locals: u16) -> Self {
        let mut c = Code::new(0, locals);
        c.b = whole[metal::FUNCTION_HEADER.len()..].to_vec();
        c
    }

    fn op(&mut self, ops: &[u8]) -> &mut Self {
        self.b.extend_from_slice(ops);
        self
    }

    fn int(&mut self, value: i32) -> &mut Self {
        self.b.extend(metal::int(value));
        self
    }

    /// A place to jump to, put down later with `here`.
    fn place(&mut self) -> usize {
        self.places.push(None);
        self.places.len() - 1
    }

    fn here(&mut self, place: usize) -> &mut Self {
        self.places[place] = Some(self.b.len());
        self
    }

    /// `GOTO` or `ELSE` to `place`.
    fn jump(&mut self, op: u8, place: usize) -> &mut Self {
        self.b.push(op);
        self.jumps.push((self.b.len(), place));
        self.b.extend([0, 0]);
        self
    }

    /// Print the value on top of the stack as `@<value>`, and drop it.
    fn say(&mut self) -> &mut Self {
        self.op(&[GETGLOBALB, AT, SECHO, DROP, IECHOLN, DROP])
    }

    /// Start the clock (local `T0`).
    fn clock(&mut self) -> &mut Self {
        self.op(&[TIME_MS, SETLOCALB, T0])
    }

    /// Say the milliseconds since the clock started.
    fn lap(&mut self) -> &mut Self {
        self.op(&[TIME_MS, GETLOCALB, T0, SUB]).say()
    }

    /// `body` `n` times, counting down in local `N`.
    fn times(&mut self, n: i32, body: impl FnOnce(&mut Code)) -> &mut Self {
        let (top, end) = (self.place(), self.place());
        self.int(n).op(&[SETLOCALB, N]).here(top);
        self.op(&[GETLOCALB, N]).jump(ELSE, end);
        body(self);
        self.op(&[GETLOCALB, N]).int(1).op(&[SUB, SETLOCALB, N]);
        self.jump(GOTO, top).here(end)
    }

    /// `global = value`, the value pushed by `value`.
    fn set(&mut self, global: u8, value: &[u8]) -> &mut Self {
        self.op(&[INTB, global]).op(value).op(&[SETGLOBAL, DROP])
    }

    /// Return 0.
    fn end(&mut self) -> &mut Self {
        self.int(0).op(&[RET])
    }

    /// The function, header and all, its jumps landed.
    fn done(&self) -> Vec<u8> {
        let mut b = self.b.clone();
        for &(at, place) in &self.jumps {
            let to = self.places[place].expect("every place put down") as u16;
            b[at..at + 2].copy_from_slice(&to.to_le_bytes());
        }
        bc::function(self.args, self.locals, &b)
    }
}

/// A bytecode of `functions` with `globals` from global 1 on: global 0
/// is what `say` prints, and a spare one ends them (the last global of
/// a served bytecode lies above the stack once its main returned).
fn program(globals: &[Global], functions: &[&Code]) -> Vec<u8> {
    let mut all = vec![Global::Str(b"@")];
    all.extend(globals.iter().map(|g| match g {
        Global::Str(s) => Global::Str(s),
        Global::Word(w) => Global::Word(*w),
    }));
    all.push(Global::Word(u32::MAX));
    let functions: Vec<Vec<u8>> = functions.iter().map(|f| f.done()).collect();
    let functions: Vec<&[u8]> = functions.iter().map(Vec::as_slice).collect();
    bc::assemble(&all, &functions)
}

/// What the program said with `say`, in order.
fn said(m: &Machine) -> Vec<i64> {
    m.console()
        .lines()
        .filter_map(|l| l.strip_prefix('@')?.trim().parse().ok())
        .collect()
}

/// How many times it said something: cheaper, to look at every step.
fn says(m: &Machine) -> usize {
    m.soc.uart_tx.windows(2).filter(|w| w == b"\n@").count()
}

/// Wait for the program's first word: from then on, it runs.
fn running(m: &mut Machine, card: &mut Card) {
    until_every(m, 1, 60_000, "the program", |m| says(m) > 0);
    card.started(m);
}

/// Run `m` until each of `marks` came true, looking every millisecond,
/// `during` acting on it before each step, for at most `limit_ms`: when
/// each first did, from now (`None`: not by then).
fn timeline(
    m: &mut Machine,
    limit_ms: u64,
    marks: &[&dyn Fn(&Machine) -> bool],
    mut during: impl FnMut(&mut Machine, u64),
) -> Vec<Option<u64>> {
    let start = m.soc.millis();
    let mut at = vec![None; marks.len()];
    loop {
        let now = m.soc.millis() - start;
        for (when, mark) in at.iter_mut().zip(marks) {
            if when.is_none() && mark(m) {
                *when = Some(now);
            }
        }
        if at.iter().all(Option::is_some) || now >= limit_ms {
            return at;
        }
        during(m, now);
        wait(m, 1);
    }
}

fn lan(m: &Machine) -> &Lan {
    m.lan.as_ref().expect("a server behind the access point")
}

/// The underruns of the sound since `since`: how many, and how long in all.
fn gaps(m: &Machine, since: u64) -> (f64, f64) {
    let gaps: Vec<_> = m
        .soc
        .board
        .codec
        .gaps
        .iter()
        .filter(|(at, _)| *at >= since)
        .collect();
    let total = gaps.iter().fold(0.0, |all, (_, ms)| all + *ms as f64);
    (gaps.len() as f64, total)
}

// Power-on to the served bytecode.

/// What the server answers in the boot scenarios: a program that prints this.
const MARK: &[u8] = b"20061225";

/// From power-on to the server's bytecode running, step by step, on
/// the network `m` is set up for (`None`: this firmware cannot join it).
fn boot(card: &mut Card, label: &str, m: Option<Machine>, psk: bool) {
    let steps = [
        "first console line",
        "boot bytecode running",
        "Wi-Fi stick up",
        "associated",
        "handshake done",
        "DHCP lease",
        "first HTTP request",
        "served bytecode running",
    ];
    let mut put = |at: &[Option<u64>]| {
        for (step, t) in steps.iter().zip(at) {
            if psk || *step != "handshake done" {
                card.ms(format!("{label}: power-on → {step}"), when(*t));
            }
        }
    };
    let Some(mut m) = m else {
        put(&[None; 8]);
        return;
    };
    serve(&mut m, metal::boot_response(&metal::print_number(20061225)));
    let marks: [&dyn Fn(&Machine) -> bool; 8] = [
        &|m| m.soc.uart_tx.contains(&b'\n'),
        &|m| find(&m.soc.uart_tx, b":started").is_some(),
        &|m| m.radio.borrow().firmware_loaded,
        &|m| ap_saw(m, &ApEvent::Associated { sta: DEFAULT_MAC }),
        &|m| handshakes(m) > 0,
        &|m| lan(m).leased_to.is_some(),
        &|m| !lan(m).requests.is_empty(),
        &|m| find(&m.soc.uart_tx, MARK).is_some(),
    ];
    let at = timeline(&mut m, 60_000, &marks, |_, _| {});
    assert!(at[7].is_some(), "{label}: the served bytecode never ran");
    put(&at);
    card.seen(&m);
}

fn boot_open(r: &Rabbit, card: &mut Card) {
    boot(card, "open", Some(on_network(&r.image, open())), false);
}

fn boot_wpa2(r: &Rabbit, card: &mut Card) {
    boot(card, "WPA2", Some(on_network(&r.image, wpa2())), true);
}

/// r3 has no WPA3: n/a.
fn boot_wpa3(r: &Rabbit, card: &mut Card) {
    let m = (r.fw == Fw::Lapin).then(|| on_wpa3_network(&r.image));
    boot(card, "WPA3", m, true);
}

/// `n` open networks around, on `channel` or spread over the band,
/// beaconing every `beacon_ms`.
fn neighbours(m: &mut Machine, n: usize, channel: Option<u8>, beacon_ms: u64) {
    for i in 0..n {
        let bssid = [2, 0, 0, 3, (i / 256) as u8, (i % 256) as u8];
        let channel = channel.unwrap_or([1, 4, 9, 11, 13][i % 5]);
        let mut ap = AccessPoint::new(&format!("Neighbour-{i}"), bssid, channel, Security::Open);
        ap.beacon_interval = beacon_ms;
        m.air.push(ap);
    }
}

/// The home network, open, on channel 11, among two hundred others on
/// channel 1 that beacon five times as often as usual.
fn boot_crowded(r: &Rabbit, card: &mut Card) {
    let mut m = machine(&r.image);
    Config::new(SSID, Wifi::Open).install(&mut m.soc.flash);
    m.air
        .push(AccessPoint::new(SSID, BSSID, 11, Security::Open));
    neighbours(&mut m, 200, Some(1), 20);
    serve(&mut m, metal::boot_response(&metal::print_number(20061225)));
    let marks: [&dyn Fn(&Machine) -> bool; 3] = [
        &|m| ap_saw(m, &ApEvent::Associated { sta: DEFAULT_MAC }),
        &|m| lan(m).leased_to.is_some(),
        &|m| find(&m.soc.uart_tx, MARK).is_some(),
    ];
    let at = timeline(&mut m, 60_000, &marks, |_, _| {});
    assert!(at[2].is_some(), "the served bytecode never ran");
    for (step, t) in ["associated", "DHCP lease", "served bytecode running"]
        .iter()
        .zip(at)
    {
        card.ms(format!("200 neighbours: power-on → {step}"), when(t));
    }
    card.seen(&m);
}

// On the home network (WPA2), with a program that joins it again
// whenever the link is idle, as the rabbit's application does.

const TABLE: u8 = 1;
const KEY: u8 = 2;
const NAME: u8 = 3;
const AP_MAC: u8 = 4;
const HEADER: u8 = 5;
const SAMPLES: u8 = 6;
const PULSE: u8 = 7;
const EVERYONE: u8 = 8;

/// The program: it says 1, then from its loop callback joins again when
/// the link is idle, and sends a pulse at every turn. With `sound`, an endless tone plays all along; with
/// `busy`, the ears turn, and each turn of the loop reads the tag reader
/// and sets the nose's colour too.
fn at_home(sound: bool, busy: bool) -> Vec<u8> {
    const POLL: i32 = 1;
    const FEED: i32 = 2;
    let mut main = Code::from_main(bc::main_with_home_network(TABLE as i32, NAME, AP_MAC), 0);
    if sound {
        main.int(1).int(FEED).op(&[PLAYSTART, DROP]);
        main.op(&[GETGLOBALB, HEADER, INTB, 0, NIL, PLAYFEED, DROP]);
    }
    if busy {
        main.op(&[INTB, 0, INTB, 1, MOTORSET, DROP, INTB, 1])
            .int(-1)
            .op(&[MOTORSET, DROP]);
    }
    main.int(1).say().int(POLL).op(&[LOOPCB, DROP]).end();

    let mut poll = Code::new(0, 0);
    let linked = poll.place();
    poll.op(&[NETSTATE, INTB, 1, EQ]).jump(ELSE, linked);
    poll.op(&[
        GETGLOBALB, TABLE, INTB, 0, INTB, 0x40, GETGLOBALB, KEY, NETAUTH, DROP,
    ]);
    // A frame to everyone at every turn, as an application's pulse: an
    // access point that forgot the rabbit throws it out at once.
    poll.here(linked);
    poll.op(&[
        GETGLOBALB, PULSE, INTB, 0, NIL, GETGLOBALB, EVERYONE, INTB, 0, INTB, 0,
    ]);
    poll.op(&[NETSEND, DROP]);
    if busy {
        poll.op(&[RFIDGET, DROP, INTB, 0, TIME_MS, LED, DROP]);
    }
    poll.end();

    let mut feed = Code::new(1, 0);
    feed.op(&[GETGLOBALB, SAMPLES, INTB, 0, GETLOCALB, 0, PLAYFEED, RET]);

    let key = nabemu::crypto::wpa_psk(PASSPHRASE, SSID);
    let header = pcm_8k_header(u32::MAX);
    let tone: Vec<u8> = (0..2048).flat_map(|i| note(i).to_le_bytes()).collect();
    let globals = [
        Global::Word(u32::MAX),
        Global::Str(&key),
        Global::Str(SSID.as_bytes()),
        Global::Str(&BSSID),
        Global::Str(&header),
        Global::Str(&tone),
        // LLC and SNAP, a type no one handles (0x88B5), four bytes.
        Global::Str(&[0xAA, 0xAA, 3, 0, 0, 0, 0x88, 0xB5, 1, 2, 3, 4]),
        Global::Str(&[0xFF; 6]),
    ];
    program(&globals, &[&main, &poll, &feed])
}

/// The rabbit on the home network, running `at_home`, two seconds after
/// it got there.
fn at_home_joined(r: &Rabbit, card: &mut Card, sound: bool, busy: bool) -> Machine {
    let mut m = on_network(&r.image, wpa2());
    serve(&mut m, metal::boot_response(&at_home(sound, busy)));
    until(&mut m, 60_000, "the program on its network", |m| {
        says(m) > 0 && authorized(m) && (!sound || m.soc.board.codec.current.is_some())
    });
    card.started(&mut m);
    wait(&mut m, 2000);
    m
}

/// The access point loses its power for `off_ms` and comes back knowing
/// no one: what the rabbit sent before is not heard again.
fn access_point_restarts(m: &mut Machine, off_ms: u64) {
    let ap = m.air.remove(0);
    wait(m, off_ms);
    m.radio.borrow_mut().tx.clear();
    m.air.insert(0, terrier(ap.security));
}

/// Thrown out by the access point (deauthentication): how long until
/// the rabbit is back on the network.
fn thrown_out_and_back(m: &mut Machine) -> Option<u64> {
    m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 2);
    let back: &dyn Fn(&Machine) -> bool = &|m| handshakes(m) >= 2 && authorized(m);
    timeline(m, 60_000, &[back], |_, _| {})[0]
}

/// Thrown out by the access point (deauthentication), and back.
fn rejoin_deauth(r: &Rabbit, card: &mut Card) {
    let mut m = at_home_joined(r, card, false, false);
    let back = thrown_out_and_back(&mut m);
    card.ms("rejoin: thrown out → back on the network", when(back));
    card.seen(&m);
}

/// The access point goes off for ten seconds, and comes back knowing
/// nothing of the rabbit.
fn rejoin_ap_restart(r: &Rabbit, card: &mut Card) {
    let mut m = at_home_joined(r, card, false, false);
    m.radio.borrow_mut().tx.clear();
    // A probe, an authentication or an association request, within the
    // ten seconds: it looks for its network again.
    let looking = |m: &Machine| {
        let radio = m.radio.borrow();
        radio
            .tx
            .iter()
            .any(|f| matches!(f.data[0], 0x40 | 0xB0 | 0x00))
    };
    access_point_restarts(&mut m, 10_000);
    let looked = looking(&m);
    let marks: [&dyn Fn(&Machine) -> bool; 2] = [
        &|m| {
            m.air[0]
                .events
                .iter()
                .any(|e| matches!(e, ApEvent::Deauthenticated { by_ap: true, .. }))
        },
        &|m| handshakes(m) >= 1 && authorized(m),
    ];
    let at = timeline(&mut m, 120_000, &marks, |_, _| {});
    card.put(
        "rejoin: access point off 10 s → rabbit looked for it",
        Some(looked as u8 as f64),
        "yes",
        Better::Higher,
    );
    // Within a turn of the loop callback, where its pulse goes: luck.
    let thrown = when(at[0]);
    card.put(
        "rejoin: access point back → rabbit thrown out (its pulse)",
        thrown,
        "ms",
        Better::Info,
    );
    card.ms(
        "rejoin: thrown out → back on the restarted access point",
        span(at[0], at[1]),
    );
    card.seen(&m);
}

/// The rabbit's power cut, and back.
fn rejoin_power_cut(r: &Rabbit, card: &mut Card) {
    let mut m = at_home_joined(r, card, false, false);
    card.booting(&mut m);
    m.power_cycle();
    let marks: [&dyn Fn(&Machine) -> bool; 2] =
        [&|m| handshakes(m) >= 2 && authorized(m), &|m| says(m) >= 2];
    let at = timeline(&mut m, 60_000, &marks, |_, _| {});
    assert!(at[1].is_some(), "the program never ran again");
    card.ms("power cut: power back → on the network", when(at[0]));
    card.ms(
        "power cut: power back → served bytecode running",
        when(at[1]),
    );
    card.seen(&m);
}

/// A tone plays on while the rabbit is thrown out and joins again.
fn sound_through_rejoin(r: &Rabbit, card: &mut Card) {
    let mut m = at_home_joined(r, card, true, false);
    let since = m.soc.millis();
    let back = thrown_out_and_back(&mut m);
    assert!(back.is_some(), "never back on the network");
    wait(&mut m, 2000);
    let (count, total) = gaps(&m, since);
    card.ms("sound through a rejoin: thrown out → back", when(back));
    card.put(
        "sound through a rejoin: underruns",
        Some(count),
        "",
        Better::Lower,
    );
    card.ms("sound through a rejoin: silence in all", Some(total));
    card.seen(&m);
}

/// Two minutes of everything: an endless tone, the ears turning, the
/// tag reader and the nose at every turn of the loop, a tag shown and
/// taken away, group keys renewed, thrown out once, the access point
/// restarted once.
fn busy_two_minutes(r: &Rabbit, card: &mut Card) {
    let mut m = at_home_joined(r, card, true, true);
    let since = m.soc.millis();
    let resets = m.events.len();
    let mut off = 0u64;
    for second in 1..=120 {
        for _ in 0..100 {
            wait(&mut m, 10);
            if !authorized(&m) {
                off += 10;
            }
        }
        let tags = &mut m.soc.board.rfid.tags;
        match second {
            20 => tags.push(Tag::new(UID)),
            40 => tags.clear(),
            30 | 100 => m.air[0].rekey_group(&mut m.radio.borrow_mut()),
            60 => m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 2),
            80 => {
                access_point_restarts(&mut m, 2000);
                off += 2000;
            }
            _ => {}
        }
    }
    let (count, total) = gaps(&m, since);
    let restarts = (m.events.len() - resets) as f64;
    card.put(
        "2 minutes busy: restarts",
        Some(restarts),
        "",
        Better::Lower,
    );
    card.ms("2 minutes busy: off the network in all", Some(off as f64));
    card.put(
        "2 minutes busy: sound underruns",
        Some(count),
        "",
        Better::Lower,
    );
    card.ms("2 minutes busy: silence in all", Some(total));
    // An estimate of the internal RAM in use: what is not zero.
    let used = m.soc.iram.iter().filter(|b| **b != 0).count();
    card.put(
        "internal RAM not zero after the busy run",
        Some(used as f64),
        "bytes",
        Better::Lower,
    );
    card.seen(&m);
}

// The bytecode's own work, timed by itself.

/// Each of these, timed, then the heap: how full when the program
/// starts, how long a collection takes once it is full, and how full
/// it is then.
fn bytecode_speed(r: &Rabbit, card: &mut Card) {
    let mut main = Code::new(0, 4);
    main.op(&[GC]).say();
    main.clock().times(100_000, |_| {}).lap();
    main.clock().op(&[INTB, 20, INTB, 1, EXEC, DROP]).lap();
    main.clock().times(2000, |c| {
        c.op(&[GETGLOBALB, 1, GETGLOBALB, 1, STRCAT, DROP]);
    });
    main.lap().clock().times(2000, |c| {
        c.op(&[GETGLOBALB, 1, INTB, 3, INTB, 20, STRSUB, DROP]);
    });
    main.lap().clock().times(2000, |c| {
        c.op(&[GETLOCALB, N, ITOA, DROP]);
    });
    main.lap()
        .op(&[NIL, INTB, 64, TABNEW, SETLOCALB, ACC])
        .clock();
    main.times(5000, |c| {
        let slot = [GETLOCALB, ACC, GETLOCALB, N, INTB, 63, AND];
        c.op(&slot)
            .op(&[GETLOCALB, N, STORE, DROP])
            .op(&slot)
            .op(&[FETCH, DROP]);
    });
    main.lap()
        .op(&[NIL, SETLOCALB, ACC])
        .clock()
        .times(20_000, |c| {
            c.op(&[
                INTB, 16, STRNEW, DROP, GETLOCALB, N, GETLOCALB, ACC, DEFTABB, 2, SETLOCALB, ACC,
            ]);
        });
    main.lap().op(&[NIL, SETLOCALB, ACC]).times(17_000, |c| {
        c.op(&[
            INTB, 4, STRNEW, DROP, INTB, 4, STRNEW, GETLOCALB, ACC, DEFTABB, 2, SETLOCALB, ACC,
        ]);
    });
    main.clock()
        .op(&[GC, SETLOCALB, X])
        .lap()
        .op(&[GETLOCALB, X])
        .say();
    main.op(&[NIL, SETLOCALB, ACC, GC, DROP]).end();

    // fib n = if n < 2 then n else fib (n-1) + fib (n-2)
    let mut fib = Code::new(1, 0);
    let deeper = fib.place();
    fib.op(&[GETLOCALB, 0, INTB, 2, LT])
        .jump(ELSE, deeper)
        .op(&[GETLOCALB, 0, RET]);
    fib.here(deeper)
        .op(&[GETLOCALB, 0, INTB, 1, SUB, INTB, 1, EXEC]);
    fib.op(&[GETLOCALB, 0, INTB, 2, SUB, INTB, 1, EXEC, ADD, RET]);

    let text = [b'x'; 32];
    let mut m = serving(&r.image, &program(&[Global::Str(&text)], &[&main, &fib]));
    running(&mut m, card);
    until_every(&mut m, 50, 120_000, "the benchmarks", |m| {
        said(m).len() >= 10
    });
    let v: Vec<f64> = said(&m).iter().map(|v| *v as f64).collect();
    card.put(
        "heap used when the served bytecode starts",
        Some(v[0]),
        "%",
        Better::Lower,
    );
    for (name, value) in [
        "loop of 100 000 turns",
        "fib 20 (21 891 calls)",
        "strcat ×2000 (32 + 32 bytes)",
        "strsub ×2000 (17 bytes)",
        "itoa ×2000",
        "table store and fetch ×5000",
        "20 000 pairs kept and 20 000 strings dropped",
        "collection with 17 000 pairs live",
    ]
    .iter()
    .zip(&v[1..9])
    {
        card.ms(*name, Some(*value));
    }
    card.put(
        "heap used by 17 000 pairs after the collection",
        Some(v[9]),
        "%",
        Better::Info,
    );
    card.seen(&m);
}

/// Say 0, then each `natives` (code that leaves one value) `n` times,
/// timed.
fn timed(natives: &[(i32, &[u8])]) -> Code {
    let mut main = Code::new(0, 2);
    main.int(0).say();
    for (n, native) in natives {
        main.clock().times(*n, |c| {
            c.op(native).op(&[DROP]);
        });
        main.lap();
    }
    main.end();
    main
}

/// `rfidGet` with a tag in front of the nose and without, `rfidRead`
/// and `rfidWrite`.
fn rfid(r: &Rabbit, card: &mut Card) {
    let read: &[u8] = &[GETGLOBALB, 1, INTB, 1, RFIDREAD];
    let write: &[u8] = &[GETGLOBALB, 1, INTB, 2, GETGLOBALB, 2, RFIDWRITE];
    let globals = [Global::Str(&UID), Global::Str(b"noix")];
    let with = program(
        &globals,
        &[&timed(&[(20, &[RFIDGET]), (10, read), (10, write)])],
    );
    let without = program(&globals, &[&timed(&[(20, &[RFIDGET])])]);
    let run = |card: &mut Card, bytecode: &[u8], tag: bool, n: usize| {
        let mut m = serving(&r.image, bytecode);
        card.booting(&mut m);
        if tag {
            m.soc.board.rfid.tags.push(Tag::new(UID));
        }
        running(&mut m, card);
        until_every(&mut m, 50, 60_000, "the tag reader timed", |m| {
            said(m).len() > n
        });
        card.seen(&m);
        said(&m)
    };
    let with = run(card, &with, true, 3);
    let without = run(card, &without, false, 1);
    card.ms("rfidGet, a tag there", Some(with[1] as f64 / 20.0));
    card.ms("rfidGet, no tag", Some(without[1] as f64 / 20.0));
    card.ms("rfidRead of a block", Some(with[2] as f64 / 10.0));
    card.ms("rfidWrite of a block", Some(with[3] as f64 / 10.0));
}

// What the program does when something happens around the rabbit.

/// A program whose loop callback, at the head button's press, starts
/// ear 0, lights the nose and starts a tone, in that order; and stops
/// the ear three teeth on.
fn reacting() -> Vec<u8> {
    const STATE: u8 = 1;
    const SOUND: u8 = 2;
    const TONE: u8 = 3;
    const TARGET: u8 = 4;
    let mut main = Code::new(0, 0);
    main.int(1).say().int(1).op(&[LOOPCB, DROP]).end();

    let mut poll = Code::new(0, 0);
    let (idle, end) = (poll.place(), poll.place());
    poll.op(&[GETGLOBALB, STATE]).jump(ELSE, idle);
    poll.op(&[GETGLOBALB, STATE, INTB, 1, EQ]).jump(ELSE, end);
    poll.op(&[INTB, 0, MOTORGET, GETGLOBALB, TARGET, GE])
        .jump(ELSE, end);
    poll.op(&[INTB, 0, INTB, 0, MOTORSET, DROP])
        .set(STATE, &[INTB, 2])
        .jump(GOTO, end);
    poll.here(idle).op(&[BUTTON2]).jump(ELSE, end);
    poll.op(&[INTB, 0, INTB, 1, MOTORSET, DROP, INTB, 0])
        .int(0xFF00FF)
        .op(&[LED, DROP]);
    poll.int(1).int(2).op(&[
        PLAYSTART, DROP, GETGLOBALB, SOUND, INTB, 0, NIL, PLAYFEED, DROP,
    ]);
    poll.set(TARGET, &[INTB, 0, MOTORGET, INTB, 3, ADD])
        .set(STATE, &[INTB, 1]);
    poll.here(end).end();

    let mut feed = Code::new(1, 0);
    feed.op(&[GETGLOBALB, TONE, INTB, 0, GETLOCALB, 0, PLAYFEED, RET]);

    let header = pcm_8k_header(u32::MAX);
    let tone: Vec<u8> = (0..2048).flat_map(|i| note(i).to_le_bytes()).collect();
    let globals = [
        Global::Word(0),
        Global::Str(&header),
        Global::Str(&tone),
        Global::Word(0),
    ];
    program(&globals, &[&main, &poll, &feed])
}

/// How many times a reaction is timed, the press or the tag coming
/// 5 ms later each time: the loop callback turns every 50 ms, and
/// where in its turn a press falls is luck.
const PHASES: u64 = 10;

/// The means of `runs`' times (each a list, in the same order).
fn means(runs: &[Vec<f64>]) -> Vec<f64> {
    (0..runs[0].len())
        .map(|i| runs.iter().map(|r| r[i]).sum::<f64>() / runs.len() as f64)
        .collect()
}

/// The head button pressed for 200 ms: when the ear starts, the nose
/// lights, the sound comes out, the ear stops; then the tone plays on.
fn button(r: &Rabbit, card: &mut Card) {
    let mut runs = Vec::new();
    let mut past = 0;
    let mut sound = (0.0, 0.0);
    for phase in 0..PHASES {
        let mut m = serving(&r.image, &reacting());
        card.booting(&mut m);
        running(&mut m, card);
        wait(&mut m, 1000 + phase * 5);
        let leds = m.soc.board.leds;
        let teeth = m.soc.board.ears.map(|e| e.pulses);
        let moved = |m: &Machine| {
            m.soc
                .board
                .ears
                .iter()
                .zip(teeth)
                .any(|(e, t)| e.pulses >= t + 3)
        };
        let marks: [&dyn Fn(&Machine) -> bool; 5] = [
            &|m| m.soc.board.ears.iter().any(|e| e.direction != 0),
            &|m| m.soc.board.leds != leds,
            &|m| m.soc.board.amplifier && m.soc.board.codec.consumed > 44,
            &moved,
            &|m| moved(m) && m.soc.board.ears.iter().all(|e| e.direction == 0),
        ];
        let pressed = m.soc.millis();
        let at = timeline(&mut m, 10_000, &marks, |m, now| {
            m.soc.board.button = now < 200
        });
        m.soc.board.button = false;
        let at: Vec<f64> = at
            .iter()
            .map(|t| t.expect("each of the button's effects") as f64)
            .collect();
        let teeth_past = m
            .soc
            .board
            .ears
            .iter()
            .zip(teeth)
            .map(|(e, t)| e.pulses - t)
            .max();
        past = past.max(teeth_past.unwrap());
        runs.push(vec![
            at[0],
            at[1],
            at[2],
            at[1] - at[0],
            at[2] - at[0],
            at[4] - at[3],
        ]);
        if phase == 0 {
            let from = pressed + at[2] as u64;
            m.run_until_ms(from + 5000);
            sound = gaps(&m, from);
        }
        card.seen(&m);
    }
    let names = [
        "button → ear starts (motorSet)",
        "button → nose lit",
        "button → first sound out",
        "led → lit (from the ear's start)",
        "playStart → first sound out (from the ear's start)",
        "ear: third tooth → motor stopped",
    ];
    for (name, mean) in names.iter().zip(means(&runs)) {
        card.ms(format!("{name}, mean of {PHASES}"), Some(mean));
    }
    card.put(
        "ear: teeth past the one asked",
        Some(past as f64 - 3.0),
        "",
        Better::Lower,
    );
    card.put("5 s of sound: underruns", Some(sound.0), "", Better::Lower);
    card.ms("5 s of sound: silence in all", Some(sound.1));
}

/// A loop callback that counts its turns for two seconds, then says how
/// many; and lights the nose when it sees a tag.
fn polling(r: &Rabbit, card: &mut Card) {
    const COUNT: u8 = 1;
    const SINCE: u8 = 2;
    const DONE: u8 = 3;
    const SEEN: u8 = 4;
    let mut main = Code::new(0, 0);
    main.set(SINCE, &[TIME_MS])
        .int(1)
        .say()
        .int(1)
        .op(&[LOOPCB, DROP])
        .end();
    let mut poll = Code::new(0, 0);
    let (count, tag, look, end) = (poll.place(), poll.place(), poll.place(), poll.place());
    poll.set(COUNT, &[GETGLOBALB, COUNT, INTB, 1, ADD]);
    poll.op(&[GETGLOBALB, DONE])
        .jump(ELSE, count)
        .jump(GOTO, tag);
    poll.here(count)
        .op(&[TIME_MS, GETGLOBALB, SINCE, SUB])
        .int(2000)
        .op(&[GE])
        .jump(ELSE, tag);
    poll.op(&[GETGLOBALB, COUNT]).say().set(DONE, &[INTB, 1]);
    poll.here(tag)
        .op(&[GETGLOBALB, SEEN])
        .jump(ELSE, look)
        .jump(GOTO, end);
    poll.here(look).op(&[RFIDGET, NIL, NE]).jump(ELSE, end);
    poll.op(&[INTB, 0])
        .int(0x00FF00)
        .op(&[LED, DROP])
        .set(SEEN, &[INTB, 1]);
    poll.here(end).end();
    let globals = [
        Global::Word(0),
        Global::Word(0),
        Global::Word(0),
        Global::Word(0),
    ];
    let bytecode = program(&globals, &[&main, &poll]);
    let mut runs = Vec::new();
    let mut turns = 0.0;
    for phase in 0..PHASES {
        let mut m = serving(&r.image, &bytecode);
        card.booting(&mut m);
        running(&mut m, card);
        until(&mut m, 60_000, "the loop counted", |m| said(m).len() >= 2);
        turns = said(&m)[1] as f64;
        wait(&mut m, phase * 5);
        let leds = m.soc.board.leds;
        m.soc.board.rfid.tags.push(Tag::new(UID));
        let at = timeline(&mut m, 5000, &[&|m| m.soc.board.leds != leds], |_, _| {});
        runs.push(vec![at[0].expect("the nose lit") as f64]);
        card.seen(&m);
    }
    card.put(
        "loop callback: period",
        Some(2000.0 / turns),
        "ms",
        Better::Same,
    );
    let mean = means(&runs)[0];
    card.ms(
        format!("tag shown → the loop callback lights the nose, mean of {PHASES}"),
        Some(mean),
    );
}

/// `recStart`, and the first block of samples given to the bytecode.
fn recording(r: &Rabbit, card: &mut Card) {
    const SINCE: u8 = 1;
    const DONE: u8 = 2;
    let mut main = Code::new(0, 0);
    main.int(0).say().set(SINCE, &[TIME_MS]);
    main.int(8000).op(&[INTB, 0, INTB, 1, RECSTART, DROP]).end();
    let mut block = Code::new(1, 0);
    let (first, end) = (block.place(), block.place());
    block
        .op(&[GETGLOBALB, DONE])
        .jump(ELSE, first)
        .jump(GOTO, end);
    block
        .here(first)
        .op(&[TIME_MS, GETGLOBALB, SINCE, SUB])
        .say();
    block
        .op(&[GETLOCALB, 0, STRLEN])
        .say()
        .set(DONE, &[INTB, 1]);
    block.here(end).end();
    let mut m = serving(
        &r.image,
        &program(&[Global::Word(0), Global::Word(0)], &[&main, &block]),
    );
    m.soc.board.codec.microphone.extend((0..16_000).map(note));
    running(&mut m, card);
    until(&mut m, 60_000, "a block recorded", |m| said(m).len() >= 3);
    let v = said(&m);
    card.ms("recStart → first block to the bytecode", Some(v[1] as f64));
    card.put(
        "recording: first block",
        Some(v[2] as f64),
        "bytes",
        Better::Same,
    );
    card.seen(&m);
}

/// `save` of 128 bytes into the settings sector.
fn settings_save(r: &Rabbit, card: &mut Card) {
    let mut main = Code::new(0, 0);
    main.int(1)
        .say()
        .op(&[GETGLOBALB, 1, INTB, 0, GETGLOBALB, 1])
        .int(1024)
        .int(128);
    main.op(&[SAVE]).say().end();
    let data: Vec<u8> = (0..128).collect();
    let mut m = on_network(&r.image, open());
    serve(
        &mut m,
        metal::boot_response(&program(&[Global::Str(&data)], &[&main])),
    );
    let ops = |m: &Machine| m.soc.flash_erases + m.soc.flash_programs;
    running(&mut m, card);
    let (erases, programs) = (m.soc.flash_erases, m.soc.flash_programs);
    let before = ops(&m);
    let marks: [&dyn Fn(&Machine) -> bool; 2] = [&|m| ops(m) > before, &|m| says(m) >= 2];
    let start = m.soc.millis();
    let at = timeline(&mut m, 30_000, &marks, |_, _| {});
    assert!(at.iter().all(Option::is_some), "the save: {at:?}");
    wait(&mut m, 200);
    let first = start + at[0].unwrap();
    card.ms(
        "settings save: first → last flash operation",
        Some((m.soc.flash_last_op - first) as f64),
    );
    card.ms(
        "settings save: the bytecode held up (between its lines)",
        when(at[1]),
    );
    card.put(
        "settings save: sector erases",
        Some((m.soc.flash_erases - erases) as f64),
        "",
        Better::Info,
    );
    card.put(
        "settings save: words programmed",
        Some((m.soc.flash_programs - programs) as f64),
        "",
        Better::Lower,
    );
    card.seen(&m);
}

/// A firmware update the way the server sends it: a bytecode that
/// carries the image, the same firmware again. (lapin leaves alone the
/// sectors that hold what they are to hold: here, all of them.)
fn update(r: &Rabbit, card: &mut Card) {
    let image = match r.fw {
        Fw::R3 => nabemu::elf::decode_sim(&r3()).expect("a .sim file"),
        Fw::Lapin => r.image.clone(),
    };
    let mut m = on_network(&r.image, open());
    serve_first(&mut m, &metal::flash_firmware(&image));
    let ops = |m: &Machine| m.soc.flash_erases + m.soc.flash_programs;
    let asked = until_every(&mut m, 1, 60_000, "the request", |m| {
        !lan(m).requests.is_empty()
    });
    card.started(&mut m);
    let before = ops(&m);
    let restart = until_every(&mut m, 1, 120_000, "the restart", restarted);
    card.booting(&mut m);
    let received = lan(&m).delivered_ms.first().copied();
    let written = ops(&m) - before;
    let said_before = m.soc.uart_tx.len();
    let running = until_every(&mut m, 1, 120_000, "the new firmware running", |m| {
        find(&m.soc.uart_tx[said_before..], b"4242").is_some()
    });
    let kb = image.len() as f64 / 1024.0;
    let download = span(Some(asked), received);
    card.put("update: image sent", Some(kb), "KB", Better::Info);
    card.ms("update: request → image received (download)", download);
    card.put(
        "update: download rate",
        download.map(|ms| kb * 1000.0 / ms),
        "KB/s",
        Better::Higher,
    );
    card.ms(
        "update: image received → restart (checks, flash)",
        span(received, Some(restart)),
    );
    card.put(
        "update: flash operations",
        Some(written as f64),
        "",
        Better::Info,
    );
    card.ms(
        "update: restart → served bytecode running",
        Some((running - restart) as f64),
    );
    card.ms(
        "update: request → running the new firmware",
        Some((running - asked) as f64),
    );
    card.seen(&m);
}

/// Setup mode: the button held at power-on, a phone joins the rabbit's
/// network, loads the page, sends the home network's settings.
fn setup(r: &Rabbit, card: &mut Card) {
    // `in_setup_mode` holds the button 2 s from power-on, then the
    // phone starts looking.
    let mut m = in_setup_mode(&r.image);
    let held = m.soc.millis();
    let marks: [&dyn Fn(&Machine) -> bool; 2] = [&|m| phone(m).link == Link::Associated, &|m| {
        phone(m).address.is_some()
    }];
    let at = timeline(&mut m, 60_000, &marks, |_, _| {});
    assert!(at[1].is_some(), "the phone never got an address");
    card.started(&mut m);
    let after = |t: Option<u64>| t.map(|t| (t + held) as f64);
    card.ms(
        "setup: power-on (button held 2 s) → phone joined",
        after(at[0]),
    );
    card.ms("setup: power-on → phone has an address", after(at[1]));
    let load = |m: &mut Machine, target: &str, marks: &[&dyn Fn(&Machine) -> bool]| {
        let before = phone(m).pages.len();
        m.visitor.as_mut().unwrap().get(target);
        let page: &dyn Fn(&Machine) -> bool = &|m| phone(m).pages.len() > before;
        let all: Vec<&dyn Fn(&Machine) -> bool> =
            std::iter::once(page).chain(marks.iter().copied()).collect();
        timeline(m, 120_000, &all, |_, _| {})
    };
    let page = load(&mut m, "/", &[]);
    m.air.push(terrier(wpa2().1));
    let saved = load(
        &mut m,
        "/b?k=Terrier&m=64&n=carotte-violette&z=1",
        &[&|m| handshakes(m) > 0],
    );
    assert!(saved[1].is_some(), "never on the home network");
    card.ms("setup: page load", when(page[0]));
    card.ms("setup: settings sent → answer", when(saved[0]));
    card.ms("setup: settings sent → on the home network", when(saved[1]));
    card.seen(&m);
}

/// `netScan` on the open home network with `n` neighbours around, as
/// `neighbours` puts them: how long it takes, what it lists, and the
/// link after it.
fn scan(r: &Rabbit, card: &mut Card, label: &str, n: usize, channel: Option<u8>, beacon_ms: u64) {
    let mut main = Code::new(0, 4);
    let (top, end) = (main.place(), main.place());
    main.int(0)
        .say()
        .clock()
        .op(&[NIL, NETSCAN, SETLOCALB, ACC])
        .lap()
        .op(&[INTB, 0, SETLOCALB, X]);
    main.here(top)
        .op(&[GETLOCALB, ACC, NIL, NE])
        .jump(ELSE, end);
    main.op(&[
        GETGLOBALB, 1, SECHO, DROP, GETLOCALB, ACC, HD, HD, SECHOLN, DROP,
    ]);
    main.op(&[
        GETLOCALB, X, INTB, 1, ADD, SETLOCALB, X, GETLOCALB, ACC, TL, SETLOCALB, ACC,
    ]);
    main.jump(GOTO, top)
        .here(end)
        .op(&[GETLOCALB, X])
        .say()
        .op(&[NETSTATE])
        .say()
        .end();
    let mut m = serving(&r.image, &program(&[Global::Str(b"%")], &[&main]));
    neighbours(&mut m, n, channel, beacon_ms);
    running(&mut m, card);
    until(&mut m, 60_000, "the scan", |m| said(m).len() >= 4);
    wait(&mut m, 3000);
    let v = said(&m);
    let console = m.console();
    let mut names: Vec<&str> = console
        .lines()
        .filter_map(|l| l.strip_prefix('%'))
        .collect();
    names.sort_unstable();
    names.dedup();
    card.ms(format!("netScan {label}: duration"), Some(v[1] as f64));
    card.put(
        format!("netScan {label}: networks found"),
        Some(names.len() as f64),
        "",
        Better::Higher,
    );
    card.put(
        format!("netScan {label}: entries listed"),
        Some(v[2] as f64),
        "",
        Better::Info,
    );
    // r3 leaves the link idle (1); lapin keeps it (4, scan_connected.rs).
    card.put(
        format!("netScan {label}: netState after"),
        Some(v[3] as f64),
        "",
        Better::Info,
    );
    card.put(
        format!("netScan {label}: still associated 3 s after"),
        Some(authorized(&m) as u8 as f64),
        "yes",
        Better::Higher,
    );
    card.seen(&m);
}

fn scan_few(r: &Rabbit, card: &mut Card) {
    scan(r, card, "(home + 5 around)", 5, None, 102);
}

fn scan_crowded(r: &Rabbit, card: &mut Card) {
    scan(r, card, "(home + 100 on channel 1)", 100, Some(1), 20);
}

/// Garenne, the rabbit's real application, when its build is there.
fn garenne_boot(r: &Rabbit, card: &mut Card) {
    let label = "garenne (WPA2): power-on → awake on its log";
    let Some(bytecode) = garenne() else {
        card.ms(label, None);
        return;
    };
    let mut m = on_network(&r.image, wpa2());
    serve(&mut m, bytecode);
    let awake: &dyn Fn(&Machine) -> bool = &|m| garenne_log(m).iter().any(|l| l.contains("awake"));
    let at = timeline(&mut m, 60_000, &[awake], |_, _| {});
    card.ms(label, when(at[0]));
    card.started(&mut m);
    // Then a minute of garenne at rest, its pulse every two seconds.
    wait(&mut m, 60_000);
    let pulses = garenne_log(&m)
        .iter()
        .filter(|l| l.contains("link=4"))
        .count();
    card.put(
        "garenne: pulses in its first minute awake",
        Some(pulses as f64),
        "",
        Better::Same,
    );
    card.put(
        "garenne: restarts",
        Some(m.events.len() as f64),
        "",
        Better::Lower,
    );
    card.seen(&m);
}

/// The images themselves: what is left of the flash below the settings.
fn images(r: &Rabbit, card: &mut Card) {
    let m = machine(&r.image);
    let below = nabemu::config::OFFSET;
    let used = m.soc.flash[..below]
        .iter()
        .rposition(|b| *b != 0xFF)
        .map_or(0, |last| last + 1);
    card.put(
        "flash: used by the image",
        Some(used as f64 / 1024.0),
        "KB",
        Better::Lower,
    );
    card.put(
        "flash: spare below the settings",
        Some((below - used) as f64 / 1024.0),
        "KB",
        Better::Higher,
    );
}

type Scenario = fn(&Rabbit, &mut Card);

const SCENARIOS: &[(&str, Scenario)] = &[
    ("boot open", boot_open),
    ("boot WPA2", boot_wpa2),
    ("boot WPA3", boot_wpa3),
    ("boot crowded", boot_crowded),
    ("rejoin deauth", rejoin_deauth),
    ("rejoin access point", rejoin_ap_restart),
    ("power cut", rejoin_power_cut),
    ("netScan few", scan_few),
    ("netScan crowded", scan_crowded),
    ("bytecode speed", bytecode_speed),
    ("rfid", rfid),
    ("button", button),
    ("polling", polling),
    ("recording", recording),
    ("sound through a rejoin", sound_through_rejoin),
    ("settings save", settings_save),
    ("update", update),
    ("setup", setup),
    ("busy", busy_two_minutes),
    ("garenne", garenne_boot),
    ("images", images),
];

/// What lapin's value is against r3's.
fn verdict(r3: Option<f64>, lapin: Option<f64>, unit: &str, better: Better) -> &'static str {
    let (Some(a), Some(b)) = (r3, lapin) else {
        return match (r3, lapin) {
            (None, Some(_)) => "lapin only",
            (Some(_), None) => "r3 only",
            _ => "n/a",
        };
    };
    // Times are looked at every millisecond: two of them is a tie.
    let resolution: f64 = if unit == "ms" { 2.0 } else { 0.0 };
    let tie = (a - b).abs() <= resolution.max(0.02 * a.abs().max(b.abs()));
    match better {
        Better::Info => "",
        _ if tie => "equal",
        Better::Same => "differs",
        Better::Lower if b < a => "better",
        Better::Higher if b > a => "better",
        _ => "worse",
    }
}

fn show(value: Option<f64>) -> String {
    match value {
        None => "n/a".into(),
        Some(v) if v.fract() == 0.0 || v.abs() >= 100.0 => format!("{v:.0}"),
        Some(v) => format!("{v:.2}"),
    }
}

fn panic_text(e: &(dyn std::any::Any + Send)) -> String {
    let text = e
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| e.downcast_ref::<&str>().copied())
        .unwrap_or("a panic");
    text.lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(300)
        .collect()
}

/// `rows` as a table, the columns `right` aligned to the right.
fn render(rows: &[Vec<String>], right: &[usize]) -> String {
    let widths: Vec<usize> = (0..rows[0].len())
        .map(|c| rows.iter().map(|row| row[c].chars().count()).max().unwrap())
        .collect();
    let mut out = String::new();
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .zip(&widths)
            .enumerate()
            .map(|(c, (cell, w))| {
                let pad = " ".repeat(w - cell.chars().count());
                if right.contains(&c) {
                    format!("{pad}{cell}")
                } else {
                    format!("{cell}{pad}")
                }
            })
            .collect();
        out += &format!("| {} |\n", cells.join(" | "));
    }
    out
}

#[test]
fn scorecard() {
    let Some(lapin) = lapin() else { return };
    let rabbits = [
        Rabbit {
            fw: Fw::R3,
            image: r3(),
        },
        Rabbit {
            fw: Fw::Lapin,
            image: lapin,
        },
    ];
    let only = std::env::var("VERSUS").unwrap_or_default();
    let chosen: Vec<&(&str, Scenario)> = SCENARIOS
        .iter()
        .filter(|(name, _)| name.contains(&only))
        .collect();
    let jobs = chosen
        .iter()
        .flat_map(|s| rabbits.iter().map(move |r| (*s, r)));
    let cards = in_parallel(jobs, |(&(name, run), rabbit)| {
        let mut card = Card::new(name);
        let failed = catch_unwind(AssertUnwindSafe(|| run(rabbit, &mut card)))
            .err()
            .map(|e| panic_text(&*e));
        (card, failed)
    });

    let header = ["measure", "r3", "lapin", "unit", "lapin is"];
    let mut table = vec![header.map(String::from).to_vec()];
    let mut highs = vec![
        std::iter::once("highs by scenario (r3 / lapin)")
            .chain(PEAKS.iter().map(|(name, _)| *name))
            .map(String::from)
            .collect::<Vec<_>>(),
    ];
    let mut failures = Vec::new();
    let mut peaks = [[(0.0, ""); 6]; 2];
    for pair in cards.chunks(2) {
        let (r3, lapin) = (&pair[0].0, &pair[1].0);
        for (fw, (card, failed)) in ["r3", "lapin"].iter().zip(pair) {
            if let Some(why) = failed {
                failures.push(format!("{} on {fw}: {why}", card.scenario));
            }
        }
        let mut row = vec![r3.scenario.to_string()];
        for ((a, _), (b, _)) in r3.peaks.iter().zip(&lapin.peaks) {
            row.push(format!("{} / {}", show(Some(*a)), show(Some(*b))));
        }
        highs.push(row);
        for (side, card) in peaks.iter_mut().zip([r3, lapin]) {
            for (peak, seen) in side.iter_mut().zip(card.peaks) {
                if seen.0 > peak.0 {
                    *peak = seen;
                }
            }
        }
        let mut metrics: Vec<&Measure> = Vec::new();
        for row in r3.rows.iter().chain(&lapin.rows) {
            if !metrics.iter().any(|m| m.metric == row.metric) {
                metrics.push(row);
            }
        }
        for row in metrics {
            let value = |card: &Card| {
                card.rows
                    .iter()
                    .find(|m| m.metric == row.metric)
                    .and_then(|m| m.value)
            };
            let (a, b) = (value(r3), value(lapin));
            table.push(vec![
                row.metric.clone(),
                show(a),
                show(b),
                row.unit.into(),
                verdict(a, b, row.unit, row.better).into(),
            ]);
        }
    }
    for (i, (name, unit)) in PEAKS.iter().enumerate() {
        let [(a, at_a), (b, at_b)] =
            [peaks[0][i], peaks[1][i]].map(|(v, at)| (v, if at.is_empty() { "none" } else { at }));
        table.push(vec![
            format!("{name} (r3 in {at_a}, lapin in {at_b})"),
            show(Some(a)),
            show(Some(b)),
            unit.to_string(),
            verdict(Some(a), Some(b), unit, Better::Lower).into(),
        ]);
    }

    let out = format!(
        "{}\n{}",
        render(&table, &[1, 2]),
        render(&highs, &[1, 2, 3, 4, 5, 6])
    );
    eprintln!("\n{out}");
    let path = format!("{}/versus.txt", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, &out).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert!(
        failures.is_empty(),
        "scenarios that did not run to their end:\n{}",
        failures.join("\n")
    );
}
