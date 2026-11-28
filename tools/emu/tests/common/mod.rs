//! What the acceptance tests share: the firmwares and where they are,
//! the rabbit's home network and the phone that visits it, the waits.
//! Each test binary compiles this on its own and uses a part of it.
#![allow(dead_code)]

use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};
use nabemu::visitor::Visitor;
use nabemu::vs1003::Format;
use nabemu::{DEFAULT_MAC, Machine, metal};

/// The home network: its name, its access point, its passphrase.
pub const SSID: &str = "Terrier";
pub const BSSID: [u8; 6] = [2, 0, 0, 0, 0, 0xA1];
pub const PASSPHRASE: &str = "carotte-violette";

/// The phone that joins the rabbit's own networks.
pub const PHONE: [u8; 6] = [2, 0, 0, 0, 0, 0xB2];

/// A tag held in front of the rabbit.
pub const UID: [u8; 8] = [0xD0, 0x02, 0x1A, 0x03, 0x52, 0xC4, 0x66, 0x7F];

/// lapin's rescue core: the first 20 KB of its image.
pub const RESCUE: usize = 20 * 1024;

/// Top of the internal RAM, where both stacks start (`lapin/fw/link.x`).
pub const STACK_TOP: u32 = 0x1000_4000;
/// The interrupt stack has 1 KB, the program the next 12 KB.
pub const IRQ_FLOOR: u32 = STACK_TOP - 0x400;
pub const PROGRAM_FLOOR: u32 = IRQ_FLOOR - 12 * 1024;
/// Half the watchdog's period: room for a real rabbit slower than this one.
pub const WATCHDOG_BUDGET_MS: u64 = 1045;
/// The processor modes whose stacks are watched (`Machine::stack_low`).
pub const IRQ: usize = 0x12;
pub const SYSTEM: usize = 0x1F;

pub const AMBER: [u8; 3] = [126, 16, 0];
pub const GREEN: [u8; 3] = [0, 126, 0];

/// What the loudspeaker plays a tone as: 16-bit samples at 8 kHz.
pub const PCM_8K: Format = Format::Wav {
    sample_rate: 8000,
    channels: 1,
    bits: 16,
    adpcm: false,
};

/// A file of `artifacts/`.
pub fn artifact(name: &str) -> Vec<u8> {
    let path = format!("{}/../../artifacts/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The C firmware the rabbits run, whichever one the tests are on.
pub fn r3() -> Vec<u8> {
    artifact("Nab-wpa23-gtk-r3.sim")
}

/// A file of lapin's build (`lapin/build.sh`), when it is there: it
/// needs a nightly toolchain, and the tests that want it are skipped
/// without it.
pub fn lapin_target(file: &str) -> Option<Vec<u8>> {
    let path = format!("{}/../../lapin/target/{file}", env!("CARGO_MANIFEST_DIR"));
    let found = std::fs::read(path).ok();
    if found.is_none() {
        eprintln!("skipped: lapin is not built");
    }
    found
}

/// lapin's whole image: the rescue core, then the application.
pub fn lapin() -> Option<Vec<u8>> {
    lapin_target("lapin-full.bin")
}

/// Garenne, the rabbit's real application bytecode. It lives in another
/// repository: its build is `NABEMU_GARENNE` when that is set, else
/// `garenne/build/garenne.bin` in the checkout of clapier beside this
/// repository's main checkout (found from git's common directory, so
/// that a worktree finds it too). Without either, the tests that want
/// it skip, and say where they looked.
pub fn garenne() -> Option<Vec<u8>> {
    let path = match std::env::var_os("NABEMU_GARENNE") {
        Some(path) => std::path::PathBuf::from(path),
        None => main_checkout()
            .parent()?
            .join("clapier/garenne/build/garenne.bin"),
    };
    let found = std::fs::read(&path).ok();
    if found.is_none() {
        eprintln!("skipped: no garenne build at {}", path.display());
    }
    found
}

/// This repository's main checkout: where git's common directory (the
/// `.git` a worktree points back to) lies, or, when git cannot say,
/// the repository this test was built in.
pub fn main_checkout() -> std::path::PathBuf {
    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let here = std::fs::canonicalize(here).unwrap_or_else(|_| here.into());
    let common = std::process::Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(&here)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| std::path::PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));
    match common.as_deref().and_then(std::path::Path::parent) {
        Some(main) => main.to_path_buf(),
        None => here.join("../.."),
    }
}

/// What garenne broadcast on its log port, UDP 9999, a line each.
pub fn garenne_log(m: &Machine) -> Vec<String> {
    m.lan
        .as_ref()
        .unwrap()
        .datagrams
        .iter()
        .filter(|d| d.to_port == 9999)
        .map(|d| String::from_utf8_lossy(&d.payload).into_owned())
        .collect()
}

/// A board flashed with `image`, not started.
pub fn machine(image: &[u8]) -> Machine {
    Machine::from_file(image).0
}

/// A board flashed with the firmware under test (`nabemu::testing`).
pub fn under_test() -> Machine {
    machine(&nabemu::testing::image())
}

/// A board flashed with `image`, that boots `bytecode` from the open
/// network (`Machine::serve`).
pub fn serving(image: &[u8], bytecode: &[u8]) -> Machine {
    let mut m = machine(image);
    m.serve(bytecode);
    m
}

/// The settings of a network and the access point's security for it,
/// the same passphrase or key on both sides.
pub fn open() -> (Wifi, Security) {
    (Wifi::Open, Security::Open)
}

pub fn wpa() -> (Wifi, Security) {
    let passphrase = PASSPHRASE.into();
    (Wifi::Wpa { passphrase }, Security::wpa(PASSPHRASE))
}

pub fn wpa2() -> (Wifi, Security) {
    let passphrase = PASSPHRASE.into();
    (Wifi::Wpa2 { passphrase }, Security::wpa2(PASSPHRASE))
}

pub fn wep(key: &str, shared_auth: bool) -> (Wifi, Security) {
    let wifi = Wifi::Wep {
        key: key.into(),
        shared_auth,
    };
    let security = Security::Wep {
        key: key.as_bytes().to_vec(),
        shared_auth,
    };
    (wifi, security)
}

/// The home network's access point, on channel 6.
pub fn terrier(security: Security) -> AccessPoint {
    AccessPoint::new(SSID, BSSID, 6, security)
}

/// A board flashed with `image`, set up for the home network, which
/// is in range: settings and access point from `network`.
pub fn on_network(image: &[u8], (wifi, security): (Wifi, Security)) -> Machine {
    let mut m = machine(image);
    Config::new(SSID, wifi).install(&mut m.soc.flash);
    m.air.push(terrier(security));
    m
}

/// The same with a WPA3-only access point: the settings say WPA2, the
/// passphrase is the same, and the rabbit finds WPA3 on the air.
pub fn on_wpa3_network(image: &[u8]) -> Machine {
    let mut m = on_network(image, wpa2());
    m.air[0].wpa3 = Wpa3::Only;
    m
}

/// A server that answers every request with `body`, as it is.
pub fn serve(m: &mut Machine, body: Vec<u8>) {
    let mut lan = Lan::new();
    lan.handler = Box::new(move |_| Response::ok(body.clone()));
    m.lan = Some(lan);
}

/// A server that answers the first request with `first` (a bytecode),
/// and every later one with a program that prints 4242.
pub fn serve_first(m: &mut Machine, first: &[u8]) {
    let mut lan = Lan::new();
    let first = metal::boot_response(first);
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
}

/// Run the board `ms` milliseconds more.
pub fn wait(m: &mut Machine, ms: u64) {
    m.run_until_ms(m.soc.millis() + ms);
}

/// Run until `done`, looking every 20 ms, within `limit_ms` from now,
/// or fail with what the access point saw and the console; the time it
/// was done.
pub fn until(m: &mut Machine, limit_ms: u64, what: &str, done: impl Fn(&Machine) -> bool) -> u64 {
    until_every(m, 20, limit_ms, what, done)
}

/// The same, looking every `step_ms`: finer, for a test that times
/// what it waits for.
pub fn until_every(
    m: &mut Machine,
    step_ms: u64,
    limit_ms: u64,
    what: &str,
    done: impl Fn(&Machine) -> bool,
) -> u64 {
    let by = m.soc.millis() + limit_ms;
    until_by(m, by, step_ms, what, done)
}

/// The same, by a time on the board's clock.
pub fn until_by(
    m: &mut Machine,
    by_ms: u64,
    step_ms: u64,
    what: &str,
    done: impl Fn(&Machine) -> bool,
) -> u64 {
    while !done(m) {
        assert!(
            m.soc.millis() < by_ms,
            "{what}: not by {by_ms} ms\nap: {:?}\n{}",
            m.air.first().map(|ap| &ap.events),
            m.console()
        );
        wait(m, step_ms);
    }
    m.soc.millis()
}

/// Whether the access point lets the rabbit's traffic through.
pub fn authorized(m: &Machine) -> bool {
    m.air[0].is_authorized(DEFAULT_MAC)
}

/// Whether the access point reported `event`.
pub fn ap_saw(m: &Machine, event: &ApEvent) -> bool {
    m.air[0].events.contains(event)
}

/// How many times the access point reported `event`.
pub fn ap_count(m: &Machine, event: &ApEvent) -> usize {
    m.air[0].events.iter().filter(|e| *e == event).count()
}

/// How many handshakes the rabbit completed with the access point.
pub fn handshakes(m: &Machine) -> usize {
    ap_count(m, &ApEvent::HandshakeComplete { sta: DEFAULT_MAC })
}

/// Whether the rabbit's IP traffic reached the wire: its DHCP request
/// went through the access point, encryption working both ways.
pub fn ip_on_the_wire(m: &Machine) -> bool {
    m.air[0].uplink.iter().any(|f| f[12..14] == [0x08, 0x00])
}

/// Where `needle` first is in `hay`.
pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The last time a bytecode measured and printed: `time_ms` before,
/// minus `time_ms` after, so a negative number.
pub fn time_printed(m: &Machine) -> Option<u64> {
    m.console()
        .lines()
        .filter_map(|l| l.strip_prefix('-')?.parse::<u64>().ok())
        .next_back()
}

/// Processor cycles as milliseconds of the board's clock.
pub fn ms(cycles: u64) -> u64 {
    cycles * 1000 / nabemu::soc::CLOCK_HZ
}

/// Sample `i` of a 500 Hz note at 8 kHz, as whistled at the microphone.
pub fn note(i: usize) -> i16 {
    (12000.0 * (i as f64 * 500.0 * std::f64::consts::TAU / 8000.0).sin()) as i16
}

/// `heard` is the note again: loud, and sixteen samples to a period,
/// so each sample the opposite of the one 8 before.
pub fn assert_the_note(heard: &[i16]) {
    let loud = heard.iter().filter(|s| s.abs() > 6000).count();
    assert!(
        loud > heard.len() / 4,
        "the note is there: {loud} loud samples of {}",
        heard.len()
    );
    let opposite = heard
        .windows(9)
        .filter(|w| (w[0] as i32 + w[8] as i32).abs() < 3000)
        .count();
    assert!(
        opposite > heard.len() * 3 / 4,
        "{opposite} of {} samples keep the period",
        heard.len()
    );
}

/// Press the head button for `held_ms`, then leave it for `then_ms`.
pub fn press(m: &mut Machine, held_ms: u64, then_ms: u64) {
    m.soc.board.button = true;
    wait(m, held_ms);
    m.soc.board.button = false;
    wait(m, then_ms);
}

/// A rabbit started with its button held for more than seven seconds,
/// in its factory test.
pub fn in_factory_test(image: &[u8]) -> Machine {
    let mut m = machine(image);
    press(&mut m, 8000, 500);
    m
}

/// A rabbit started with its button held, in setup mode, and a phone
/// looking for it.
pub fn in_setup_mode(image: &[u8]) -> Machine {
    let mut m = machine(image);
    press(&mut m, 2000, 0);
    phone_looks_for(&mut m, "Nabaztag");
    m
}

/// Wait for the phone to get an address from the rabbit in setup mode.
pub fn phone_gets_an_address(m: &mut Machine) {
    until_by(m, 30_000, 20, "an address for the phone", |m| {
        phone(m).address.is_some()
    });
}

/// The whole first-time setup: the rabbit in setup mode, the home
/// network in range, its settings typed in the page from a phone. The
/// rabbit's answer to them, once it has joined the network.
pub fn set_up_from_the_page(image: &[u8]) -> (Machine, String) {
    let mut m = in_setup_mode(image);
    m.air.push(terrier(Security::wpa2(PASSPHRASE)));
    phone_gets_an_address(&mut m);
    let answer = page(&mut m, 30_000, |v| {
        v.get("/b?k=Terrier&m=64&n=carotte-violette&z=1")
    });
    until_by(&mut m, 120_000, 20, "the rabbit on its network", |m| {
        handshakes(m) > 0
    });
    (m, answer)
}

/// A lapin whose application is gone, as after a power cut that took
/// it, on its rescue network.
pub fn without_application(image: &[u8]) -> Machine {
    let mut m = machine(image);
    m.soc.flash[RESCUE..RESCUE + 4096].fill(0xFF);
    rescue_network_up(&mut m);
    m
}

/// Wait for lapin's rescue network.
pub fn rescue_network_up(m: &mut Machine) {
    until(m, 20_000, "the rescue network", |m| {
        m.console().contains("secours: network up")
    });
}

/// A phone on lapin's rescue network, with an address: the one there
/// already, or a new one.
pub fn phone_on_the_rescue_network(m: &mut Machine) {
    if m.visitor.is_none() {
        phone_looks_for(m, "Nabaztag-secours");
    }
    until(m, 60_000, "an address on the rescue network", |m| {
        phone(m).address.is_some()
    });
}

/// The phone, once there is one.
pub fn phone(m: &Machine) -> &Visitor {
    m.visitor.as_ref().unwrap()
}

/// A phone that looks for the network whose name starts with `network`.
pub fn phone_looks_for(m: &mut Machine, network: &str) {
    m.visitor = Some(Visitor::new(PHONE, network));
}

/// What the phone loads when it is asked to: the page, which has to
/// come within `limit_ms`.
pub fn page(m: &mut Machine, limit_ms: u64, ask: impl FnOnce(&mut Visitor)) -> String {
    let before = phone(m).pages.len();
    ask(m.visitor.as_mut().unwrap());
    until(m, limit_ms, "the page", |m| phone(m).pages.len() > before);
    phone(m).pages[before].text()
}

/// An 802.11 frame: frame control, the three addresses, then `rest`
/// from the sequence control on.
pub fn frame(control: [u8; 2], a1: [u8; 6], a2: [u8; 6], a3: [u8; 6], rest: &[u8]) -> Vec<u8> {
    let mut f = control.to_vec();
    f.extend([0, 0]);
    f.extend(a1);
    f.extend(a2);
    f.extend(a3);
    f.extend(rest);
    f
}
