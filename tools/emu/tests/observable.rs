//! What the bytecode can see of the firmware: the same small programs
//! on both firmwares, r3 being the reference, except where r3 is wrong
//! ("Known defect", checked as lapin does it right).

mod common;

use common::{ap_count, ap_saw, find, until, wait};
use nabemu::air::ApEvent;
use nabemu::config::{Config, Wifi};
use nabemu::{DEFAULT_MAC, Machine, metal};

const NIL: u8 = 4;
const DROP: u8 = 5;
const IECHOLN: u8 = 95;
const HD: u8 = 45;
const NETSTATE: u8 = 105;
const NETSETMODE: u8 = 108;
const NETSCAN: u8 = 109;
const NETAUTH: u8 = 110;
const REBOOT: u8 = 136;

/// A function that prints 7770, runs `body`, then prints 8880.
fn program(body: &[u8]) -> Vec<u8> {
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.extend(metal::int(7770));
    f.extend([IECHOLN, DROP]);
    f.extend_from_slice(body);
    f.extend(metal::int(8880));
    f.extend([IECHOLN, metal::OP_RET]);
    f
}

/// The rabbit on the open network "Terrier", served `bytecode`, run
/// until it printed 8880.
fn ran(bytecode: &[u8]) -> Machine {
    let mut m = common::under_test();
    m.serve(bytecode);
    until(&mut m, 40_000, "the program's end", |m| {
        find(&m.soc.uart_tx, b"8880").is_some()
    });
    m
}

/// The numbers the program printed between 7770 and 8880.
fn printed(m: &Machine) -> Vec<i64> {
    let c = m.console();
    let from = c.find("7770").expect("the program ran") + 4;
    let to = c[from..].find("8880").map_or(c.len(), |i| from + i);
    c[from..to]
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect()
}

/// `netState` pushed and printed.
fn print_state() -> Vec<u8> {
    vec![NETSTATE, IECHOLN, DROP]
}

/// `netSetmode` with a mode the driver does not know changes nothing:
/// the link stays up (the C driver only flushed what was received).
#[test]
fn net_setmode_with_an_unknown_mode_changes_nothing() {
    let mut body = print_state();
    body.extend(metal::int(2));
    body.push(NIL);
    body.extend(metal::int(1));
    body.extend([NETSETMODE, DROP]);
    body.extend(print_state());
    let m = ran(&metal::bytecode(&[], &program(&body)));
    // RT2501_S_CONNECTED, before and after.
    assert_eq!(printed(&m), [4, 4]);
}

/// `netAuth` on the network the scan found, with authentication mode
/// `authmode` and the encryption the scan reported.
fn reauth(authmode: i32) -> Vec<u8> {
    let mut body = vec![NIL, NETSCAN, HD];
    body.extend(metal::int(authmode));
    body.extend(metal::int(0));
    body.push(NIL);
    body.extend([NETAUTH, DROP]);
    body
}

/// Known defect of r3: `rt2501_auth` sends a shared-key authentication
/// for any authentication mode other than 0, whatever the network's
/// security, then reads the answer as open system authentication's:
/// on an open network the access point refuses (status 13) and the
/// rabbit is left off the network. Shared keys are WEP's alone; lapin
/// authenticates an open network as open, whatever the mode.
#[test]
fn net_auth_with_a_shared_key_mode_on_an_open_network() {
    let mut m = ran(&metal::bytecode(&[], &program(&reauth(1))));
    wait(&mut m, 10000);
    let refused = ApEvent::AuthRejected {
        sta: DEFAULT_MAC,
        status: 13,
    };
    let associated = ap_count(&m, &ApEvent::Associated { sta: DEFAULT_MAC });
    if nabemu::testing::is_lapin() {
        assert!(!ap_saw(&m, &refused), "{:?}", m.air[0].events);
        assert_eq!(associated, 2, "{:?}", m.air[0].events);
    } else {
        assert!(ap_saw(&m, &refused), "{:?}", m.air[0].events);
        assert_eq!(associated, 1, "{:?}", m.air[0].events);
    }
}

/// On a WEP network any mode but 0 is a shared key's, as in the C
/// driver: settings whose mode byte says 2 join a network that demands
/// a shared key.
#[test]
fn a_wep_mode_other_than_0_or_1_is_a_shared_key() {
    let (wifi, security) = common::wep("abcde", true);
    let mut m = common::on_network(&nabemu::testing::image(), (wifi, security));
    // CONF_WIFIAUTH, byte 90 of the settings.
    m.soc.flash[nabemu::config::OFFSET + 90] = 2;
    until(&mut m, 20_000, "associated", |m| {
        ap_saw(
            m,
            &ApEvent::Authenticated {
                sta: DEFAULT_MAC,
                shared_key: true,
            },
        )
    });
}

/// The stick stops delivering what it receives (its bulk endpoint in
/// stalls) for five seconds, then works again: on both firmwares the
/// rabbit is back on its network after.
///
/// r3 never says broken: `rt2501_rx_callback` would, on a failed
/// receive, but the host controller driver overwrites the failure with
/// the transfer's condition code, a positive number
/// (`hcd_bulk_transfer_done`), which passes for a short packet; the
/// boot sees the link lost (idle) when its own wait runs out. lapin
/// says broken (0) while receiving fails, as the C driver meant to.
#[test]
fn a_stick_that_stops_receiving_is_reported_broken() {
    let mut m = common::under_test();
    Config::new(common::SSID, Wifi::Open).install(&mut m.soc.flash);
    m.air.push(common::terrier(common::open().1));
    until(&mut m, 20_000, "associated", |m| {
        ap_saw(m, &ApEvent::Associated { sta: DEFAULT_MAC })
    });
    wait(&mut m, 2000);
    let before = m.console().len();
    m.radio.borrow_mut().rx_stall = true;
    wait(&mut m, 5000);
    m.radio.borrow_mut().rx_stall = false;
    wait(&mut m, 20_000);
    let after = &m.console()[before..];
    let lost = if nabemu::testing::is_lapin() {
        "wifi state=0"
    } else {
        assert!(!after.contains("wifi state=0"), "{after}");
        "wifi state=1"
    };
    let at = after.find(lost).expect(after);
    assert!(after[at..].contains("wifi state=4"), "{after}");
    assert_eq!(m.events, [], "no restart");
}

/// A bytecode that reboots the rabbit at once, every time: r3 does as
/// it is told, each time. lapin counted those restarts as failed
/// starts, and its rescue core took over after the third.
#[test]
fn reboots_asked_by_the_bytecode_are_not_failed_starts() {
    let mut body = metal::int(0x0407_FE58).to_vec();
    body.extend(metal::int(0x13FB_6754));
    body.extend([REBOOT, DROP]);
    let mut m = common::under_test();
    m.serve(&metal::bytecode(&[], &program(&body)));
    until(&mut m, 120_000, "the program run six times", |m| {
        m.console().matches("7770").count() >= 6
    });
    assert!(
        !m.console().contains("secours"),
        "the rescue core took over"
    );
    assert!(m.events.len() >= 5, "{:?}", m.events);
}

const DUP: u8 = 6;
const ADD: u8 = 9;
const EQ: u8 = 22;
const GT: u8 = 25;
const GOTO: u8 = 28;
const ELSE: u8 = 29;
const TIME_MS: u8 = 53;

/// Where `body`'s byte `at` is for a jump (from the code after the
/// function's header; `program` puts 7 bytes before the body).
fn label(at: usize) -> [u8; 2] {
    ((7 + at) as u16).to_le_bytes()
}

/// A loop of up to `ms` that asks `netState` all along, and stops as
/// soon as the link is no longer up; then the state is printed.
fn while_connected(ms: i32) -> Vec<u8> {
    let mut b = vec![TIME_MS];
    b.extend(metal::int(ms));
    b.push(ADD);
    let top = b.len();
    b.extend([DUP, TIME_MS, GT, ELSE, 0, 0]);
    let exit_1 = b.len() - 2;
    b.push(NETSTATE);
    b.extend(metal::int(4));
    b.extend([EQ, ELSE, 0, 0]);
    let exit_2 = b.len() - 2;
    b.push(GOTO);
    b.extend(label(top));
    let exit = label(b.len());
    b[exit_1..exit_1 + 2].copy_from_slice(&exit);
    b[exit_2..exit_2 + 2].copy_from_slice(&exit);
    b.push(DROP);
    b.extend(print_state());
    b
}

/// The bytecode busy for seconds, asking `netState`: the access point
/// throws the rabbit out meanwhile, and the state says so at once, as
/// in the C firmware, which handled management frames in the USB
/// interrupt. lapin saw them only between two turns of its main loop.
#[test]
fn net_state_moves_while_the_bytecode_runs() {
    let mut m = common::under_test();
    m.serve(&metal::bytecode(&[], &program(&while_connected(8000))));
    until(&mut m, 40_000, "the program", |m| {
        find(&m.soc.uart_tx, b"7770").is_some()
    });
    wait(&mut m, 1000);
    m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 1);
    let kicked = m.soc.millis();
    let done = until(&mut m, 10_000, "the program's end", |m| {
        find(&m.soc.uart_tx, b"8880").is_some()
    });
    assert!(done - kicked < 1000, "{} ms", done - kicked);
    assert_ne!(printed(&m), [4]);
}

const NETCB: u8 = 103;

/// A loop that keeps the bytecode busy `ms`, asking nothing of the
/// network, placed at byte `base` of the body.
fn busy(base: usize, ms: i32) -> Vec<u8> {
    let mut b = vec![TIME_MS];
    b.extend(metal::int(ms));
    b.push(ADD);
    let top = b.len();
    b.extend([DUP, TIME_MS, GT, ELSE, 0, 0]);
    let exit = b.len() - 2;
    b.push(GOTO);
    b.extend(label(base + top));
    let end = label(base + b.len());
    b[exit..exit + 2].copy_from_slice(&end);
    b.push(DROP);
    b
}

/// The bytecode busy for three seconds while forty frames come for it,
/// on a channel that thirty neighbours fill with beacons: every frame
/// reaches it after, as in the C firmware, which kept the frames for
/// the bytecode in its USB interrupt and nothing of the beacons. lapin
/// queued every frame the stick delivered, beacons first: the queue
/// was full in a fraction of a second.
#[test]
fn frames_that_come_while_the_bytecode_is_busy_are_kept() {
    // The callback (function 1) is given once the loop is over.
    let mut main = busy(0, 3000);
    main.extend(metal::int(1));
    main.extend([NETCB, DROP]);
    let main = program(&main);
    // The callback: (frame, source), prints 6666.
    let mut callback = vec![2, 0, 0];
    callback.extend(metal::int(6666));
    callback.extend([IECHOLN, metal::OP_RET]);
    let mut m = common::under_test();
    m.serve(&metal::bytecode_functions(&[], &[&main, &callback]));
    until(&mut m, 40_000, "the program", |m| {
        find(&m.soc.uart_tx, b"7770").is_some()
    });
    for i in 0..20u8 {
        let mut ap = nabemu::air::AccessPoint::new(
            &format!("Voisin{i:02}"),
            [2, 0, 0, 3, 0, i],
            6,
            nabemu::air::Security::Open,
        );
        ap.beacon_interval = 50;
        m.air.push(ap);
    }
    wait(&mut m, 500);
    let mut eth = DEFAULT_MAC.to_vec();
    eth.extend_from_slice(&[2, 0, 0, 0, 0, 0x55, 0x88, 0xB5]);
    eth.extend_from_slice(&[0x5A; 200]);
    for _ in 0..40 {
        m.air[0].send(&mut m.radio.borrow_mut(), &eth);
        wait(&mut m, 20);
    }
    until(&mut m, 10_000, "the program's end", |m| {
        find(&m.soc.uart_tx, b"8880").is_some()
    });
    wait(&mut m, 2000);
    let c = m.console();
    let delivered = c[c.find("8880").unwrap()..].matches("6666").count();
    assert!(delivered >= 40, "{delivered} delivered");
}

const TIME: u8 = 61;

/// Where lapin keeps the static whose name ends so, from its ELF.
fn lapin_static(suffix: &str) -> Option<u32> {
    let elf = common::lapin_target("thumbv4t-none-eabi/release/lapin")?;
    let elf = nabemu::elf::Elf::parse(&elf)?;
    elf.symbols
        .iter()
        .find(|(_, name)| name.ends_with(suffix))
        .map(|(addr, _)| *addr)
}

/// `time` counts seconds apart from the milliseconds, as the C
/// firmware's `counter_timer_s` did: a 32-bit count of seconds, where
/// the milliseconds wrap after 49.7 days. lapin divided the
/// milliseconds by 1000, and `time` fell back to 0 at their wrap.
/// (lapin only: r3's counters are not where a test can find them.)
#[test]
fn time_goes_on_across_the_wrap_of_the_milliseconds() {
    if !nabemu::testing::is_lapin() {
        return;
    }
    let Some(millis) = lapin_static("5timer6MILLIS") else {
        return;
    };
    let mut body = vec![TIME, IECHOLN, DROP];
    body.extend(busy(body.len(), 6000));
    body.extend([TIME, IECHOLN, DROP]);
    let mut m = common::under_test();
    m.serve(&metal::bytecode(&[], &program(&body)));
    until(&mut m, 40_000, "on the network", |m| {
        m.console().contains("-------------dhcp")
    });
    // Three seconds before the milliseconds wrap.
    let at = (millis - 0x1000_0000) as usize;
    m.soc.iram[at..at + 4].copy_from_slice(&(u32::MAX - 3000).to_le_bytes());
    until(&mut m, 40_000, "the program's end", |m| {
        find(&m.soc.uart_tx, b"8880").is_some()
    });
    let [before, after] = printed(&m)[..] else {
        panic!("{:?}", printed(&m));
    };
    assert!((5..=7).contains(&(after - before)), "{before} then {after}");
}

const STRLEN: u8 = 68;
const STRGET: u8 = 69;
const BYTECODE: u8 = 93;
const ENVGET: u8 = 98;
const ENVSET: u8 = 99;

/// The environment a bytecode leaves (`len` bytes, byte `i` = i % 251)
/// as the next one sees it: its length, and bytes along it (nil, not
/// printed as a number, past its end).
fn environment_carried(len: usize) -> Vec<i64> {
    let mut next = metal::FUNCTION_HEADER.to_vec();
    next.extend([ENVGET, STRLEN, IECHOLN, DROP]);
    for at in [
        0, 4095, 4096, 4500, 6999, 8191, 8192, 20_000, 32_767, 32_768,
    ] {
        next.extend([ENVGET]);
        next.extend(metal::int(at));
        next.extend([STRGET, IECHOLN, DROP]);
    }
    next.extend(metal::int(8880));
    next.extend([IECHOLN, metal::OP_RET]);
    let next = metal::bytecode(&[], &next);
    let env: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let mut first = metal::FUNCTION_HEADER.to_vec();
    first.extend(metal::int(7770));
    first.extend([IECHOLN, DROP]);
    first.extend([metal::OP_GETGLOBALB, 1, ENVSET, DROP]);
    first.extend([metal::OP_GETGLOBALB, 0, BYTECODE, metal::OP_RET]);
    let m = ran(&metal::bytecode(&[&next, &env], &first));
    printed(&m)
}

/// An environment of more than 4 KB handed to the next bytecode: the
/// C firmware copies it through its 4 KB audio buffer and on over what
/// follows (another 4 KB buffer of scratch, then free memory), and the
/// next bytecode gets it whole, up to the USB heap 32 KB on. lapin cut
/// it to 4 KB. (A busy neighbourhood makes the boot's own large: it
/// carries the scan.)
#[test]
fn an_environment_of_7000_bytes_goes_whole_to_the_next_bytecode() {
    let at = |i: i64| i % 251;
    let expected = [7000, at(0), at(4095), at(4096), at(4500), at(6999)];
    assert_eq!(environment_carried(7000), expected);
}

#[test]
fn an_environment_of_32_kb_goes_whole_to_the_next_bytecode() {
    let at = |i: i64| i % 251;
    let expected = [
        32_768,
        at(0),
        at(4095),
        at(4096),
        at(4500),
        at(6999),
        at(8191),
        at(8192),
        at(20_000),
        at(32_767),
    ];
    assert_eq!(environment_carried(32_768), expected);
}

/// Known defect of r3: an environment longer than 32 KB is copied over
/// the USB heap that follows: the watchdog restarts the rabbit, again
/// and again. lapin carries the first 32 KB, and runs on.
#[test]
fn an_environment_past_32_kb_is_cut() {
    if nabemu::testing::is_lapin() {
        let carried = environment_carried(40_000);
        assert_eq!(carried[0], 32_768, "{carried:?}");
        return;
    }
    let mut m = common::under_test();
    let env = vec![0x41u8; 40_000];
    let mut first = metal::FUNCTION_HEADER.to_vec();
    first.extend([metal::OP_GETGLOBALB, 1, ENVSET, DROP]);
    first.extend([metal::OP_GETGLOBALB, 0, BYTECODE, metal::OP_RET]);
    let next = metal::print_number(8880);
    m.serve(&metal::bytecode(&[&next, &env], &first));
    wait(&mut m, 40_000);
    // The watchdog restarts the rabbit, again and again.
    assert!(m.events.len() >= 2, "{:?}", m.events);
}

/// A WPA2 rabbit fetching and running its bytecode, the stick leaving
/// the IV words of what it decrypts zero (`rx_no_iv`), or not.
fn wpa2_with_a_stick_that_reports_iv(reports: bool) -> Machine {
    let mut m = common::on_network(&nabemu::testing::image(), common::wpa2());
    m.radio.borrow_mut().rx_no_iv = !reports;
    common::serve(&mut m, metal::boot_response(&metal::print_number(4242)));
    until(&mut m, 40_000, "the served bytecode", |m| {
        m.console().contains("4242")
    });
    m
}

const NO_PN: &str = "the stick reports no packet numbers";

/// The replay check takes each packet number from the words of the
/// receive descriptor, which nothing has proven the stick fills: one
/// that left them zero would see every frame after the first dropped
/// as a replay, a link dead after its handshake. It stays up, the check
/// left out and the console saying so once; with them, the check is
/// kept. (r3 never read them.)
#[test]
fn a_stick_that_reports_no_packet_numbers_still_carries_traffic() {
    let m = wpa2_with_a_stick_that_reports_iv(false);
    if nabemu::testing::is_lapin() {
        assert_eq!(m.console().matches(NO_PN).count(), 1);
    }
    let m = wpa2_with_a_stick_that_reports_iv(true);
    assert!(!m.console().contains(NO_PN));
}
