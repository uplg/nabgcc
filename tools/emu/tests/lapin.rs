//! The Rust firmware (`../../lapin`) on the emulated rabbit. It needs
//! a nightly toolchain to build, so the test runs when the image is
//! there (`lapin/build.sh`) and is skipped otherwise.

mod common;

use common::{AMBER, GREEN, PCM_8K, UID, lapin, lapin_target, machine, note, until_every, wait};
/// The board comes up, finds its stick, and hands over to the boot
/// bytecode, which keeps the watchdog fed and looks for a network.
#[test]
fn the_firmware_boots_its_bytecode_and_stays_up() {
    let Some(mut m) = lapin().as_deref().map(machine) else {
        return;
    };
    m.run_until_ms(10_500);
    assert_eq!(m.events, [], "no reset in ten seconds");
    assert!(m.soc.bus_faults.is_empty(), "{:x?}", m.soc.bus_faults);
    assert!(m.soc.unmodelled.is_empty(), "{:x?}", m.soc.unmodelled);
    assert_eq!(m.soc.cpu_clock_hz(), Some(32_000_000));
    let console = m.console();
    // The bytecode starts at once, as with the C firmware, and the stick
    // comes up in the first turn of the main loop.
    assert!(console.starts_with("lapin 0.1\n"), "{console}");
    assert!(
        console.contains("\nwifi 00:19:db:00:00:01 radio 02\n"),
        "{console}"
    );
    assert!(console.contains("wifi state="), "{console}");
    // The bytecode's amber, blinking: no network found yet.
    let leds = m.soc.board.leds;
    assert!(leds.iter().all(|l| *l == AMBER || *l == [0; 3]), "{leds:?}");
    assert!(leds.contains(&AMBER), "{leds:?}");
    assert_eq!(m.soc.ohci.errors, 0);
    assert!(m.radio.borrow().firmware_loaded);
    // The receiver goes off while the radio changes channel: back on
    // within moments.
    until_every(&mut m, 1, 200, "the receiver back on", |m| {
        m.radio.borrow().rx_enabled
    });
}

/// Without its Wi-Fi stick the firmware says so and carries on: the
/// bytecode runs, the network stays broken.
#[test]
fn a_missing_wifi_stick_is_reported() {
    let Some(mut m) = lapin().as_deref().map(machine) else {
        return;
    };
    m.soc.ohci.device = None;
    m.run_until_ms(10_000);
    let console = m.console();
    assert!(console.contains("\nwifi: no stick\n"), "{console}");
    assert!(console.contains("started"), "{console}");
    assert_eq!(m.events, []);
}

/// The firmware tunes the two radio chips that do 2.4 GHz only. A stick
/// that names one of the others is refused, by name, before anything
/// is written to its radio.
#[test]
fn a_stick_with_a_radio_it_cannot_tune_is_refused() {
    let Some(mut m) = lapin().as_deref().map(machine) else {
        return;
    };
    m.radio.borrow_mut().rf_chip = 3;
    m.run_until_ms(6000);
    assert!(
        m.console().contains("\nwifi: radio 03\n"),
        "{}",
        m.console()
    );
    assert_eq!(m.events, []);
}

/// A stick with the RT2527 radio is tuned with that chip's own words:
/// the rabbit finds its network and joins it.
#[test]
fn a_stick_with_the_rt2527_radio_joins_too() {
    use nabemu::air::{AccessPoint, ApEvent, Security};
    use nabemu::config::{Config, Wifi};

    let Some(mut m) = lapin().as_deref().map(machine) else {
        return;
    };
    m.radio.borrow_mut().rf_chip = 4;
    Config::new("Garenne", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Garenne",
        [2, 0, 0, 0, 0, 0xA2],
        11,
        Security::Open,
    ));
    m.run_until_ms(15_000);
    assert!(m.console().contains(" radio 04\n"), "{}", m.console());
    assert!(
        m.air[0].events.contains(&ApEvent::Associated {
            sta: nabemu::DEFAULT_MAC
        }),
        "{:?}",
        m.air[0].events
    );
}

/// The bench replays the WPA3 test vector of the standard and prints a
/// marker before each step.
#[test]
fn the_wpa3_exchange_is_right_and_fast_enough_on_the_arm7() {
    let Some(image) = lapin_target("bench-full.bin") else {
        return;
    };
    let mut m = machine(&image);
    let mut marks: Vec<(String, f64)> = Vec::new();
    let mut seen = 0;
    while !m.console().ends_with("end\n") {
        assert!(m.soc.millis() < 60_000, "never finished:\n{}", m.console());
        wait(&mut m, 1);
        let console = m.console();
        while let Some(end) = console[seen..].find('\n') {
            marks.push((console[seen..seen + end].to_string(), m.soc.millis() as f64));
            seen += end + 1;
        }
    }
    let console = m.console();
    for check in ["commit ok", "keys ok", "confirm ok", "hash-to-element ok"] {
        assert!(console.contains(check), "{console}");
    }
    assert_eq!(m.events, []);
    assert!(m.soc.bus_faults.is_empty());

    // Duration of each step: from its marker to the next.
    let took = |name: &str| {
        let i = marks
            .iter()
            .position(|(line, _)| line == &format!("> {name}"))
            .unwrap();
        marks[i + 1].1 - marks[i].1
    };
    eprintln!(
        "hunting {} ms, commit {} ms, shared {} ms, point {} ms, element {} ms",
        took("hunting"),
        took("commit"),
        took("shared"),
        took("point"),
        took("element")
    );
    // A connection by either method stays under two seconds and a half.
    assert!(took("hunting") + took("commit") + took("shared") < 2500.0);
    assert!(took("element") + took("commit") + took("shared") < 2000.0);
    // No single step outlasts the watchdog's 2.09 s.
    for step in ["hunting", "commit", "shared", "point", "element"] {
        assert!(took(step) < 2000.0, "{step} takes {} ms", took(step));
    }
}

#[test]
fn the_image_leaves_room_in_the_flash() {
    let Some(m) = lapin().as_deref().map(machine) else {
        return;
    };
    let used = m.soc.flash[..0x1F000]
        .iter()
        .rposition(|b| *b != 0xFF)
        .map_or(0, |last| last + 1);
    eprintln!("lapin uses {used} bytes of flash");
    // 124 KB is all there is below the settings sector.
    assert!(used < 124 * 1024);
}

/// The self-test exercises each driver; here is what the board saw.
#[test]
fn every_driver_does_its_job() {
    use nabemu::rfid::Tag;
    use nabemu::vs1003::{Format, adpcm_decode};

    let Some(image) = lapin_target("selftest-full.bin") else {
        return;
    };
    let mut m = machine(&image);
    let mut tag = Tag::new(UID);
    tag.blocks[8] = *b"miam";
    m.soc.board.rfid.tags.push(tag);
    // Something to listen to: a 500 Hz note, as long as it takes.
    let mut sung = 0;
    while !m.console().ends_with("end\n") {
        assert!(m.soc.millis() < 60_000, "never finished:\n{}", m.console());
        wait(&mut m, 10);
        let microphone = &mut m.soc.board.codec.microphone;
        while microphone.len() < 800 {
            microphone.push_back(note(sung));
            sung += 1;
        }
    }
    let console = m.console();
    assert_eq!(m.events, [], "{console}");
    assert!(m.soc.bus_faults.is_empty(), "{:x?}", m.soc.bus_faults);
    assert!(m.soc.unmodelled.is_empty(), "{:x?}", m.soc.unmodelled);
    assert_eq!(m.soc.cpu_clock_hz(), Some(32_000_000));

    // Ears: seventeen teeth between two passes of the gap, both sides.
    assert!(console.contains("ears 17 17\n"), "{console}");
    assert_eq!(
        m.soc.board.ears.map(|e| e.direction),
        [0, 0],
        "and they are stopped"
    );

    // Tag: found, read, written.
    assert!(console.contains("tag d0021a0352c4667f\n"), "{console}");
    assert!(console.contains("block 6d69616d\n"), "{console}");
    assert!(console.contains("written\n"), "{console}");
    // ...and what it held put back.
    assert_eq!(m.soc.board.rfid.tags[0].blocks[9], [0; 4]);

    // Flash: the settings sector rewritten from RAM, then put back as it
    // was; nothing else touched.
    assert!(console.contains("flash ok\n"), "{console}");
    assert!(m.soc.flash[0x1F000..].iter().all(|b| *b == 0xFF));
    // The sector was blank: written without an erase, which the manual
    // forbids twice in a row (20.5.5); one erase to put it back.
    assert_eq!(m.soc.flash_erases, 1);
    assert_eq!(m.soc.flash_reads_while_busy, 0, "the routine ran from RAM");
    let rules = &m.soc.flash_rules;
    assert_eq!(rules.breaches, 0, "the manual's rules: {:?}", rules.log);
    let fresh = machine(&image);
    assert_eq!(m.soc.flash[..0x1F000], fresh.soc.flash[..0x1F000]);

    // Loudspeaker: a second of 8 kHz sound, fed at the pace it plays.
    let tracks = m.soc.board.codec.all_tracks();
    let tone = tracks
        .iter()
        .find(|t| t.format == PCM_8K)
        .expect("the tone");
    assert_eq!(tone.data.len(), 48 + 16000);
    let played = console.find("tone played").unwrap();
    assert!(console[..played].contains("flash ok"));

    // Microphone: what was sung comes back, a 500 Hz note.
    assert!(
        console.contains("heard 1920 words\n"),
        "fifteen blocks in a second: {console}"
    );
    let back = tracks
        .iter()
        .find(|t| matches!(t.format, Format::Wav { adpcm: true, .. }))
        .expect("the playback");
    let heard = adpcm_decode(&back.data[48..]);
    assert_eq!(heard.len(), 15 * 505);
    common::assert_the_note(&heard);

    assert_eq!(m.soc.board.leds, [GREEN; 5], "green at the end");
}

/// WPA3 on the rabbit's own processor: the password exchange, its
/// timing against the watchdog, and the restart that finds the access
/// point still holding the old association.
mod wpa3 {
    use super::common::{
        authorized, handshakes, ip_on_the_wire, lapin, on_wpa3_network, until_by, until_every,
    };
    use nabemu::air::ApEvent;
    use nabemu::{DEFAULT_MAC, Machine};

    fn rabbit() -> Option<Machine> {
        Some(on_wpa3_network(&lapin()?))
    }

    #[test]
    fn joins_and_its_watchdog_never_bites() {
        let Some(mut m) = rabbit() else { return };
        let asked = until_every(&mut m, 5, 30_000, "the scan", |m| {
            !m.radio.borrow().tx.is_empty() && m.console().contains("## SCAN")
        });
        let done = until_every(&mut m, 5, 30_000, "authorized", authorized);
        eprintln!("authorized {} ms after the scan ended", done - asked);
        assert!(done - asked < 3000, "{} ms", done - asked);
        m.run_until_ms(done + 5000);
        assert_eq!(m.events, []);
        assert!(m.console().contains("-------------dhcp"));
        assert_eq!(m.radio.borrow().rx_cipher_errors, [0; 4]);
    }

    /// Thrown out, the rabbit comes back with the key of its first
    /// exchange (PMKSA caching): no password exchange the second time.
    #[test]
    fn comes_back_without_a_second_password_exchange() {
        let Some(mut m) = rabbit() else { return };
        let first = until_every(&mut m, 5, 30_000, "authorized", authorized);
        m.run_until_ms(first + 1000);
        m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 3);
        let kicked = m.soc.millis();
        let back = until_every(&mut m, 5, 30_000, "back", |m| handshakes(m) == 2);
        let events = &m.air[0].events;
        assert!(
            events.contains(&ApEvent::PmksaCacheUsed { sta: DEFAULT_MAC }),
            "{events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, ApEvent::SaeComplete { .. }))
                .count(),
            1
        );
        eprintln!("back {} ms after being thrown out", back - kicked);
        assert_eq!(m.events, []);
    }

    #[test]
    fn after_a_power_cut_it_waits_out_the_old_association() {
        let Some(mut m) = rabbit() else { return };
        let first = until_every(&mut m, 5, 30_000, "authorized", authorized);
        m.run_until_ms(first + 1000);
        m.power_cycle();
        let again = until_by(&mut m, first + 40_000, 5, "back", |m| handshakes(m) == 2);
        assert!(authorized(&m));
        let events = &m.air[0].events;
        assert!(
            events.contains(&ApEvent::SaQueryStarted { sta: DEFAULT_MAC }),
            "{events:?}"
        );
        assert!(
            events.contains(&ApEvent::AssocRejected {
                sta: DEFAULT_MAC,
                status: 30
            }),
            "{events:?}"
        );
        eprintln!("back {} ms after the power came back", again - first - 1000);
        m.run_until_ms(again + 3000);
        assert!(ip_on_the_wire(&m));
    }
}

/// The interpreter's speed against the C one's, on the same bytecode,
/// timed by the bytecode itself with `time_ms`, on each firmware: a
/// loop of five instructions turned 100 000 times, and `fib 20`, the
/// recursive way (21 891 calls).
#[test]
fn the_interpreter_outruns_the_c_one() {
    use common::{serving, time_printed};
    use nabemu::metal;

    let Some(lapin) = lapin() else { return };
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.push(53); // time_ms
    f.extend(metal::int(100_000));
    f.extend([6, 29, 19, 0]); // dup; else 19
    f.extend(metal::int(1));
    f.extend([10, 28, 6, 0]); // sub; goto 6
    f.extend([5, 53, 10, 95, 1]); // drop; time_ms; sub; Iecholn; ret
    let lp = metal::bytecode(&[], &f);

    // Function 0: time_ms; fib 20; drop; time_ms; sub; Iecholn; ret.
    let main = [53u8, 2, 20, 2, 1, 0, 5, 53, 10, 95, 1];
    // Function 1, fib n: if n < 2 then n else fib (n-1) + fib (n-2).
    let fib = [
        7u8, 0, 2, 2, 24, 29, 11, 0, 7, 0, 1, 7, 0, 2, 1, 10, 2, 1, 0, 7, 0, 2, 2, 10, 2, 1, 0, 9,
        1,
    ];
    let mut code = vec![0u8, 0, 0];
    code.extend(main);
    let second = code.len() as u32;
    code.extend([1u8, 0, 0]);
    code.extend(fib);
    let mut fb = 4u32.to_le_bytes().to_vec();
    fb.extend((code.len() as u32).to_le_bytes());
    fb.extend(&code);
    fb.extend(2u16.to_le_bytes());
    fb.extend(0u32.to_le_bytes());
    fb.extend(second.to_le_bytes());

    let r3 = common::r3();
    let time = |image: &[u8], bytecode: &[u8]| {
        let mut m = serving(image, bytecode);
        until_every(&mut m, 50, 60_000, "a time printed", |m| {
            time_printed(m).is_some()
        });
        time_printed(&m).unwrap()
    };
    for (name, bytecode) in [("loop", &lp), ("fib 20", &fb)] {
        let (c, rust) = (time(&r3, bytecode), time(&lapin, bytecode));
        eprintln!("{name}: {c} ms on r3, {rust} ms on lapin");
        assert!(rust * 10 <= c * 7, "{name}: {rust} ms against {c} ms");
    }
}
