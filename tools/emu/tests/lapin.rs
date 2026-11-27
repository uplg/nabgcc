//! The Rust firmware (`../../lapin`) on the emulated rabbit. It needs
//! a nightly toolchain to build, so the test runs when the image is
//! there (`lapin/build.sh`) and is skipped otherwise.

use nabemu::Machine;

fn image(name: &str) -> Option<Vec<u8>> {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../lapin/target/thumbv4t-none-eabi/release/"
    );
    let image = std::fs::read(format!("{dir}{name}")).ok();
    if image.is_none() {
        eprintln!("skipped: lapin is not built");
    }
    image
}

const AMBER: [u8; 3] = [126, 16, 0];

/// The board comes up, finds its stick, and hands over to the boot
/// bytecode, which keeps the watchdog fed and looks for a network.
#[test]
fn the_firmware_boots_its_bytecode_and_stays_up() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.run_until_ms(10_500);
    assert_eq!(m.events, [], "no reset in ten seconds");
    assert!(m.soc.bus_faults.is_empty(), "{:x?}", m.soc.bus_faults);
    assert!(m.soc.unmodelled.is_empty(), "{:x?}", m.soc.unmodelled);
    assert_eq!(m.soc.cpu_clock_hz(), Some(32_000_000));
    let console = m.console();
    assert!(
        console.starts_with("lapin 0.1\nwifi 00:19:db:00:00:01 radio 02\n"),
        "{console}"
    );
    assert!(console.contains("wifi state="), "{console}");
    // The bytecode's amber: no network found yet.
    assert_eq!(m.soc.board.leds, [AMBER; 5]);
    assert_eq!(m.soc.ohci.errors, 0);
    let radio = m.radio.borrow();
    assert!(radio.firmware_loaded && radio.rx_enabled);
}

/// Without its Wi-Fi stick the firmware says so and carries on: the
/// bytecode runs, the network stays broken.
#[test]
fn a_missing_wifi_stick_is_reported() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.soc.ohci.device = None;
    m.run_until_ms(10_000);
    let console = m.console();
    assert!(
        console.starts_with("lapin 0.1\nwifi: no stick\n"),
        "{console}"
    );
    assert!(console.contains("started"), "{console}");
    assert_eq!(m.events, []);
}

/// The firmware tunes the two radio chips that do 2.4 GHz only. A stick
/// that names one of the others is refused, by name, before anything
/// is written to its radio.
#[test]
fn a_stick_with_a_radio_it_cannot_tune_is_refused() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.radio.borrow_mut().rf_chip = 3;
    m.run_until_ms(6000);
    assert!(
        m.console().starts_with("lapin 0.1\nwifi: radio 03\n"),
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

    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
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
    let Some(image) = image("bench") else { return };
    let mut m = Machine::from_file(&image).0;
    let mut marks: Vec<(String, f64)> = Vec::new();
    let mut seen = 0;
    while !m.console().ends_with("end\n") {
        assert!(m.soc.millis() < 60_000, "never finished:\n{}", m.console());
        m.run_until_ms(m.soc.millis() + 1);
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
    let Some(image) = image("lapin") else { return };
    let m = Machine::from_file(&image).0;
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

    let Some(image) = image("selftest") else {
        return;
    };
    let mut m = Machine::from_file(&image).0;
    let mut tag = Tag::new([0xD0, 0x02, 0x1A, 0x03, 0x52, 0xC4, 0x66, 0x7F]);
    tag.blocks[8] = *b"miam";
    m.soc.board.rfid.tags.push(tag);
    // Something to listen to: a 500 Hz note, as long as it takes.
    let note =
        |i: usize| (12000.0 * (i as f64 * 500.0 * std::f64::consts::TAU / 8000.0).sin()) as i16;
    let mut sung = 0;
    while !m.console().ends_with("end\n") {
        assert!(m.soc.millis() < 60_000, "never finished:\n{}", m.console());
        m.run_until_ms(m.soc.millis() + 10);
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
    assert_eq!(m.soc.board.rfid.tags[0].blocks[9], *b"lapi");

    // Flash: the settings sector rewritten from RAM, nothing else touched.
    assert!(console.contains("flash ok\n"), "{console}");
    assert_eq!(m.soc.flash[0x1F000..0x1F008], *b"LAPINCFG");
    assert!(m.soc.flash[0x1F008..].iter().all(|b| *b == 0xFF));
    assert_eq!(m.soc.flash_erases, 1);
    assert_eq!(m.soc.flash_reads_while_busy, 0, "the routine ran from RAM");
    let fresh = Machine::from_file(&image).0;
    assert_eq!(m.soc.flash[..0x1F000], fresh.soc.flash[..0x1F000]);

    // Loudspeaker: a second of 8 kHz sound, fed at the pace it plays.
    let tracks = m.soc.board.codec.all_tracks();
    let tone = tracks
        .iter()
        .find(|t| {
            t.format
                == Format::Wav {
                    sample_rate: 8000,
                    channels: 1,
                    bits: 16,
                    adpcm: false,
                }
        })
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
    let opposite = heard
        .windows(9)
        .filter(|w| (w[0] as i32 + w[8] as i32).abs() < 3000)
        .count();
    assert!(
        opposite > heard.len() * 3 / 4,
        "{opposite} of {} samples keep the period",
        heard.len()
    );
    assert!(heard.iter().filter(|s| s.abs() > 6000).count() > heard.len() / 4);

    assert_eq!(m.soc.board.leds, [[0, 126, 0]; 5], "green at the end");
}

/// WPA3 on the rabbit's own processor: the password exchange, its
/// timing against the watchdog, and the restart that finds the access
/// point still holding the old association.
mod wpa3 {
    use super::image;
    use nabemu::air::{AccessPoint, ApEvent, Security, Wpa3};
    use nabemu::config::{Config, Wifi};
    use nabemu::{DEFAULT_MAC, Machine};

    const PASSPHRASE: &str = "carotte-violette";

    fn rabbit() -> Option<Machine> {
        let image = image("lapin")?;
        let mut m = Machine::from_file(&image).0;
        Config::new(
            "Terrier",
            Wifi::Wpa2 {
                passphrase: PASSPHRASE.into(),
            },
        )
        .install(&mut m.soc.flash);
        let mut ap = AccessPoint::new(
            "Terrier",
            [2, 0, 0, 0, 0, 0xA1],
            6,
            Security::wpa2(PASSPHRASE),
        );
        ap.wpa3 = Wpa3::Only;
        m.air.push(ap);
        Some(m)
    }

    fn until(m: &mut Machine, limit: u64, done: impl Fn(&Machine) -> bool) -> u64 {
        while !done(m) {
            assert!(
                m.soc.millis() < limit,
                "not by {limit} ms: {:?}\n{}",
                m.air[0].events,
                m.console()
            );
            m.run_until_ms(m.soc.millis() + 5);
        }
        m.soc.millis()
    }

    fn authorized(m: &Machine) -> bool {
        m.air[0].is_authorized(DEFAULT_MAC)
    }

    #[test]
    fn joins_and_its_watchdog_never_bites() {
        let Some(mut m) = rabbit() else { return };
        let asked = until(&mut m, 30_000, |m| {
            !m.radio.borrow().tx.is_empty() && m.console().contains("## SCAN")
        });
        let done = until(&mut m, 30_000, authorized);
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
        let first = until(&mut m, 30_000, authorized);
        m.run_until_ms(first + 1000);
        m.air[0].kick(&mut m.radio.borrow_mut(), DEFAULT_MAC, 3);
        let kicked = m.soc.millis();
        let back = until(&mut m, kicked + 30_000, |m| {
            m.air[0]
                .events
                .iter()
                .filter(|e| matches!(e, ApEvent::HandshakeComplete { .. }))
                .count()
                == 2
        });
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
        let first = until(&mut m, 30_000, authorized);
        m.run_until_ms(first + 1000);
        m.power_cycle();
        let again = until(&mut m, first + 40_000, |m| {
            m.air[0]
                .events
                .iter()
                .filter(|e| matches!(e, ApEvent::HandshakeComplete { .. }))
                .count()
                == 2
        });
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
        assert!(m.air[0].uplink.iter().any(|f| f[12..14] == [0x08, 0x00]));
    }
}

/// The interpreter's speed against the C one's, on the same bytecode,
/// timed by the bytecode itself with `time_ms`, on each firmware: a
/// loop of five instructions turned 100 000 times, and `fib 20`, the
/// recursive way (21 891 calls).
#[test]
fn the_interpreter_outruns_the_c_one() {
    use nabemu::air::{AccessPoint, Security};
    use nabemu::config::{Config, Wifi};
    use nabemu::lan::{Lan, Response};
    use nabemu::metal;

    let Some(lapin) = image("lapin") else { return };
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

    let r3 = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../artifacts/Nab-wpa23-gtk-r3.sim"
    ))
    .unwrap();
    let time = |image: &[u8], bytecode: &[u8]| {
        let served = metal::boot_response(bytecode);
        let mut m = Machine::from_file(image).0;
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
        m.run_until_ms(40_000);
        let console = m.console();
        console
            .lines()
            .filter_map(|l| l.strip_prefix('-')?.parse::<u64>().ok())
            .next_back()
            .unwrap_or_else(|| panic!("no time printed:\n{console}"))
    };
    for (name, bytecode) in [("loop", &lp), ("fib 20", &fb)] {
        let (c, rust) = (time(&r3, bytecode), time(&lapin, bytecode));
        eprintln!("{name}: {c} ms on r3, {rust} ms on lapin");
        assert!(rust * 10 <= c * 7, "{name}: {rust} ms against {c} ms");
    }
}
