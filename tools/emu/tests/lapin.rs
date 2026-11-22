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
const BLUE: [u8; 3] = [0, 0, 126];

/// Clock, interrupts, timer, watchdog, leds: the board comes up, says
/// so, and keeps its watchdog fed.
#[test]
fn the_firmware_boots_and_stays_up() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.run_until_ms(10_500);
    assert_eq!(m.events, [], "no reset in ten seconds");
    assert!(m.soc.bus_faults.is_empty(), "{:x?}", m.soc.bus_faults);
    // The same amber as the firmware it replaces, on all five leds.
    assert_eq!(m.soc.board.leds, [AMBER; 5]);
    // It found its Wi-Fi stick, read its address, went through the
    // channels, then one dot a second, counted by the timer interrupt.
    let console = m.console();
    assert!(
        console.starts_with("lapin 0.1\nrun\nwifi 00:19:db:00:00:01\n...."),
        "{console}"
    );
    assert_eq!(console.matches('.').count(), 10, "{console}");
    assert_eq!(m.soc.ohci.errors, 0);
    let radio = m.radio.borrow();
    assert!(radio.firmware_loaded && radio.rx_enabled);
    assert_eq!(radio.mac, nabemu::DEFAULT_MAC);
}

/// With the stick up, the firmware probes every channel and names the
/// networks it hears. Its probe requests carry the network name
/// element the C firmware leaves out, so access points answer them.
#[test]
fn the_firmware_finds_the_networks_around() {
    use nabemu::air::{AccessPoint, Security};

    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::wpa2("carotte-violette"),
    ));
    m.air.push(AccessPoint::new(
        "Garenne",
        [2, 0, 0, 0, 0, 0xA2],
        11,
        Security::Open,
    ));
    m.run_until_ms(4000);
    let console = m.console();
    assert!(console.contains("answer Terrier channel 06\n"), "{console}");
    assert!(console.contains("beacon Terrier channel 06\n"), "{console}");
    assert!(console.contains("answer Garenne channel 0b\n"), "{console}");
    assert!(!console.contains("Terrier channel 0b"), "{console}");
    for ap in &m.air {
        assert_eq!(
            (ap.probes_answered, ap.probes_ignored),
            (1, 0),
            "{}",
            ap.ssid
        );
    }
    // One probe a channel, from its own address, in clear.
    let radio = m.radio.borrow();
    let channels: Vec<u8> = radio.tx.iter().map(|f| f.channel).collect();
    assert_eq!(channels, (1..=13).collect::<Vec<u8>>());
    assert!(
        radio
            .tx
            .iter()
            .all(|f| f.data[0] == 0x40 && f.data[10..16] == nabemu::DEFAULT_MAC)
    );
    assert_eq!(m.events, []);
}

#[test]
fn the_button_at_power_on_asks_for_setup() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.soc.board.button = true;
    m.run_until_ms(500);
    assert!(
        m.console().starts_with("lapin 0.1\nsetup\n"),
        "{}",
        m.console()
    );
    assert_eq!(m.soc.board.leds, [BLUE; 5]);
}

/// Without its Wi-Fi stick the firmware says so and carries on.
#[test]
fn a_missing_wifi_stick_is_reported() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    m.soc.ohci.device = None;
    m.run_until_ms(6000);
    assert!(
        m.console()
            .starts_with("lapin 0.1\nrun\nwifi: no stick\n.."),
        "{}",
        m.console()
    );
    assert_eq!(m.events, []);
}

/// A firmware that stops feeding its watchdog is restarted by it.
#[test]
fn the_watchdog_restarts_a_hung_firmware() {
    let Some(image) = image("lapin") else { return };
    let mut m = Machine::from_file(&image).0;
    // Once it is up and idling, hold the button until it notices.
    m.run_until_ms(4500);
    m.soc.board.button = true;
    while !m.console().ends_with("hang\n") {
        assert!(m.soc.millis() < 6000, "{}", m.console());
        m.run_until_ms(m.soc.millis() + 10);
    }
    m.soc.board.button = false;
    let hung_at = m.soc.millis();
    while m.events.is_empty() {
        assert!(m.soc.millis() < hung_at + 3000, "the watchdog never bit");
        m.run_until_ms(m.soc.millis() + 10);
    }
    assert_eq!(
        m.events,
        [nabemu::Event::Reset(nabemu::soc::ResetCause::Watchdog)]
    );
    let waited = m.soc.millis() - hung_at;
    assert!((2000..=2200).contains(&waited), "bit after {waited} ms");
    m.run_until_ms(m.soc.millis() + 500);
    assert!(
        m.console().ends_with("hang\nlapin 0.1\nrun\n"),
        "{}",
        m.console()
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
