//! The factory test built into the boot bytecode, step by step: it
//! exercises the ears, the tag reader, the loudspeaker and the
//! microphone, which makes it a good way to check them here.
//!
//! Button held more than seven seconds at power-on starts it; every
//! click moves to the next step, which begins two seconds later.

use nabemu::Machine;
use nabemu::board::{LED_LEFT, LED_RIGHT};
use nabemu::rfid::Tag;
use nabemu::vs1003::{Format, adpcm_decode};

const GREEN: [u8; 3] = [0, 126, 0];

fn in_factory_test() -> Machine {
    let mut m = Machine::from_file(&nabemu::testing::image()).0;
    m.soc.board.button = true;
    m.run_until_ms(8000);
    m.soc.board.button = false;
    m.run_until_ms(8500);
    m
}

fn wait(m: &mut Machine, ms: u64) {
    m.run_until_ms(m.soc.millis() + ms);
}

fn click(m: &mut Machine) {
    m.soc.board.button = true;
    wait(m, 200);
    m.soc.board.button = false;
    wait(m, 300);
}

/// Click until the test reaches the given step (the first click after
/// entering leads to step 2).
fn go_to_step(m: &mut Machine, step: u32) {
    for _ in 1..step {
        click(m);
    }
}

fn run_until(m: &mut Machine, limit_ms: u64, what: &str, done: impl Fn(&Machine) -> bool) {
    let limit = m.soc.millis() + limit_ms;
    while !done(m) {
        assert!(
            m.soc.millis() < limit,
            "{what}: not within {limit_ms} ms\n{}",
            m.console()
        );
        wait(m, 20);
    }
}

#[test]
fn step_2_swings_the_ears_in_opposite_directions() {
    let mut m = in_factory_test();
    go_to_step(&mut m, 2);
    wait(&mut m, 3000);
    let ears = m.soc.board.ears;
    assert_ne!(ears[0].direction, 0);
    assert_eq!(ears[0].direction, -ears[1].direction);
    assert!(ears[0].pulses > 0 && ears[1].pulses > 0);
}

#[test]
fn step_3_counts_seventeen_teeth_per_turn_on_each_ear() {
    let mut m = in_factory_test();
    go_to_step(&mut m, 3);
    run_until(&mut m, 20_000, "both ears measured", |m| {
        let c = m.console();
        c.contains("refpos0 17") && c.contains("refpos1 17")
    });
    // It lights the side leds green on a good count, then lets them go
    // dark as the turn goes on; no red, which would be a bad count.
    assert!(!m.console().contains("refpos0 16") && !m.console().contains("refpos0 18"));
    let leds = m.soc.board.leds;
    assert!([GREEN, [0, 0, 0]].contains(&leds[LED_LEFT]), "{leds:?}");
    assert!([GREEN, [0, 0, 0]].contains(&leds[LED_RIGHT]), "{leds:?}");
}

#[test]
fn step_4_turns_green_when_a_tag_is_shown() {
    let mut m = in_factory_test();
    go_to_step(&mut m, 4);
    wait(&mut m, 3000);
    assert_eq!(
        m.soc.board.leds,
        [[0, 0, 0]; 5],
        "nothing in front of the nose"
    );
    m.soc
        .board
        .rfid
        .tags
        .push(Tag::new([0xD0, 0x02, 0x1A, 0x03, 0x52, 0xC4, 0x66, 0x7F]));
    wait(&mut m, 1000);
    assert_eq!(m.soc.board.leds, [GREEN; 5]);
    assert!(m.console().contains("RFID : "));
    m.soc.board.rfid.tags.clear();
    wait(&mut m, 1000);
    assert_eq!(m.soc.board.leds, [[0, 0, 0]; 5]);
}

#[test]
fn step_5_plays_a_tone() {
    let mut m = in_factory_test();
    go_to_step(&mut m, 5);
    wait(&mut m, 2500);
    let started = m.soc.millis();
    wait(&mut m, 4000);
    let codec = &m.soc.board.codec;
    let track = codec.current.as_ref().expect("something is playing");
    assert_eq!(
        track.format,
        Format::Wav {
            sample_rate: 8000,
            channels: 1,
            bits: 16,
            adpcm: false
        }
    );
    assert!(m.soc.board.amplifier, "the loudspeaker amplifier is on");
    // It is fed at the pace it plays: 16000 bytes a second, give or
    // take the buffer.
    let fed = track.data.len() as u64;
    let expected = (m.soc.millis() - started.min(track.started_ms).max(track.started_ms)) * 16;
    assert!(
        fed.abs_diff(expected) < 6000,
        "{fed} bytes fed, {expected} expected"
    );
    // And it is a tone, not silence: the samples swing both ways.
    let samples: Vec<i16> = track.data[44..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| i16::from_le_bytes(*b))
        .collect();
    assert!(samples.iter().any(|s| *s > 1000) && samples.iter().any(|s| *s < -1000));
}

#[test]
fn step_6_records_while_the_button_is_held_and_plays_it_back() {
    let mut m = in_factory_test();
    go_to_step(&mut m, 6);
    wait(&mut m, 2500);

    // Whistle a 500 Hz note at the microphone while holding the button.
    let note =
        |i: usize| (12000.0 * (i as f64 * 500.0 * std::f64::consts::TAU / 8000.0).sin()) as i16;
    m.soc.board.codec.microphone.extend((0..16000).map(note));
    m.soc.board.button = true;
    wait(&mut m, 2000);
    assert_eq!(
        m.soc.board.leds[0],
        [126, 126, 0],
        "yellow while it records"
    );
    m.soc.board.button = false;
    wait(&mut m, 3000);

    let tracks = m.soc.board.codec.all_tracks();
    let playback = tracks
        .iter()
        .rev()
        .find(|t| matches!(t.format, Format::Wav { adpcm: true, .. }))
        .unwrap_or_else(|| {
            panic!(
                "no recording played back: {:?}",
                tracks.iter().map(|t| t.format).collect::<Vec<_>>()
            )
        });
    assert_eq!(
        playback.format,
        Format::Wav {
            sample_rate: 8000,
            channels: 1,
            bits: 4,
            adpcm: true
        }
    );
    // What comes back is what went in: a 500 Hz note, sixteen samples
    // to a period, so each sample is the opposite of the one 8 before.
    let data = playback
        .data
        .windows(4)
        .position(|w| w == b"data")
        .expect("a data chunk")
        + 8;
    let heard = adpcm_decode(&playback.data[data..]);
    assert!(heard.len() > 4000, "{} samples played back", heard.len());
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
