//! The audio converters from odd offsets: the C reads and writes its
//! samples as `int16_t`, and from an odd address the ARM7TDMI loads a
//! sign-extended byte and stores to the halfword below. lapin must give
//! the same bytes as r3 on the same processor. Skipped when lapin is
//! not built.

mod common;

use common::bc::op::*;
use common::{find, program_ended, serving, until_every};
use nabemu::metal;

fn run(image: &[u8], bytecode: &[u8]) -> Vec<u8> {
    let mut m = serving(image, bytecode);
    until_every(&mut m, 50, 60_000, "the end of the output", program_ended);
    let out = &m.soc.uart_tx;
    let start = find(out, b"7770").expect("no output");
    let end = find(&out[start..], b"8880").unwrap() + start;
    out[start..end].to_vec()
}

/// Each converter from offsets of every parity: `dst index, src start`.
fn program() -> Vec<u8> {
    let dst = vec![0u8; 1100];
    let mut src: Vec<u8> = (0..1100u32).map(|i| (i * 37 + 11) as u8).collect();
    // An ADPCM block's step index (its bytes 2 and 3) must be a real one
    // from every start used: the C indexes its table unchecked.
    src[2..9].fill(0);
    let mut f = metal::FUNCTION_HEADER.to_vec();
    f.extend(metal::int(7770));
    f.extend([IECHOLN, DROP]);
    for (op, len, mu) in [
        (ADP2WAV, 256, None),
        (WAV2ADP, 1010, None),
        (ALAW2WAV, 400, Some(0)),
        (ALAW2WAV, 400, Some(1)),
        (WAV2ALAW, 400, Some(0)),
        (WAV2ALAW, 400, Some(1)),
    ] {
        for (index, start) in [(0, 0), (1, 0), (0, 1), (1, 1), (3, 5)] {
            // A fresh destination each time: copy of the zeros.
            f.extend([GETGLOBALB, 0]);
            f.extend(metal::int(index));
            f.extend([GETGLOBALB, 1]);
            f.extend(metal::int(start));
            f.extend(metal::int(len));
            if let Some(mu) = mu {
                f.extend(metal::int(mu));
            }
            f.push(op);
            f.push(SECHOLN);
            f.push(DROP);
            // Zero the destination again for the next run.
            f.extend([GETGLOBALB, 0]);
            f.extend(metal::int(0));
            f.extend([GETGLOBALB, 2]);
            f.extend(metal::int(0));
            f.extend(metal::int(1100));
            f.push(STRCPY);
            f.push(DROP);
        }
    }
    f.extend(metal::int(8880));
    f.extend([IECHOLN, RET]);
    metal::bytecode(&[&dst, &src, &vec![0u8; 1100]], &f)
}

#[test]
fn the_audio_converters_match_r3_from_odd_offsets() {
    let Some(lapin) = common::lapin() else { return };
    let bc = program();
    let (c, rust) = (run(&common::r3(), &bc), run(&lapin, &bc));
    assert!(c.len() > 5000, "{} bytes", c.len());
    if c != rust {
        let at = c
            .iter()
            .zip(&rust)
            .position(|(a, b)| a != b)
            .unwrap_or(c.len().min(rust.len()));
        panic!(
            "first difference at byte {at} of {}: r3 {:02x?}, lapin {:02x?}",
            c.len(),
            &c[at.saturating_sub(4)..(at + 12).min(c.len())],
            &rust[at.saturating_sub(4)..(at + 12).min(rust.len())]
        );
    }
}
