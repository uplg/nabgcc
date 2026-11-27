//! The audio converters from odd offsets: the C reads and writes its
//! samples as `int16_t`, and from an odd address the ARM7TDMI loads a
//! sign-extended byte and stores to the halfword below. lapin must give
//! the same bytes as r3 on the same processor. Skipped when lapin is
//! not built.

use nabemu::Machine;
use nabemu::air::{AccessPoint, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};
use nabemu::metal;

const ADP2WAV: u8 = 138;
const WAV2ADP: u8 = 139;
const ALAW2WAV: u8 = 140;
const WAV2ALAW: u8 = 141;

fn run(image: &[u8], bytecode: &[u8]) -> Vec<u8> {
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
    let out = &m.soc.uart_tx;
    let start = find(out, b"7770").unwrap_or_else(|| panic!("no output:\n{}", m.console()));
    let end = find(&out[start..], b"8880").expect("no end") + start;
    out[start..end].to_vec()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
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
    f.extend([metal::OP_IECHOLN, metal::OP_DROP]);
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
            f.extend([metal::OP_GETGLOBALB, 0]);
            f.extend(metal::int(index));
            f.extend([metal::OP_GETGLOBALB, 1]);
            f.extend(metal::int(start));
            f.extend(metal::int(len));
            if let Some(mu) = mu {
                f.extend(metal::int(mu));
            }
            f.push(op);
            f.push(metal::OP_SECHOLN);
            f.push(metal::OP_DROP);
            // Zero the destination again for the next run.
            f.extend([metal::OP_GETGLOBALB, 0]);
            f.extend(metal::int(0));
            f.extend([metal::OP_GETGLOBALB, 2]);
            f.extend(metal::int(0));
            f.extend(metal::int(1100));
            f.push(STRCPY);
            f.push(metal::OP_DROP);
        }
    }
    f.extend(metal::int(8880));
    f.extend([metal::OP_IECHOLN, metal::OP_RET]);
    metal::bytecode(&[&dst, &src, &vec![0u8; 1100]], &f)
}

const STRCPY: u8 = 64;

#[test]
fn the_audio_converters_match_r3_from_odd_offsets() {
    let root = env!("CARGO_MANIFEST_DIR");
    let Ok(lapin) = std::fs::read(format!("{root}/../../lapin/target/lapin-full.bin")) else {
        eprintln!("skipped: lapin is not built");
        return;
    };
    let r3 = std::fs::read(format!("{root}/../../artifacts/Nab-wpa23-gtk-r3.sim")).unwrap();
    let bc = program();
    let (c, rust) = (run(&r3, &bc), run(&lapin, &bc));
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
