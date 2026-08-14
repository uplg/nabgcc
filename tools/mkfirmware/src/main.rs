use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;

/// Nabaztag .sim firmware cipher lookup table.
///
/// Used by the `-violet-` bootloader to decrypt firmware on the rabbit.
/// Each entry is the modular inverse of `(2*index + 1)` mod 256,
/// i.e. `inv8[i] * (2*i + 1) ≡ 1 (mod 256)`.
const INV8: [u8; 128] = [
    1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223, 225, 139, 173, 151, 25,
    131, 165, 207, 209, 251, 29, 135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175, 177,
    219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71, 201,
    179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95, 97, 11,
    45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47,
    49, 91, 125, 231, 105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199, 73,
    51, 85, 255,
];

const MARKER: &[u8] = b"-violet-";

/// Encrypt the firmware binary with the Nabaztag stream cipher.
///
/// For each byte `v` in the input:
///   output = (alpha + v * inv8[key >> 1]) mod 256
///   key    = (1 + 2 * v) mod 256
fn strcrypt8(data: &[u8], initial_key: u8, alpha: u8) -> Vec<u8> {
    let mut key = initial_key;
    let mut out = Vec::with_capacity(data.len());
    for &v in data {
        let encrypted = alpha.wrapping_add((v as u16 * INV8[(key >> 1) as usize] as u16) as u8);
        out.push(encrypted);
        key = (1u16 + 2u16 * v as u16) as u8; // (1 + 2*v) mod 256
    }
    out
}

/// Encode a byte slice as lowercase hex.
fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// Build the .sim firmware file contents:
///   `-violet-` + hex(2 * size, 8 digits) + hex(encrypted_bytes) + `-violet-`
fn mkfirmware(bin_data: &[u8]) -> Vec<u8> {
    let size = bin_data.len();
    let encrypted = strcrypt8(bin_data, 0x47, 47);
    let hex_size = format!("{:08x}", 2 * size);
    let hex_data = hex_encode(&encrypted);

    let mut out = Vec::with_capacity(MARKER.len() * 2 + 8 + hex_data.len());
    out.extend_from_slice(MARKER);
    out.extend_from_slice(hex_size.as_bytes());
    out.extend_from_slice(hex_data.as_bytes());
    out.extend_from_slice(MARKER);
    out
}

fn usage() -> ! {
    eprintln!("mkfirmware — Convert a raw ARM binary to Nabaztag .sim format");
    eprintln!();
    eprintln!("Usage: mkfirmware <input.bin> [output.sim]");
    eprintln!();
    eprintln!("If output is omitted, defaults to firmware0.0.0.13.sim");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        usage();
    }

    let input_path = PathBuf::from(&args[1]);
    let output_path = if args.len() == 3 {
        PathBuf::from(&args[2])
    } else {
        PathBuf::from("firmware0.0.0.13.sim")
    };

    let bin_data = match fs::read(&input_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading {}: {e}", input_path.display());
            process::exit(1);
        }
    };

    eprintln!(
        "Input:  {} ({} bytes)",
        input_path.display(),
        bin_data.len()
    );

    let sim_data = mkfirmware(&bin_data);

    match fs::File::create(&output_path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(&sim_data) {
                eprintln!("Error writing {}: {e}", output_path.display());
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error creating {}: {e}", output_path.display());
            process::exit(1);
        }
    }

    eprintln!(
        "Output: {} ({} bytes)",
        output_path.display(),
        sim_data.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inv8_table() {
        // Each inv8[i] should satisfy: inv8[i] * (2*i + 1) ≡ 1 (mod 256)
        for i in 0u16..128 {
            let odd = (2 * i + 1) as u8;
            let inv = INV8[i as usize];
            assert_eq!(
                odd.wrapping_mul(inv),
                1,
                "inv8[{i}] = {inv} but {odd} * {inv} = {} (expected 1 mod 256)",
                odd.wrapping_mul(inv)
            );
        }
    }

    #[test]
    fn test_strcrypt8_deterministic() {
        let data = b"Hello";
        let enc1 = strcrypt8(data, 0x47, 47);
        let enc2 = strcrypt8(data, 0x47, 47);
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_mkfirmware_format() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let sim = mkfirmware(&data);
        let sim_str = String::from_utf8(sim).unwrap();

        // Must start and end with -violet-
        assert!(sim_str.starts_with("-violet-"));
        assert!(sim_str.ends_with("-violet-"));

        // After first marker: 8 hex chars for size (2 * 3 = 6 → "00000006")
        let inner = &sim_str[8..sim_str.len() - 8];
        assert!(inner.starts_with("00000006"));

        // Then 6 hex chars for 3 encrypted bytes
        let hex_payload = &inner[8..];
        assert_eq!(hex_payload.len(), 6);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x42]), "00ff42");
    }
}
