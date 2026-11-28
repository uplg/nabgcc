//! The portable part of the rabbit's firmware: everything that needs
//! no hardware and no heap, so that it runs on the ARM7 and is tested
//! on the machine that builds it.

#![no_std]

#[cfg(test)]
extern crate std;

pub use lapin_p256 as p256;

pub mod aes;
pub mod ccmp;
mod hash;
pub mod lz;
pub mod md5;
pub mod rng;
pub mod sae;
pub mod sha1;
pub mod sha256;
pub mod wifi;

/// Bytes from hex digits, white space ignored: the test vectors as
/// their documents print them.
#[cfg(test)]
fn hex(s: &str) -> std::vec::Vec<u8> {
    let s: std::string::String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
