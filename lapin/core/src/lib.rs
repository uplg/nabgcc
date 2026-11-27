//! The portable part of the rabbit's firmware: everything that needs
//! no hardware and no heap, so that it runs on the ARM7 and is tested
//! on the machine that builds it.

#![no_std]

pub use lapin_p256 as p256;

pub mod aes;
pub mod ccmp;
pub mod md5;
pub mod rng;
pub mod sae;
pub mod sha1;
pub mod sha256;
pub mod wifi;
