//! Wi-Fi: the Ralink RT2573 stick on the USB port.

pub mod link;
pub mod rt2573;
mod rxq;

pub use rxq::Received;
