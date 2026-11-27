//! For the acceptance tests in `tests/`: which firmware they run. The
//! released C one (r3) unless `NABEMU_FIRMWARE=lapin` names the Rust
//! one, built in `../../lapin` (`lapin/build.sh`).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Firmware {
    R3,
    Lapin,
}

pub fn firmware() -> Firmware {
    match std::env::var("NABEMU_FIRMWARE").as_deref() {
        Ok("lapin") => Firmware::Lapin,
        Ok("r3") | Err(_) => Firmware::R3,
        Ok(other) => panic!("NABEMU_FIRMWARE: no firmware called {other}"),
    }
}

/// Whether the tests run the Rust firmware.
pub fn is_lapin() -> bool {
    firmware() == Firmware::Lapin
}

/// The image of the firmware under test, as a file: r3's `.sim`, or
/// lapin's whole image (rescue core and application, `lapin/build.sh`).
pub fn image() -> Vec<u8> {
    let root = env!("CARGO_MANIFEST_DIR");
    let path = match firmware() {
        Firmware::R3 => format!("{root}/../../artifacts/Nab-wpa23-gtk-r3.sim"),
        Firmware::Lapin => format!("{root}/../../lapin/target/lapin-full.bin"),
    };
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}
