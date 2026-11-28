// The compressor lives with its decoder, in lapin-core.
#[path = "../core/src/lz_pack.rs"]
mod lz_pack;

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // The linker script lives beside the crate.
    println!("cargo:rustc-link-search={dir}");
    println!("cargo:rerun-if-changed=link.x");
    println!("cargo:rerun-if-changed=rescue.x");
    println!("cargo:rerun-if-changed=common.x");
    // The rescue core holds the first sectors; every other program is
    // an application after it (src/boot.rs).
    println!("cargo:rustc-link-arg-bin=rescue=-Trescue.x");
    for app in ["lapin", "bench", "selftest"] {
        println!("cargo:rustc-link-arg-bin={app}=-Tlink.x");
    }

    // The boot bytecode goes in compressed, and must come out the same.
    println!("cargo:rerun-if-changed=src/boot.bc");
    println!("cargo:rerun-if-changed=../core/src/lz_pack.rs");
    let boot = std::fs::read(format!("{dir}/src/boot.bc")).unwrap();
    let packed = lz_pack::pack(&boot);
    let mut back = vec![0u8; boot.len()];
    assert_eq!(lapin_core::lz::unpack(&packed, &mut back), boot.len());
    assert!(
        back == boot,
        "the boot bytecode does not survive its packing"
    );
    // The firmware's buffer for it (`BOOT_LEN` in `bin/lapin.rs`).
    let main = std::fs::read_to_string(format!("{dir}/src/bin/lapin.rs")).unwrap();
    assert!(
        main.contains(&format!("const BOOT_LEN: usize = {};", boot.len())),
        "BOOT_LEN in bin/lapin.rs must be {}",
        boot.len()
    );
    println!("cargo:rerun-if-changed=src/bin/lapin.rs");
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out}/boot.lz"), &packed).unwrap();
}
