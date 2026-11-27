//! Write the boot bytecode the r3 firmware carries to the path given.
fn main() {
    let path = std::env::args().nth(1).expect("a path");
    std::fs::write(&path, lapin_metal_cref::boot_bytecode()).unwrap();
}
