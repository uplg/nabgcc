//! Put a rabbit in setup mode and print one of its beacons.
use nabemu::Machine;
fn main() {
    let path = std::env::args().nth(1).expect("firmware path");
    let (mut m, _) = Machine::from_file(&std::fs::read(path).unwrap());
    m.soc.board.button = true;
    m.run_until_ms(2000);
    m.soc.board.button = false;
    m.run_until_ms(12_000);
    let radio = m.radio.borrow();
    if let Some(f) = radio.tx.iter().rev().find(|f| f.data[0] == 0x80) {
        let hex: String = f.data.iter().map(|b| format!("{b:02x}")).collect();
        println!("ch{} {hex}", f.channel);
    }
}
