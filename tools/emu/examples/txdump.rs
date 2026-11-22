//! Boot a firmware image and list every frame it transmits.
use nabemu::Machine;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: txdump <firmware> [ms]");
    let ms = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let (mut m, _) = Machine::from_file(&std::fs::read(path).expect("readable firmware"));
    m.run_until_ms(ms);
    for f in &m.radio.borrow().tx {
        let hex: Vec<String> = f.data.iter().map(|b| format!("{b:02x}")).collect();
        println!("ch{:<2} {}", f.channel, hex.join(""));
    }
}
