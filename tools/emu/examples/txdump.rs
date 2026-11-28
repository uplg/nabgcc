//! Boot a firmware image and list every frame it transmits.
mod common;

fn main() {
    let mut args = common::Args::new();
    let mut m = args.machine();
    let ms = args.number(5000);
    m.run_until_ms(ms);
    for f in &m.radio.borrow().tx {
        let hex: Vec<String> = f.data.iter().map(|b| format!("{b:02x}")).collect();
        println!("ch{:<2} {}", f.channel, hex.join(""));
    }
}
