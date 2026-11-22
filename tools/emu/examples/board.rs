//! Boot a firmware and print the state of the board once a second.
//! usage: board <firmware> [seconds] [button]
use nabemu::Machine;

fn main() {
    let mut args = std::env::args().skip(1);
    let firmware = std::fs::read(args.next().expect("firmware path")).expect("readable firmware");
    let seconds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(10);
    let (mut m, _) = Machine::from_file(&firmware);
    m.soc.board.button = args.next().is_some();
    for s in 1..=seconds {
        m.run_until_ms(s * 1000);
        if s == 2 {
            // Held at power-on then released: setup mode.
            m.soc.board.button = false;
        }
        let b = &m.soc.board;
        let radio = m.radio.borrow();
        let beacons = radio.tx.iter().filter(|f| f.data[0] == 0x80).count();
        println!(
            "{s:3}s leds {:?} ears {:?}/{:?} audio {} tracks, beacons sent {beacons}, channel {}",
            b.leds,
            (b.ears[0].slot, b.ears[0].direction),
            (b.ears[1].slot, b.ears[1].direction),
            b.codec.all_tracks().len(),
            radio.channel
        );
    }
    let console = m.console();
    for line in console.lines().filter(|l| !l.starts_with("0000")) {
        println!("| {line}");
    }
}
