//! Run a firmware and print each line of its serial output with the
//! board time it was completed at, and the time since the line before.
//! usage: trace <firmware> [seconds]
mod common;

fn main() {
    let mut args = common::Args::new();
    let mut m = args.machine();
    let seconds = args.number(60);
    let (mut seen, mut last) = (0, 0.0);
    let mut line = Vec::new();
    while m.soc.millis() < seconds * 1000 {
        m.step();
        while seen < m.soc.uart_tx.len() {
            let byte = m.soc.uart_tx[seen];
            seen += 1;
            if byte != b'\n' {
                line.push(byte);
                continue;
            }
            let now = m.soc.cycles as f64 / 32_000.0;
            println!(
                "{now:10.1} ms  (+{:8.1})  {}",
                now - last,
                String::from_utf8_lossy(&line)
            );
            last = now;
            if line == b"end" {
                println!(
                    "events: {:?}, stray accesses: {:x?}",
                    m.events, m.soc.bus_faults
                );
                return;
            }
            line.clear();
        }
    }
    println!("still running after {seconds} s, pc={:08x}", m.cpu.pc());
}
