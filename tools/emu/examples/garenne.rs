//! Boot a firmware on an open network whose server hands out the given
//! bytecode file (already in its `amber...Mind` envelope), and show
//! what the rabbit says and asks for.
//! usage: garenne <firmware> <bc.jsp content> [ms]
use nabemu::Machine;
use nabemu::air::{AccessPoint, Security};
use nabemu::config::{Config, Wifi};
use nabemu::lan::{Lan, Response};

fn main() {
    let mut args = std::env::args().skip(1);
    let firmware = std::fs::read(args.next().expect("firmware path")).expect("readable firmware");
    let bytecode = std::fs::read(args.next().expect("bytecode path")).expect("readable bytecode");
    let ms = args.next().and_then(|s| s.parse().ok()).unwrap_or(60_000);
    let (mut m, _) = Machine::from_file(&firmware);
    Config::new("Terrier", Wifi::Open).install(&mut m.soc.flash);
    m.air.push(AccessPoint::new(
        "Terrier",
        [2, 0, 0, 0, 0, 0xA1],
        6,
        Security::Open,
    ));
    let mut lan = Lan::new();
    lan.handler = Box::new(move |r| {
        if r.target.contains("bc.jsp") {
            Response::ok(bytecode.clone())
        } else {
            Response::not_found()
        }
    });
    m.lan = Some(lan);
    m.run_until_ms(ms);
    let console = m.console();
    let after = console
        .split("BOOT DONE")
        .nth(1)
        .unwrap_or("(never booted the bytecode)");
    for line in after.lines().filter(|l| !l.starts_with("00")).take(60) {
        println!("| {line}");
    }
    let lan = m.lan.as_ref().unwrap();
    for d in lan
        .datagrams
        .iter()
        .filter(|d| d.to_port != 67 && d.to_port != 53)
        .take(40)
    {
        let text = String::from_utf8_lossy(&d.payload);
        println!("udp {:?}:{} | {}", d.to, d.to_port, text.trim_end());
    }
    for r in &lan.requests {
        println!("http: {} {}", r.method, r.target);
    }
    println!("dns: {:?}; events: {:?}", lan.dns_queries, m.events);
}
