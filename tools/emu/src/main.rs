use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;

use nabemu::air::{AccessPoint, Security};
use nabemu::elf::Elf;
use nabemu::{Event, Machine};

const USAGE: &str = "\
usage: nabemu [options] <firmware.elf|firmware.bin|firmware.sim>

  --ms <n>         run for n milliseconds of board time (default 2000)
  --symbols <elf>  ELF to take function names from (when booting a .bin)
  --ap <ssid>      put an open access point with that name on channel 6
  --calls          print every function the firmware enters, once
  --profile        print where the time went, by function
";

struct Args {
    image: String,
    symbols: Option<String>,
    ms: u64,
    calls: bool,
    profile: bool,
    ap: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        image: String::new(),
        symbols: None,
        ms: 2000,
        calls: false,
        profile: false,
        ap: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--ms" => {
                a.ms = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("--ms wants a number")?
            }
            "--symbols" => a.symbols = Some(it.next().ok_or("--symbols wants a path")?),
            "--ap" => a.ap = Some(it.next().ok_or("--ap wants a network name")?),
            "--calls" => a.calls = true,
            "--profile" => a.profile = true,
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            s => a.image = s.to_string(),
        }
    }
    if a.image.is_empty() {
        return Err("no firmware image given".into());
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprint!("nabemu: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let data = match std::fs::read(&args.image) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("nabemu: {}: {e}", args.image);
            return ExitCode::from(2);
        }
    };

    let (mut m, mut elf) = Machine::from_file(&data);
    if let Some(path) = &args.symbols {
        match std::fs::read(path).ok().and_then(|d| Elf::parse(&d)) {
            Some(e) => elf = Some(e),
            None => {
                eprintln!("nabemu: {path}: not an ELF file");
                return ExitCode::from(2);
            }
        }
    }

    if let Some(ssid) = &args.ap {
        let bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0xA1];
        m.air.push(AccessPoint::new(ssid, bssid, 6, Security::Open));
    }
    let target = args.ms * nabemu::soc::CLOCK_HZ / 1000;
    let mut seen = std::collections::BTreeSet::new();
    let mut profile: BTreeMap<u32, u64> = BTreeMap::new();
    let mut uart_seen = 0;
    let mut events_seen = 0;
    let stdout = std::io::stdout();

    while m.soc.cycles < target {
        if args.calls || args.profile {
            let pc = m.cpu.pc() & !1;
            if let Some(e) = &elf {
                if args.calls && e.symbols.contains_key(&pc) && seen.insert(pc) {
                    println!("[{:>8} ms] -> {}", m.soc.millis(), e.symbols[&pc]);
                }
                if args.profile
                    && let Some((base, _)) = e.symbols.range(..=pc).next_back()
                {
                    *profile.entry(*base).or_default() += 1;
                }
            }
        }
        m.step();
        if m.soc.uart_tx.len() > uart_seen {
            let mut out = stdout.lock();
            let _ = out.write_all(&m.soc.uart_tx[uart_seen..]);
            let _ = out.flush();
            uart_seen = m.soc.uart_tx.len();
        }
        while events_seen < m.events.len() {
            match &m.events[events_seen] {
                Event::Reset(cause) => {
                    println!("[{:>8} ms] reset: {cause:?}", m.soc.millis())
                }
                Event::Undefined { addr, opcode } => println!(
                    "[{:>8} ms] undefined instruction {opcode:08x} at {addr:08x}",
                    m.soc.millis()
                ),
            }
            events_seen += 1;
        }
    }

    let pc = m.cpu.pc();
    let place = elf
        .as_ref()
        .and_then(|e| e.locate(pc & !1))
        .map(|(n, o)| format!(" ({n}+{o:#x})"))
        .unwrap_or_default();
    println!(
        "\nstopped at {} ms, pc={pc:08x}{place}, cpsr={:08x}, {} reset(s)",
        m.soc.millis(),
        m.cpu.cpsr,
        m.resets
    );
    {
        let radio = m.radio.borrow();
        println!(
            "radio: channel {}, receiver {}, {} frame(s) sent; flash: {} erase(s), {} word(s) programmed",
            radio.channel,
            if radio.rx_enabled { "on" } else { "off" },
            radio.tx.len(),
            m.soc.flash_erases,
            m.soc.flash_programs
        );
    }
    println!(
        "external bus: {:.1} ms spent waiting on the SRAM and the USB controller",
        m.soc.ext_wait_total as f64 * 1000.0 / nabemu::soc::CLOCK_HZ as f64
    );
    if !m.soc.bus_faults.is_empty() {
        let list: Vec<String> = m
            .soc
            .bus_faults
            .iter()
            .take(16)
            .map(|a| format!("{a:08x}"))
            .collect();
        println!("accesses outside the memory map: {}", list.join(" "));
    }
    if !m.soc.unmodelled.is_empty() {
        let list: Vec<String> = m
            .soc
            .unmodelled
            .iter()
            .take(32)
            .map(|a| format!("{a:08x}"))
            .collect();
        println!(
            "registers read before any write, no model: {}",
            list.join(" ")
        );
    }
    if args.profile
        && let Some(e) = &elf
    {
        let mut rows: Vec<_> = profile.into_iter().collect();
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        let total: u64 = rows.iter().map(|r| r.1).sum();
        println!("\nwhere the instructions went:");
        for (addr, n) in rows.into_iter().take(15) {
            println!(
                "  {:5.1}%  {}",
                n as f64 * 100.0 / total as f64,
                e.symbols[&addr]
            );
        }
    }
    ExitCode::SUCCESS
}
