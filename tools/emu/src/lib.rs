//! Emulator for the Nabaztag:tag main board.

// Register lists are walked by number; indexing reads better there.
#![allow(clippy::needless_range_loop)]

pub mod air;
pub mod board;
pub mod config;
pub mod cpu;
pub mod crypto;
pub mod elf;
pub mod lan;
pub mod metal;
pub mod ohci;
pub mod p256;
pub mod regmap;
pub mod rfid;
pub mod rt2573;
pub mod sae;
pub mod soc;
pub mod supplicant;
pub mod testing;
pub mod visitor;
pub mod vs1003;
#[cfg(target_arch = "wasm32")]
pub mod web;

use cpu::{Cpu, Trap};
use rt2573::{Rt2573, SharedRadio};
use soc::{ResetCause, Soc};

/// MAC address in the emulated stick's EEPROM (a Violet prefix).
pub const DEFAULT_MAC: [u8; 6] = [0x00, 0x19, 0xDB, 0x00, 0x00, 0x01];

/// One thing worth telling the outside about, in the order it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Reset(ResetCause),
    Undefined { addr: u32, opcode: u32 },
}

pub struct Machine {
    pub cpu: Cpu,
    pub soc: Soc,
    /// The air side of the Wi-Fi stick.
    pub radio: SharedRadio,
    /// Access points within range.
    pub air: Vec<air::AccessPoint>,
    /// Someone's phone or laptop, for when the rabbit is the access point.
    pub visitor: Option<visitor::Visitor>,
    /// The wired network behind the access points, if there is one.
    pub lan: Option<lan::Lan>,
    next_air: u64,
    pub events: Vec<Event>,
    pub resets: u32,
    /// Instructions executed since the machine was made.
    pub instructions: u64,
    /// The lowest stack pointer seen in each processor mode (indexed by
    /// the mode's low five bits), since power-on, inside the internal RAM:
    /// how deep the stacks went.
    pub stack_low: [u32; 32],
    /// Where the program was when each of those lows was reached.
    pub stack_low_pc: [u32; 32],
    /// The highest stack pointer seen in each processor mode, inside the
    /// internal RAM: where each stack starts, whatever the firmware's
    /// layout; `stack_high - stack_low` is how deep it went.
    pub stack_high: [u32; 32],
    /// The program stack's words at its deepest, from the top of the
    /// stack pointer up: the return addresses in it say how it got there.
    pub stack_low_words: Vec<u32>,
    /// The longest stretch, in board cycles, the program spent outside
    /// an interrupt with interrupts held back.
    pub masked_longest: u64,
    masked_since: Option<u64>,
    /// Skip the turns of a loop that changes nothing, to the next thing
    /// that happens (on unless `NABEMU_NO_SKIP` is set): the program
    /// sees the same, much sooner.
    pub skip_idle: bool,
    idle: Option<Idle>,
    /// Board cycles skipped so.
    pub skipped: u64,
}

/// The state at the head of a loop, to tell an idle turn.
#[derive(Clone, Copy, PartialEq)]
struct Idle {
    pc: u32,
    r: [u32; 16],
    cpsr: u32,
    touched: u64,
    feeds: u64,
    cycles: u64,
}

impl Machine {
    /// A board with the given flash content and its Wi-Fi stick.
    pub fn new(flash: &[u8]) -> Self {
        let mut soc = Soc::new();
        soc.load_flash(flash);
        let (stick, radio) = Rt2573::new(DEFAULT_MAC);
        soc.ohci.device = Some(Box::new(stick));
        Machine {
            cpu: Cpu::new(),
            soc,
            radio,
            air: Vec::new(),
            lan: None,
            visitor: None,
            next_air: 0,
            events: Vec::new(),
            resets: 0,
            instructions: 0,
            stack_low: [u32::MAX; 32],
            stack_low_pc: [0; 32],
            stack_high: [0; 32],
            stack_low_words: Vec::new(),
            masked_longest: 0,
            masked_since: None,
            skip_idle: std::env::var_os("NABEMU_NO_SKIP").is_none(),
            idle: None,
            skipped: 0,
        }
    }

    /// A board flashed with a firmware file: an ELF, a Violet `.sim` or
    /// a raw image. The ELF, when it is one, comes back for its symbols.
    pub fn from_file(data: &[u8]) -> (Self, Option<elf::Elf>) {
        let mut flash = vec![0xFF; soc::FLASH_SIZE];
        let parsed = elf::Elf::parse(data);
        match &parsed {
            Some(e) => {
                for (addr, bytes) in &e.segments {
                    let off = addr.wrapping_sub(soc::FLASH_BASE) as usize;
                    if let Some(slot) = flash.get_mut(off..off + bytes.len()) {
                        slot.copy_from_slice(bytes);
                    }
                }
            }
            None => {
                let image = elf::decode_sim(data).unwrap_or_else(|| data.to_vec());
                let n = image.len().min(flash.len());
                flash[..n].copy_from_slice(&image[..n]);
            }
        }
        (Machine::new(&flash), parsed)
    }

    /// Give the rabbit everything it needs to boot `bytecode`: settings
    /// for an open network called "Terrier", that network, and a server
    /// behind it that answers every request with the bytecode.
    pub fn serve(&mut self, bytecode: &[u8]) {
        config::Config::new("Terrier", config::Wifi::Open).install(&mut self.soc.flash);
        self.air.push(air::AccessPoint::new(
            "Terrier",
            [2, 0, 0, 0, 0, 0xA1],
            6,
            air::Security::Open,
        ));
        let mut lan = lan::Lan::new();
        let body = metal::boot_response(bytecode);
        lan.handler = Box::new(move |_| lan::Response::ok(body.clone()));
        self.lan = Some(lan);
    }

    /// What the firmware has printed on its serial port so far.
    pub fn console(&self) -> String {
        String::from_utf8_lossy(&self.soc.uart_tx).into_owned()
    }

    #[inline]
    pub fn step(&mut self) {
        self.cpu.irq_line = self.soc.irq_asserted();
        let before = self.cpu.pc();
        let cycles = self.cpu.step(&mut self.soc);
        self.instructions += 1;
        // The skip does not know the late line: none with it.
        if self.skip_idle && !self.soc.irq_lag && self.cpu.pc() < before {
            self.at_loop_head();
        }
        // Before the firmware sets a stack, the register holds anything.
        let sp = self.cpu.r[13];
        if (soc::IRAM_BASE..soc::IRAM_BASE + soc::IRAM_SIZE as u32).contains(&sp) {
            let mode = (self.cpu.mode() & 0x1F) as usize;
            self.stack_high[mode] = self.stack_high[mode].max(sp);
            if sp < self.stack_low[mode] {
                self.stack_low[mode] = sp;
                self.stack_low_pc[mode] = self.cpu.pc();
                if mode == 0x1F {
                    let at = (sp - soc::IRAM_BASE) as usize;
                    self.stack_low_words = self.soc.iram[at..]
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|w| u32::from_le_bytes(*w))
                        .collect();
                }
            }
        }
        let mode = self.cpu.mode() & 0x1F;
        if self.cpu.cpsr & 0x80 != 0 && matches!(mode, 0x10 | 0x13 | 0x1F) {
            let since = *self.masked_since.get_or_insert(self.soc.cycles);
            self.masked_longest = self.masked_longest.max(self.soc.cycles - since);
        } else {
            self.masked_since = None;
        }
        if let Trap::Undefined { addr, opcode } = self.cpu.last_trap {
            self.events.push(Event::Undefined { addr, opcode });
        }
        self.soc.tick(cycles);
        if self.soc.cycles >= self.next_air {
            self.next_air += soc::CLOCK_HZ / 1000;
            let now = self.soc.millis();
            let mut radio = self.radio.borrow_mut();
            for ap in &mut self.air {
                ap.poll(&mut radio, now);
            }
            if let Some(visitor) = &mut self.visitor {
                visitor.poll(&mut radio, now);
            }
            if let Some(lan) = &mut self.lan {
                for ap in &mut self.air {
                    while let Some(frame) = ap.uplink.pop_front() {
                        lan.input(frame);
                    }
                }
                lan.poll(now);
                while let Some(frame) = lan.output() {
                    for ap in &mut self.air {
                        ap.send(&mut radio, &frame);
                    }
                }
            }
        }
        if let Some(cause) = self.soc.pending_reset {
            self.events.push(Event::Reset(cause));
            self.resets += 1;
            if cause == ResetCause::PowerLoss {
                self.soc.power_cycle();
            } else {
                self.soc.reset();
            }
            self.cpu.reset();
        }
    }

    /// Just jumped back: the head of a loop. Two turns that end here
    /// with the same registers and nothing touched in between (no store
    /// that changed memory, no peripheral access but watchdog feeds) are
    /// the same turn: every following one is too, until something
    /// happens on its own. Skip those turns, whole, to just before it.
    fn at_loop_head(&mut self) {
        let now = Idle {
            pc: self.cpu.pc(),
            r: self.cpu.r,
            cpsr: self.cpu.cpsr,
            touched: self.soc.touched,
            feeds: self.soc.feeds,
            cycles: self.soc.cycles,
        };
        let same = |a: &Idle, b: &Idle| {
            a.pc == b.pc && a.r == b.r && a.cpsr == b.cpsr && a.touched == b.touched
        };
        if let Some(last) = self.idle
            && same(&last, &now)
            && self.soc.at_board_pace()
            && !(self.cpu.irq_line && self.cpu.cpsr & 0x80 == 0)
        {
            let turn = now.cycles - last.cycles;
            let next = self.soc.next_event().min(self.next_air);
            let turns = next.saturating_sub(now.cycles + 1) / turn.max(1);
            if turn > 0 && turns > 0 {
                let fed = now.feeds != last.feeds;
                self.soc.skip(turns * turn, fed);
                self.skipped += turns * turn;
            }
        }
        self.idle = Some(Idle {
            cycles: self.soc.cycles,
            feeds: self.soc.feeds,
            ..now
        });
    }

    /// Unplug the rabbit and plug it back in.
    pub fn power_cycle(&mut self) {
        self.soc.power_cycle();
        self.cpu.reset();
    }

    /// Run until the board clock reaches `ms` milliseconds.
    pub fn run_until_ms(&mut self, ms: u64) {
        let target = ms * soc::CLOCK_HZ / 1000;
        while self.soc.cycles < target {
            self.step();
        }
    }
}
