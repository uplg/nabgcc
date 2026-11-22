//! The ML67Q4051 and what hangs off its bus on the Nabaztag:tag board.
//!
//! Memory map (from `sys/ml67q4051.ld` and the register headers):
//!
//! | range                    | what                                   |
//! |--------------------------|----------------------------------------|
//! | `0000_0000` + 128K       | internal flash, as seen at reset       |
//! | `0800_0000` + 128K       | internal flash                         |
//! | `1000_0000` + 16K        | internal RAM                           |
//! | `7800_0000`, `7Bxx_xxxx` | interrupt controller, bus, DMA         |
//! | `B6..B8xx_xxxx`          | APB peripherals                        |
//! | `D000_0000` + 1M         | external SRAM                          |
//! | `F000_0000` + 8K         | ML60842 USB host controller and its RAM |

use std::collections::{BTreeMap, BTreeSet};

use crate::board::Board;
use crate::cpu::Bus;
use crate::ohci::{self, Ohci};

pub const FLASH_BASE: u32 = 0x0800_0000;
pub const FLASH_SIZE: usize = 128 * 1024;
pub const IRAM_BASE: u32 = 0x1000_0000;
pub const IRAM_SIZE: usize = 16 * 1024;
pub const XRAM_BASE: u32 = 0xD000_0000;
pub const XRAM_SIZE: usize = 1024 * 1024;
pub const USB_BASE: u32 = 0xF000_0000;

/// CPU clock once the firmware has set up its PLL.
pub const CLOCK_HZ: u64 = 32_000_000;
/// One USB frame: a millisecond.
const FRAME_CYCLES: u64 = CLOCK_HZ / 1000;

pub const INT_SYSTEM_TIMER: u32 = 0;
pub const INT_UART0: u32 = 9;
pub const INT_EXINT2_USB: u32 = 36;

// Register addresses the model gives a behaviour to. Anything else in
// the peripheral ranges is plain storage: reads return the last write.
const IRQ: u32 = 0x7800_0000;
const IRN: u32 = 0x7800_0014;
const CIL: u32 = 0x7800_0018;
const ILC0: u32 = 0x7800_0020;
const ILC1: u32 = 0x7800_0024;
const CILCL: u32 = 0x7800_0028;
const EXIRQA: u32 = 0x7BF0_0010;
const EXILCA: u32 = 0x7BF0_0018;
const EXIRQB: u32 = 0x7BF0_0020;
const EXILCB: u32 = 0x7BF0_0028;
const EXIRQC: u32 = 0x7BF0_0030;
const EXILCC: u32 = 0x7BF0_0038;
const FLACON: u32 = 0xB700_0100;
const TMEN: u32 = 0xB800_1004;
const TMRLR: u32 = 0xB800_1008;
const TMOVF: u32 = 0xB800_1010;
const WDTCON: u32 = 0xB7E0_0000;
const TBGCON: u32 = 0xB7E0_0004;
const WDTCNT: u32 = 0xB7E0_0010;
const UART0: u32 = 0xB7B0_0000;
const SPI0: u32 = 0xB7B0_2000;
const SPI1: u32 = 0xB7B0_3000;
const GPIO: u32 = 0xB7A0_0000;
const ADCON1: u32 = 0xB600_0004;
const ADR2: u32 = 0xB600_001C;
const FTM0GR: u32 = 0xB7F0_0010;
const FTM1GR: u32 = 0xB7F0_0030;
const FTM2GR: u32 = 0xB7F0_0050;
const PO2: u32 = 0xB7A0_2000;
const PO4: u32 = 0xB7A0_4000;
const PO11: u32 = 0xB7A0_B000;
const I2CCTL: u32 = 0xB780_0C04;
const I2CSR: u32 = 0xB780_0C08;
const I2CDR: u32 = 0xB780_0C0C;
/// Bus address of the RFID reader, the only I2C device on the board.
const CRX14_ADDRESS: u8 = 0xA0;

/// Time a sector erase keeps the flash busy. With 1024 word programs
/// this adds up to the 63 ms per sector the firmware's comments quote.
const ERASE_CYCLES: u64 = CLOCK_HZ * 22 / 1000;
/// Time programming one 32-bit word takes.
const PROGRAM_CYCLES: u64 = CLOCK_HZ * 40 / 1_000_000;
const SECTOR: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FlashState {
    #[default]
    Idle,
    Unlock1,
    Unlock2,
    EraseSetup,
    EraseUnlock1,
    EraseUnlock2,
    Program(u8),
}

/// Command sequencer of the internal flash.
#[derive(Default)]
struct FlashCtl {
    state: FlashState,
    busy_until: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetCause {
    Watchdog,
    /// The supply dropped (see [`Soc::cut_power_after_flash_ops`]).
    PowerLoss,
}

/// The I2C master, as far as the firmware's driver exercises it.
#[derive(Default)]
struct I2c {
    data: u8,
    active: bool,
    reading: bool,
    nak: bool,
}

#[derive(Default)]
struct Timer {
    enabled: bool,
    reload: u32,
    overflow: bool,
    next: u64,
}

impl Timer {
    fn period(&self) -> u64 {
        (0x1_0000 - (self.reload & 0xFFFF) as u64) * 16
    }
}

#[derive(Default)]
struct Watchdog {
    running: bool,
    tbgcon: u8,
    tbg_unlocked: bool,
    cnt_unlocked: bool,
    armed_c3: bool,
    deadline: u64,
}

impl Watchdog {
    fn tick_cycles(&self) -> u64 {
        32u64 << (self.tbgcon & 7)
    }
}

pub struct Soc {
    pub flash: Vec<u8>,
    pub iram: Vec<u8>,
    pub xram: Vec<u8>,
    /// RAM inside the USB controller, where its descriptors live.
    pub usb_ram: Vec<u8>,
    pub ohci: Ohci,
    next_frame: u64,
    pub cycles: u64,
    regs: BTreeMap<u32, u32>,
    /// Interrupt request lines, one bit per source (0..64).
    pub irq_lines: u64,
    cil: u32,
    timer: Timer,
    i2c: I2c,
    wdt: Watchdog,
    flash_ctl: FlashCtl,
    /// Sector erases and word programs carried out since power-on.
    pub flash_erases: u64,
    pub flash_programs: u64,
    /// Reads of the flash while it was erasing or programming. The real
    /// part answers garbage then; here they read as all ones.
    pub flash_reads_while_busy: u64,
    /// Lose power once this many flash operations (erases and word
    /// programs together) have completed since power-on.
    pub cut_power_after_flash_ops: Option<u64>,
    /// Board time of the first and the latest flash operation.
    pub flash_first_op: Option<u64>,
    pub flash_last_op: u64,
    /// Bytes the firmware sent on UART0.
    pub uart_tx: Vec<u8>,
    /// Leds, audio codec, ears, button, volume wheel.
    pub board: Board,
    /// Levels driven from outside on GPIO ports 0..15.
    pub gpio_in: [u8; 16],
    pub pending_reset: Option<ResetCause>,
    /// Accesses outside every known range, by address.
    pub bus_faults: BTreeSet<u32>,
    /// Peripheral registers touched without a model, by address.
    pub unmodelled: BTreeSet<u32>,
}

impl Default for Soc {
    fn default() -> Self {
        Self::new()
    }
}

impl Soc {
    pub fn new() -> Self {
        Soc {
            flash: vec![0xFF; FLASH_SIZE],
            iram: vec![0; IRAM_SIZE],
            xram: vec![0; XRAM_SIZE],
            usb_ram: vec![0; ohci::RAM_SIZE],
            ohci: Ohci::new(),
            next_frame: FRAME_CYCLES,
            cycles: 0,
            regs: BTreeMap::new(),
            irq_lines: 0,
            cil: 0,
            timer: Timer::default(),
            i2c: I2c::default(),
            wdt: Watchdog::default(),
            flash_ctl: FlashCtl::default(),
            flash_erases: 0,
            flash_programs: 0,
            flash_reads_while_busy: 0,
            cut_power_after_flash_ops: None,
            flash_first_op: None,
            flash_last_op: 0,
            uart_tx: Vec::new(),
            board: Board::new(),
            gpio_in: [0xFF; 16],
            pending_reset: None,
            bus_faults: BTreeSet::new(),
            unmodelled: BTreeSet::new(),
        }
    }

    /// Hardware reset: registers go back to their defaults, memories keep
    /// their content (the SRAM is not cleared by a watchdog reset).
    pub fn reset(&mut self) {
        self.regs.clear();
        self.irq_lines = 0;
        self.cil = 0;
        self.timer = Timer::default();
        self.i2c = I2c::default();
        self.wdt = Watchdog::default();
        self.pending_reset = None;
        self.flash_ctl = FlashCtl::default();
        self.ohci.reset();
        self.board.reset();
    }

    pub fn load_flash(&mut self, image: &[u8]) {
        let n = image.len().min(FLASH_SIZE);
        self.flash[..n].copy_from_slice(&image[..n]);
    }

    pub fn millis(&self) -> u64 {
        self.cycles * 1000 / CLOCK_HZ
    }

    /// Advance time by the cycles one instruction took and update what
    /// depends on it.
    #[inline]
    pub fn tick(&mut self, cycles: u32) {
        self.cycles += cycles as u64;
        if self.timer.enabled && self.cycles >= self.timer.next {
            self.timer.overflow = true;
            self.timer.next += self.timer.period();
            self.set_line(INT_SYSTEM_TIMER, true);
        }
        if self.cycles >= self.next_frame {
            self.next_frame += FRAME_CYCLES;
            let duty =
                [FTM2GR, FTM2GR + 0x20, FTM2GR + 0x40, FTM2GR + 0x60].map(|r| self.reg(r) as u16);
            self.board.tick_ms(duty, self.millis());
            self.ohci.frame(&mut self.usb_ram);
            let irq = self.ohci.irq();
            self.set_line(INT_EXINT2_USB, irq);
        }
        if self.wdt.running && self.cycles >= self.wdt.deadline {
            self.wdt.running = false;
            self.pending_reset = Some(ResetCause::Watchdog);
        }
    }

    pub fn set_line(&mut self, source: u32, level: bool) {
        if level {
            self.irq_lines |= 1 << source;
        } else {
            self.irq_lines &= !(1 << source);
        }
    }

    fn reg(&self, addr: u32) -> u32 {
        self.regs.get(&addr).copied().unwrap_or(0)
    }

    fn irq_level(&self, source: u32) -> u32 {
        let (reg, nibble) = match source {
            0 => (ILC0, 0),
            1..=3 => (ILC0, 1),
            4..=5 => (ILC0, 4),
            6..=7 => (ILC0, 6),
            8..=15 => (ILC1, source - 8),
            16..=31 => (EXILCA, (source - 16) / 2),
            32..=47 => (EXILCB, (source - 32) / 2),
            _ => (EXILCC, (source - 48) / 2),
        };
        (self.reg(reg) >> (nibble * 4)) & 7
    }

    fn current_level(&self) -> u32 {
        if self.cil == 0 {
            0
        } else {
            31 - self.cil.leading_zeros()
        }
    }

    /// The pending source the controller would hand out now, if any.
    fn best_irq(&self) -> Option<(u32, u32)> {
        let floor = self.current_level();
        let mut best: Option<(u32, u32)> = None;
        let mut lines = self.irq_lines;
        while lines != 0 {
            let n = lines.trailing_zeros();
            lines &= lines - 1;
            let lvl = self.irq_level(n);
            if lvl > floor && best.is_none_or(|(_, b)| lvl > b) {
                best = Some((n, lvl));
            }
        }
        best
    }

    /// State of the nIRQ input of the core.
    #[inline]
    pub fn irq_asserted(&self) -> bool {
        self.irq_lines != 0 && self.best_irq().is_some()
    }

    // ---- memory-mapped registers --------------------------------------

    fn mmio_read(&mut self, addr: u32) -> u32 {
        match addr {
            IRQ => (self.irq_lines & 0xFFFF) as u32,
            IRN => match self.best_irq() {
                Some((n, lvl)) => {
                    self.cil |= 1 << lvl;
                    n
                }
                None => 64,
            },
            CIL => self.cil,
            EXIRQA => ((self.irq_lines >> 16) & 0xFFFF) as u32,
            EXIRQB => ((self.irq_lines >> 32) & 0xFFFF) as u32,
            EXIRQC => ((self.irq_lines >> 48) & 0xFFFF) as u32,
            // Flash sequencer: bit 1 is "command completed", no error bits.
            FLACON => {
                let ready = (self.cycles >= self.flash_ctl.busy_until) as u32;
                (self.reg(addr) & !0x0E) | ready << 1
            }
            TMEN => self.timer.enabled as u32,
            TMRLR => self.timer.reload,
            TMOVF => self.timer.overflow as u32,
            WDTCON | TBGCON | WDTCNT => self.reg(addr),
            a if a & !0xFFF == UART0 => match a & 0xFFF {
                // LSR: transmitter always empty, nothing received.
                0x14 => 0x60,
                // IIR: no interrupt pending.
                0x08 => 0x01,
                _ => self.reg(a),
            },
            a if a & !0xFFF == SPI0 || a & !0xFFF == SPI1 => match a & 0xFFF {
                // SPSR: transfer complete, both FIFOs empty.
                0x08 => 0x0014_0020,
                0x10 => self.board.spi_read((a & !0xFFF == SPI1) as usize) as u32,
                _ => self.reg(a),
            },
            a if a & 0xFFFF_0000 == GPIO && a & 0xFFF == 0x04 => {
                let port = ((a >> 12) & 15) as usize;
                let out = self.reg(a - 4) & 0xFF;
                let dir = self.reg(a + 4) & 0xFF;
                let mut pins = self.gpio_in[port];
                if port == 1 {
                    // The codec's data request line.
                    pins = (pins & !0x04)
                        | if self.board.codec.wants_data() {
                            0x04
                        } else {
                            0
                        };
                }
                if port == 3 {
                    // The head button pulls its pin low.
                    pins = (pins & !0x02) | if self.board.button { 0 } else { 0x02 };
                }
                (out & dir) | (pins as u32 & !dir)
            }
            // ADC: a conversion is never in progress.
            ADCON1 => self.reg(addr) & !0x10,
            // Channel 2 is the volume wheel; the firmware inverts it.
            ADR2 => (255 - self.board.volume as u32) << 2,
            FTM0GR => self.board.ear_count(0) as u32,
            FTM1GR => self.board.ear_count(1) as u32,
            // I2C: transfer complete, bus free; bit 0 is "no acknowledge".
            I2CSR => 0x80 | self.i2c.nak as u32,
            I2CDR => {
                if self.i2c.active && self.i2c.reading {
                    self.board.rfid.read() as u32
                } else {
                    self.i2c.data as u32
                }
            }
            a if a >= USB_BASE => self.ohci.read(a - USB_BASE),
            _ => {
                if !self.regs.contains_key(&addr) {
                    self.unmodelled.insert(addr);
                }
                self.reg(addr)
            }
        }
    }

    /// `mask` tells which bits of the word the access really wrote.
    fn mmio_write(&mut self, addr: u32, val: u32, mask: u32) {
        let merged = (self.reg(addr) & !mask) | (val & mask);
        match addr {
            CIL => self.cil &= !(val & mask),
            CILCL => {
                if self.cil != 0 {
                    self.cil &= !(1 << self.current_level());
                }
            }
            // Edge latches are not modelled: the lines are levels.
            EXIRQA | EXIRQB | EXIRQC => {}
            TMEN => {
                let on = merged & 1 != 0;
                if on && !self.timer.enabled {
                    self.timer.next = self.cycles + self.timer.period();
                }
                self.timer.enabled = on;
            }
            TMRLR => self.timer.reload = merged & 0xFFFF,
            TMOVF => {
                if val & mask & 1 != 0 {
                    self.timer.overflow = false;
                    self.set_line(INT_SYSTEM_TIMER, false);
                }
            }
            WDTCON => {
                let v = (val & mask & 0xFF) as u8;
                if v == 0xC3 {
                    self.wdt.armed_c3 = true;
                } else if v == 0x3C {
                    // First 0x3C starts the counter, 0xC3 then 0x3C clears it.
                    if !self.wdt.running || self.wdt.armed_c3 {
                        self.wdt.running = true;
                        self.wdt.deadline = self.cycles + 0x1_0000 * self.wdt.tick_cycles();
                    }
                    self.wdt.armed_c3 = false;
                }
            }
            TBGCON => {
                let v = (val & mask & 0xFF) as u8;
                if self.wdt.tbg_unlocked {
                    self.wdt.tbgcon = v;
                    self.wdt.tbg_unlocked = false;
                    self.regs.insert(addr, v as u32);
                } else if v == 0x5A {
                    self.wdt.tbg_unlocked = true;
                }
            }
            WDTCNT => {
                let v = val & mask & 0xFFFF;
                if self.wdt.cnt_unlocked {
                    self.wdt.cnt_unlocked = false;
                    self.wdt.deadline =
                        self.cycles + (0x1_0000 - v as u64) * self.wdt.tick_cycles();
                } else if v == 0x5A5A {
                    self.wdt.cnt_unlocked = true;
                }
            }
            a if a & !0xFFF == UART0 => {
                let dlab = self.reg(UART0 + 0x0C) & 0x80 != 0;
                if a & 0xFFF == 0 && !dlab && mask & 0xFF != 0 {
                    self.uart_tx.push(val as u8);
                } else {
                    self.regs.insert(a, merged);
                }
            }
            a if (a & !0xFFF == SPI0 || a & !0xFFF == SPI1) && a & 0xFFF == 0x0C => {
                let bus = (a & !0xFFF == SPI1) as usize;
                // The codec's two chip selects are active low.
                let sci = self.reg(PO2) & 0x08 == 0;
                let sdi = self.reg(PO11) & 0x01 == 0;
                self.board.spi_write(bus, val as u8, sci, sdi);
            }
            a if a >= USB_BASE => {
                self.ohci.write(a - USB_BASE, val, mask);
                let irq = self.ohci.irq();
                self.set_line(INT_EXINT2_USB, irq);
            }
            I2CDR => {
                self.i2c.data = val as u8;
                if self.i2c.active && !self.i2c.reading && !self.i2c.nak {
                    self.board.rfid.write(val as u8);
                }
            }
            I2CCTL => {
                // Master bit: set sends a start and the address waiting
                // in the data register, cleared sends a stop.
                let master = merged & 0x20 != 0;
                if master && !self.i2c.active {
                    self.i2c.active = true;
                    self.i2c.reading = self.i2c.data & 1 != 0;
                    self.i2c.nak = self.i2c.data & 0xFE != CRX14_ADDRESS;
                    if !self.i2c.nak {
                        self.board.rfid.start();
                    }
                } else if !master && self.i2c.active {
                    if !self.i2c.nak {
                        self.board.rfid.stop();
                    }
                    self.i2c = I2c::default();
                }
                self.regs.insert(addr, merged);
            }
            PO4 => {
                // Rising edge on the led driver's latch.
                if merged & !self.reg(addr) & 0x20 != 0 {
                    self.board.led_latch();
                }
                self.board.amplifier = merged & 0x40 != 0;
                self.regs.insert(addr, merged);
            }
            PO2 => {
                if merged & !self.reg(addr) & 0x08 != 0 {
                    self.board.sci_released();
                }
                self.regs.insert(addr, merged);
            }
            _ => {
                self.regs.insert(addr, merged);
            }
        }
    }

    /// A byte store into the flash address space: a step of a command
    /// sequence when programming is permitted, nothing otherwise.
    fn flash_store(&mut self, addr: u32, val: u8) {
        if self.reg(FLACON) & 1 == 0 {
            return;
        }
        let off = addr as usize & (FLASH_SIZE - 1);
        use FlashState::*;
        let before = self.flash_erases + self.flash_programs;
        self.flash_ctl.state = match (self.flash_ctl.state, off, val) {
            (Idle, 0x15554, 0xAA) => Unlock1,
            (Unlock1, 0x0AAA8, 0x55) => Unlock2,
            (Unlock2, 0x15554, 0x80) => EraseSetup,
            (Unlock2, 0x15554, 0xA0) => Program(4),
            (EraseSetup, 0x15554, 0xAA) => EraseUnlock1,
            (EraseUnlock1, 0x0AAA8, 0x55) => EraseUnlock2,
            (EraseUnlock2, _, 0x30) => {
                let start = off & !(SECTOR - 1);
                self.flash[start..start + SECTOR].fill(0xFF);
                self.flash_erases += 1;
                self.flash_ctl.busy_until = self.cycles + ERASE_CYCLES;
                Idle
            }
            (Program(left), _, _) => {
                // Programming can only clear bits.
                self.flash[off] &= val;
                if left == 1 {
                    self.flash_programs += 1;
                    self.flash_ctl.busy_until = self.cycles + PROGRAM_CYCLES;
                    Idle
                } else {
                    Program(left - 1)
                }
            }
            _ => Idle,
        };
        let done = self.flash_erases + self.flash_programs;
        if done != before {
            let now = self.millis();
            self.flash_first_op.get_or_insert(now);
            self.flash_last_op = now;
            if self.cut_power_after_flash_ops == Some(done) {
                self.pending_reset = Some(ResetCause::PowerLoss);
            }
        }
    }

    /// Everything volatile is lost: registers, both RAMs, the USB chip.
    pub fn power_cycle(&mut self) {
        self.reset();
        self.iram.fill(0);
        self.xram.fill(0);
        self.usb_ram.fill(0);
        self.ohci.power_cycle();
        self.cut_power_after_flash_ops = None;
    }

    /// While it erases or programs, the flash does not give its content
    /// back: code that keeps running from it, or reads it, is lost.
    #[inline]
    fn flash_is_away(&mut self, addr: u32) -> bool {
        if addr >> 28 != 0 || self.cycles >= self.flash_ctl.busy_until {
            return false;
        }
        self.flash_reads_while_busy += 1;
        true
    }

    fn is_mmio(addr: u32) -> bool {
        matches!(addr >> 24, 0x78 | 0x7B | 0xB6 | 0xB7 | 0xB8)
            || (USB_BASE..ohci::RAM_BASE).contains(&addr)
    }

    #[inline]
    fn mem(&mut self, addr: u32, len: u32) -> Option<&mut [u8]> {
        let (buf, off) = match addr >> 28 {
            0x0 if addr < 0x0800_0000 => (&mut self.flash, addr),
            0x0 => (&mut self.flash, addr - FLASH_BASE),
            0x1 => (&mut self.iram, addr - IRAM_BASE),
            0xD => (&mut self.xram, addr - XRAM_BASE),
            0xF if addr >= ohci::RAM_BASE => (&mut self.usb_ram, addr - ohci::RAM_BASE),
            _ => return None,
        };
        let off = off as usize;
        buf.get_mut(off..off + len as usize)
    }

    fn fault(&mut self, addr: u32) {
        self.bus_faults.insert(addr);
    }
}

impl Bus for Soc {
    #[inline]
    fn read8(&mut self, addr: u32) -> u8 {
        if self.flash_is_away(addr) {
            return !0;
        }
        if let Some(m) = self.mem(addr, 1) {
            return m[0];
        }
        if Self::is_mmio(addr) {
            return (self.mmio_read(addr & !3) >> ((addr & 3) * 8)) as u8;
        }
        self.fault(addr);
        0
    }

    #[inline]
    fn read16(&mut self, addr: u32) -> u16 {
        if self.flash_is_away(addr) {
            return !0;
        }
        if let Some(m) = self.mem(addr, 2) {
            return u16::from_le_bytes([m[0], m[1]]);
        }
        if Self::is_mmio(addr) {
            return (self.mmio_read(addr & !3) >> ((addr & 2) * 8)) as u16;
        }
        self.fault(addr);
        0
    }

    #[inline]
    fn read32(&mut self, addr: u32) -> u32 {
        if self.flash_is_away(addr) {
            return !0;
        }
        if let Some(m) = self.mem(addr, 4) {
            return u32::from_le_bytes([m[0], m[1], m[2], m[3]]);
        }
        if Self::is_mmio(addr) {
            return self.mmio_read(addr);
        }
        self.fault(addr);
        0
    }

    #[inline]
    fn write8(&mut self, addr: u32, val: u8) {
        if addr >> 28 == 0 {
            return self.flash_store(addr, val);
        }
        if let Some(m) = self.mem(addr, 1) {
            m[0] = val;
        } else if Self::is_mmio(addr) {
            let sh = (addr & 3) * 8;
            self.mmio_write(addr & !3, (val as u32) << sh, 0xFF << sh);
        } else {
            self.fault(addr);
        }
    }

    #[inline]
    fn write16(&mut self, addr: u32, val: u16) {
        if addr >> 28 == 0 {
            return;
        }
        if let Some(m) = self.mem(addr, 2) {
            m.copy_from_slice(&val.to_le_bytes());
        } else if Self::is_mmio(addr) {
            let sh = (addr & 2) * 8;
            self.mmio_write(addr & !3, (val as u32) << sh, 0xFFFF << sh);
        } else {
            self.fault(addr);
        }
    }

    #[inline]
    fn write32(&mut self, addr: u32, val: u32) {
        if addr >> 28 == 0 {
            return;
        }
        if let Some(m) = self.mem(addr, 4) {
            m.copy_from_slice(&val.to_le_bytes());
        } else if Self::is_mmio(addr) {
            self.mmio_write(addr, val, 0xFFFF_FFFF);
        } else {
            self.fault(addr);
        }
    }
}
