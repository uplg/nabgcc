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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
pub const INT_WDT: u32 = 1;
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
const PLL1: u32 = 0xB700_0008;
const PLL2: u32 = 0xB700_000C;
const CLKCNT: u32 = 0xB700_0010;
/// The crystal on SYSCLK.
const SYSCLK_HZ: u64 = 8_000_000;
/// The chip's ring oscillator, which it starts on (BOOTCLK is low on
/// the rabbit). The manual bounds it between 4 and 16 MHz and calls 16
/// the specified maximum; nobody measured the rabbit's.
pub const RING_OSC_HZ: u64 = 16_000_000;
/// RTCCLK, the 32.768 kHz watch crystal input.
const RTCCLK_HZ: u64 = 32_768;
const TMEN: u32 = 0xB800_1004;
const TMRLR: u32 = 0xB800_1008;
const TMOVF: u32 = 0xB800_1010;
const WDTCON: u32 = 0xB7E0_0000;
const TBGCON: u32 = 0xB7E0_0004;
const WDTCNT: u32 = 0xB7E0_0010;
const INTST: u32 = 0xB7E0_0008;
const UART0: u32 = 0xB7B0_0000;
/// Where the divisor latches are kept, apart from THR/IER (internal).
const UART0_DIVISOR: u32 = 0xB7B0_0800;
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
const BWC: u32 = 0x7810_0000;
const RAMAC: u32 = 0x7810_0008;
const IO0AC: u32 = 0x7810_000C;
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
    /// An erase or program was started and has not yet raised FWEND.
    started: bool,
    /// FWEND: set when an operation ends, until the program writes 1.
    ended: bool,
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

/// A cycle on the external bus, by the kind of the one before it
/// matters for when the next may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtCycle {
    RamRead,
    RamWrite,
    IoRead,
    IoWrite,
}

/// The external memory controller as the processor sees it: SRAM bank
/// (the 1 MB at `D000_0000`) and I/O bank 0 (the USB host controller),
/// timed as chapter 7 of the ML67Q4050/4060 user's manual gives it.
/// Internal flash and RAM sit on the processor bus and have no wait
/// setting at all; they are taken to answer in one clock.
#[derive(Default)]
struct ExtBus {
    last: Option<ExtCycle>,
    /// Board time at which the last cycle released its chip select.
    released_at: u64,
}

/// (OE_N/WR_N pulse, read-off) for RAMTYPE, manual table 7.5.4.
fn ram_timing(ramac: u32) -> Option<(u64, u64)> {
    match ramac & 7 {
        0 => Some((1, 0)),
        1 => Some((2, 0)),
        2 => Some((3, 2)),
        3 => Some((4, 2)),
        7 => Some((8, 4)),
        _ => None,
    }
}

/// (address setup, OE_N/WR_N pulse, data-off) for IOTYPE, table 7.5.5.
fn io_timing(ioac: u32) -> Option<(u64, u64, u64)> {
    match ioac & 7 {
        0 => Some((1, 1, 1)),
        1 => Some((1, 4, 2)),
        3 => Some((2, 8, 4)),
        4 => Some((2, 12, 6)),
        5 => Some((2, 16, 7)),
        7 => Some((4, 24, 10)),
        _ => None,
    }
}

/// Clocks from one chip select going away to the next coming, for
/// cycles from the processor (manual 7.5.8). `off` is the read-off or
/// data-off setting of the earlier cycle.
fn ext_gap(before: ExtCycle, off: u64, after: ExtCycle) -> u64 {
    use ExtCycle::*;
    match (before, after) {
        (RamRead, RamRead) => 0,
        (RamRead, RamWrite) => off.max(1),
        (RamRead, _) => off.max(2),
        (RamWrite, RamRead) => 1,
        (RamWrite, RamWrite) => 0,
        (RamWrite, _) => 2,
        (IoRead, RamRead | RamWrite) => off.saturating_sub(1).max(1),
        (IoRead, IoRead) => 1,
        (IoRead, IoWrite) => off,
        (IoWrite, _) => 1,
    }
}

/// UART0's transmit side (manual chapter 17, a 16550): a 16-byte FIFO
/// in front of the shift register when FCR enables it, one holding
/// register otherwise, each character taking its start, data, parity
/// and stop bits at the divisor's baud rate.
#[derive(Default)]
struct UartTx {
    fifo: VecDeque<u8>,
    /// The shift register is busy until this board time.
    shifting_until: Option<u64>,
    /// THRE interrupt pending (IIR 02H), when ETHREI allows it.
    thre_pending: bool,
}

struct Timer {
    enabled: bool,
    reload: u32,
    overflow: bool,
    next: u64,
    /// Its clock, APB_CLK.
    apb_hz: u64,
}

impl Default for Timer {
    fn default() -> Self {
        Timer {
            enabled: false,
            reload: 0,
            overflow: false,
            next: 0,
            apb_hz: RING_OSC_HZ,
        }
    }
}

impl Timer {
    /// Board cycles from reload to overflow: APB_CLK/16 counts.
    fn period(&self) -> u64 {
        (0x1_0000 - (self.reload & 0xFFFF) as u64) * 16 * CLOCK_HZ / self.apb_hz
    }
}

/// The watchdog timer (manual chapter 11): a 16-bit counter clocked
/// at APB_CLK/32 to /4096 that resets the chip, or raises interrupt 1,
/// when it overflows.
#[derive(Default)]
struct Watchdog {
    running: bool,
    /// WDHLT, OFINTMODE, WDCKS. Kept across a watchdog reset.
    tbgcon: u8,
    tbg_unlocked: bool,
    cnt_unlocked: bool,
    armed_c3: bool,
    /// Counter value at `since`, and the board time it was taken.
    count: u64,
    since: u64,
    /// INTST: RSTSTATUS (bit 0, kept across a watchdog reset) and
    /// WDTINT (bit 4).
    intst: u8,
    intst_unlocked: bool,
    /// Its clock, APB_CLK; 0 until the board sets it.
    apb_hz: u64,
}

impl Watchdog {
    /// Board cycles per count: APB_CLK/32 to /4096.
    fn tick_cycles(&self) -> u64 {
        (32u64 << (self.tbgcon & 7)) * CLOCK_HZ / self.apb_hz.max(1)
    }

    fn counting(&self) -> bool {
        self.running && self.tbgcon & 0x80 == 0
    }

    /// Fold the time elapsed into the counter (before anything that
    /// changes its rate, its value or whether it runs).
    fn settle(&mut self, now: u64) {
        if self.counting() {
            let tick = self.tick_cycles();
            let ticks = (now - self.since) / tick;
            self.count += ticks;
            self.since += ticks * tick;
        } else {
            self.since = now;
        }
    }

    /// Board time of the next overflow, if the counter runs.
    fn overflow_at(&self) -> Option<u64> {
        self.counting()
            .then(|| self.since + (0x1_0000 - self.count.min(0xFFFF)) * self.tick_cycles())
    }

    fn set_count(&mut self, now: u64, value: u64) {
        self.settle(now);
        self.count = value;
        self.since = now;
    }
}

pub struct Soc {
    /// Longest time, in board clocks, the watchdog ran without being
    /// fed (a bite counts as the end of such a time), and when it was
    /// last fed or started.
    pub watchdog_longest: u64,
    watchdog_fed_at: u64,
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
    uart: UartTx,
    wdt: Watchdog,
    flash_ctl: FlashCtl,
    ext: ExtBus,
    /// CPU_CLK as the clock registers set it, and the part of a board
    /// cycle carried over from the last instruction when it is not a
    /// divisor of 32 MHz.
    cpu_hz: u64,
    cpu_cycle_rest: u64,
    /// Clocks the processor spent waiting on the external bus during
    /// the instruction being executed; added to its time by `tick`.
    ext_wait: u64,
    /// Clocks spent waiting on the external bus since power-on.
    pub ext_wait_total: u64,
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
    /// Addresses in the peripheral ranges where the chip has no
    /// register, or registers read before any write whose value after a
    /// reset is undefined (see [`crate::regmap`]).
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
            watchdog_longest: 0,
            watchdog_fed_at: 0,
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
            uart: UartTx::default(),
            wdt: Watchdog {
                apb_hz: RING_OSC_HZ,
                ..Watchdog::default()
            },
            flash_ctl: FlashCtl::default(),
            ext: ExtBus::default(),
            cpu_hz: RING_OSC_HZ,
            cpu_cycle_rest: 0,
            ext_wait: 0,
            ext_wait_total: 0,
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
    /// How long the watchdog has gone unfed now, in board clocks (zero
    /// while it is stopped).
    pub fn watchdog_unfed(&self) -> u64 {
        if self.wdt.running {
            self.cycles - self.watchdog_fed_at
        } else {
            0
        }
    }

    pub fn reset(&mut self) {
        self.watchdog_fed_at = self.cycles;
        self.regs.clear();
        self.irq_lines = 0;
        self.cil = 0;
        self.timer = Timer::default();
        self.i2c = I2c::default();
        self.uart = UartTx::default();
        // Only part of the watchdog goes back to its defaults on its own
        // reset: its clock setting and reset status stay.
        self.wdt = Watchdog {
            tbgcon: self.wdt.tbgcon,
            intst: self.wdt.intst,
            apb_hz: RING_OSC_HZ,
            ..Watchdog::default()
        };
        self.cpu_hz = RING_OSC_HZ;
        self.cpu_cycle_rest = 0;
        self.pending_reset = None;
        self.flash_ctl = FlashCtl::default();
        self.ext = ExtBus::default();
        self.ext_wait = 0;
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
        // Instructions and bus waits are in CPU clocks; the board counts
        // time in cycles of 32 MHz.
        let spent = cycles as u64 + self.ext_wait;
        self.ext_wait_total += self.ext_wait;
        self.ext_wait = 0;
        if self.cpu_hz == CLOCK_HZ {
            self.cycles += spent;
        } else {
            let scaled = spent * CLOCK_HZ + self.cpu_cycle_rest;
            self.cycles += scaled / self.cpu_hz;
            self.cpu_cycle_rest = scaled % self.cpu_hz;
        }
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
            if self.uart.shifting_until.is_some() {
                self.uart_advance();
            }
            self.ohci.frame(&mut self.usb_ram);
            let irq = self.ohci.irq();
            self.set_line(INT_EXINT2_USB, irq);
        }
        if let Some(at) = self.wdt.overflow_at()
            && self.cycles >= at
        {
            self.wdt.settle(at);
            self.wdt.count = 0;
            if self.wdt.tbgcon & 0x40 != 0 {
                self.wdt.running = false;
                self.wdt.intst |= 1;
                self.pending_reset = Some(ResetCause::Watchdog);
            } else {
                self.wdt.intst |= 0x10;
                self.set_line(INT_WDT, true);
            }
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
        match self.regs.get(&addr) {
            Some(v) => *v,
            None => crate::regmap::find(addr)
                .and_then(|(_, reset)| reset)
                .unwrap_or(0),
        }
    }

    /// The processor clock CLKCNT, PLL1 and PLL2 give (manual 4.3), when
    /// it runs from the crystal; `None` on the ring oscillator or the
    /// real-time clock.
    pub fn cpu_clock_hz(&self) -> Option<u64> {
        let (pll1, pll2, clkcnt) = (self.reg(PLL1), self.reg(PLL2), self.reg(CLKCNT));
        if (clkcnt >> 8) & 3 != 0 {
            return None;
        }
        self.crystal_clock_hz(pll1, pll2, clkcnt)
    }

    fn crystal_clock_hz(&self, pll1: u32, pll2: u32, clkcnt: u32) -> Option<u64> {
        let field = |v: u32, at: u32, bits: u32, zero: u64| match (v >> at) & ((1 << bits) - 1) {
            0 => zero,
            n => n as u64,
        };
        let (dvcoa, drefa, dvcob, drefb) = (
            field(pll1, 0, 8, 256),
            field(pll1, 8, 4, 16),
            field(pll1, 16, 8, 256),
            field(pll1, 24, 4, 16),
        );
        let (diva, divb, divc) = (
            field(pll2, 0, 8, 256),
            field(pll2, 8, 8, 256),
            field(pll2, 16, 8, 256),
        );
        let plla = SYSCLK_HZ * dvcoa / drefa / diva / divb;
        let source = match clkcnt & 3 {
            0 => SYSCLK_HZ,
            1 => plla,
            2 => plla * dvcob / drefb / divc,
            _ => return None,
        };
        let diva = 1u64 << ((clkcnt >> 2) & 7).min(5);
        let eighths = [8, 5, 6, 7][((clkcnt >> 5) & 3) as usize];
        Some(source / diva * eighths / 8)
    }

    /// Follow a change of the clock registers: the processor, and the
    /// system timer and watchdog on APB_CLK, run at what they now say.
    fn check_clock(&mut self) {
        let clkcnt = self.reg(CLKCNT);
        let hz = match (clkcnt >> 8) & 3 {
            0 => self.cpu_clock_hz(),
            1 => Some(RING_OSC_HZ),
            2 => Some(RTCCLK_HZ),
            _ => None,
        };
        let Some(hz) = hz.filter(|hz| *hz > 0) else {
            self.unmodelled.insert(CLKCNT);
            return;
        };
        let apb = match (clkcnt >> 10) & 3 {
            0 => hz,
            1 => hz / 2,
            2 => hz / 4,
            _ => {
                self.unmodelled.insert(CLKCNT);
                hz
            }
        };
        let now = self.cycles;
        self.wdt.settle(now);
        self.wdt.apb_hz = apb;
        if self.timer.enabled && self.timer.apb_hz != apb {
            // What is left of the period goes at the new pace.
            let left = self.timer.next.saturating_sub(now);
            self.timer.next = now + left * self.timer.apb_hz / apb;
        }
        self.timer.apb_hz = apb;
        self.cpu_hz = hz;
    }

    /// Board cycles one character takes on the line: start bit, 5 to 8
    /// data bits, parity, 1 or 2 stop bits (1.5 with 5 data bits), at
    /// APB_CLK / (16 x divisor).
    fn uart_char_cycles(&self) -> u64 {
        let lcr = self.reg(UART0 + 0x0C);
        let divisor = (self.uart_divisor_byte(0) | self.uart_divisor_byte(4) << 8).max(1) as u64;
        let data = 5 + (lcr & 3) as u64;
        let parity = (lcr >> 3) & 1;
        // In half bits, for the 1.5 stop bits.
        let stop2 = match (lcr & 4 != 0, data) {
            (false, _) => 2,
            (true, 5) => 3,
            (true, _) => 4,
        };
        let half_bits = 2 * (1 + data + parity as u64) + stop2;
        half_bits * 16 * divisor * CLOCK_HZ / self.timer.apb_hz / 2
    }

    /// DLL (0) or DLM (4); 1 and 0 after a reset.
    fn uart_divisor_byte(&self, which: u32) -> u32 {
        let reset = if which == 0 { 1 } else { 0 };
        self.regs
            .get(&(UART0_DIVISOR + which))
            .copied()
            .unwrap_or(reset)
    }

    /// Let the transmitter catch up with the board time: characters
    /// leave the shift register one after the other, the next taken from
    /// the FIFO the moment the line is free.
    fn uart_advance(&mut self) {
        loop {
            match self.uart.shifting_until {
                Some(end) if self.cycles >= end => {
                    self.uart.shifting_until = None;
                    if let Some(c) = self.uart.fifo.pop_front() {
                        self.uart_tx.push(c);
                        self.uart.shifting_until = Some(end + self.uart_char_cycles());
                        if self.uart.fifo.is_empty() {
                            self.uart_thre();
                        }
                    }
                }
                Some(_) => return,
                None => {
                    let Some(c) = self.uart.fifo.pop_front() else {
                        return;
                    };
                    self.uart_tx.push(c);
                    self.uart.shifting_until = Some(self.cycles + self.uart_char_cycles());
                    if self.uart.fifo.is_empty() {
                        self.uart_thre();
                    }
                }
            }
        }
    }

    fn uart_thre(&mut self) {
        if self.reg(UART0 + 4) & 2 != 0 {
            self.uart.thre_pending = true;
            self.set_line(INT_UART0, true);
        }
    }

    /// One access from the processor to the SRAM or the USB controller:
    /// false if its bank is switched off in BWC, which answers with an
    /// abort (recorded as a bus fault); otherwise the clocks it costs
    /// beyond the one the instruction timing already counts are added
    /// to the processor's wait.
    fn external(&mut self, addr: u32, size: u32, write: bool) -> bool {
        let bwc = self.reg(BWC);
        let io = addr >> 28 == 0xF;
        let width = if io { (bwc >> 6) & 3 } else { (bwc >> 4) & 3 };
        let bus_bytes = match width {
            1 if io => 1,
            2 => 2,
            3 => 4,
            _ => {
                self.fault(addr);
                return false;
            }
        };
        let stages = size.div_ceil(bus_bytes) as u64;
        let (kind, length) = if io {
            let Some((setup, pulse, _)) = io_timing(self.reg(IO0AC)) else {
                self.unmodelled.insert(IO0AC);
                return true;
            };
            if write {
                (ExtCycle::IoWrite, stages * (1 + setup + pulse + 1))
            } else if stages == 1 {
                // Address held one clock after a single read.
                (ExtCycle::IoRead, setup + pulse + 1)
            } else {
                (ExtCycle::IoRead, stages * (setup + pulse))
            }
        } else {
            let Some((pulse, _)) = ram_timing(self.reg(RAMAC)) else {
                self.unmodelled.insert(RAMAC);
                return true;
            };
            if write {
                // Half a clock of setup and of hold around the pulse.
                (ExtCycle::RamWrite, stages * (pulse + 1))
            } else {
                (ExtCycle::RamRead, stages * pulse)
            }
        };
        let now = self.cycles + self.ext_wait;
        let start = match self.ext.last {
            Some(before) => {
                now.max(self.ext.released_at + ext_gap(before, self.ext_off(before), kind))
            }
            None => now,
        };
        self.ext.last = Some(kind);
        self.ext.released_at = start + length;
        self.ext_wait += (start - now) + length - 1;
        true
    }

    /// The off-time setting that applies after a cycle of this kind.
    fn ext_off(&self, kind: ExtCycle) -> u64 {
        match kind {
            ExtCycle::RamRead | ExtCycle::RamWrite => {
                ram_timing(self.reg(RAMAC)).map_or(0, |(_, off)| off)
            }
            ExtCycle::IoRead | ExtCycle::IoWrite => {
                io_timing(self.reg(IO0AC)).map_or(0, |(_, _, off)| off)
            }
        }
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
            // FLWE (0) as written, FWEND (1) latched at the end of an
            // operation, BUSY (2) and BUSYNVW (3) high while the core
            // works or while programming is not permitted. Security
            // released: SEQM (5) reads 0.
            FLACON => {
                let busy = self.cycles < self.flash_ctl.busy_until;
                if self.flash_ctl.started && !busy {
                    self.flash_ctl.started = false;
                    self.flash_ctl.ended = true;
                }
                let flwe = self.reg(addr) & 1;
                let busy = (busy || flwe == 0) as u32;
                flwe | (self.flash_ctl.ended as u32) << 1
                    | busy << 2
                    | busy << 3
                    | (self.reg(addr) & 0x10)
            }
            TMEN => self.timer.enabled as u32,
            TMRLR => self.timer.reload,
            TMOVF => self.timer.overflow as u32,
            TBGCON => self.wdt.tbgcon as u32,
            INTST => self.wdt.intst as u32,
            WDTCNT => {
                let now = self.cycles;
                self.wdt.settle(now);
                self.wdt.count as u32 & 0xFFFF
            }
            a if a & !0xFFF == UART0 => {
                self.uart_advance();
                let dlab = self.reg(UART0 + 0x0C) & 0x80 != 0;
                match a & 0xFFF {
                    // LSR: THRE when the FIFO (or holding register) is
                    // empty, TEMT when the shift register is too; the
                    // receiver is not wired, nothing ever arrives.
                    0x14 => {
                        let thre = self.uart.fifo.is_empty();
                        let temt = thre && self.uart.shifting_until.is_none();
                        (thre as u32) << 5 | (temt as u32) << 6
                    }
                    // IIR: FIFO mode in bits 6-7, then the pending source.
                    0x08 => {
                        let fifo = if self.reg(UART0 + 0x08) & 1 != 0 {
                            0xC0
                        } else {
                            0
                        };
                        if self.uart.thre_pending {
                            // Reading IIR clears a THRE interrupt.
                            self.uart.thre_pending = false;
                            self.set_line(INT_UART0, false);
                            fifo | 0x02
                        } else {
                            fifo | 0x01
                        }
                    }
                    // Receive buffer: empty.
                    0x00 if !dlab => 0,
                    // The divisor latches share their addresses with the
                    // buffer and IER; they are kept apart.
                    0x00 | 0x04 if dlab => self.uart_divisor_byte(a & 4),
                    _ => self.reg(a),
                }
            }
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
                // A register the chip does not have, or one whose value
                // after a reset is undefined, read before any write.
                let known = crate::regmap::find(addr).is_some_and(|(_, r)| r.is_some());
                if !self.regs.contains_key(&addr) && !known {
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
            PLL1 | PLL2 | CLKCNT => {
                self.regs.insert(addr, merged);
                self.check_clock();
            }
            FLACON => {
                let v = val & mask;
                if v & 2 != 0 {
                    // Settle a pending end first: writing 1 clears FWEND.
                    if self.flash_ctl.started && self.cycles >= self.flash_ctl.busy_until {
                        self.flash_ctl.started = false;
                    }
                    self.flash_ctl.ended = false;
                }
                // FLWE and SEQMD are kept; FLRST resets the core at once.
                if v & 0x40 != 0 {
                    self.flash_ctl.state = FlashState::Idle;
                }
                self.regs.insert(addr, v & 0x11);
            }
            WDTCON => {
                let v = (val & mask & 0xFF) as u8;
                let now = self.cycles;
                if !self.wdt.running {
                    // The first 3CH starts the counter from zero.
                    if v == 0x3C {
                        self.wdt.set_count(now, 0);
                        self.wdt.running = true;
                        self.wdt.since = now;
                        self.watchdog_fed_at = now;
                    }
                } else if v == 0xC3 {
                    self.wdt.armed_c3 = true;
                } else if v == 0x3C && self.wdt.armed_c3 {
                    // C3H then 3CH clears it.
                    self.watchdog_longest = self.watchdog_longest.max(now - self.watchdog_fed_at);
                    self.watchdog_fed_at = now;
                    self.wdt.set_count(now, 0);
                    self.wdt.armed_c3 = false;
                } else {
                    self.wdt.armed_c3 = false;
                }
            }
            TBGCON => {
                let v = (val & mask & 0xFF) as u8;
                if self.wdt.tbg_unlocked {
                    // The counter keeps its value across a change of
                    // clock, a halt or a resumption.
                    let now = self.cycles;
                    self.wdt.settle(now);
                    self.wdt.tbgcon = v & 0xC7;
                    self.wdt.since = now;
                    self.wdt.tbg_unlocked = false;
                } else if v == 0x5A {
                    self.wdt.tbg_unlocked = true;
                }
            }
            INTST => {
                let v = (val & mask & 0xFF) as u8;
                if v == 0x3C {
                    self.wdt.intst_unlocked = true;
                } else {
                    // Writing 1 is ignored; 0 clears, RSTSTATUS only
                    // after the unlock.
                    if v & 0x10 == 0 {
                        self.wdt.intst &= !0x10;
                        self.set_line(INT_WDT, false);
                    }
                    if v & 1 == 0 && self.wdt.intst_unlocked {
                        self.wdt.intst &= !1;
                    }
                    self.wdt.intst_unlocked = false;
                }
            }
            WDTCNT => {
                let v = val & mask & 0xFFFF;
                if self.wdt.cnt_unlocked {
                    self.wdt.cnt_unlocked = false;
                    let now = self.cycles;
                    self.wdt.set_count(now, v as u64);
                } else if v == 0x5A5A {
                    self.wdt.cnt_unlocked = true;
                }
            }
            a if a & !0xFFF == UART0 => {
                self.uart_advance();
                let dlab = self.reg(UART0 + 0x0C) & 0x80 != 0;
                match a & 0xFFF {
                    0x00 if !dlab => {
                        let depth = if self.reg(UART0 + 0x08) & 1 != 0 {
                            16
                        } else {
                            1
                        };
                        // A full FIFO drops what is written to it.
                        if self.uart.fifo.len() < depth {
                            self.uart.fifo.push_back(val as u8);
                        }
                        self.uart.thre_pending = false;
                        self.set_line(INT_UART0, false);
                        self.uart_advance();
                    }
                    0x00 | 0x04 if dlab => {
                        self.regs.insert(UART0_DIVISOR + (a & 4), val & 0xFF);
                    }
                    // FCR: bit 2 empties the transmit FIFO; only FIFO
                    // enable and the trigger level are kept.
                    0x08 => {
                        if val & 4 != 0 {
                            self.uart.fifo.clear();
                        }
                        self.regs.insert(a, val & 0xC1);
                    }
                    _ => {
                        self.regs.insert(a, merged);
                    }
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
                if crate::regmap::find(addr).is_none() {
                    self.unmodelled.insert(addr);
                }
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
                self.flash_ctl.started = true;
                Idle
            }
            (Program(left), _, _) => {
                // Programming can only clear bits.
                self.flash[off] &= val;
                if left == 1 {
                    self.flash_programs += 1;
                    self.flash_ctl.busy_until = self.cycles + PROGRAM_CYCLES;
                    self.flash_ctl.started = true;
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
        self.wdt = Watchdog {
            apb_hz: RING_OSC_HZ,
            ..Watchdog::default()
        };
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
        if addr >= XRAM_BASE && !self.external(addr, 1, false) {
            return 0;
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
        if addr >= XRAM_BASE && !self.external(addr, 2, false) {
            return 0;
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
        if addr >= XRAM_BASE && !self.external(addr, 4, false) {
            return 0;
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
        if addr >= XRAM_BASE && !self.external(addr, 1, true) {
            return;
        }
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
        if addr >= XRAM_BASE && !self.external(addr, 2, true) {
            return;
        }
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
        if addr >= XRAM_BASE && !self.external(addr, 4, true) {
            return;
        }
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
