//! USB host: the OKI ML60842 controller, an OHCI core with 4 KB of RAM
//! of its own, and the one device the rabbit has, its Wi-Fi stick.
//!
//! Every descriptor and buffer the controller touches lives in its RAM
//! at fixed places: one control endpoint, one bulk endpoint each way.
//! The interrupt handler takes finished transfers off the done queue:
//! received packets go to the Wi-Fi driver at once and their transfer
//! descriptors straight back in the queue.

use crate::sync::Shared;
use crate::{irq, reg, timer, watchdog};
const CHIP: usize = 0xF000_0000;
/// The controller's RAM, which it sees at the same addresses we do.
const RAM: usize = CHIP + 0x1000;

reg! {
    HOST_PERI_SEL: u32 = CHIP;
    HOST_PERI_SEL8: u8 = CHIP;
    ENDIAN8: u8 = CHIP + 0x008;
    RST_CLK_CTL8: u8 = CHIP + 0x01C;
    HOST_CTL8: u8 = CHIP + 0x200;
    OTG_CTL: u32 = CHIP + 0x010;
    OTG_INT_MASK: u32 = CHIP + 0x018;
    RST_CLK_CTL: u32 = CHIP + 0x01C;
    HC_REVISION: u32 = CHIP + 0x100;
    HC_CONTROL: u32 = CHIP + 0x104;
    HC_COMMAND_STATUS: u32 = CHIP + 0x108;
    HC_INTERRUPT_STATUS: u32 = CHIP + 0x10C;
    HC_INTERRUPT_ENABLE: u32 = CHIP + 0x110;
    HC_INTERRUPT_DISABLE: u32 = CHIP + 0x114;
    HC_HCCA: u32 = CHIP + 0x118;
    HC_CONTROL_HEAD: u32 = CHIP + 0x120;
    HC_BULK_HEAD: u32 = CHIP + 0x128;
    HC_FM_INTERVAL: u32 = CHIP + 0x134;
    HC_PERIODIC_START: u32 = CHIP + 0x140;
    HC_LS_THRESHOLD: u32 = CHIP + 0x144;
    HC_RH_STATUS: u32 = CHIP + 0x150;
    HC_RH_PORT: u32 = CHIP + 0x154;
    HOST_CTL: u32 = CHIP + 0x200;
    STT_TRNS_CNT: u32 = CHIP + 0x204;
    RAM_ADR: u32 = CHIP + 0x20C;
    INT_ENBL: u16 = CHIP + 0x314;
    EXIRQB: u16 = 0x7BF0_0020;
}

const OPERATING: u32 = 1 << 1;
const CHIP_RESET: u8 = 1 << 6;
const PULL_DOWN_BOTH: u32 = 0x60;
const OHCI_IRQ: u32 = 1 << 1;

const CONTROL_LIST: u32 = 1 << 4;
const BULK_LIST: u32 = 1 << 5;
const PERIODIC_LIST: u32 = 1 << 2;
const STATE_OPERATIONAL: u32 = 2 << 6;
const CONTROL_FILLED: u32 = 1 << 1;
const BULK_FILLED: u32 = 1 << 2;

const INT_OVERRUN: u32 = 1 << 0;
const INT_DONE: u32 = 1 << 1;
const INT_UNRECOVERABLE: u32 = 1 << 4;
const INT_ROOT_HUB: u32 = 1 << 6;
const INT_MASTER: u32 = 1 << 31;

const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_CONNECT_CHANGE: u32 = 1 << 16;
const PORT_ENABLE_CHANGE: u32 = 1 << 17;
const PORT_RESET_CHANGE: u32 = 1 << 20;

// Layout of the controller's RAM.
const HCCA: usize = RAM;
const HCCA_DONE_HEAD: usize = HCCA + 0x84;
const ED_CONTROL: usize = RAM + 0x100;
const ED_OUT: usize = RAM + 0x110;
const ED_IN: usize = RAM + 0x120;
const TD_CONTROL: usize = RAM + 0x130;
const TD_OUT: usize = RAM + 0x170;
const TD_IN: usize = RAM + 0x190;
const SETUP: usize = RAM + 0x1E0;
const CONTROL_DATA: usize = RAM + 0x200;
const RX_BUFFERS: usize = RAM + 0x300;
const TX_BUFFER: usize = RAM + 0x440;

/// Largest data stage of a control transfer.
pub const CONTROL_MAX: usize = 256;
/// Largest bulk transfer out: what is left of the RAM.
pub const TX_MAX: usize = RAM + 0x1000 - TX_BUFFER;
pub const PACKET: usize = 64;
const RX_TDS: usize = 5;

// Endpoint descriptor fields.
const ED_SKIP: u32 = 1 << 14;
const ED_OUT_DIR: u32 = 1 << 11;
const ED_IN_DIR: u32 = 2 << 11;
// Transfer descriptor fields.
const TD_ROUNDING: u32 = 1 << 18;
const TD_SETUP: u32 = 0 << 19;
const TD_OUT_PID: u32 = 1 << 19;
const TD_IN_PID: u32 = 2 << 19;
const TD_NO_INTERRUPT: u32 = 7 << 21;
const TD_DATA0: u32 = 2 << 24;
const TD_DATA1: u32 = 3 << 24;
const TD_NOT_ACCESSED: u32 = 0xF << 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The controller is not the one expected, or will not start.
    Controller,
    /// Nothing answered in time.
    Timeout,
    /// The device refused the request or the transfer failed; the
    /// number is the controller's condition code.
    Transfer(u8),
    /// What is plugged in is not the Wi-Fi stick.
    UnknownDevice,
}

fn word(address: usize) -> crate::reg::Reg<u32> {
    // SAFETY: callers pass addresses inside the controller's RAM.
    unsafe { crate::reg::Reg::at(address) }
}

/// What the interrupt handler tells the main program.
static CONTROL_RESULT: Shared<u32> = Shared::new(PENDING);
static PORT_CHANGED: Shared<bool> = Shared::new(false);
static TX_BUSY: Shared<bool> = Shared::new(false);
/// When the transfer out on its way was queued.
static TX_AT: Shared<u32> = Shared::new(0);
/// Since when transfers out have been taken back without one going
/// through (0: none is). One word: the interrupt clears it.
static STUCK_SINCE: Shared<u32> = Shared::new(0);
static BROKEN: Shared<bool> = Shared::new(false);
/// What takes the packets received on the bulk endpoint.
type PacketHandler = fn(&[u8]);
static RX_HANDLER: Shared<Option<PacketHandler>> = Shared::new(None);
/// Transfers the controller gave up on, both directions.
static BULK_ERRORS: Shared<u32> = Shared::new(0);

const PENDING: u32 = 0xFFFF_FFFF;

fn set_ed(ed: usize, address: u8, endpoint: u8, direction: u32, max_packet: u16, first_td: usize) {
    word(ed).write(address as u32 | (endpoint as u32) << 7 | direction | (max_packet as u32) << 16);
    word(ed + 4).write(first_td as u32);
    word(ed + 8).write(first_td as u32);
    word(ed + 12).write(0);
}

fn fill_td(td: usize, control: u32, buffer: usize, len: usize, next: usize) {
    word(td).write(control | TD_NOT_ACCESSED);
    word(td + 4).write(if len == 0 { 0 } else { buffer as u32 });
    word(td + 8).write(next as u32);
    word(td + 12).write(if len == 0 {
        0
    } else {
        (buffer + len - 1) as u32
    });
}

/// The two bulk endpoints, empty, for the device at `address`, the out
/// one first in the list.
fn set_bulk_eds(address: u8, flags: u32) {
    set_ed(
        ED_OUT,
        address,
        1,
        flags | ED_OUT_DIR,
        PACKET as u16,
        TD_OUT,
    );
    set_ed(ED_IN, address, 1, flags | ED_IN_DIR, PACKET as u16, TD_IN);
    word(ED_OUT + 12).write(ED_IN as u32);
}

/// Bytes a finished descriptor moved into or out of its buffer from
/// `start`, of the `asked`: the controller leaves its current pointer
/// at the next byte, or at zero when all of them went.
fn moved(td: usize, start: usize, asked: usize) -> usize {
    match word(td + 4).read() as usize {
        0 => asked,
        end => end - start,
    }
}

/// Hand a descriptor to a bulk endpoint: its placeholder `td` becomes
/// the request, `spare` the new placeholder.
fn queue_bulk(ed: usize, td: usize, control: u32, buffer: usize, len: usize, spare: usize) {
    fill_td(td, control, buffer, len, spare);
    word(ed + 4).write(spare as u32);
    HC_COMMAND_STATUS.write(BULK_FILLED);
}

/// Take back from the controller what an endpoint holds (lost): the
/// endpoint skipped, time for the controller to let go, then its
/// queue emptied, the head brought to the tail with the bits of `keep`
/// it had (the data toggle).
fn take_back(ed: usize, keep: u32) {
    word(ed).set(ED_SKIP);
    timer::delay_ms(2);
    let kept = word(ed + 8).read() & keep;
    word(ed + 8).write(word(ed + 4).read() | kept);
}

/// A bulk transfer failed: counted, and the endpoint the controller
/// halted on it let go again.
fn bulk_failed(ed: usize) {
    BULK_ERRORS.set(BULK_ERRORS.get() + 1);
    word(ed + 8).clear(1);
}

/// Bring the controller up as a host and power its port.
pub fn init() -> Result<(), Error> {
    let settle = || {
        for _ in 0..100 {
            if HOST_PERI_SEL.read() & OPERATING == 0 {
                return Ok(());
            }
        }
        Err(Error::Controller)
    };
    RST_CLK_CTL.write(0);
    RST_CLK_CTL8.write(CHIP_RESET);
    settle()?;
    ENDIAN8.write(0);
    STT_TRNS_CNT.write(STT_TRNS_CNT.read());
    OTG_INT_MASK.write(0);
    INT_ENBL.write(0);
    // Both of the chip's interrupt sources masked while it is set up.
    HOST_CTL8.write(0x03);
    // Host role: both data lines pulled down, port power under the
    // root hub's control.
    OTG_CTL.write((OTG_CTL.read() & !0xE0) | PULL_DOWN_BOTH);
    HOST_PERI_SEL8.write(0);
    settle()?;
    OTG_CTL.clear(0x0000_1F00);
    OTG_CTL.clear(0x0000_001F);

    if HC_REVISION.read() != 0x10 {
        return Err(Error::Controller);
    }
    RAM_ADR.write(RAM as u32);
    for offset in (0..0x1000).step_by(4) {
        word(RAM + offset).write(0);
    }
    HC_HCCA.write(HCCA as u32);

    // Endpoints start empty and skipped: head equals tail.
    set_ed(ED_CONTROL, 0, 0, ED_SKIP, 8, TD_CONTROL);
    set_bulk_eds(0, ED_SKIP);
    HC_CONTROL_HEAD.write(ED_CONTROL as u32);
    HC_BULK_HEAD.write(ED_OUT as u32);

    let interval = 0x2EDF;
    HC_PERIODIC_START.write(interval * 9 / 10);
    HC_FM_INTERVAL.write(interval | ((interval - 500) * 6 / 7) << 16);
    HC_LS_THRESHOLD.write(0x628);
    HC_CONTROL.write(PERIODIC_LIST | CONTROL_LIST | BULK_LIST | STATE_OPERATIONAL);
    HC_INTERRUPT_ENABLE
        .write(INT_MASTER | INT_UNRECOVERABLE | INT_DONE | INT_ROOT_HUB | INT_OVERRUN);

    // The controller's interrupt pin, at the highest level.
    EXIRQB.set(0x10);
    irq::EXILCB.set(0x700);
    HOST_CTL.write(0);
    // Power the port: a device already there shows up as a change.
    HC_RH_STATUS.write(1 << 16);
    Ok(())
}

/// Called by the interrupt dispatcher for the controller's pin.
pub(crate) fn on_interrupt() {
    EXIRQB.set(0x10);
    if STT_TRNS_CNT.read() & OHCI_IRQ == 0 {
        return;
    }
    let status = HC_INTERRUPT_STATUS.read();
    if status & INT_UNRECOVERABLE != 0 {
        HC_INTERRUPT_DISABLE.write(!0);
        BROKEN.set(true);
    }
    if status & INT_DONE != 0 {
        // Take the list before telling the controller it may write
        // the next one.
        let mut td = (word(HCCA_DONE_HEAD).read() & !0xF) as usize;
        word(HCCA_DONE_HEAD).write(0);
        HC_INTERRUPT_STATUS.write(INT_DONE);
        // The list comes newest first: turn it round.
        let mut oldest_first = 0usize;
        while td != 0 {
            let next = (word(td + 8).read() & !0xF) as usize;
            word(td + 8).write(oldest_first as u32);
            oldest_first = td;
            td = next;
        }
        td = oldest_first;
        while td != 0 {
            let next = word(td + 8).read() as usize;
            retire(td);
            td = next;
        }
    }
    if status & INT_ROOT_HUB != 0 {
        HC_INTERRUPT_STATUS.write(INT_ROOT_HUB);
        PORT_CHANGED.set(true);
    }
    if status & INT_OVERRUN != 0 {
        HC_INTERRUPT_STATUS.write(INT_OVERRUN);
    }
    STT_TRNS_CNT.write(OHCI_IRQ);
}

/// A transfer descriptor came back from the controller.
fn retire(td: usize) {
    let condition = word(td).read() >> 28;
    if (TD_IN..TD_IN + RX_TDS * 16).contains(&td) {
        let buffer = rx_buffer(td);
        let len = moved(td, buffer, PACKET);
        // The buffer is read plainly between the descriptor's register
        // reads and writes: keep it there.
        crate::sync::barrier();
        if condition == 0 {
            if let Some(handler) = RX_HANDLER.get() {
                // SAFETY: the controller is done with this buffer until
                // the descriptor is queued again, below.
                handler(unsafe { core::slice::from_raw_parts(buffer as *const u8, len) });
            }
        } else {
            bulk_failed(ED_IN);
        }
        crate::sync::barrier();
        queue_rx(td);
    } else if (TD_OUT..TD_OUT + 32).contains(&td) {
        if condition != 0 {
            bulk_failed(ED_OUT);
        }
        TX_BUSY.set(false);
        STUCK_SINCE.set(0);
    } else if condition != 0 {
        // A failed stage ends the control transfer: drop the others.
        let tail = word(ED_CONTROL + 4).read();
        word(ED_CONTROL + 8).write(tail);
        CONTROL_RESULT.set(0x8000_0000 | condition);
    } else if td == TD_CONTROL + 16 {
        // The data stage: note how much of the buffer was used.
        let asked = word(td + 12).read() as usize + 1 - CONTROL_DATA;
        DATA_MOVED.set(moved(td, CONTROL_DATA, asked) as u32);
    } else if td == TD_CONTROL + 32 {
        CONTROL_RESULT.set(DATA_MOVED.get());
    }
}

static DATA_MOVED: Shared<u32> = Shared::new(0);

/// The packet buffer of a receive descriptor, one each.
fn rx_buffer(td: usize) -> usize {
    RX_BUFFERS + (td - TD_IN) / 16 * PACKET
}

/// Put a receive descriptor (back) at the end of the bulk-in queue:
/// the current placeholder becomes a real request, and `spare` the
/// new placeholder.
fn queue_rx(spare: usize) {
    let td = word(ED_IN + 4).read() as usize;
    queue_bulk(
        ED_IN,
        td,
        TD_ROUNDING | TD_IN_PID,
        rx_buffer(td),
        PACKET,
        spare,
    );
}

/// Whether the controller reported an unrecoverable error.
pub fn broken() -> bool {
    BROKEN.get()
}

pub fn bulk_errors() -> u32 {
    BULK_ERRORS.get()
}

/// Wait for a device on the port and reset it. Returns once it is
/// ready to be talked to at address 0.
pub fn attach(timeout_ms: u32) -> Result<(), Error> {
    let start = timer::millis();
    let mut resetting = false;
    loop {
        watchdog::feed();
        if timer::since(start) > timeout_ms {
            return Err(Error::Timeout);
        }
        if !PORT_CHANGED.get() {
            continue;
        }
        PORT_CHANGED.set(false);
        let port = HC_RH_PORT.read();
        HC_RH_PORT.write(port & (PORT_CONNECT_CHANGE | PORT_ENABLE_CHANGE | PORT_RESET_CHANGE));
        if port & PORT_CONNECTED == 0 {
            resetting = false;
        } else if !resetting {
            // Let the plug settle, then reset the bus.
            timer::delay_ms(40);
            HC_RH_PORT.write(PORT_RESET);
            resetting = true;
        } else if port & PORT_RESET_CHANGE != 0 && port & PORT_ENABLED != 0 {
            timer::delay_ms(40);
            return Ok(());
        }
    }
}

/// One control transfer on endpoint 0, waited for. `data` is sent or
/// filled according to the direction bit of the request; the result is
/// the number of bytes that moved.
pub fn control(
    address: u8,
    max_packet: u16,
    setup: [u8; 8],
    data: &mut [u8],
) -> Result<usize, Error> {
    let len = data.len().min(CONTROL_MAX);
    let read = setup[0] & 0x80 != 0;
    irq::free(|| {
        for (i, chunk) in setup.as_chunks::<4>().0.iter().enumerate() {
            word(SETUP + 4 * i).write(u32::from_le_bytes(*chunk));
        }
        if !read {
            for (i, byte) in data[..len].iter().enumerate() {
                // SAFETY: inside the control data area.
                unsafe { ((CONTROL_DATA + i) as *mut u8).write_volatile(*byte) };
            }
        }
        // Setup, optional data, status, and a new placeholder: always
        // the same four descriptors, in a ring.
        let (t0, t1, t2, t3) = (
            TD_CONTROL,
            TD_CONTROL + 16,
            TD_CONTROL + 32,
            TD_CONTROL + 48,
        );
        let (data_pid, status_pid) = if read {
            (TD_IN_PID, TD_OUT_PID)
        } else {
            (TD_OUT_PID, TD_IN_PID)
        };
        let after_setup = if len > 0 { t1 } else { t2 };
        fill_td(
            t0,
            TD_SETUP | TD_DATA0 | TD_NO_INTERRUPT,
            SETUP,
            8,
            after_setup,
        );
        fill_td(
            t1,
            TD_ROUNDING | data_pid | TD_DATA1 | TD_NO_INTERRUPT,
            CONTROL_DATA,
            len,
            t2,
        );
        fill_td(t2, status_pid | TD_DATA1, 0, 0, t3);
        DATA_MOVED.set(0);
        CONTROL_RESULT.set(PENDING);
        word(ED_CONTROL).write(address as u32 | (max_packet as u32) << 16);
        word(ED_CONTROL + 8).write(t0 as u32);
        word(ED_CONTROL + 4).write(t3 as u32);
        HC_COMMAND_STATUS.write(CONTROL_FILLED);
    });

    let start = timer::millis();
    let result = loop {
        watchdog::feed();
        let result = CONTROL_RESULT.get();
        if result != PENDING {
            break result;
        }
        if broken() || timer::since(start) > 500 {
            // Take the transfer back from the controller; the next one
            // brings its own toggles, and lets the endpoint go again.
            irq::free(|| take_back(ED_CONTROL, 0));
            return Err(Error::Timeout);
        }
    };
    if result & 0x8000_0000 != 0 {
        return Err(Error::Transfer(result as u8));
    }
    let moved = (result as usize).min(len);
    if read {
        for (i, byte) in data[..moved].iter_mut().enumerate() {
            // SAFETY: inside the control data area.
            *byte = unsafe { ((CONTROL_DATA + i) as *const u8).read_volatile() };
        }
    }
    Ok(moved)
}

/// The device found by [`enumerate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub vendor: u16,
    pub product: u16,
    pub max_packet: u16,
}

pub const ADDRESS: u8 = 1;

/// The Wi-Fi sticks Violet soldered in, by vendor and product.
const KNOWN: [(u16, u16); 3] = [(0x148F, 0x2573), (0x0DF6, 0x9712), (0x0DB0, 0x6877)];

/// Identify the device, give it an address and configure it. Leaves
/// the two bulk endpoints running.
pub fn enumerate() -> Result<Device, Error> {
    let mut d = [0u8; 18];
    // The first eight bytes are safe to ask whatever the packet size.
    control(0, 8, [0x80, 6, 0, 1, 0, 0, 8, 0], &mut d[..8])?;
    let max_packet = d[7] as u16;
    control(0, 8, [0x00, 5, ADDRESS, 0, 0, 0, 0, 0], &mut [])?;
    timer::delay_ms(10);
    if control(ADDRESS, max_packet, [0x80, 6, 0, 1, 0, 0, 18, 0], &mut d)? < 18 {
        return Err(Error::UnknownDevice);
    }
    let device = Device {
        vendor: u16::from_le_bytes([d[8], d[9]]),
        product: u16::from_le_bytes([d[10], d[11]]),
        max_packet,
    };
    if !KNOWN.contains(&(device.vendor, device.product)) {
        return Err(Error::UnknownDevice);
    }
    // The configuration must offer a bulk endpoint each way, numbered 1.
    let mut c = [0u8; 64];
    let got = control(ADDRESS, max_packet, [0x80, 6, 0, 2, 0, 0, 64, 0], &mut c)?;
    let (mut has_out, mut has_in) = (false, false);
    let mut at = 0;
    while at + 2 <= got && c[at] as usize >= 2 {
        if c[at + 1] == 5 && at + 4 <= got && c[at + 3] & 3 == 2 {
            has_out |= c[at + 2] == 0x01;
            has_in |= c[at + 2] == 0x81;
        }
        at += c[at] as usize;
    }
    if !(has_out && has_in) {
        return Err(Error::UnknownDevice);
    }
    // Without this the stick leaves part of itself unpowered.
    control(ADDRESS, max_packet, [0x00, 9, 1, 0, 0, 0, 0, 0], &mut [])?;

    irq::free(|| {
        set_bulk_eds(ADDRESS, 0);
        // Four receive requests in flight, the fifth descriptor waits.
        for slot in 1..RX_TDS {
            queue_rx(TD_IN + slot * 16);
        }
    });
    Ok(device)
}

/// Have every received packet handed to `handler`, from the interrupt.
pub fn on_receive(handler: PacketHandler) {
    RX_HANDLER.set(Some(handler));
}

/// Whether a transfer out is still on its way.
pub fn tx_busy() -> bool {
    TX_BUSY.get()
}

/// Send `len` bytes prepared by `fill` in the transmit buffer. Returns
/// false, without calling `fill`, while the previous transfer is still
/// on its way.
pub fn transmit(len: usize, fill: impl FnOnce(&mut [u8])) -> bool {
    let now = timer::millis();
    if tx_busy() && now.wrapping_sub(TX_AT.get()) > 1000 {
        // A second on its way: the stick will not take it. Ten seconds of
        // that and it is not coming back: start again from scratch, which
        // brings the stick up anew.
        let since = match STUCK_SINCE.get() {
            0 => now.max(1),
            t => t,
        };
        if now.wrapping_sub(since) > 10_000 {
            watchdog::reset_now();
        }
        STUCK_SINCE.set(since);
        // Take the frame back from the controller (it is lost, as on the
        // air), keeping the data toggle the stick expects next.
        irq::free(|| {
            take_back(ED_OUT, 2);
            word(ED_OUT).clear(ED_SKIP);
            TX_BUSY.set(false);
        });
    }
    if tx_busy() || len == 0 || len > TX_MAX {
        return false;
    }
    // SAFETY: the buffer is ours until the descriptor is queued.
    fill(unsafe { core::slice::from_raw_parts_mut(TX_BUFFER as *mut u8, len) });
    // The buffer is written plainly, the controller started by register
    // writes: the frame must be all there before.
    crate::sync::barrier();
    irq::free(|| {
        TX_BUSY.set(true);
        TX_AT.set(timer::millis());
        let td = word(ED_OUT + 4).read() as usize;
        let spare = if td == TD_OUT { TD_OUT + 16 } else { TD_OUT };
        queue_bulk(ED_OUT, td, TD_OUT_PID, TX_BUFFER, len, spare);
    });
    true
}
