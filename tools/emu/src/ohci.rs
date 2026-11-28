//! ML60842 USB host controller: an OHCI core with 4K of on-chip RAM.
//!
//! The firmware keeps every ED, TD and data buffer in that RAM (it tells
//! the chip where it sits through `RamAdr`), so the controller never has
//! to reach into the CPU's memory. Only what the firmware uses is here:
//! one root-hub port, the control and bulk lists, the done queue.

pub const RAM_BASE: u32 = 0xF000_1000;
pub const RAM_SIZE: usize = 0x1000;

const HOST_CTL: u32 = 0x200;
const RST_CLK_CTL: u32 = 0x01C;
const CHIP_RESET: u32 = 1 << 6;
const STT_TRNS_CNT: u32 = 0x204;
const HC_REVISION: u32 = 0x100;
const HC_CONTROL: u32 = 0x104;
const HC_COMMAND_STATUS: u32 = 0x108;
const HC_INTERRUPT_STATUS: u32 = 0x10C;
const HC_INTERRUPT_ENABLE: u32 = 0x110;
const HC_INTERRUPT_DISABLE: u32 = 0x114;
const HC_HCCA: u32 = 0x118;
const HC_CONTROL_HEAD_ED: u32 = 0x120;
const HC_BULK_HEAD_ED: u32 = 0x128;
const HC_DONE_HEAD: u32 = 0x130;
const HC_FM_NUMBER: u32 = 0x13C;
const HC_RH_DESCRIPTOR_A: u32 = 0x148;
const HC_RH_STATUS: u32 = 0x150;
const HC_RH_PORT_STATUS: u32 = 0x154;

const CTRL_CLE: u32 = 1 << 4;
const CTRL_BLE: u32 = 1 << 5;
const CTRL_HCFS: u32 = 3 << 6;
const USB_OPER: u32 = 2 << 6;

const INTR_WDH: u32 = 1 << 1;
const INTR_SF: u32 = 1 << 2;
const INTR_UE: u32 = 1 << 4;
const INTR_FNO: u32 = 1 << 5;
const INTR_RHSC: u32 = 1 << 6;
const INTR_MIE: u32 = 1 << 31;

const PS_CCS: u32 = 1 << 0;
const PS_PES: u32 = 1 << 1;
const PS_PRS: u32 = 1 << 4;
const PS_PPS: u32 = 1 << 8;
const PS_CSC: u32 = 1 << 16;
const PS_PESC: u32 = 1 << 17;
const PS_PRSC: u32 = 1 << 20;

const ED_SKIP: u32 = 1 << 14;
const ED_HALT: u32 = 1;
const ED_CARRY: u32 = 2;

const CC_NO_ERROR: u32 = 0;
const CC_STALL: u32 = 4;
const CC_NOT_RESPONDING: u32 = 5;
const CC_DATA_OVERRUN: u32 = 8;
const CC_DATA_UNDERRUN: u32 = 9;

/// Milliseconds a port reset lasts.
const RESET_FRAMES: u32 = 10;
/// Transfer descriptors retired per frame at most, all lists together.
const TDS_PER_FRAME: u32 = 16;
/// Bytes of a full-speed frame (12 Mb/s for 1 ms) the transactions
/// share, and what each costs beyond its data: tokens, handshake, CRC,
/// sync and gaps. USB 2.0, 5.8.4 and table 5-10: nineteen bulk
/// transactions of 64 bytes at most in a frame (1216 bytes of data),
/// 71 of 8 bytes.
const FRAME_BYTES: usize = 1500;
const TRANSACTION_OVERHEAD: usize = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Xfer {
    /// The device took or gave this many bytes.
    Done(usize),
    Nak,
    Stall,
}

/// A device on the root-hub port, seen at the transfer level.
pub trait UsbDevice {
    /// Bus reset: back to address 0, unconfigured.
    fn bus_reset(&mut self);
    fn address(&self) -> u8;
    fn setup(&mut self, packet: [u8; 8]) -> Xfer;
    /// Host reads from endpoint `ep`; fill `buf`, return how much.
    fn data_in(&mut self, ep: u8, buf: &mut [u8]) -> Xfer;
    /// Host writes `data` to endpoint `ep`.
    fn data_out(&mut self, ep: u8, data: &[u8]) -> Xfer;
    /// Called once per frame (1 ms of board time).
    fn frame(&mut self) {}
    /// The device lost its supply and got it back.
    fn power_cycle(&mut self) {
        self.bus_reset();
    }
}

pub struct Ohci {
    regs: [u32; 0x400],
    int_status: u32,
    int_enable: u32,
    port: u32,
    reset_left: u32,
    pub device: Option<Box<dyn UsbDevice>>,
    /// Transfers the controller could not carry out (bad pointers).
    pub errors: u32,
    pub frames: u64,
    /// The root hub's status change interrupt as a level: asserted
    /// again as long as a port change bit is set, as some controllers
    /// do (Linux's `ohci_irq` copes with those). Off, it is raised once
    /// per change. On by default with `NABEMU_RHSC_LEVEL` set.
    pub rhsc_level: bool,
    /// The chip's own interrupt status (StatusTransferCount's OHCI bit),
    /// set while the core interrupts and cleared by writing it, which
    /// both drivers do last in their handler. With `latched`, the pin
    /// follows it rather than the core: it falls at that write, just
    /// before the handler's end (and its CILCL write).
    stt_ohci: bool,
    pub latched: bool,
    /// The device's data toggles on its bulk endpoints, by number: the
    /// one it expects next out (`[ep][0]`), the one it sends next in
    /// (`[ep][1]`). Back to DATA0 at a bus reset, SET_CONFIGURATION,
    /// SET_INTERFACE, and CLEAR_FEATURE(ENDPOINT_HALT) for the endpoint.
    toggles: [[bool; 2]; 16],
    /// Packets thrown away for a toggle that repeats the last one (USB
    /// 2.0, 8.6.4): an OUT packet the device takes for a retry of one it
    /// has, an IN packet the host takes for one it has. Both are
    /// acknowledged all the same.
    pub toggle_drops: u64,
    /// What is left of the current frame's bus time, in bytes.
    bus_left: usize,
}

struct Ram<'a>(&'a mut [u8]);

impl Ram<'_> {
    fn range(&mut self, addr: u32, len: usize) -> Option<&mut [u8]> {
        let off = addr.checked_sub(RAM_BASE)? as usize;
        self.0.get_mut(off..off.checked_add(len)?)
    }

    fn rd32(&mut self, addr: u32) -> Option<u32> {
        let m = self.range(addr, 4)?;
        Some(u32::from_le_bytes([m[0], m[1], m[2], m[3]]))
    }

    fn wr32(&mut self, addr: u32, v: u32) -> Option<()> {
        self.range(addr, 4)?.copy_from_slice(&v.to_le_bytes());
        Some(())
    }
}

impl Default for Ohci {
    fn default() -> Self {
        Self::new()
    }
}

impl Ohci {
    pub fn new() -> Self {
        Ohci {
            regs: [0; 0x400],
            int_status: 0,
            int_enable: 0,
            port: 0,
            reset_left: 0,
            device: None,
            errors: 0,
            frames: 0,
            rhsc_level: std::env::var_os("NABEMU_RHSC_LEVEL").is_some(),
            stt_ohci: false,
            latched: false,
            toggles: [[false; 2]; 16],
            toggle_drops: 0,
            bus_left: 0,
        }
    }

    /// Pull the device out of the port: the port says so (connect and
    /// enable changes), and the device is handed back.
    pub fn unplug(&mut self) -> Option<Box<dyn UsbDevice>> {
        let device = self.device.take()?;
        if self.port & PS_PPS != 0 {
            if self.port & PS_CCS != 0 {
                self.port |= PS_CSC;
            }
            if self.port & PS_PES != 0 {
                self.port |= PS_PESC;
            }
            self.port &= !(PS_CCS | PS_PES | PS_PRS);
            self.reset_left = 0;
            self.int_status |= INTR_RHSC;
        }
        Some(device)
    }

    /// Plug a device in (it comes up from power-off).
    pub fn plug(&mut self, mut device: Box<dyn UsbDevice>) {
        device.power_cycle();
        self.toggles = [[false; 2]; 16];
        self.device = Some(device);
        if self.port & PS_PPS != 0 {
            self.port |= PS_CCS | PS_CSC;
            self.int_status |= INTR_RHSC;
        }
    }

    fn rhsc_again(&mut self) {
        if self.rhsc_level && self.port & 0x001F_0000 != 0 {
            self.int_status |= INTR_RHSC;
        }
    }

    /// Chip reset. The device stays plugged in.
    pub fn reset(&mut self) {
        let device = self.device.take();
        let (level, latched) = (self.rhsc_level, self.latched);
        *self = Ohci::new();
        self.rhsc_level = level;
        self.latched = latched;
        self.device = device;
        if let Some(d) = &mut self.device {
            d.bus_reset();
        }
    }

    /// Power lost and restored, for the chip and what is plugged in it.
    pub fn power_cycle(&mut self) {
        self.reset();
        if let Some(d) = &mut self.device {
            d.power_cycle();
        }
    }

    fn r(&self, off: u32) -> u32 {
        self.regs[(off / 4) as usize]
    }

    fn ohci_irq(&self) -> bool {
        self.int_enable & INTR_MIE != 0 && self.int_status & self.int_enable & !INTR_MIE != 0
    }

    /// The chip's interrupt status: the core's, or the latch of it.
    fn status(&mut self) -> bool {
        if self.ohci_irq() {
            self.stt_ohci = true;
        }
        if self.latched {
            self.stt_ohci
        } else {
            self.ohci_irq()
        }
    }

    /// Level of the chip's interrupt pin towards the CPU (EXINT2).
    pub fn irq(&mut self) -> bool {
        self.status() && self.r(HOST_CTL) & 2 == 0
    }

    pub fn read(&mut self, off: u32) -> u32 {
        match off {
            HC_REVISION => 0x10,
            HC_INTERRUPT_STATUS => self.int_status,
            HC_INTERRUPT_ENABLE | HC_INTERRUPT_DISABLE => self.int_enable,
            HC_RH_DESCRIPTOR_A => 1,
            HC_RH_STATUS => 0,
            HC_RH_PORT_STATUS => self.port,
            STT_TRNS_CNT => (self.status() as u32) << 1,
            _ => self.r(off),
        }
    }

    pub fn write(&mut self, off: u32, val: u32, mask: u32) {
        let v = val & mask;
        match off {
            HC_INTERRUPT_STATUS => self.int_status &= !v,
            HC_INTERRUPT_ENABLE => self.int_enable |= v,
            HC_INTERRUPT_DISABLE => self.int_enable &= !v,
            HC_COMMAND_STATUS => {
                // Bit 0 is a controller reset that clears itself.
                if v & 1 != 0 {
                    self.reset();
                }
            }
            HC_RH_STATUS => {
                // LPSC written as 1 switches the port power on.
                if v & (1 << 16) != 0 {
                    self.power_port();
                }
            }
            HC_RH_PORT_STATUS => {
                self.port &= !(v & 0x001F_0000);
                if v & PS_PPS != 0 {
                    self.power_port();
                }
                if v & PS_PRS != 0 && self.port & PS_CCS != 0 {
                    self.port |= PS_PRS;
                    self.reset_left = RESET_FRAMES;
                }
                if v & PS_PES != 0 && self.port & PS_CCS != 0 {
                    self.port |= PS_PES;
                }
                if v & PS_CCS != 0 {
                    self.port &= !PS_PES;
                }
            }
            STT_TRNS_CNT => {
                if v & 2 != 0 {
                    self.stt_ohci = false;
                }
            }
            // RstClkCtl's chip reset (B_CRST): the whole controller, its
            // port too, starts over (the device sees a bus reset).
            RST_CLK_CTL if v & CHIP_RESET != 0 => self.reset(),
            _ => {
                let i = (off / 4) as usize;
                self.regs[i] = (self.regs[i] & !mask) | v;
            }
        }
        self.rhsc_again();
    }

    fn power_port(&mut self) {
        if self.port & PS_PPS != 0 {
            return;
        }
        self.port |= PS_PPS;
        if self.device.is_some() {
            self.port |= PS_CCS | PS_CSC;
            self.int_status |= INTR_RHSC;
        }
    }

    /// One millisecond of bus time.
    pub fn frame(&mut self, ram: &mut [u8]) {
        self.rhsc_again();
        if self.reset_left > 0 {
            self.reset_left -= 1;
            if self.reset_left == 0 {
                self.port = (self.port & !PS_PRS) | PS_PES | PS_PRSC;
                self.int_status |= INTR_RHSC;
                self.toggles = [[false; 2]; 16];
                if let Some(d) = &mut self.device {
                    d.bus_reset();
                }
            }
        }
        if self.r(HC_CONTROL) & CTRL_HCFS != USB_OPER {
            return;
        }
        self.frames += 1;
        if let Some(d) = &mut self.device {
            d.frame();
        }
        let mut ram = Ram(ram);

        let fm = (self.r(HC_FM_NUMBER) + 1) & 0xFFFF;
        self.regs[(HC_FM_NUMBER / 4) as usize] = fm;
        let hcca = self.r(HC_HCCA);
        if hcca != 0 {
            // HccaFrameNumber, and the pad word the controller zeroes.
            if ram.wr32(hcca + 0x80, fm).is_none() {
                self.unrecoverable();
                return;
            }
        }
        self.int_status |= INTR_SF;
        if fm == 0 || fm == 0x8000 {
            self.int_status |= INTR_FNO;
        }

        let mut budget = TDS_PER_FRAME;
        self.bus_left = FRAME_BYTES;
        let control = self.r(HC_CONTROL);
        // The control list first, then the bulk list, from one budget.
        for (enable, head) in [(CTRL_CLE, HC_CONTROL_HEAD_ED), (CTRL_BLE, HC_BULK_HEAD_ED)] {
            if control & enable != 0 {
                let head = self.r(head);
                self.serve_list(&mut ram, head, &mut budget);
            }
        }

        // Hand the done queue over, but only once the driver has
        // acknowledged the previous one.
        let done = self.r(HC_DONE_HEAD);
        if done != 0 && self.int_status & INTR_WDH == 0 && hcca != 0 {
            let other = self.int_status & self.int_enable & !(INTR_MIE | INTR_WDH) != 0;
            if ram.wr32(hcca + 0x84, done | other as u32).is_none() {
                self.unrecoverable();
                return;
            }
            self.regs[(HC_DONE_HEAD / 4) as usize] = 0;
            self.int_status |= INTR_WDH;
        }
    }

    fn unrecoverable(&mut self) {
        self.errors += 1;
        self.int_status |= INTR_UE;
    }

    fn serve_list(&mut self, ram: &mut Ram, head: u32, budget: &mut u32) {
        // Round-robin over the list until nothing moves any more.
        loop {
            let mut progressed = false;
            let mut ed = head & !0xF;
            let mut hops = 0;
            while ed != 0 && *budget > 0 {
                hops += 1;
                if hops > 64 {
                    return self.unrecoverable();
                }
                match self.serve_ed(ram, ed) {
                    Some(moved) => {
                        if moved {
                            progressed = true;
                            *budget -= 1;
                        }
                    }
                    None => return self.unrecoverable(),
                }
                ed = match ram.rd32(ed + 12) {
                    Some(n) => n & !0xF,
                    None => return self.unrecoverable(),
                };
            }
            if !progressed || *budget == 0 {
                return;
            }
        }
    }

    /// Try the first TD of an endpoint. `Some(true)` if it was retired.
    fn serve_ed(&mut self, ram: &mut Ram, ed: u32) -> Option<bool> {
        let ed_ctl = ram.rd32(ed)?;
        let tail = ram.rd32(ed + 4)? & !0xF;
        let head_raw = ram.rd32(ed + 8)?;
        let td = head_raw & !0xF;
        if ed_ctl & ED_SKIP != 0 || head_raw & ED_HALT != 0 || td == tail {
            return Some(false);
        }
        let td_ctl = ram.rd32(td)?;
        let cbp = ram.rd32(td + 4)?;
        let next = ram.rd32(td + 8)?;
        let be = ram.rd32(td + 12)?;
        let len = if cbp == 0 {
            0
        } else {
            (be.wrapping_sub(cbp) as usize) + 1
        };
        if len > RAM_SIZE {
            return None;
        }

        let addr = (ed_ctl & 0x7F) as u8;
        let ep = ((ed_ctl >> 7) & 0xF) as u8;
        let mps = (((ed_ctl >> 16) & 0x7FF) as usize).max(1);
        // Direction: from the ED, or from the TD when the ED says so.
        let pid = match (ed_ctl >> 11) & 3 {
            1 => 1,
            2 => 2,
            _ => (td_ctl >> 19) & 3,
        };

        // The toggle of the next packet: the descriptor's own once it
        // has one (its top bit set), else the endpoint's carry.
        let mut toggle = if td_ctl & (1 << 25) != 0 {
            td_ctl & (1 << 24) != 0
        } else {
            head_raw & ED_CARRY != 0
        };
        // Only the bulk endpoints' toggles are the device's to check
        // here; endpoint 0's are set by every stage's descriptor.
        let bulk = ep != 0;
        let mut device_toggles = self.toggles[ep as usize];
        let mut drops = 0;
        // Packets that went through, and the descriptor as they leave
        // it: its toggle field, once a packet moved.
        let mut packets_ok = 0u32;
        // Bytes moved by a transfer the device cut short with a NAK:
        // they stay moved, the rest waits for the next frame.
        let mut partly = None;
        let td_toggle = |td_ctl: u32, packets_ok: u32, toggle: bool| {
            if packets_ok == 0 {
                td_ctl & (3 << 24)
            } else {
                (2 | toggle as u32) << 24
            }
        };

        // Bytes that went through before a packet failed: the buffer
        // pointer is left after them (Linux's `td_done` counts them, from
        // it, as the transfer's actual length, error or not).
        let mut moved_on_error = 0;
        // The bus time left in this frame: a transaction that would not
        // fit waits for the next frame, as one the device answered NAK.
        let mut bus = self.bus_left;
        let fits = |bus: usize, n: usize| bus >= n + TRANSACTION_OVERHEAD;
        let Some(dev) = self.device.as_mut() else {
            return Some(false);
        };
        let outcome = if self.port & PS_PES == 0 || dev.address() != addr {
            None
        } else {
            Some(match pid {
                0 if !fits(bus, 8) => Xfer::Nak,
                0 => {
                    bus -= 8 + TRANSACTION_OVERHEAD;
                    let m = ram.range(cbp, 8)?;
                    let mut pkt = [0u8; 8];
                    pkt.copy_from_slice(m);
                    let x = dev.setup(pkt);
                    if let Xfer::Done(_) = x {
                        packets_ok += 1;
                        toggle = !toggle;
                        // Requests that put the data toggles back to DATA0.
                        match (pkt[0], pkt[1]) {
                            (0x00, 9) | (0x01, 11) => self.toggles = [[false; 2]; 16],
                            (0x02, 1) if pkt[2] == 0 && pkt[3] == 0 => {
                                let n = (pkt[4] & 0xF) as usize;
                                self.toggles[n][(pkt[4] >> 7) as usize] = false;
                            }
                            _ => {}
                        }
                    }
                    x
                }
                1 => {
                    let data = if len == 0 {
                        Vec::new()
                    } else {
                        ram.range(cbp, len)?.to_vec()
                    };
                    let mut sent = 0;
                    let mut result = None;
                    let packets: Vec<&[u8]> = if data.is_empty() {
                        vec![&[]]
                    } else {
                        data.chunks(mps).collect()
                    };
                    for packet in packets {
                        // A repeated toggle: the device takes the packet
                        // for a retry of the last it has, acknowledges it,
                        // and throws it away.
                        let fresh = !bulk || toggle == device_toggles[0];
                        let x = if !fits(bus, packet.len()) {
                            Xfer::Nak
                        } else if fresh {
                            dev.data_out(ep, packet)
                        } else {
                            drops += 1;
                            Xfer::Done(packet.len())
                        };
                        if x != Xfer::Nak {
                            bus = bus.saturating_sub(packet.len() + TRANSACTION_OVERHEAD);
                        }
                        match x {
                            Xfer::Done(_) => {
                                sent += packet.len();
                                packets_ok += 1;
                                toggle = !toggle;
                                if bulk && fresh {
                                    device_toggles[0] = !device_toggles[0];
                                }
                            }
                            Xfer::Nak if sent > 0 => {
                                partly = Some(sent);
                                result = Some(Xfer::Nak);
                                break;
                            }
                            other => {
                                moved_on_error = sent;
                                result = Some(other);
                                break;
                            }
                        }
                    }
                    result.unwrap_or(Xfer::Done(sent))
                }
                _ => {
                    // Packet by packet, until the buffer is full or the
                    // device sends a short one.
                    let mut got = 0;
                    let mut packet = vec![0u8; mps];
                    loop {
                        // Room is kept for a whole packet: the device may
                        // send one.
                        let x = if fits(bus, mps) {
                            dev.data_in(ep, &mut packet)
                        } else {
                            Xfer::Nak
                        };
                        if let Xfer::Done(n) = x {
                            bus -= n.min(mps) + TRANSACTION_OVERHEAD;
                        }
                        match x {
                            Xfer::Done(n) => {
                                // The device sent it with its toggle, and
                                // goes on to the next once acknowledged;
                                // the host throws away one it has.
                                let fresh = !bulk || toggle == device_toggles[1];
                                if bulk {
                                    device_toggles[1] = !device_toggles[1];
                                }
                                if !fresh {
                                    drops += 1;
                                    continue;
                                }
                                packets_ok += 1;
                                toggle = !toggle;
                                let take = n.min(len - got);
                                if take > 0 {
                                    ram.range(cbp + got as u32, take)?
                                        .copy_from_slice(&packet[..take]);
                                }
                                got += take;
                                if n > take {
                                    break Xfer::Done(len + 1);
                                }
                                if n < mps || got == len {
                                    break Xfer::Done(got);
                                }
                            }
                            Xfer::Nak if got > 0 => {
                                partly = Some(got);
                                break Xfer::Nak;
                            }
                            other => {
                                moved_on_error = got;
                                break other;
                            }
                        }
                    }
                }
            })
        };
        self.bus_left = bus;
        if bulk {
            self.toggles[ep as usize] = device_toggles;
        }
        self.toggle_drops += drops;
        if let Some(moved) = partly {
            // Come back next frame for the rest, with its toggle.
            ram.wr32(
                td,
                (td_ctl & !(3 << 24)) | td_toggle(td_ctl, packets_ok, toggle),
            )?;
            ram.wr32(td + 4, cbp + moved as u32)?;
            return Some(false);
        }

        let (cc, moved) = match outcome {
            None => (CC_NOT_RESPONDING, 0),
            Some(Xfer::Nak) => return Some(false),
            Some(Xfer::Stall) => (CC_STALL, moved_on_error),
            Some(Xfer::Done(n)) if n > len => (CC_DATA_OVERRUN, len),
            Some(Xfer::Done(n)) if n < len && td_ctl & (1 << 18) == 0 => (CC_DATA_UNDERRUN, n),
            Some(Xfer::Done(n)) => (CC_NO_ERROR, n),
        };

        // Retire the TD: status, buffer pointer, toggle, done queue.
        let new_cbp = if moved == len { 0 } else { cbp + moved as u32 };
        let t = td_toggle(td_ctl, packets_ok, toggle);
        ram.wr32(td, (td_ctl & 0x00FF_FFFF) | t | (cc << 28))?;
        ram.wr32(td + 4, new_cbp)?;
        let done = self.r(HC_DONE_HEAD);
        ram.wr32(td + 8, done)?;
        self.regs[(HC_DONE_HEAD / 4) as usize] = td;

        // The endpoint carries the toggle of the next packet.
        let carry = if toggle { ED_CARRY } else { 0 };
        let halt = if cc != CC_NO_ERROR { ED_HALT } else { 0 };
        ram.wr32(ed + 8, (next & !0xF) | carry | halt)?;
        Some(true)
    }
}

/// Endpoint 0 bookkeeping shared by device models: collects the stages
/// of a control transfer and hands complete requests to the model.
#[derive(Default)]
pub struct ControlPipe {
    setup: [u8; 8],
    data: Vec<u8>,
    pos: usize,
}

pub struct Setup {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl ControlPipe {
    pub fn current(&self) -> Setup {
        let s = &self.setup;
        Setup {
            request_type: s[0],
            request: s[1],
            value: u16::from_le_bytes([s[2], s[3]]),
            index: u16::from_le_bytes([s[4], s[5]]),
            length: u16::from_le_bytes([s[6], s[7]]),
        }
    }

    fn is_in(&self) -> bool {
        self.setup[0] & 0x80 != 0
    }

    /// SETUP stage. For device-to-host requests `answer` produces the data.
    pub fn setup(
        &mut self,
        packet: [u8; 8],
        answer: impl FnOnce(&Setup) -> Option<Vec<u8>>,
    ) -> Xfer {
        self.setup = packet;
        self.data.clear();
        self.pos = 0;
        if self.is_in() {
            let s = self.current();
            match answer(&s) {
                Some(mut d) => {
                    d.truncate(s.length as usize);
                    self.data = d;
                }
                None => return Xfer::Stall,
            }
        }
        Xfer::Done(8)
    }

    /// IN token on endpoint 0: data stage of a read, or status stage of a
    /// write, in which case `commit` carries the request out.
    pub fn data_in(&mut self, buf: &mut [u8], commit: impl FnOnce(&Setup, &[u8]) -> bool) -> Xfer {
        if self.is_in() {
            let n = buf.len().min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Xfer::Done(n)
        } else if commit(&self.current(), &self.data) {
            Xfer::Done(0)
        } else {
            Xfer::Stall
        }
    }

    /// OUT token on endpoint 0: data stage of a write, or status of a read.
    pub fn data_out(&mut self, data: &[u8]) -> Xfer {
        if !self.is_in() {
            self.data.extend_from_slice(data);
        }
        Xfer::Done(data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A device at address 1 whose bulk endpoint in always has full
    /// packets to give, and stalls the one numbered `stall_at`.
    struct Streaming {
        sent: usize,
        stall_at: Option<usize>,
    }

    impl UsbDevice for Streaming {
        fn bus_reset(&mut self) {}
        fn address(&self) -> u8 {
            1
        }
        fn setup(&mut self, _: [u8; 8]) -> Xfer {
            Xfer::Stall
        }
        fn data_in(&mut self, _: u8, buf: &mut [u8]) -> Xfer {
            self.sent += 1;
            if self.stall_at == Some(self.sent - 1) {
                return Xfer::Stall;
            }
            buf.fill(self.sent as u8);
            Xfer::Done(buf.len())
        }
        fn data_out(&mut self, _: u8, _: &[u8]) -> Xfer {
            Xfer::Stall
        }
    }

    const ED: u32 = RAM_BASE + 0x100;
    const TD: u32 = RAM_BASE + 0x110;
    const SPARE: u32 = RAM_BASE + 0x120;
    const BUFFER: u32 = RAM_BASE + 0x200;

    /// The controller running, the device on its port, one receive
    /// descriptor of `len` bytes on the bulk endpoint in.
    fn streaming(len: u32, stall_at: Option<usize>) -> (Ohci, Vec<u8>) {
        let mut hc = Ohci::new();
        hc.device = Some(Box::new(Streaming { sent: 0, stall_at }));
        hc.port = PS_PPS | PS_CCS | PS_PES;
        let mut ram = vec![0u8; RAM_SIZE];
        let mut r = Ram(&mut ram);
        r.wr32(ED, 1 | 1 << 7 | 2 << 11 | 64 << 16).unwrap();
        r.wr32(ED + 4, SPARE).unwrap();
        r.wr32(ED + 8, TD).unwrap();
        r.wr32(TD, 1 << 18 | 2 << 19 | 0xF << 28).unwrap();
        r.wr32(TD + 4, BUFFER).unwrap();
        r.wr32(TD + 8, SPARE).unwrap();
        r.wr32(TD + 12, BUFFER + len - 1).unwrap();
        hc.write(HC_HCCA, RAM_BASE, !0);
        hc.write(HC_BULK_HEAD_ED, ED, !0);
        hc.write(HC_CONTROL, CTRL_BLE | USB_OPER, !0);
        (hc, ram)
    }

    fn word(ram: &mut [u8], at: u32) -> u32 {
        Ram(ram).rd32(at).unwrap()
    }

    /// A full-speed frame carries nineteen bulk packets of 64 bytes at
    /// most: a transfer of more waits for the next frame for the rest.
    #[test]
    fn a_frame_carries_nineteen_full_packets_at_most() {
        let (mut hc, mut ram) = streaming(40 * 64, None);
        hc.frame(&mut ram);
        assert_eq!(word(&mut ram, TD) >> 28, 0xF, "not retired yet");
        assert_eq!(word(&mut ram, TD + 4), BUFFER + 19 * 64);
        hc.frame(&mut ram);
        assert_eq!(word(&mut ram, TD + 4), BUFFER + 38 * 64);
        hc.frame(&mut ram);
        assert_eq!(word(&mut ram, TD) >> 28, CC_NO_ERROR);
        assert_eq!(word(&mut ram, TD + 4), 0, "all of it");
    }

    /// A packet that fails retires its descriptor with the buffer
    /// pointer after the packets that went through.
    #[test]
    fn a_failed_packet_leaves_the_buffer_pointer_after_those_that_went() {
        let (mut hc, mut ram) = streaming(8 * 64, Some(3));
        hc.frame(&mut ram);
        assert_eq!(word(&mut ram, TD) >> 28, CC_STALL);
        assert_eq!(word(&mut ram, TD + 4), BUFFER + 3 * 64);
        assert_eq!(ram[0x200 + 3 * 64 - 1], 3, "the third packet is in");
    }
}
