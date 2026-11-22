//! The Ralink RT2573 Wi-Fi stick soldered on the board, seen from USB.
//!
//! The model keeps the chip's register file, EEPROM and key tables, and
//! turns bulk transfers into frames on a shared [`Radio`]: what the
//! firmware transmits lands in `Radio::tx`, what a test puts in
//! `Radio::rx` is received by the firmware. Like the real chip, the model
//! encrypts and decrypts (WEP, TKIP, CCMP) with the keys the firmware
//! loaded into its shared key table, so the frames on the air are real.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::crypto::{self, Cipher, CipherError, Key};
use crate::ohci::{ControlPipe, Setup, UsbDevice, Xfer};

const PACKET: usize = 64;
const TXD_SIZE: usize = 24;
const RXD_SIZE: usize = 24;

const REQ_DEVICE_MODE: u8 = 0x01;
const REQ_WRITE_MULTI_MAC: u8 = 0x06;
const REQ_READ_MULTI_MAC: u8 = 0x07;
const REQ_READ_EEPROM: u8 = 0x09;

const SHARED_KEY_TABLE: usize = 0x1000;
const PAIRWISE_KEY_TABLE: usize = 0x1200;
const KEY_ENTRY_SIZE: usize = 32;
const MAC_CSR2: usize = 0x3008;
const MAC_CSR12: usize = 0x3030;
const TXRX_CSR0: usize = 0x3040;
const PHY_CSR3: usize = 0x308C;
const PHY_CSR4: usize = 0x3090;

const TXRX_CSR9: usize = 0x3064;
const HW_BEACON_BASE0: usize = 0x2400;
/// Power-on value of TXRX_CSR9: a beacon interval of 100 time units.
/// The firmware never writes the interval and its beacons announce
/// 100, so the chip must start with it; the value is inferred.
const BEACON_DEFAULT: u32 = 100 * 16;
const SEC_CSR0: usize = 0x30A0;
const SEC_CSR1: usize = 0x30A4;

/// A frame on the air, exactly as transmitted (without its FCS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFrame {
    pub data: Vec<u8>,
    pub channel: u8,
}

/// A frame arriving at the stick's antenna.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RxFrame {
    pub data: Vec<u8>,
    /// Raw RSSI byte as the baseband reports it.
    pub rssi: u8,
}

impl RxFrame {
    pub fn new(data: Vec<u8>) -> Self {
        RxFrame {
            data,
            rssi: 0x79 + 50,
        }
    }
}

/// What the chip calls its cipher algorithms, as our cipher and key length.
fn cipher_of(alg: u32) -> Option<(Cipher, usize)> {
    match alg {
        1 => Some((Cipher::Wep, 5)),
        2 => Some((Cipher::Wep, 13)),
        3 => Some((Cipher::Tkip, 16)),
        4 => Some((Cipher::Ccmp, 16)),
        _ => None,
    }
}

/// The air side of the stick, shared with whoever plays the access point.
#[derive(Default)]
pub struct Radio {
    pub tx: VecDeque<TxFrame>,
    pub rx: VecDeque<RxFrame>,
    pub channel: u8,
    pub mac: [u8; 6],
    pub rx_enabled: bool,
    pub firmware_loaded: bool,
    /// Frames dropped because the receiver was off or they were not for us.
    pub rx_dropped: u64,
    /// Protected frames received that failed to decrypt, by cause.
    pub rx_cipher_errors: [u64; 4],
}

pub type SharedRadio = Rc<RefCell<Radio>>;

pub struct Rt2573 {
    address: u8,
    pending_address: Option<u8>,
    configured: bool,
    ctrl: ControlPipe,
    mem: Vec<u8>,
    bbp: [u8; 128],
    eeprom: [u8; 256],
    rf_r2: u32,
    rf_r4: u32,
    tx_seq: u16,
    beacon_wait: u32,
    beacons: u64,
    out: Vec<u8>,
    inbound: Vec<u8>,
    in_pos: usize,
    radio: SharedRadio,
}

fn device_descriptor() -> Vec<u8> {
    vec![
        18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x8F, 0x14, 0x73, 0x25, 0x01, 0x00, 1, 2, 0, 1,
    ]
}

fn config_descriptor() -> Vec<u8> {
    vec![
        9, 2, 32, 0, 1, 1, 0, 0x80, 150, // configuration
        9, 4, 0, 0, 2, 0xFF, 0xFF, 0xFF, 0, // interface
        7, 5, 0x81, 2, 64, 0, 0, // bulk IN
        7, 5, 0x01, 2, 64, 0, 0, // bulk OUT
    ]
}

impl Rt2573 {
    /// The same stick with another radio chip named in its calibration
    /// data (1 RT5226, 2 RT2528, 3 RT5225, 4 RT2527). Only the name
    /// changes: the model stays that of the RT2528.
    pub fn with_radio_chip(mut self, chip: u8) -> Self {
        self.eeprom[0x21] = (self.eeprom[0x21] & 0x07) | chip << 3;
        self
    }

    pub fn new(mac: [u8; 6]) -> (Self, SharedRadio) {
        let radio = Rc::new(RefCell::new(Radio::default()));
        let mut eeprom = [0xFFu8; 256];
        eeprom[4..10].copy_from_slice(&mac);
        // Antenna word: two antennas, defaults on A, RF chip RT2528.
        let antenna: u16 = 2 | (1 << 2) | (1 << 4) | (2 << 11);
        eeprom[0x20..0x22].copy_from_slice(&antenna.to_le_bytes());
        // Per-channel transmit power, a mid-range value everywhere.
        eeprom[0x46..0x54].fill(12);
        let mut bbp = [0u8; 128];
        bbp[0] = 0x16;
        let mut mem = vec![0; 0x4000];
        mem[TXRX_CSR9..TXRX_CSR9 + 4].copy_from_slice(&BEACON_DEFAULT.to_le_bytes());
        (
            Rt2573 {
                address: 0,
                pending_address: None,
                configured: false,
                ctrl: ControlPipe::default(),
                mem,
                bbp,
                eeprom,
                rf_r2: 0,
                rf_r4: 0,
                tx_seq: 0,
                beacon_wait: 0,
                beacons: 0,
                out: Vec::new(),
                inbound: Vec::new(),
                in_pos: 0,
                radio: radio.clone(),
            },
            radio,
        )
    }

    fn word(&self, reg: usize) -> u32 {
        u32::from_le_bytes(self.mem[reg..reg + 4].try_into().unwrap())
    }

    fn read_mem(&self, s: &Setup) -> Option<Vec<u8>> {
        let start = s.index as usize;
        let end = start.checked_add(s.length as usize)?;
        let mut data = self.mem.get(start..end)?.to_vec();
        if start <= MAC_CSR12 && MAC_CSR12 < end {
            // Awake, baseband and RF ready.
            data[MAC_CSR12 - start] |= 0x09;
        }
        Some(data)
    }

    fn write_mem(&mut self, s: &Setup, data: &[u8]) -> bool {
        let start = s.index as usize;
        let Some(end) = start.checked_add(data.len()) else {
            return false;
        };
        let Some(slot) = self.mem.get_mut(start..end) else {
            return false;
        };
        slot.copy_from_slice(data);
        if start <= PHY_CSR3 && PHY_CSR3 + 4 <= end {
            self.bbp_access();
        }
        if start <= PHY_CSR4 && PHY_CSR4 + 4 <= end {
            self.rf_access();
        }
        if start <= TXRX_CSR0 + 3 && TXRX_CSR0 < end {
            self.radio.borrow_mut().rx_enabled = self.word(TXRX_CSR0) & (1 << 16) == 0;
        }
        if start <= MAC_CSR2 + 7 && MAC_CSR2 < end {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&self.mem[MAC_CSR2..MAC_CSR2 + 6]);
            self.radio.borrow_mut().mac = mac;
        }
        true
    }

    /// PHY_CSR3 was written: carry out the baseband register access.
    fn bbp_access(&mut self) {
        let w = self.word(PHY_CSR3);
        if w & (1 << 16) == 0 {
            return;
        }
        let reg = ((w >> 8) & 0x7F) as usize;
        let done = if w & (1 << 15) != 0 {
            (w & 0xFF00) | self.bbp[reg] as u32
        } else {
            self.bbp[reg] = w as u8;
            w & 0xFFFF
        };
        self.mem[PHY_CSR3..PHY_CSR3 + 4].copy_from_slice(&done.to_le_bytes());
    }

    /// PHY_CSR4 was written: a word was shifted out to the RF chip.
    fn rf_access(&mut self) {
        let w = self.word(PHY_CSR4);
        match w & 3 {
            2 => self.rf_r2 = w,
            3 => self.rf_r4 = w,
            _ => {}
        }
        self.mem[PHY_CSR4..PHY_CSR4 + 4].copy_from_slice(&(w & 0x7FFF_FFFF).to_le_bytes());
        // Channel from the RT2528 synthesiser words (two channels share
        // an R2 value, R4 tells them apart).
        let step = ((self.rf_r2 & 0xFFFFC).wrapping_sub(0x784)) / 4;
        let channel = match (step, self.rf_r4 & 0xFF) {
            (7, _) => 14,
            (0..=6, 0x1F) => step * 2 + 2,
            (0..=6, _) => step * 2 + 1,
            _ => 0,
        };
        self.radio.borrow_mut().channel = channel as u8;
    }

    fn control_read(&self, s: &Setup) -> Option<Vec<u8>> {
        match (s.request_type, s.request) {
            (0x80, 6) => match s.value >> 8 {
                1 => Some(device_descriptor()),
                2 => Some(config_descriptor()),
                _ => None,
            },
            (0x80, 0) => Some(vec![0, 0]),
            (0x80, 8) => Some(vec![self.configured as u8]),
            (0xC0, REQ_READ_MULTI_MAC) => self.read_mem(s),
            (0xC0, REQ_READ_EEPROM) => {
                let start = s.index as usize;
                self.eeprom
                    .get(start..start + s.length as usize)
                    .map(|d| d.to_vec())
            }
            _ => None,
        }
    }

    fn control_write(&mut self, s: &Setup, data: &[u8]) -> bool {
        match (s.request_type, s.request) {
            (0x00, 5) => {
                self.pending_address = Some(s.value as u8 & 0x7F);
                true
            }
            (0x00, 9) => {
                self.configured = s.value != 0;
                true
            }
            (0x00, 1) | (0x00, 3) | (0x02, 1) => true,
            (0x40, REQ_WRITE_MULTI_MAC) => self.write_mem(s, data),
            (0x40, REQ_DEVICE_MODE) => {
                if s.value == 0x08 {
                    self.radio.borrow_mut().firmware_loaded = true;
                }
                true
            }
            _ => false,
        }
    }

    /// A complete bulk OUT transfer: descriptor, then the frame. The chip
    /// numbers the frame, encrypts it if asked to, and sends it.
    fn transmit(&mut self) {
        let buf = std::mem::take(&mut self.out);
        if buf.len() < TXD_SIZE {
            return;
        }
        let word = |i: usize| u32::from_le_bytes(buf[i * 4..i * 4 + 4].try_into().unwrap());
        let (w0, w1) = (word(0), word(1));
        let len = ((w0 >> 16) & 0xFFF) as usize;
        let Some(data) = buf.get(TXD_SIZE..TXD_SIZE + len) else {
            return;
        };
        let mut frame = data.to_vec();
        if w1 & (1 << 28) != 0 && frame.len() >= crypto::HEADER_LEN {
            frame[22..24].copy_from_slice(&(self.tx_seq << 4).to_le_bytes());
            self.tx_seq = (self.tx_seq + 1) & 0xFFF;
        }
        if let Some((cipher, key_len)) = cipher_of(w0 >> 29)
            && frame.len() >= crypto::HEADER_LEN
        {
            let base = if w0 & (1 << 9) != 0 {
                PAIRWISE_KEY_TABLE
            } else {
                SHARED_KEY_TABLE
            };
            let entry = base + ((w0 >> 10) & 0x3F) as usize * KEY_ENTRY_SIZE;
            let Some(entry) = self.mem.get(entry..entry + KEY_ENTRY_SIZE) else {
                return;
            };
            let key = Key {
                cipher,
                key: &entry[..key_len],
                mic: entry[16..24].try_into().unwrap(),
            };
            frame = crypto::protect(&key, &frame, word(3), word(4));
        }
        let mut radio = self.radio.borrow_mut();
        let channel = radio.channel;
        radio.tx.push_back(TxFrame {
            data: frame,
            channel,
        });
    }

    /// Decrypt a protected frame with the shared key its header names.
    /// Returns the frame to hand over and the descriptor's cipher
    /// fields: algorithm, error code, key index, IV, EIV.
    fn decrypt(&self, mpdu: Vec<u8>) -> (Vec<u8>, u32, u32, u32, u32, u32) {
        let protected =
            mpdu.len() > crypto::HEADER_LEN + 4 && mpdu[1] & 0x40 != 0 && mpdu[0] & 0x0C == 0x08;
        if !protected {
            return (mpdu, 0, 0, 0, 0, 0);
        }
        let index = (mpdu[27] >> 6) as usize;
        let alg = (self.word(SEC_CSR1) >> (index * 4)) & 7;
        let valid = self.word(SEC_CSR0) & (1 << index) != 0;
        let Some((cipher, key_len)) = cipher_of(alg).filter(|_| valid) else {
            // No usable key: the frame goes up as it came, flagged.
            return (mpdu, 0, 3, index as u32, 0, 0);
        };
        let entry = &self.mem[SHARED_KEY_TABLE + index * KEY_ENTRY_SIZE..][..KEY_ENTRY_SIZE];
        let key = Key {
            cipher,
            key: &entry[..key_len],
            mic: entry[24..32].try_into().unwrap(),
        };
        match crypto::unprotect(&key, &mpdu) {
            Ok((clear, iv, eiv)) => (clear, alg, 0, index as u32, iv, eiv),
            Err(CipherError::Mic) => (mpdu, alg, 2, index as u32, 0, 0),
            Err(_) => (mpdu, alg, 1, index as u32, 0, 0),
        }
    }

    /// Take the next frame off the air, if the receiver wants it.
    fn load_inbound(&mut self) -> bool {
        loop {
            let (f, mine, group) = {
                let mut radio = self.radio.borrow_mut();
                let Some(f) = radio.rx.pop_front() else {
                    return false;
                };
                let to = f.data.get(4..10).unwrap_or(&[]);
                let group = to.first().is_some_and(|b| b & 1 != 0);
                let mine = to == radio.mac;
                if !radio.rx_enabled || f.data.len() < 10 || !(group || mine) {
                    radio.rx_dropped += 1;
                    continue;
                }
                (f, mine, group)
            };
            let broadcast = f.data[4..10] == [0xFF; 6];
            let (data, alg, err, index, iv, eiv) = self.decrypt(f.data);
            if err != 0 {
                self.radio.borrow_mut().rx_cipher_errors[err as usize] += 1;
            }
            let w0: u32 = (mine as u32) << 2
                | ((group && !broadcast) as u32) << 3
                | (broadcast as u32) << 4
                | 1 << 5
                | err << 8
                | index << 10
                | (data.len() as u32 & 0xFFF) << 16
                | alg << 29;
            let w1: u32 = (f.rssi as u32) << 8;
            let mut buf = Vec::with_capacity(RXD_SIZE + data.len() + 4);
            buf.extend_from_slice(&w0.to_le_bytes());
            buf.extend_from_slice(&w1.to_le_bytes());
            buf.extend_from_slice(&iv.to_le_bytes());
            buf.extend_from_slice(&eiv.to_le_bytes());
            buf.extend_from_slice(&[0; 8]);
            buf.extend_from_slice(&data);
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
            // A transfer ends on a short packet, so never an exact multiple.
            if buf.len() % PACKET == 0 {
                buf.extend_from_slice(&[0; 4]);
            }
            self.inbound = buf;
            self.in_pos = 0;
            return true;
        }
    }
}

impl UsbDevice for Rt2573 {
    fn bus_reset(&mut self) {
        self.address = 0;
        self.pending_address = None;
        self.configured = false;
        self.out.clear();
        self.inbound.clear();
        self.in_pos = 0;
    }

    fn power_cycle(&mut self) {
        self.bus_reset();
        self.mem.fill(0);
        self.mem[TXRX_CSR9..TXRX_CSR9 + 4].copy_from_slice(&BEACON_DEFAULT.to_le_bytes());
        self.bbp = [0; 128];
        self.bbp[0] = 0x16;
        self.tx_seq = 0;
        let mut radio = self.radio.borrow_mut();
        radio.rx.clear();
        radio.rx_enabled = false;
        radio.firmware_loaded = false;
        radio.channel = 0;
    }

    /// Once a millisecond: when the beacon generator is on, the chip
    /// sends the frame stored in its beacon memory at every interval.
    fn frame(&mut self) {
        let csr9 = self.word(TXRX_CSR9);
        if csr9 & (1 << 20) == 0 {
            self.beacon_wait = 0;
            return;
        }
        // The interval is in sixteenths of a time unit (1.024 ms).
        let interval = ((csr9 & 0xFFFF) / 16).max(1);
        self.beacon_wait += 1;
        if self.beacon_wait < interval {
            return;
        }
        self.beacon_wait = 0;
        let len = ((self.word(HW_BEACON_BASE0) >> 16) & 0xFFF) as usize;
        let start = HW_BEACON_BASE0 + TXD_SIZE;
        let Some(frame) = self.mem.get(start..start + len).filter(|f| f.len() >= 36) else {
            return;
        };
        let mut frame = frame.to_vec();
        frame[22..24].copy_from_slice(&(self.tx_seq << 4).to_le_bytes());
        self.tx_seq = (self.tx_seq + 1) & 0xFFF;
        self.beacons += 1;
        frame[24..32].copy_from_slice(&(self.beacons * interval as u64 * 1024).to_le_bytes());
        let mut radio = self.radio.borrow_mut();
        let channel = radio.channel;
        radio.tx.push_back(TxFrame {
            data: frame,
            channel,
        });
    }

    fn address(&self) -> u8 {
        self.address
    }

    fn setup(&mut self, packet: [u8; 8]) -> Xfer {
        let mut ctrl = std::mem::take(&mut self.ctrl);
        let x = ctrl.setup(packet, |s| self.control_read(s));
        self.ctrl = ctrl;
        x
    }

    fn data_in(&mut self, ep: u8, buf: &mut [u8]) -> Xfer {
        if ep == 0 {
            let mut ctrl = std::mem::take(&mut self.ctrl);
            let x = ctrl.data_in(buf, |s, d| self.control_write(s, d));
            self.ctrl = ctrl;
            // A new address takes effect once the status stage is over.
            if let Some(a) = self.pending_address.take() {
                self.address = a;
            }
            return x;
        }
        if ep != 1 {
            return Xfer::Stall;
        }
        if self.in_pos >= self.inbound.len() && !self.load_inbound() {
            return Xfer::Nak;
        }
        let n = buf.len().min(PACKET).min(self.inbound.len() - self.in_pos);
        buf[..n].copy_from_slice(&self.inbound[self.in_pos..self.in_pos + n]);
        self.in_pos += n;
        Xfer::Done(n)
    }

    fn data_out(&mut self, ep: u8, data: &[u8]) -> Xfer {
        match ep {
            0 => self.ctrl.data_out(data),
            1 => {
                self.out.extend_from_slice(data);
                if data.len() < PACKET {
                    self.transmit();
                }
                Xfer::Done(data.len())
            }
            _ => Xfer::Stall,
        }
    }
}
