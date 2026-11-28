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
/// The longest frame the receiver passes (bits 0-11).
const MAC_CSR6: usize = 0x3018;
const HW_BEACON_BASE0: usize = 0x2400;
/// Power-on value of TXRX_CSR9: a beacon interval of 100 time units.
/// The firmware never writes the interval and its beacons announce
/// 100, so the chip must start with it; the value is inferred.
const BEACON_DEFAULT: u32 = 100 * 16;
const SEC_CSR0: usize = 0x30A0;
const SEC_CSR1: usize = 0x30A4;
/// Pairwise key table valid bits, entries 0-31 and 32-63.
const SEC_CSR2: usize = 0x30A8;
const SEC_CSR3: usize = 0x30AC;
/// Pairwise key lookup on, one bit per BSS.
const SEC_CSR4: usize = 0x30B0;
/// Transmitter addresses of the pairwise keys: address, cipher, spare.
const PAIRWISE_TA_TABLE: usize = 0x1A00;
const PAIRWISE_ENTRIES: usize = 64;

/// A frame on the air, exactly as transmitted (without its FCS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFrame {
    pub data: Vec<u8>,
    pub channel: u8,
}

/// The RSSI byte frames arrive with unless the sender says otherwise.
pub const DEFAULT_RSSI: u8 = 0x79 + 50;

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
            rssi: DEFAULT_RSSI,
        }
    }
}

/// The key in an entry of a key table: the key, then the Michael keys
/// of the transmit and of the receive direction.
fn entry_key(entry: &[u8], cipher: Cipher, key_len: usize, rx: bool) -> Key<'_> {
    let mic = if rx { &entry[24..32] } else { &entry[16..24] };
    Key {
        cipher,
        key: &entry[..key_len],
        mic: mic.try_into().unwrap(),
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
    /// The RF chip the stick carries, as its calibration data numbers
    /// them: 2 an RT2528 (also what 0 stands for), 4 an RT2527. Each
    /// tunes only on its own synthesiser words; the other two (1 an
    /// RT5226, 3 an RT5225) are named to the firmware but not modelled.
    pub rf_chip: u8,
    /// The bulk endpoint out answers NAK to every packet while set: a
    /// stick that has stopped taking frames to send.
    pub tx_stuck: bool,
    /// The bulk endpoint in stalls every transfer while set: a stick
    /// that has stopped delivering what it receives.
    pub rx_stall: bool,
    /// Receive descriptors leave the IV words of a decrypted frame zero,
    /// as a stick might that does not report them (nothing has shown
    /// the RT2573 does; the C driver never read them).
    pub rx_no_iv: bool,
    /// Faults to inject. The next this many control requests are
    /// refused at their setup stage (a stall), as a stick still coming
    /// up may do.
    pub refuse_requests: u32,
    /// The status stage of the request that starts the stick's own
    /// firmware answers NAK for this many milliseconds.
    pub firmware_start_nak_ms: u32,
    /// Writes to the baseband's command register are refused (stall).
    pub refuse_bbp: bool,
    /// This packet (counting from 0) of the next frame handed over the
    /// bulk endpoint in fails (a stall) and its bytes are lost.
    pub lose_rx_packet: Option<usize>,
    /// Frames longer than MAC_CSR6 allows are handed over all the same,
    /// as a broken (or lying) stick might: the firmware's reassembly
    /// then sees a transfer longer than any it should.
    pub rx_any_length: bool,
    /// Every baseband register write, in order: (register, value).
    pub bbp_writes: Vec<(u8, u8)>,
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
            self.radio
                .borrow_mut()
                .bbp_writes
                .push((reg as u8, w as u8));
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
        // Channel from the synthesiser words (two channels share an R2
        // value, R4 tells them apart). An RT2527 takes words of 21 bits
        // with other fixed bits than the RT2528's 20: a chip sent the
        // other's words tunes nowhere.
        let (bits, r2_base) = match self.radio.borrow().rf_chip {
            0 | 2 => (20, 0x0784),
            4 => (21, 0x4784),
            _ => (0, 0),
        };
        let fits = |w: u32| (w >> 24) & 0x1F == bits;
        let step = if fits(self.rf_r2) && fits(self.rf_r4) {
            ((self.rf_r2 & 0xFFFFC).wrapping_sub(r2_base)) / 4
        } else {
            u32::MAX
        };
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
                let mut eeprom = self.eeprom;
                match self.radio.borrow().rf_chip {
                    0 => {}
                    chip => eeprom[0x21] = (eeprom[0x21] & 0x07) | chip << 3,
                }
                eeprom
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
            (0x40, REQ_WRITE_MULTI_MAC) => {
                let at = s.index as usize;
                let touches_bbp = at <= PHY_CSR3 && PHY_CSR3 < at + data.len().max(1);
                if touches_bbp && self.radio.borrow().refuse_bbp {
                    return false;
                }
                self.write_mem(s, data)
            }
            (0x40, REQ_DEVICE_MODE) => {
                if s.value == 0x08 {
                    self.radio.borrow_mut().firmware_loaded = true;
                }
                true
            }
            _ => false,
        }
    }

    /// Give a frame the chip's next sequence number.
    fn number(&mut self, frame: &mut [u8]) {
        frame[22..24].copy_from_slice(&(self.tx_seq << 4).to_le_bytes());
        self.tx_seq = (self.tx_seq + 1) & 0xFFF;
    }

    /// Put a frame on the air, on the channel the radio is tuned to.
    fn send(&self, frame: Vec<u8>) {
        let mut radio = self.radio.borrow_mut();
        let channel = radio.channel;
        radio.tx.push_back(TxFrame {
            data: frame,
            channel,
        });
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
            self.number(&mut frame);
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
            let key = entry_key(entry, cipher, key_len, false);
            frame = crypto::protect(&key, &frame, word(3), word(4));
        }
        self.send(frame);
    }

    /// The pairwise key entry for frames from this transmitter, when
    /// pairwise lookup is on for BSS 0 and a valid entry holds its
    /// address (as Linux's rt73usb programs the table).
    fn pairwise_entry(&self, ta: &[u8]) -> Option<(usize, u32)> {
        if self.word(SEC_CSR4) & 1 == 0 {
            return None;
        }
        (0..PAIRWISE_ENTRIES).find_map(|i| {
            let bits = if i < 32 {
                self.word(SEC_CSR2)
            } else {
                self.word(SEC_CSR3)
            };
            let entry = &self.mem[PAIRWISE_TA_TABLE + i * 8..][..8];
            (bits & (1 << (i % 32)) != 0 && entry[..6] == *ta).then_some((i, entry[6] as u32 & 7))
        })
    }

    /// Decrypt a protected data frame: with the pairwise key of its
    /// transmitter when the pairwise table has one (frames to us alone),
    /// otherwise with the shared key its header names. Management frames
    /// are left alone: the chip cannot protect them. Returns the frame to
    /// hand over and the descriptor's cipher fields: algorithm, error
    /// code, key index, IV, EIV.
    fn decrypt(&self, mpdu: Vec<u8>) -> (Vec<u8>, u32, u32, u32, u32, u32) {
        let protected =
            mpdu.len() > crypto::HEADER_LEN + 4 && mpdu[1] & 0x40 != 0 && mpdu[0] & 0x0C == 0x08;
        if !protected {
            return (mpdu, 0, 0, 0, 0, 0);
        }
        let unicast = mpdu[4] & 1 == 0;
        let (base, index, alg, valid) = match self.pairwise_entry(&mpdu[10..16]).filter(|_| unicast)
        {
            Some((i, alg)) => (PAIRWISE_KEY_TABLE, i, alg, true),
            None => {
                let index = (mpdu[27] >> 6) as usize;
                let alg = (self.word(SEC_CSR1) >> (index * 4)) & 7;
                let valid = self.word(SEC_CSR0) & (1 << index) != 0;
                (SHARED_KEY_TABLE, index, alg, valid)
            }
        };
        let Some((cipher, key_len)) = cipher_of(alg).filter(|_| valid) else {
            // No usable key: the frame goes up as it came, flagged.
            return (mpdu, 0, 3, index as u32, 0, 0);
        };
        let entry = &self.mem[base + index * KEY_ENTRY_SIZE..][..KEY_ENTRY_SIZE];
        let key = entry_key(entry, cipher, key_len, true);
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
                let max = (self.word(MAC_CSR6) & 0xFFF) as usize;
                let too_long = max != 0 && f.data.len() > max && !radio.rx_any_length;
                if !radio.rx_enabled || f.data.len() < 10 || !(group || mine) || too_long {
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
            // Words 2 and 3, the IV of what it decrypted; left zero by a
            // stick that does not report them (`rx_no_iv`).
            let (iv, eiv) = if self.radio.borrow().rx_no_iv {
                (0, 0)
            } else {
                (iv, eiv)
            };
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
        self.number(&mut frame);
        self.beacons += 1;
        frame[24..32].copy_from_slice(&(self.beacons * interval as u64 * 1024).to_le_bytes());
        self.send(frame);
    }

    fn address(&self) -> u8 {
        self.address
    }

    fn setup(&mut self, packet: [u8; 8]) -> Xfer {
        {
            let mut radio = self.radio.borrow_mut();
            if radio.refuse_requests > 0 {
                radio.refuse_requests -= 1;
                return Xfer::Stall;
            }
        }
        let mut ctrl = std::mem::take(&mut self.ctrl);
        let x = ctrl.setup(packet, |s| self.control_read(s));
        self.ctrl = ctrl;
        x
    }

    fn data_in(&mut self, ep: u8, buf: &mut [u8]) -> Xfer {
        if ep == 0 {
            let s = self.ctrl.current();
            if (s.request_type, s.request, s.value) == (0x40, REQ_DEVICE_MODE, 0x08) {
                let mut radio = self.radio.borrow_mut();
                if radio.firmware_start_nak_ms > 0 {
                    radio.firmware_start_nak_ms -= 1;
                    return Xfer::Nak;
                }
            }
            let mut ctrl = std::mem::take(&mut self.ctrl);
            let x = ctrl.data_in(buf, |s, d| self.control_write(s, d));
            self.ctrl = ctrl;
            // A new address takes effect once the status stage is over.
            if let Some(a) = self.pending_address.take() {
                self.address = a;
            }
            return x;
        }
        if ep != 1 || self.radio.borrow().rx_stall {
            return Xfer::Stall;
        }
        if self.in_pos >= self.inbound.len() && !self.load_inbound() {
            return Xfer::Nak;
        }
        let n = buf.len().min(PACKET).min(self.inbound.len() - self.in_pos);
        {
            let mut radio = self.radio.borrow_mut();
            if radio.lose_rx_packet == Some(self.in_pos / PACKET) {
                radio.lose_rx_packet = None;
                self.in_pos += n;
                return Xfer::Stall;
            }
        }
        buf[..n].copy_from_slice(&self.inbound[self.in_pos..self.in_pos + n]);
        self.in_pos += n;
        Xfer::Done(n)
    }

    fn data_out(&mut self, ep: u8, data: &[u8]) -> Xfer {
        match ep {
            0 => self.ctrl.data_out(data),
            1 if self.radio.borrow().tx_stuck => Xfer::Nak,
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

#[cfg(test)]
mod tests {
    use super::*;

    const AP: [u8; 6] = [2, 0, 0, 0, 0, 0xA1];
    const ME: [u8; 6] = [0, 0x19, 0xDB, 0, 0, 1];
    const TK: [u8; 16] = [0x5A; 16];

    fn sealed(to: [u8; 6], fc0: u8, key_id: u8) -> Vec<u8> {
        let mut f = vec![fc0, 0x02, 0, 0];
        f.extend_from_slice(&to);
        f.extend_from_slice(&AP);
        f.extend_from_slice(&AP);
        f.extend_from_slice(&[0x10, 0]);
        f.extend_from_slice(b"\xAA\xAA\x03\x00\x00\x00\x08\x00bonjour");
        let key = Key {
            cipher: Cipher::Ccmp,
            key: &TK,
            mic: &[0; 8],
        };
        crypto::protect(&key, &f, 0x2000_0001 | (key_id as u32) << 30, 0)
    }

    /// A stick with a CCMP pairwise key for the access point in entry 3,
    /// as Linux's rt73usb loads one.
    fn stick_with_pairwise_key() -> Rt2573 {
        let (mut s, _) = Rt2573::new(ME);
        s.mem[PAIRWISE_KEY_TABLE + 3 * KEY_ENTRY_SIZE..][..16].copy_from_slice(&TK);
        let ta = PAIRWISE_TA_TABLE + 3 * 8;
        s.mem[ta..ta + 6].copy_from_slice(&AP);
        s.mem[ta + 6] = 4;
        s.mem[SEC_CSR2..SEC_CSR2 + 4].copy_from_slice(&(1u32 << 3).to_le_bytes());
        s.mem[SEC_CSR4..SEC_CSR4 + 4].copy_from_slice(&1u32.to_le_bytes());
        s
    }

    #[test]
    fn frames_to_us_are_opened_with_their_transmitters_pairwise_key() {
        let s = stick_with_pairwise_key();
        let (clear, alg, err, index, iv, _) = s.decrypt(sealed(ME, 0x08, 0));
        assert_eq!((alg, err, index), (4, 0, 3));
        assert_eq!(iv & 0xFFFF, 1);
        assert!(clear.ends_with(b"bonjour"));
    }

    #[test]
    fn without_pairwise_lookup_the_shared_table_is_used() {
        let mut s = stick_with_pairwise_key();
        s.mem[SEC_CSR4..SEC_CSR4 + 4].fill(0);
        let (_, _, err, index, _, _) = s.decrypt(sealed(ME, 0x08, 0));
        assert_eq!((err, index), (3, 0), "no valid shared key 0");
        // An invalid entry is not looked at either.
        let mut s = stick_with_pairwise_key();
        s.mem[SEC_CSR2..SEC_CSR2 + 4].fill(0);
        assert_eq!(s.decrypt(sealed(ME, 0x08, 0)).2, 3);
    }

    #[test]
    fn group_frames_use_the_shared_key_their_header_names() {
        let mut s = stick_with_pairwise_key();
        s.mem[SHARED_KEY_TABLE + KEY_ENTRY_SIZE..][..16].copy_from_slice(&TK);
        s.mem[SEC_CSR0..SEC_CSR0 + 4].copy_from_slice(&2u32.to_le_bytes());
        s.mem[SEC_CSR1..SEC_CSR1 + 4].copy_from_slice(&(4u32 << 4).to_le_bytes());
        let (clear, alg, err, index, _, _) = s.decrypt(sealed([0xFF; 6], 0x08, 1));
        assert_eq!((alg, err, index), (4, 0, 1));
        assert!(clear.ends_with(b"bonjour"));
    }

    #[test]
    fn protected_management_frames_are_handed_over_as_they_came() {
        let s = stick_with_pairwise_key();
        let frame = sealed(ME, 0xC0, 0);
        let (out, alg, err, ..) = s.decrypt(frame.clone());
        assert_eq!((alg, err), (0, 0));
        assert_eq!(out, frame);
    }
}
