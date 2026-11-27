//! Driver for the RT2573 (sold as RT2501USB): bring-up, tuning, keys,
//! transmission and reception of raw 802.11 frames.
//!
//! The register values, their order and the delays come from the C
//! driver this replaces (`src/usb/rt2501usb.c`), itself after Ralink's.

use core::cell::UnsafeCell;

use super::rxq::{self, Received};
use crate::sync::Shared;
use crate::usb::{self, ADDRESS, PACKET};
use crate::{timer, watchdog};

/// The program the stick's own 8051 runs, loaded at each power-on.
static FIRMWARE: &[u8; 1600] = include_bytes!("rt2573.bin");

const FIRMWARE_BASE: u16 = 0x0800;
const SHARED_KEYS: u16 = 0x1000;
const BEACON: u16 = 0x2400;
const MAC_CSR1: u16 = 0x3004;
const MAC_CSR2: u16 = 0x3008;
const MAC_CSR3: u16 = 0x300C;
const MAC_CSR4: u16 = 0x3010;
const MAC_CSR5: u16 = 0x3014;
const MAC_CSR12: u16 = 0x3030;
const TXRX_CSR0: u16 = 0x3040;
const TXRX_CSR5: u16 = 0x3054;
const TXRX_CSR9: u16 = 0x3064;
const PHY_CSR1: u16 = 0x3084;
const PHY_CSR3: u16 = 0x308C;
const PHY_CSR4: u16 = 0x3090;
const SEC_CSR0: u16 = 0x30A0;
const SEC_CSR1: u16 = 0x30A4;

/// Receiver off, and on with the filters the station needs.
const RX_OFF: u32 = 0x0257_B032;
const RX_ON: u32 = 0x025E_B032;

const MAC_DEFAULTS: [(u16, u32); 22] = [
    (TXRX_CSR0, 0x025F_B032),
    (0x3044, 0x9EAA_9EAF),
    (0x3048, 0x8A8B_8C8D),
    (0x304C, 0x0085_8687),
    (0x305C, 0x2E31_353B),
    (0x3060, 0x2A2A_2A2C),
    (0x307C, 0x0000_000F),
    (0x3018, 0x0000_0FFF),
    (0x3020, 0x016C_030A),
    (0x3028, 0x0000_0718),
    (MAC_CSR12, 0x0000_0004),
    (0x3034, 0x0000_7F00),
    (SEC_CSR0, 0),
    (SEC_CSR1, 0),
    (0x30B4, 0),
    (PHY_CSR1, 0x0000_23B0),
    (0x3094, 0x0004_0A06),
    (0x3098, 0x0008_0606),
    (0x309C, 0x0000_0408),
    (0x0400, 0x0000_2273),
    (0x0404, 0x0000_2344),
    (0x0408, 0x0000_34AA),
];

const BBP_DEFAULTS: [(u8, u8); 26] = [
    (3, 0x80),
    (15, 0x30),
    (17, 0x20),
    (21, 0xC8),
    (22, 0x38),
    (23, 0x06),
    (24, 0xFE),
    (25, 0x0A),
    (26, 0x0D),
    (32, 0x0B),
    (34, 0x12),
    (37, 0x07),
    (39, 0xF8),
    (41, 0x60),
    (53, 0x10),
    (54, 0x18),
    (60, 0x10),
    (61, 0x04),
    (62, 0x04),
    (75, 0xFE),
    (86, 0xFE),
    (88, 0xFE),
    (90, 0x0F),
    (99, 0x00),
    (102, 0x16),
    (107, 0x04),
];

const EEPROM_MAC: u16 = 0x04;
const EEPROM_BBP: u16 = 0x20;
const EEPROM_TX_POWER: u16 = 0x46;
const EEPROM_TSSI: u16 = 0x54;
const EEPROM_FREQUENCY: u16 = 0x5E;

/// The radio chips handled, as the stick's calibration data numbers
/// them: the two that do 2.4 GHz only. The RT2528 is the one Ralink
/// sold with the RT2571W; the RT2527 is kept in case some rabbits got
/// it. The two that also do 5 GHz (RT5226, RT5225) are refused.
const RF_2528: u8 = 2;
const RF_2527: u8 = 4;

const BBP_R94_DEFAULT: i8 = 6;
/// What to take off the baseband's signal reading to get dBm.
const RSSI_TO_DBM: i16 = 0x79;
/// Calls of [`Stick::tick`] between two power calibrations.
const CALIBRATION_PERIOD: u8 = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Usb(usb::Error),
    /// The baseband or the radio never reported ready.
    NotReady,
    /// The stick carries a radio chip this driver does not tune; this
    /// is the type its calibration data gives.
    Radio(u8),
}

impl From<usb::Error> for Error {
    fn from(e: usb::Error) -> Self {
        Error::Usb(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    None = 0,
    Wep40 = 1,
    Wep104 = 2,
    Tkip = 3,
    Ccmp = 4,
}

/// Transmit rates, as the stick numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub enum Rate {
    Mbps1 = 0,
    Mbps2 = 1,
    Mbps5_5 = 2,
    Mbps11 = 3,
    Mbps6 = 4,
    Mbps9 = 5,
    Mbps12 = 6,
    Mbps18 = 7,
    Mbps24 = 8,
    Mbps36 = 9,
    Mbps48 = 10,
    Mbps54 = 11,
}

/// How a frame is to be sent.
#[derive(Debug, Clone, Copy)]
pub struct TxOptions {
    pub rate: Rate,
    /// Expect an acknowledgement, retry without one.
    pub ack: bool,
    pub cipher: Cipher,
    /// Slot of the shared key table to encrypt with.
    pub key_index: u8,
    /// The two words the stick inserts after the header when it
    /// encrypts: initialisation vector, then its extension.
    pub iv: u32,
    pub eiv: u32,
    /// The stick writes its clock into the frame (probe responses).
    pub timestamp: bool,
}

impl TxOptions {
    /// In clear, acknowledged, at the lowest rate: management frames.
    pub const PLAIN: TxOptions = TxOptions {
        rate: Rate::Mbps1,
        ack: true,
        cipher: Cipher::None,
        key_index: 0,
        iv: 0,
        eiv: 0,
        timestamp: false,
    };
}

pub struct Stick {
    max_packet: u16,
    pub mac: [u8; 6],
    antenna: u16,
    tx_power: [i8; 14],
    frequency_offset: u32,
    auto_power: bool,
    tssi_minus: [u8; 5],
    tssi_plus: [u8; 5],
    power_step: u8,
    rf: [u32; 4],
    channel: u8,
    calibration_in: u8,
}

/// Where the interrupt handler puts a frame together from its packets.
struct Assembly(UnsafeCell<[u8; 2048]>);
// SAFETY: only the USB interrupt handler touches it.
unsafe impl Sync for Assembly {}
#[unsafe(link_section = ".xram.wifi")]
static ASSEMBLY: Assembly = Assembly(UnsafeCell::new([0; 2048]));
static ASSEMBLED: Shared<usize> = Shared::new(0);

/// Called from the USB interrupt with each packet from the stick. A
/// frame ends on a packet shorter than the maximum.
fn on_packet(packet: &[u8]) {
    // SAFETY: see `Assembly`.
    let buffer = unsafe { &mut *ASSEMBLY.0.get() };
    let at = ASSEMBLED.get();
    if at + packet.len() > buffer.len() {
        ASSEMBLED.set(0);
        return;
    }
    buffer[at..at + packet.len()].copy_from_slice(packet);
    let total = at + packet.len();
    if packet.len() == PACKET {
        ASSEMBLED.set(total);
        return;
    }
    ASSEMBLED.set(0);
    if total < 24 {
        return;
    }
    // The stick's descriptor: six words in front of the frame.
    let word0 = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    let crc_error = word0 & (1 << 6) != 0;
    let cipher_error = (word0 >> 8) & 3;
    let cipher = word0 >> 29;
    let len = ((word0 >> 16) & 0xFFF) as usize;
    if crc_error || (cipher != 0 && cipher_error != 0) || 24 + len > total {
        return;
    }
    let rssi = (buffer[5] as i16 - RSSI_TO_DBM).clamp(-128, 127) as i8;
    rxq::push(&buffer[24..24 + len], rssi, cipher != 0);
}

impl Stick {
    fn request(
        &self,
        kind: u8,
        request: u8,
        value: u16,
        index: u16,
        data: &mut [u8],
    ) -> Result<usize, usb::Error> {
        let len = data.len() as u16;
        let setup = [
            kind,
            request,
            value as u8,
            (value >> 8) as u8,
            index as u8,
            (index >> 8) as u8,
            len as u8,
            (len >> 8) as u8,
        ];
        usb::control(ADDRESS, self.max_packet, setup, data)
    }

    fn read(&self, register: u16) -> Result<u32, usb::Error> {
        let mut bytes = [0u8; 4];
        self.request(0xC0, 0x07, 0, register, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn write(&self, register: u16, value: u32) -> Result<(), usb::Error> {
        self.request(0x40, 0x06, 0, register, &mut value.to_le_bytes())
            .map(|_| ())
    }

    fn eeprom(&self, address: u16, data: &mut [u8]) -> Result<(), usb::Error> {
        self.request(0xC0, 0x09, 0, address, data).map(|_| ())
    }

    /// Wait for a register's busy bit to clear and return the register.
    fn idle(&self, register: u16, busy: u32) -> Result<u32, Error> {
        for _ in 0..1000 {
            let value = self.read(register)?;
            if value & busy == 0 {
                return Ok(value);
            }
            watchdog::feed();
        }
        Err(Error::NotReady)
    }

    fn bbp_read(&self, register: u8) -> Result<u8, Error> {
        const BUSY: u32 = 1 << 16;
        const READ: u32 = 1 << 15;
        self.idle(PHY_CSR3, BUSY)?;
        self.write(PHY_CSR3, BUSY | READ | (register as u32) << 8)?;
        Ok(self.idle(PHY_CSR3, BUSY)? as u8)
    }

    fn bbp_write(&self, register: u8, value: u8) -> Result<(), Error> {
        const BUSY: u32 = 1 << 16;
        self.idle(PHY_CSR3, BUSY)?;
        Ok(self.write(PHY_CSR3, BUSY | (register as u32) << 8 | value as u32)?)
    }

    fn rf_write(&self, value: u32) -> Result<(), Error> {
        self.idle(PHY_CSR4, 1 << 31)?;
        Ok(self.write(PHY_CSR4, value)?)
    }

    /// The stick's radio chip, from its calibration data.
    pub fn radio(&self) -> u8 {
        (self.antenna >> 11) as u8
    }

    /// Load the stick's firmware, set it up, read its calibration data
    /// and address, tune to channel 1 and start receiving.
    pub fn start(device: usb::Device) -> Result<Stick, Error> {
        let mut s = Stick {
            max_packet: device.max_packet,
            mac: [0; 6],
            antenna: 0,
            tx_power: [0; 14],
            frequency_offset: 0,
            auto_power: false,
            tssi_minus: [0; 5],
            tssi_plus: [0; 5],
            power_step: 0,
            rf: [0; 4],
            channel: 1,
            calibration_in: CALIBRATION_PERIOD,
        };
        for (i, word) in FIRMWARE.as_chunks::<4>().0.iter().enumerate() {
            s.write(FIRMWARE_BASE + 4 * i as u16, u32::from_le_bytes(*word))?;
        }
        // Run it.
        s.request(0x40, 0x01, 0x08, 0, &mut [])?;
        for (register, value) in MAC_DEFAULTS {
            s.write(register, value)?;
        }
        // Reset the baseband and the MAC, then let them go.
        s.write(MAC_CSR1, 3)?;
        s.write(MAC_CSR1, 0)?;
        let mut tries = 0;
        while s.read(MAC_CSR12)? & (1 << 3) == 0 {
            // Force a wake-up and give it a second.
            s.write(MAC_CSR12, 4)?;
            timer::delay_ms(1000);
            tries += 1;
            if tries == 10 {
                return Err(Error::NotReady);
            }
        }
        tries = 0;
        while s.bbp_read(0)? == 0 {
            timer::delay_ms(500);
            tries += 1;
            if tries == 20 {
                return Err(Error::NotReady);
            }
        }
        for (register, value) in BBP_DEFAULTS {
            s.bbp_write(register, value)?;
        }
        // Tell the stick its host is ready.
        s.write(MAC_CSR1, 4)?;
        s.read_calibration()?;
        s.set_channel(1)?;
        usb::on_receive(on_packet);
        Ok(s)
    }

    fn read_calibration(&mut self) -> Result<(), Error> {
        let mut bbp = [0u8; 38];
        self.eeprom(EEPROM_BBP, &mut bbp)?;
        self.antenna = u16::from_le_bytes([bbp[0], bbp[1]]);
        self.auto_power = self.antenna & (1 << 9) != 0;
        match self.radio() {
            RF_2528 => {}
            RF_2527 => {
                let value = self.read(PHY_CSR1)?;
                self.write(PHY_CSR1, value | 0x1_0000)?;
            }
            other => return Err(Error::Radio(other)),
        }

        let mut power = [0u8; 14];
        self.eeprom(EEPROM_TX_POWER, &mut power)?;
        for (slot, raw) in self.tx_power.iter_mut().zip(power) {
            let value = raw as i8;
            // Out of range means the stick was never calibrated.
            *slot = if (-6..=36).contains(&value) {
                value
            } else {
                24
            };
        }

        let mut tssi = [0u8; 10];
        self.eeprom(EEPROM_TSSI, &mut tssi)?;
        let reference = tssi[8];
        self.tssi_minus = [reference, tssi[3], tssi[2], tssi[1], tssi[0]];
        self.tssi_plus = [reference, tssi[4], tssi[5], tssi[6], tssi[7]];
        self.power_step = tssi[9];
        if reference == 0xFF {
            self.auto_power = false;
        }

        let mut offset = [0u8; 2];
        self.eeprom(EEPROM_FREQUENCY, &mut offset)?;
        self.frequency_offset = if offset[0] == 0xFF {
            0
        } else {
            offset[0] as u32
        };

        // Baseband settings particular to this stick.
        for pair in bbp[6..].as_chunks::<2>().0 {
            let word = u16::from_le_bytes(*pair);
            if word != 0xFFFF && word != 0 {
                self.bbp_write((word >> 8) as u8, word as u8)?;
            }
        }

        let mut mac = [0u8; 6];
        self.eeprom(EEPROM_MAC, &mut mac)?;
        self.mac = mac;
        self.write(
            MAC_CSR2,
            u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]),
        )?;
        self.write(MAC_CSR3, mac[4] as u32 | (mac[5] as u32) << 8 | 0xFF << 16)?;
        Ok(())
    }

    /// Select the receive antenna (always B on the rabbit) in the
    /// baseband. The receiver is left off.
    fn select_antenna(&self) -> Result<(), Error> {
        self.write(TXRX_CSR0, RX_OFF)?;
        let r3 = self.bbp_read(3)? & 0xFE;
        let mut r4 = self.bbp_read(4)? & !0x23;
        let r77 = self.bbp_read(77)? & 0xFC;
        let frame_type_mask = !((((self.antenna >> 6) & 1) as u8) << 5);
        r4 |= 0x21;
        r4 &= frame_type_mask;
        self.bbp_write(77, r77)?;
        self.bbp_write(3, r3)?;
        self.bbp_write(4, r4)?;
        Ok(())
    }

    /// Send the four synthesiser words three times, toggling the bit
    /// that makes the radio take them.
    fn update_rf(&self) -> Result<(), Error> {
        for r3 in [self.rf[2] & !4, self.rf[2] | 4, self.rf[2] & !4] {
            self.rf_write(self.rf[0])?;
            self.rf_write(self.rf[1])?;
            self.rf_write(r3)?;
            self.rf_write(self.rf[3])?;
        }
        Ok(())
    }

    pub fn channel(&self) -> u8 {
        self.channel
    }

    /// Tune to a channel, 1 to 14, and turn the receiver on.
    pub fn set_channel(&mut self, channel: u8) -> Result<(), Error> {
        let channel = channel.clamp(1, 14);
        self.channel = channel;
        self.select_antenna()?;

        // Transmit power: 0 to 31 in the radio, the rest in the baseband.
        let power = self.tx_power[channel as usize - 1];
        let mut r94 = BBP_R94_DEFAULT;
        let r3_power = if power > 31 {
            r94 += power - 31;
            31
        } else if power < 0 {
            r94 = (r94 + power).max(0);
            0
        } else {
            power as u32
        };
        // Synthesiser words: the two radio chips differ by their length
        // (20 bits, 21 for the RT2527) and a few fixed bits, the
        // frequency is in the second and fourth.
        let rt2527 = self.radio() == RF_2527;
        let (r1, r2_base, r3_base, r4_base) = if rt2527 {
            (0x9500_2CCC, 0x9500_4786, 0x9506_8455, 0x950F_FA00)
        } else {
            (0x9400_2C0C, 0x9400_0786, 0x9406_8255, 0x940F_EA00)
        };
        let (r2, r4_low) = match channel {
            14 => (r2_base + 0x1C, 0x13),
            c => (
                r2_base + 4 * ((c as u32 - 1) / 2),
                if c % 2 == 1 { 0x0B } else { 0x1F },
            ),
        };
        let r4: u32 = r4_base | r4_low;
        self.rf = [
            r1,
            r2,
            (r3_power << 9) | (r3_base & 0xFFFF_C1FF),
            (r4 & !0x0003_F000) | self.frequency_offset << 12,
        ];
        let smart = self.bbp_read(3)?;
        let smart = if rt2527 { smart & 0xFE } else { smart | 1 };
        self.bbp_write(3, smart)?;
        if r94 != BBP_R94_DEFAULT {
            self.bbp_write(94, r94 as u8)?;
        }
        self.update_rf()?;
        // Let the baseband and the radio settle.
        timer::delay_ms(2);
        Ok(self.write(TXRX_CSR0, RX_ON)?)
    }

    /// Follow the temperature: nudge the transmit power by what the
    /// stick's own power sensor reads. To be called now and then; only
    /// one call in forty does anything.
    pub fn tick(&mut self) -> Result<(), Error> {
        self.calibration_in -= 1;
        if self.calibration_in != 0 {
            return Ok(());
        }
        self.calibration_in = CALIBRATION_PERIOD;
        let power = self.tx_power[self.channel as usize - 1];
        let mut r3 = if (0..=31).contains(&power) {
            power as i32
        } else {
            0
        };
        if self.auto_power {
            let sensed = self.bbp_read(1)?;
            let step = self.power_step as i32;
            if sensed > self.tssi_minus[1] {
                // Too much power: one step down per boundary crossed.
                let steps = (1..5).find(|i| sensed <= self.tssi_minus[*i]).unwrap_or(5) as i32 - 1;
                r3 -= (step * steps).min(r3);
            } else if sensed < self.tssi_plus[1] {
                let steps = (1..5).find(|i| sensed >= self.tssi_plus[*i]).unwrap_or(5) as i32 - 1;
                r3 += step * steps;
            }
        }
        let r3 = r3.clamp(0, 31) as u32;
        if (self.rf[2] >> 9) & 0x1F != r3 {
            self.rf[2] = (self.rf[2] & 0xFFFF_C1FF) | r3 << 9;
            self.update_rf()?;
        }
        Ok(())
    }

    /// The rates the stick may answer at (acknowledgements), by its
    /// rate numbers.
    pub fn set_answer_rates(&self, mask: u16) -> Result<(), Error> {
        Ok(self.write(TXRX_CSR5, mask as u32)?)
    }

    /// The network whose frames count as ours.
    pub fn set_bssid(&self, bssid: &[u8; 6]) -> Result<(), Error> {
        self.write(
            MAC_CSR4,
            u32::from_le_bytes([bssid[0], bssid[1], bssid[2], bssid[3]]),
        )?;
        Ok(self.write(MAC_CSR5, bssid[4] as u32 | (bssid[5] as u32) << 8 | 3 << 16)?)
    }

    /// Load (or, with `Cipher::None`, clear) one of the four shared
    /// keys. `key` is 5, 13 or 16 bytes; the two Michael keys are used
    /// by TKIP only.
    pub fn set_key(
        &self,
        index: u8,
        cipher: Cipher,
        key: &[u8],
        tx_mic: &[u8; 8],
        rx_mic: &[u8; 8],
    ) -> Result<(), Error> {
        let index = index & 3;
        // Never leave a half-written key marked valid.
        let valid = self.read(SEC_CSR0)? & !(1 << index);
        self.write(SEC_CSR0, valid)?;
        if cipher == Cipher::None {
            return Ok(());
        }
        let mut entry = [0u8; 32];
        entry[..key.len().min(16)].copy_from_slice(&key[..key.len().min(16)]);
        entry[16..24].copy_from_slice(tx_mic);
        entry[24..].copy_from_slice(rx_mic);
        let base = SHARED_KEYS + index as u16 * 32;
        for (i, word) in entry.as_chunks::<4>().0.iter().enumerate() {
            self.write(base + 4 * i as u16, u32::from_le_bytes(*word))?;
        }
        let algorithms = self.read(SEC_CSR1)? & !(0xF << (index * 4));
        self.write(SEC_CSR1, algorithms | (cipher as u32) << (index * 4))?;
        Ok(self.write(SEC_CSR0, valid | 1 << index)?)
    }

    /// Hand a frame (802.11 header and body) to the stick. False if
    /// the previous one is still on its way, or the frame is too long.
    pub fn transmit(&self, frame: &[u8], options: &TxOptions) -> bool {
        let mut total = 24 + frame.len();
        // Whole words, and never a multiple of the USB packet size:
        // the stick takes a short packet as the end of the frame.
        total = (total + 3) & !3;
        if total.is_multiple_of(PACKET) {
            total += 4;
        }
        usb::transmit(total, |buffer| {
            buffer.fill(0);
            buffer[..24].copy_from_slice(&descriptor_with(frame.len(), options, options.timestamp));
            buffer[24..24 + frame.len()].copy_from_slice(frame);
        })
    }

    /// Frames lost because nobody took them in time.
    pub fn dropped(&self) -> u32 {
        rxq::dropped()
    }

    /// Take the oldest received frame into `out`.
    pub fn receive(&self, out: &mut [u8]) -> Option<Received> {
        rxq::pop(out)
    }

    /// Have the stick send `frame` (with its descriptor in front) as a
    /// beacon at every interval, or stop with `None`.
    pub fn set_beacon(&self, frame: Option<&[u8]>) -> Result<(), Error> {
        let control = self.read(TXRX_CSR9)? & !0x001F_0000;
        self.write(TXRX_CSR9, control)?;
        let Some(frame) = frame else { return Ok(()) };
        for slot in 0..4 {
            self.write(BEACON + slot * 0x100, 0)?;
        }
        let mut options = TxOptions::PLAIN;
        options.ack = false;
        let head = descriptor_with(frame.len(), &options, true);
        let mut at = BEACON;
        let mut word = [0u8; 4];
        for (i, byte) in head.iter().chain(frame).enumerate() {
            word[i % 4] = *byte;
            if i % 4 == 3 {
                self.write(at, u32::from_le_bytes(word))?;
                at += 4;
                word = [0; 4];
            }
        }
        if (24 + frame.len()) % 4 != 0 {
            self.write(at, u32::from_le_bytes(word))?;
        }
        // Clock running, no synchronisation to anyone, beacons on.
        Ok(self.write(TXRX_CSR9, control | 0x001F_0000)?)
    }
}

/// The six words that precede a frame handed to the stick.
fn descriptor_with(len: usize, options: &TxOptions, timestamp: bool) -> [u8; 24] {
    /// What the physical layer header says for each rate.
    const SIGNAL: [u8; 12] = [0, 1, 2, 3, 11, 15, 10, 14, 9, 3, 8, 12];
    let rate = options.rate as u32;
    let ofdm = options.rate >= Rate::Mbps6;
    let encrypted = options.cipher != Cipher::None;

    // Valid frame, retries on, the chip numbers the frame.
    let mut word0 = 1 << 1 | 1 << 7 | (len as u32 & 0xFFF) << 16 | (options.cipher as u32) << 29;
    word0 |= (options.ack as u32) << 3 | (timestamp as u32) << 4 | (ofdm as u32) << 5;
    if encrypted {
        // Shared key table; the chip adds the TKIP integrity code.
        word0 |= 1 << 8 | (options.key_index as u32 & 0x3F) << 10;
    }
    // Contention parameters, and where the IV goes: after the header.
    let word1 = 2 << 4 | 4 << 8 | 10 << 12 | (if encrypted { 24 } else { 0 }) << 16 | 1 << 28;

    // Length on the air: checksum, and what the cipher adds.
    let mut air = len as u32 + 4;
    air += match options.cipher {
        Cipher::None => 0,
        Cipher::Wep40 | Cipher::Wep104 => 8,
        Cipher::Tkip => 20,
        Cipher::Ccmp => 16,
    };
    let mut service = 4u32;
    let (low, high) = if ofdm {
        (air % 64, air >> 6)
    } else {
        // The older rates announce a duration in microseconds.
        let micros = match options.rate {
            Rate::Mbps1 | Rate::Mbps2 => air * 8 / (rate + 1),
            _ => {
                let per = 11 * (rate - 1);
                let remainder = (air * 16) % per;
                if remainder != 0 && remainder <= 3 * (rate - 1) && options.rate == Rate::Mbps11 {
                    service |= 0x80;
                }
                air * 16 / per + (remainder != 0) as u32
            }
        };
        (micros % 256, micros >> 8)
    };
    let word2 = SIGNAL[rate as usize] as u32 | service << 8 | low << 16 | high << 24;

    let mut out = [0u8; 24];
    for (chunk, word) in
        out.as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip([word0, word1, word2, options.iv, options.eiv, 0])
    {
        *chunk = word.to_le_bytes();
    }
    out
}
