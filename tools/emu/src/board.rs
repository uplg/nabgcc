//! What is soldered around the processor on the Nabaztag:tag board
//! (revision LLC2_4c): the five RGB leds, the audio codec, the two ear
//! motors with their encoders, the head button, the volume wheel.

use crate::rfid::Reader;
use crate::vs1003::Vs1003;

/// Slots on an ear's encoder wheel: seventeen teeth, then a gap three
/// teeth wide that marks the reference position.
pub const EAR_SLOTS: u32 = 20;
pub const EAR_TEETH: u32 = 17;
/// Time an ear takes to move by one slot at full speed. An estimate
/// bounded by the factory test in the boot bytecode, which takes any
/// pause between two teeth longer than 600 ms for the gap: the gap is
/// four slots, so a slot lasts more than 150 ms and a turn about 3 s.
const EAR_SLOT_MS: u32 = 160;

/// The leds as the bytecode numbers them.
pub const LED_NOSE: usize = 0;
pub const LED_LEFT: usize = 1;
pub const LED_MIDDLE: usize = 2;
pub const LED_RIGHT: usize = 3;
pub const LED_BOTTOM: usize = 4;

/// Position of each bytecode led number in the driver's shift register.
const LED_CHANNEL: [usize; 5] = [4, 2, 0, 3, 1];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ear {
    /// Where the wheel is, in slots (0..[`EAR_SLOTS`]).
    pub slot: u32,
    /// -1 backwards, 0 stopped, 1 forwards.
    pub direction: i8,
    /// Encoder pulses seen since power-on.
    pub pulses: u32,
    progress: u32,
}

impl Ear {
    /// One slot on (`step` 1) or back (-1).
    fn turn(&mut self, step: i32) {
        self.slot = (self.slot as i32 + step).rem_euclid(EAR_SLOTS as i32) as u32;
        if self.slot < EAR_TEETH {
            // A tooth passes the sensor and clocks the counter.
            self.pulses += 1;
        }
    }
}

pub struct Board {
    /// Red, green, blue of each led, indexed by bytecode led number.
    /// Each is the driver's 7-bit current setting, 0 (off) to 127.
    pub leds: [[u8; 3]; 5],
    /// How many times the led driver was loaded.
    pub led_updates: u64,
    pub ears: [Ear; 2],
    /// Head button held down.
    pub button: bool,
    /// Volume wheel as the bytecode reads it, 0..=255.
    pub volume: u8,
    /// The audio codec: what was played, and the microphone.
    pub codec: Vs1003,
    /// The loudspeaker amplifier is switched on.
    pub amplifier: bool,
    /// The tag reader in the nose, with the tags held in front of it.
    pub rfid: Reader,
    led_shift: Vec<u8>,
    spi_reply: [u8; 2],
}

impl Default for Board {
    fn default() -> Self {
        Self::new()
    }
}

impl Board {
    pub fn new() -> Self {
        Board {
            leds: [[0; 3]; 5],
            led_updates: 0,
            ears: [Ear::default(); 2],
            button: false,
            volume: 128,
            codec: Vs1003::new(),
            amplifier: false,
            rfid: Reader::default(),
            led_shift: Vec::new(),
            spi_reply: [0; 2],
        }
    }

    /// Power-on state of the chips; what a person set stays.
    pub fn reset(&mut self) {
        self.leds = [[0; 3]; 5];
        self.codec.reset();
        self.amplifier = false;
        self.led_shift.clear();
        self.rfid.reset();
        for ear in &mut self.ears {
            ear.direction = 0;
        }
    }

    /// A byte clocked out on a SPI bus. `sci` and `sdi` tell which of
    /// the codec's two chip selects is asserted.
    pub fn spi_write(&mut self, bus: usize, byte: u8, sci: bool, sdi: bool) {
        self.spi_reply[bus] = 0;
        if bus == 1 {
            self.led_shift.push(byte);
        } else if sci {
            self.codec.control(byte);
            self.spi_reply[0] = self.codec.reply();
        } else if sdi {
            self.codec.data(byte);
        }
    }

    /// What the last byte clocked out brought back.
    pub fn spi_read(&self, bus: usize) -> u8 {
        self.spi_reply[bus]
    }

    /// The codec's control chip select was released.
    pub fn sci_released(&mut self) {
        self.codec.control_done();
    }

    /// The led driver's latch was pulsed: what was shifted in takes
    /// effect. Fourteen bytes are the fifteen 7-bit current settings.
    pub fn led_latch(&mut self) {
        let bytes = std::mem::take(&mut self.led_shift);
        if bytes.len() != 14 {
            return;
        }
        let field = |n: usize| {
            (0..7).fold(0u8, |v, i| {
                let bit = n * 7 + i;
                v << 1 | (bytes[bit / 8] >> (7 - bit % 8)) & 1
            })
        };
        for (led, channel) in LED_CHANNEL.iter().enumerate() {
            self.leds[led] = [
                field(channel * 3),
                field(channel * 3 + 1),
                field(channel * 3 + 2),
            ];
        }
        self.led_updates += 1;
    }

    /// One millisecond passes. `duty` holds the four motor PWM settings:
    /// ear 0 forwards, ear 0 backwards, ear 1 forwards, ear 1 backwards.
    pub fn tick_ms(&mut self, duty: [u16; 4], now_ms: u64) {
        self.codec.tick_ms(now_ms);
        for (n, ear) in self.ears.iter_mut().enumerate() {
            ear.direction = match (duty[n * 2] != 0, duty[n * 2 + 1] != 0) {
                (true, false) => 1,
                (false, true) => -1,
                _ => 0,
            };
            if ear.direction == 0 {
                continue;
            }
            ear.progress += 1;
            if ear.progress < EAR_SLOT_MS {
                continue;
            }
            ear.progress = 0;
            ear.turn(ear.direction as i32);
        }
    }

    /// Someone turns an ear by hand, by `slots` (backwards when
    /// negative): the encoder counts the teeth that pass, as when the
    /// motor turns it.
    pub fn turn_ear_by_hand(&mut self, ear: usize, slots: i32) {
        for _ in 0..slots.unsigned_abs() {
            self.ears[ear].turn(slots.signum());
        }
    }

    /// Count of an ear's encoder timer, which the teeth clock.
    pub fn ear_count(&self, ear: usize) -> u16 {
        self.ears[ear].pulses as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn led_settings_come_out_of_the_shift_register() {
        let mut b = Board::new();
        // 105 bits: channel 0 red at 127, channel 4 blue at 1.
        let mut bytes = [0u8; 14];
        bytes[0] = 0xFE;
        bytes[13] = 0x80;
        for byte in bytes {
            b.spi_write(1, byte, false, false);
        }
        b.led_latch();
        assert_eq!(b.leds[LED_MIDDLE], [127, 0, 0]);
        assert_eq!(b.leds[LED_NOSE], [0, 0, 1]);
        assert_eq!(b.led_updates, 1);
    }

    #[test]
    fn an_ear_turns_and_its_encoder_skips_the_gap() {
        let mut b = Board::new();
        for ms in 0..(EAR_SLOTS * EAR_SLOT_MS) {
            b.tick_ms([0xFFFF, 0, 0, 0], ms as u64);
        }
        assert_eq!(b.ears[0].slot, 0, "one full turn");
        assert_eq!(b.ears[0].pulses, EAR_TEETH);
        assert_eq!(b.ears[1].pulses, 0);
        b.tick_ms([0, 0, 0, 0], 0);
        assert_eq!(b.ears[0].direction, 0);
    }
}
