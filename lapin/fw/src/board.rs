//! Pins: what each one is for, and the head button and volume wheel.

use crate::reg;

reg! {
    pub(crate) PORTSEL1: u32 = 0xB700_0024;
    pub(crate) PORTSEL2: u32 = 0xB700_0028;
    PORTSEL3: u32 = 0xB700_002C;
    PORTSEL4: u32 = 0xB700_0030;
    PORTSEL5: u32 = 0xB700_0034;
    BWC: u32 = 0x7810_0000;
    RAMAC: u32 = 0x7810_0008;
    IO0AC: u32 = 0x7810_000C;
    PI1: u8 = 0xB7A0_1004;
    pub(crate) PO2: u8 = 0xB7A0_2000;
    PM2: u8 = 0xB7A0_2008;
    PI3: u8 = 0xB7A0_3004;
    pub(crate) PO4: u8 = 0xB7A0_4000;
    PM4: u8 = 0xB7A0_4008;
    PO5: u8 = 0xB7A0_5000;
    PM5: u8 = 0xB7A0_5008;
    PO11: u8 = 0xB7A0_B000;
    PM11: u8 = 0xB7A0_B008;
    ADCON0: u16 = 0xB600_0000;
    ADCON1: u16 = 0xB600_0004;
    ADCON2: u16 = 0xB600_0008;
    ADR2: u16 = 0xB600_001C;
}

// Port 2
pub(crate) const AUDIO_CONTROL_SELECT: u8 = 1 << 3;
pub(crate) const LED_MODE: u8 = 1 << 7;
// Port 3
const BUTTON: u8 = 1 << 1;
// Port 4
pub(crate) const LED_LATCH: u8 = 1 << 5;
const AUDIO_AMPLIFIER: u8 = 1 << 6;
// Port 5
const MOTOR_PINS: u8 = 0b0011_1100;
// Port 11
const AUDIO_DATA_SELECT: u8 = 1 << 0;
const AUDIO_RESET: u8 = 1 << 7;

/// The codec's "send me more" line.
pub(crate) fn codec_wants_data() -> bool {
    PI1.read() & (1 << 2) != 0
}

pub(crate) fn amplifier(on: bool) {
    PO4.put(AUDIO_AMPLIFIER, on);
}

/// The codec's reset and data select lines are active low.
pub(crate) fn codec_reset(held: bool) {
    PO11.put(AUDIO_RESET, !held);
}

pub(crate) fn codec_data_select(on: bool) {
    PO11.put(AUDIO_DATA_SELECT, !on);
}

/// Give every pin its function, direction and resting level.
pub fn init() {
    // External bus: 16-bit static RAM and 16-bit USB controller, with
    // their access timings.
    BWC.write(0xA0);
    RAMAC.write(0x2);
    IO0AC.write(0x1);

    PORTSEL1.write(0);
    PORTSEL2.write(0);
    PORTSEL3.write(0);
    PORTSEL4.write(0);
    PORTSEL5.write(0);
    for port in 0..15usize {
        // Everything an input until said otherwise.
        // SAFETY: the mode register of each of the fifteen ports.
        unsafe { crate::reg::Reg::<u8>::at(0xB7A0_0008 + port * 0x1000) }.write(0);
    }
    // Upper data bus pins as plain ports; timers 0 to 5 for the ears;
    // the serial port; the USB interrupt, the button, the volume wheel;
    // the I2C bus.
    PORTSEL4.set(0x0000_0040);
    PORTSEL3.set(0x0555_0000);
    PORTSEL1.set(0x0005_0000);
    PORTSEL2.set(0x001A_0000);
    PORTSEL1.set(0x0500_0000);

    PM4.set(AUDIO_AMPLIFIER | LED_LATCH);
    PM2.set(LED_MODE | AUDIO_CONTROL_SELECT);
    PM11.set(AUDIO_RESET | AUDIO_DATA_SELECT);
    PM5.set(MOTOR_PINS);

    // Amplifier off, chip selects released, codec held in reset, ears still.
    PO4.clear(AUDIO_AMPLIFIER);
    PO4.set(LED_LATCH);
    PO2.clear(LED_MODE);
    PO2.set(AUDIO_CONTROL_SELECT);
    PO11.clear(AUDIO_RESET);
    PO11.set(AUDIO_DATA_SELECT);
    PO5.clear(MOTOR_PINS);

    // Analogue input 2, the volume wheel; conversion clock at 1 MHz.
    ADCON0.write(0);
    ADCON1.write(2);
    ADCON2.write(3);
}

/// Whether the head button is held down.
pub fn button() -> bool {
    PI3.read() & BUTTON == 0
}

/// A sample of noise for the random pool, taking a millisecond: how
/// many conversions of the volume wheel's ADC fit before the next tick
/// (it varies with the interrupts that come and the flash's waits), and
/// the readings themselves, all ten bits (the last ones wander).
pub fn noise() -> u32 {
    let tick = crate::timer::millis();
    let mut x = 0u32;
    let mut n = 0u32;
    while crate::timer::millis() == tick && n < 100_000 {
        x = x.rotate_left(3) ^ convert() as u32;
        n += 1;
    }
    crate::watchdog::feed();
    x ^ n << 16
}

/// The volume wheel, 0 to 255.
pub fn volume() -> u8 {
    // The wheel is wired so that the reading goes down as it goes up.
    255 - (convert() >> 2) as u8
}

/// One conversion of the volume wheel's input, ten bits.
fn convert() -> u16 {
    const START: u16 = 0x10;
    ADCON1.set(START | 2);
    while ADCON1.read() & START != 0 {}
    ADR2.read()
}
