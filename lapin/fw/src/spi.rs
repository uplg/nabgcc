//! The two SPI buses: 0 goes to the audio codec, 1 to the led driver.

use crate::reg;

reg! {
    PORTSEL2: u32 = 0xB700_0028;
}

const CONTROL: usize = 0x00;
const BAUD: usize = 0x04;
const STATUS: usize = 0x08;
const WRITE: usize = 0x0C;
const READ: usize = 0x10;

const ENABLE: u32 = 1 << 0;
const MASTER: u32 = 1 << 1;
const BIT_ORDER: u32 = 1 << 4;
const PHASE: u32 = 1 << 5;
const POLARITY: u32 = 1 << 6;
const FIFO_CLEAR: u32 = 1 << 24;
const DONE: u32 = 1 << 5;
const OVERRUN: u32 = 1 << 3;

#[derive(Clone, Copy)]
pub struct Spi(usize);

pub const CODEC: Spi = Spi(0xB7B0_2000);
pub const LEDS: Spi = Spi(0xB7B0_3000);

impl Spi {
    fn reg(self, offset: usize) -> crate::reg::Reg<u32> {
        // SAFETY: a register of one of the two SPI controllers.
        unsafe { crate::reg::Reg::at(self.0 + offset) }
    }

    fn init(self) {
        let control = self.reg(CONTROL);
        control.set(BIT_ORDER);
        control.clear(POLARITY | PHASE);
        // Eight bits, half the peripheral clock.
        self.reg(BAUD).write(0);
        control.set(MASTER);
        control.set(FIFO_CLEAR);
        control.clear(FIFO_CLEAR);
        // Reading the status clears a stale completion flag.
        self.reg(STATUS).read();
        control.set(ENABLE);
    }

    /// Clock a byte out and return the one that came back.
    pub fn transfer(self, byte: u8) -> u8 {
        // SAFETY: the data registers take byte accesses.
        let (write, read) = unsafe {
            (
                crate::reg::Reg::<u8>::at(self.0 + WRITE),
                crate::reg::Reg::<u8>::at(self.0 + READ),
            )
        };
        write.write(byte);
        while self.reg(STATUS).read() & DONE == 0 {}
        read.read()
    }
}

impl Spi {
    /// Bus clock: the peripheral clock divided by `2 * (divider + 1)`.
    pub fn set_divider(self, divider: u32) {
        let control = self.reg(CONTROL);
        control.clear(ENABLE);
        self.reg(BAUD).write(divider);
        control.set(ENABLE);
    }
}

pub fn init() {
    // Hand the pins of both buses to their controllers.
    PORTSEL2.set(0x0000_0015);
    CODEC.init();
    PORTSEL2.set(0x0000_1500);
    LEDS.init();
    LEDS.reg(STATUS).set(OVERRUN);
}
