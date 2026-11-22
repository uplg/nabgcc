//! Memory-mapped registers.

/// A register of the processor or of a chip on its bus.
#[derive(Clone, Copy)]
pub struct Reg<T>(*mut T);

// SAFETY: a register is an address; what makes access to it sound is
// said where it is used.
unsafe impl<T> Sync for Reg<T> {}

impl<T: Copy> Reg<T> {
    /// # Safety
    /// `address` must be a register of that width on this board.
    pub const unsafe fn at(address: usize) -> Self {
        Reg(address as *mut T)
    }

    #[inline(always)]
    pub fn read(self) -> T {
        // SAFETY: by construction this is a device register.
        unsafe { self.0.read_volatile() }
    }

    #[inline(always)]
    pub fn write(self, value: T) {
        // SAFETY: as above.
        unsafe { self.0.write_volatile(value) }
    }
}

macro_rules! bit_ops {
    ($t:ty) => {
        impl Reg<$t> {
            #[inline(always)]
            pub fn set(self, bits: $t) {
                self.write(self.read() | bits);
            }

            #[inline(always)]
            pub fn clear(self, bits: $t) {
                self.write(self.read() & !bits);
            }
        }
    };
}
bit_ops!(u8);
bit_ops!(u16);
bit_ops!(u32);

/// Declare registers: `reg!(NAME: u32 = 0xB700_0000);`
#[macro_export]
macro_rules! reg {
    ($($name:ident : $t:ty = $addr:expr;)*) => {
        $(
            #[allow(dead_code)]
            // SAFETY: addresses from the processor's register map.
            const $name: $crate::reg::Reg<$t> = {
                let address: usize = $addr;
                unsafe { $crate::reg::Reg::at(address) }
            };
        )*
    };
}
