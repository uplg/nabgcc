//! Sharing between the main program and interrupt handlers.

use core::cell::UnsafeCell;

/// A word-sized value that one side writes and the other reads. On
/// this processor a load or a store of a word is one instruction, so a
/// reader never sees half a value. Anything that reads, changes and
/// writes back must do it with interrupts held back.
pub struct Shared<T: Copy>(UnsafeCell<T>);

// SAFETY: see above; `T` is limited to what fits a register by the
// constructors below.
unsafe impl<T: Copy> Sync for Shared<T> {}

impl<T: Copy> Shared<T> {
    pub const fn new(value: T) -> Self {
        Shared(UnsafeCell::new(value))
    }

    #[inline]
    pub fn get(&self) -> T {
        // SAFETY: a single load.
        unsafe { self.0.get().read_volatile() }
    }

    #[inline]
    pub fn set(&self, value: T) {
        // SAFETY: a single store.
        unsafe { self.0.get().write_volatile(value) }
    }
}
