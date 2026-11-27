//! Received frames waiting for the main program: the interrupt handler
//! puts them in, the main loop takes them out.

use core::cell::UnsafeCell;

use crate::sync::Shared;

const SIZE: usize = 16 * 1024;
/// What precedes each frame: length, signal strength, flags.
const HEADER: usize = 4;

struct Ring(UnsafeCell<[u8; SIZE]>);
// SAFETY: the writer only touches bytes between `TAIL` and `HEAD`'s
// free side, the reader the other part; each moves only its own index.
unsafe impl Sync for Ring {}
#[unsafe(link_section = ".xram.rxq")]
static RING: Ring = Ring(UnsafeCell::new([0; SIZE]));
static HEAD: Shared<usize> = Shared::new(0);
static TAIL: Shared<usize> = Shared::new(0);
static DROPPED: Shared<u32> = Shared::new(0);

/// A frame as the stick delivered it.
#[derive(Debug, Clone, Copy)]
pub struct Received {
    pub len: usize,
    /// Signal strength, in dBm.
    pub rssi: i8,
    /// The stick decrypted it.
    pub decrypted: bool,
}

fn byte(at: usize) -> *mut u8 {
    // SAFETY: `at` is taken modulo the size.
    unsafe { RING.0.get().cast::<u8>().add(at % SIZE) }
}

/// From the interrupt handler: queue a frame, or drop it if there is
/// no room.
pub(super) fn push(frame: &[u8], rssi: i8, decrypted: bool) {
    let (head, tail) = (HEAD.get(), TAIL.get());
    // The indexes are volatile, the bytes are not: without these fences
    // the compiler may move a byte's access across an index's, and the
    // other side see a frame half written, or have it overwritten.
    crate::sync::barrier();
    let used = head.wrapping_sub(tail);
    if frame.len() > 0xFFFF || used + HEADER + frame.len() > SIZE {
        DROPPED.set(DROPPED.get() + 1);
        return;
    }
    let header = [
        frame.len() as u8,
        (frame.len() >> 8) as u8,
        rssi as u8,
        decrypted as u8,
    ];
    for (i, b) in header.iter().chain(frame).enumerate() {
        // SAFETY: free space, checked above.
        unsafe { byte(head + i).write(*b) };
    }
    crate::sync::barrier();
    HEAD.set(head + HEADER + frame.len());
}

/// From the main program: take the oldest frame into `out`. A frame
/// longer than `out` is discarded.
pub(super) fn pop(out: &mut [u8]) -> Option<Received> {
    loop {
        let tail = TAIL.get();
        if tail == HEAD.get() {
            return None;
        }
        crate::sync::barrier();
        // SAFETY: bytes the writer has finished with.
        let at = |i: usize| unsafe { byte(tail + i).read() };
        let len = at(0) as usize | (at(1) as usize) << 8;
        let info = Received {
            len,
            rssi: at(2) as i8,
            decrypted: at(3) != 0,
        };
        let fits = len <= out.len();
        if fits {
            for (i, slot) in out[..len].iter_mut().enumerate() {
                *slot = at(HEADER + i);
            }
        }
        crate::sync::barrier();
        TAIL.set(tail + HEADER + len);
        if fits {
            return Some(info);
        }
    }
}

/// Frames lost because the main program was not keeping up.
pub(super) fn dropped() -> u32 {
    DROPPED.get()
}
