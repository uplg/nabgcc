//! Received frames waiting for the main program: the interrupt handler
//! puts them in, the main loop takes them out.

use core::cell::UnsafeCell;

use crate::sync::Shared;

const SIZE: usize = 16 * 1024;
/// What precedes each frame: length, signal strength, flags, then the
/// IV and extended IV of the stick's descriptor.
const HEADER: usize = 12;

struct Ring(UnsafeCell<[u8; SIZE]>);
// SAFETY: the writer only touches bytes between `TAIL` and `HEAD`'s
// free side, the reader the other part; each moves only its own index.
unsafe impl Sync for Ring {}
#[unsafe(link_section = ".xram.rxq")]
static RING: Ring = Ring(UnsafeCell::new([0; SIZE]));
static HEAD: Shared<usize> = Shared::new(0);
static TAIL: Shared<usize> = Shared::new(0);
static DROPPED: Shared<u32> = Shared::new(0);
static RECEIVED: Shared<u32> = Shared::new(0);
/// Whether beacons and probe responses of every network are kept (a
/// scan), or only those of `BSS_LOW`/`BSS_HIGH`'s network.
static ALL_NETWORKS: Shared<bool> = Shared::new(true);
static BSS_LOW: Shared<u32> = Shared::new(0);
static BSS_HIGH: Shared<u32> = Shared::new(0);

/// Keep the announcements (beacons, probe responses) of every network,
/// for a scan, or of `bss`'s alone. The C driver handled them in the
/// interrupt and kept nothing of them: here, with the main program
/// busy (a long bytecode), the neighbours' would fill the queue and
/// push out the frames that matter.
pub fn keep_announcements(bss: Option<&[u8; 6]>) {
    crate::irq::free(|| match bss {
        None => ALL_NETWORKS.set(true),
        Some(b) => {
            BSS_LOW.set(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            BSS_HIGH.set(u16::from_le_bytes([b[4], b[5]]) as u32);
            ALL_NETWORKS.set(false);
        }
    });
}

/// An announcement of a network other than the one followed.
fn foreign_announcement(frame: &[u8]) -> bool {
    if ALL_NETWORKS.get() || frame.len() < 22 || !matches!(frame[0], 0x80 | 0x50) {
        return false;
    }
    let b = &frame[16..22];
    u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != BSS_LOW.get()
        || u16::from_le_bytes([b[4], b[5]]) as u32 != BSS_HIGH.get()
}

/// A frame as the stick delivered it.
#[derive(Debug, Clone, Copy)]
pub struct Received {
    pub len: usize,
    /// Signal strength, in dBm.
    pub rssi: i8,
    /// The stick decrypted it.
    pub decrypted: bool,
    /// Words 2 and 3 of the receive descriptor: the frame's IV and
    /// extended IV, which hold its packet number.
    pub iv: u32,
    pub eiv: u32,
}

fn byte(at: usize) -> *mut u8 {
    // SAFETY: `at` is taken modulo the size.
    unsafe { RING.0.get().cast::<u8>().add(at % SIZE) }
}

/// From the interrupt handler: queue a frame, or drop it if there is
/// no room.
pub(super) fn push(frame: &[u8], rssi: i8, decrypted: bool, iv: u32, eiv: u32) {
    RECEIVED.set(RECEIVED.get().wrapping_add(1));
    if foreign_announcement(frame) {
        return;
    }
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
    let [i0, i1, i2, i3] = iv.to_le_bytes();
    let [e0, e1, e2, e3] = eiv.to_le_bytes();
    let header = [
        frame.len() as u8,
        (frame.len() >> 8) as u8,
        rssi as u8,
        decrypted as u8,
        i0,
        i1,
        i2,
        i3,
        e0,
        e1,
        e2,
        e3,
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
        let word = |i: usize| u32::from_le_bytes([at(i), at(i + 1), at(i + 2), at(i + 3)]);
        let info = Received {
            len,
            rssi: at(2) as i8,
            decrypted: at(3) != 0,
            iv: word(4),
            eiv: word(8),
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

/// Frames the stick delivered so far, kept or not.
pub fn received() -> u32 {
    RECEIVED.get()
}

/// Frames lost because the main program was not keeping up.
pub(super) fn dropped() -> u32 {
    DROPPED.get()
}
