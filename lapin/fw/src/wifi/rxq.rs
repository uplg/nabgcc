//! Received frames waiting for the main program: the interrupt handler
//! puts them in, the main loop takes them out.

use core::cell::UnsafeCell;

use crate::sync::Shared;

const SIZE: usize = 16 * 1024;
/// What precedes each frame: length, signal strength, flags, then the
/// IV and extended IV of the stick's descriptor. Each frame starts on a
/// word, so that it is copied in and out a word at a time (the ring is
/// in the external RAM, where every access waits).
const HEADER: usize = 12;

#[repr(align(4))]
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

/// The networks an announcement of which was queued since the scan
/// began: their addresses in an open-addressed set, each entry's second
/// word carrying the scan's number in its top half (a new scan empties
/// the set at once). Once the queue is half full, another announcement
/// of one of them is dropped: in a band so crowded that frames come
/// faster than the scan reads them, the room goes to the networks not
/// heard yet. Until then each is kept, the strongest heard listed.
const SEEN: usize = 512;
struct Seen(UnsafeCell<[[u32; 2]; SEEN]>);
// SAFETY: only the USB interrupt handler touches it.
unsafe impl Sync for Seen {}
// Not initialised: an entry of what was there at power-on is free but
// for one chance in 65 536, and then only taken.
#[unsafe(link_section = ".xram_high.seen")]
static SEEN_SET: Seen = Seen(UnsafeCell::new([[0; 2]; SEEN]));
static SCAN: Shared<u32> = Shared::new(1);

/// Keep the announcements (beacons, probe responses) of every network,
/// for a scan, or of `bss`'s alone. The C driver handled them in the
/// interrupt and kept nothing of them: here, with the main program
/// busy (a long bytecode), the neighbours' would fill the queue and
/// push out the frames that matter.
pub fn keep_announcements(bss: Option<&[u8; 6]>) {
    crate::irq::free(|| match bss {
        None => {
            ALL_NETWORKS.set(true);
            SCAN.set(SCAN.get() % 0xFFFF + 1);
        }
        Some(b) => {
            BSS_LOW.set(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            BSS_HIGH.set(u16::from_le_bytes([b[4], b[5]]) as u32);
            ALL_NETWORKS.set(false);
        }
    });
}

/// The network's address in an announcement, as two words.
fn announcer(frame: &[u8]) -> Option<(u32, u32)> {
    if frame.len() < 22 || !matches!(frame[0], 0x80 | 0x50) {
        return None;
    }
    let b = &frame[16..22];
    Some((
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]) as u32,
    ))
}

/// Where a network is in the set of those heard during the scan, or
/// the free entry it would take (false); `None` when the set is full
/// there.
fn seen(low: u32, high: u32) -> Option<(usize, bool)> {
    // SAFETY: see `Seen`.
    let set = unsafe { &*SEEN_SET.0.get() };
    let scan = SCAN.get();
    let mut i = ((low >> 8 ^ high).wrapping_mul(0x9E37_79B1) >> 23) as usize;
    for _ in 0..16 {
        let [a, b] = set[i % SEEN];
        if b >> 16 != scan {
            return Some((i % SEEN, false));
        }
        if a == low && b == high | scan << 16 {
            return Some((i % SEEN, true));
        }
        i += 1;
    }
    None
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

/// The ring's bytes from `at` on, `len` of them, as at most two slices
/// (where it wraps round). Each side touches only its own part (see
/// `Ring`).
fn span(at: usize, len: usize) -> (&'static mut [u8], &'static mut [u8]) {
    let base = RING.0.get().cast::<u8>();
    let at = at % SIZE;
    let first = len.min(SIZE - at);
    // SAFETY: inside the ring (`len` is never more than its size), and
    // in the part of it that is the caller's alone.
    unsafe {
        (
            core::slice::from_raw_parts_mut(base.add(at), first),
            core::slice::from_raw_parts_mut(base, len - first),
        )
    }
}

/// What a frame of `len` bytes takes of the ring: whole words.
fn entry(len: usize) -> usize {
    (HEADER + len + 3) & !3
}

/// From the interrupt handler: queue a frame, or drop it if there is
/// no room.
pub(super) fn push(frame: &[u8], rssi: i8, decrypted: bool, iv: u32, eiv: u32) {
    RECEIVED.set(RECEIVED.get().wrapping_add(1));
    let (head, tail) = (HEAD.get(), TAIL.get());
    // The indexes are volatile, the bytes are not: without these fences
    // the compiler may move a byte's access across an index's, and the
    // other side see a frame half written, or have it overwritten.
    crate::sync::barrier();
    let used = head.wrapping_sub(tail);
    let mut new = None;
    if let Some((low, high)) = announcer(frame) {
        if !ALL_NETWORKS.get() {
            // An announcement of a network other than the one followed.
            if low != BSS_LOW.get() || high != BSS_HIGH.get() {
                return;
            }
        } else {
            match seen(low, high) {
                Some((_, true)) if used > SIZE / 2 => return,
                Some((i, false)) => new = Some((i, [low, high | SCAN.get() << 16])),
                _ => {}
            }
        }
    }
    let len = frame.len();
    if len > 0xFFFF || used + entry(len) > SIZE {
        DROPPED.set(DROPPED.get() + 1);
        return;
    }
    let first = len as u32 | (rssi as u8 as u32) << 16 | (decrypted as u32) << 24;
    for (i, w) in [first, iv, eiv].into_iter().enumerate() {
        // Free space, checked above; a word never straddles the wrap.
        span(head + 4 * i, 4).0.copy_from_slice(&w.to_le_bytes());
    }
    let (a, b) = span(head + HEADER, len);
    let (x, y) = frame.split_at(a.len());
    a.copy_from_slice(x);
    b.copy_from_slice(y);
    crate::sync::barrier();
    HEAD.set(head + entry(len));
    if let Some((i, e)) = new {
        // SAFETY: see `Seen`.
        unsafe { (*SEEN_SET.0.get())[i] = e };
    }
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
        // Bytes the writer has finished with.
        let word = |i: usize| {
            let w = span(tail + i, 4).0;
            u32::from_le_bytes([w[0], w[1], w[2], w[3]])
        };
        let first = word(0);
        let len = first as u16 as usize;
        let info = Received {
            len,
            rssi: (first >> 16) as i8,
            decrypted: first >> 24 != 0,
            iv: word(4),
            eiv: word(8),
        };
        let fits = len <= out.len();
        if fits {
            let (a, b) = span(tail + HEADER, len);
            let (x, y) = out[..len].split_at_mut(a.len());
            x.copy_from_slice(a);
            y.copy_from_slice(b);
        }
        crate::sync::barrier();
        TAIL.set(tail + entry(len));
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
