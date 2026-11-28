//! The frames waiting for the bytecode, in the order they came: the C
//! driver's queue of received buffers (`rt2501buffer_new`), which held
//! as many as its USB heap did. Here a ring of bytes, each frame behind
//! its length and source; a frame that does not fit is dropped, as the
//! C driver dropped one it could not allocate.

/// Room for the frames: the C driver's heap was 32 KB, shared with its
/// USB transfers.
pub const SIZE: usize = 16 * 1024;
const HEADER: usize = 8;

pub struct Inbox {
    ring: &'static mut [u8; SIZE],
    head: usize,
    tail: usize,
    /// Frames dropped for want of room.
    pub dropped: u32,
}

impl Inbox {
    pub fn new(ring: &'static mut [u8; SIZE]) -> Inbox {
        Inbox {
            ring,
            head: 0,
            tail: 0,
            dropped: 0,
        }
    }

    fn put(&mut self, at: usize, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate() {
            self.ring[at.wrapping_add(i) % SIZE] = *b;
        }
    }

    fn byte(&self, at: usize) -> u8 {
        self.ring[at % SIZE]
    }

    /// Queue `frame`, from `source`.
    pub fn push(&mut self, frame: &[u8], source: &[u8; 6]) {
        let used = self.head.wrapping_sub(self.tail);
        if frame.len() > 0xFFFF || used + HEADER + frame.len() > SIZE {
            self.dropped = self.dropped.wrapping_add(1);
            return;
        }
        let n = frame.len() as u16;
        self.put(self.head, &n.to_le_bytes());
        self.put(self.head.wrapping_add(2), source);
        self.put(self.head.wrapping_add(HEADER), frame);
        self.head = self.head.wrapping_add(HEADER + frame.len());
    }

    /// The length of the oldest frame, if there is one.
    pub fn front(&self) -> Option<usize> {
        (self.head != self.tail).then(|| {
            self.byte(self.tail) as usize | (self.byte(self.tail.wrapping_add(1)) as usize) << 8
        })
    }

    /// Take the oldest frame: as much of it as `data` holds, and its
    /// source.
    pub fn pop(&mut self, data: &mut [u8], source: &mut [u8; 6]) {
        let Some(len) = self.front() else {
            return;
        };
        for (i, s) in source.iter_mut().enumerate() {
            *s = self.byte(self.tail.wrapping_add(2 + i));
        }
        for (i, d) in data.iter_mut().take(len).enumerate() {
            *d = self.byte(self.tail.wrapping_add(HEADER + i));
        }
        self.tail = self.tail.wrapping_add(HEADER + len);
        if self.tail == self.head {
            self.tail = 0;
            self.head = 0;
        }
    }

    /// Forget every frame.
    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}
