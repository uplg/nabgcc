//! Reading a fuzzer's input as a stream of choices; past its end,
//! zeros.

pub struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Input { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn u8(&mut self) -> u8 {
        match self.data.split_first() {
            Some((b, rest)) => {
                self.data = rest;
                *b
            }
            None => 0,
        }
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }

    pub fn bool(&mut self) -> bool {
        self.u8() & 1 != 0
    }

    /// Up to `n` bytes (fewer at the end).
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.data.len());
        let (b, rest) = self.data.split_at(n);
        self.data = rest;
        b
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0u8; N];
        let b = self.bytes(N);
        a[..b.len()].copy_from_slice(b);
        a
    }

    /// A length byte (or two, if `wide`) then that many bytes.
    pub fn chunk(&mut self, wide: bool) -> &'a [u8] {
        let n = if wide {
            self.u16() as usize % 2400
        } else {
            self.u8() as usize
        };
        self.bytes(n)
    }
}
