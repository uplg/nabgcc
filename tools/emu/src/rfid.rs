//! The RFID reader in the rabbit's nose: an ST CRX14 on the I2C bus,
//! and the ISO 14443-B tags (ST SRI family, sold as "Ztamps") held in
//! front of it.
//!
//! The reader has four registers. Writing a frame to the I/O frame
//! register sends it to the tags; reading the register gives back the
//! answer, preceded by its length. Writing the slot marker register
//! runs the sixteen-slot anticollision and leaves one identifier per
//! slot that answered.

const REG_PARAMETER: u8 = 0;
const REG_IO_FRAME: u8 = 1;
const REG_SLOT_MARKER: u8 = 3;

/// Bit of the parameter register that switches the radio field on.
const CARRIER_ON: u8 = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// The identifier as the bytecode sees it, most significant byte
    /// first (ST tags start with `D0 02`).
    pub uid: [u8; 8],
    /// Memory blocks of four bytes. The firmware's block `n` is tag
    /// block `n + 7`.
    pub blocks: [[u8; 4]; 128],
    chip_id: u8,
}

impl Tag {
    pub fn new(uid: [u8; 8]) -> Self {
        Tag {
            uid,
            blocks: [[0; 4]; 128],
            chip_id: 0,
        }
    }
}

#[derive(Default)]
pub struct Reader {
    /// Tags within range, at most one per anticollision slot is seen.
    pub tags: Vec<Tag>,
    /// Frames sent to the tags since power-on.
    pub exchanges: u64,
    parameter: u8,
    pointer: u8,
    answer: Vec<u8>,
    selected: Option<usize>,
    incoming: Vec<u8>,
    read_at: usize,
    draws: u8,
}

impl Reader {
    pub fn reset(&mut self) {
        let tags = std::mem::take(&mut self.tags);
        *self = Reader {
            tags,
            ..Reader::default()
        };
    }

    /// Start of an I2C transfer addressed to the reader.
    pub fn start(&mut self) {
        self.incoming.clear();
        self.read_at = 0;
    }

    /// A byte written by the host: register number, then its content.
    pub fn write(&mut self, byte: u8) {
        self.incoming.push(byte);
    }

    /// A byte read by the host from the register last pointed at.
    pub fn read(&mut self) -> u8 {
        let byte = match self.pointer {
            REG_PARAMETER => self.parameter,
            REG_IO_FRAME => self.answer.get(self.read_at).copied().unwrap_or(0),
            _ => 0,
        };
        self.read_at += 1;
        byte
    }

    /// End of the transfer: a write takes effect.
    pub fn stop(&mut self) {
        let bytes = std::mem::take(&mut self.incoming);
        let Some((&register, data)) = bytes.split_first() else {
            return;
        };
        self.pointer = register;
        match (register, data) {
            (REG_PARAMETER, [value, ..]) => {
                self.parameter = *value;
                if value & CARRIER_ON == 0 {
                    // Field off: the tags lose power and forget everything.
                    self.selected = None;
                }
            }
            (REG_IO_FRAME, [len, frame @ ..]) => {
                let frame = &frame[..(*len as usize).min(frame.len())];
                self.answer = self.exchange(frame);
            }
            (REG_SLOT_MARKER, _) => self.answer = self.slot_markers(),
            _ => {}
        }
    }

    fn field_on(&self) -> bool {
        self.parameter & CARRIER_ON != 0
    }

    /// Send a frame to the tags; the answer with its length in front.
    fn exchange(&mut self, frame: &[u8]) -> Vec<u8> {
        self.exchanges += 1;
        if !self.field_on() {
            return vec![0];
        }
        match frame {
            // Initiate: every tag draws a fresh identifier and says it.
            [0x06, 0x00] => {
                self.selected = None;
                for tag in &mut self.tags {
                    self.draws = self.draws.wrapping_mul(5).wrapping_add(tag.uid[7] | 1);
                    tag.chip_id = self.draws;
                }
                // Tags sharing a slot would shout over each other for
                // ever: keep the low nibbles apart, as redraws end up doing.
                for i in 0..self.tags.len() {
                    while self.tags[..i]
                        .iter()
                        .any(|t| t.chip_id & 15 == self.tags[i].chip_id & 15)
                    {
                        self.tags[i].chip_id = self.tags[i].chip_id.wrapping_add(1);
                    }
                }
                match &self.tags[..] {
                    [] => vec![0],
                    [one] => vec![1, one.chip_id],
                    // Several answers at once: the reader reports garbage.
                    _ => vec![0xFF],
                }
            }
            [0x0E, id] => {
                self.selected = self.tags.iter().position(|t| t.chip_id == *id);
                if self.selected.is_some() {
                    vec![1, *id]
                } else {
                    vec![0]
                }
            }
            [0x0F] => {
                self.selected = None;
                vec![0]
            }
            [0x0B] => match self.selected {
                Some(i) => {
                    // Least significant byte first on the air.
                    let mut answer = vec![8];
                    answer.extend(self.tags[i].uid.iter().rev());
                    answer
                }
                None => vec![0],
            },
            [0x08, block] => match self.selected {
                Some(i) if (*block as usize) < 128 => {
                    let mut answer = vec![4];
                    answer.extend_from_slice(&self.tags[i].blocks[*block as usize]);
                    answer
                }
                _ => vec![0],
            },
            [0x09, block, data @ ..] if data.len() == 4 => {
                if let Some(i) = self.selected
                    && (*block as usize) < 128
                {
                    self.tags[i].blocks[*block as usize].copy_from_slice(data);
                }
                vec![0]
            }
            _ => vec![0],
        }
    }

    /// The sixteen-slot poll: which slots answered, and with what.
    fn slot_markers(&mut self) -> Vec<u8> {
        self.exchanges += 1;
        let mut mask = 0u16;
        let mut ids = [0u8; 16];
        if self.field_on() {
            for tag in &self.tags {
                let slot = (tag.chip_id & 15) as usize;
                mask |= 1 << slot;
                ids[slot] = tag.chip_id;
            }
        }
        let mut answer = vec![18, mask as u8, (mask >> 8) as u8];
        answer.extend_from_slice(&ids);
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(r: &mut Reader, bytes: &[u8]) {
        r.start();
        for b in bytes {
            r.write(*b);
        }
        r.stop();
    }

    fn read(r: &mut Reader, register: u8, n: usize) -> Vec<u8> {
        write(r, &[register]);
        r.start();
        (0..n).map(|_| r.read()).collect()
    }

    const UID: [u8; 8] = [0xD0, 0x02, 0x1A, 0x03, 0x52, 0xC4, 0x66, 0x7F];

    #[test]
    fn nothing_answers_without_a_tag_or_without_the_field() {
        let mut r = Reader::default();
        write(&mut r, &[REG_PARAMETER, CARRIER_ON]);
        assert_eq!(read(&mut r, REG_PARAMETER, 1), [CARRIER_ON]);
        write(&mut r, &[REG_IO_FRAME, 2, 0x06, 0x00]);
        assert_eq!(read(&mut r, REG_IO_FRAME, 2), [0, 0]);

        r.tags.push(Tag::new(UID));
        write(&mut r, &[REG_PARAMETER, 0]);
        write(&mut r, &[REG_IO_FRAME, 2, 0x06, 0x00]);
        assert_eq!(read(&mut r, REG_IO_FRAME, 2), [0, 0]);
    }

    #[test]
    fn a_tag_is_found_selected_read_and_written() {
        let mut r = Reader::default();
        r.tags.push(Tag::new(UID));
        r.tags[0].blocks[7] = *b"carr";
        write(&mut r, &[REG_PARAMETER, CARRIER_ON]);
        write(&mut r, &[REG_IO_FRAME, 2, 0x06, 0x00]);
        let id = read(&mut r, REG_IO_FRAME, 2)[1];

        write(&mut r, &[REG_SLOT_MARKER]);
        let slots = read(&mut r, REG_IO_FRAME, 19);
        let mask = u16::from_le_bytes([slots[1], slots[2]]);
        assert_eq!(mask, 1 << (id & 15));
        assert_eq!(slots[3 + (id & 15) as usize], id);

        write(&mut r, &[REG_IO_FRAME, 2, 0x0E, id]);
        assert_eq!(read(&mut r, REG_IO_FRAME, 2), [1, id]);
        write(&mut r, &[REG_IO_FRAME, 1, 0x0B]);
        let uid = read(&mut r, REG_IO_FRAME, 9);
        assert_eq!(uid[0], 8);
        assert_eq!(uid[1..].iter().rev().copied().collect::<Vec<_>>(), UID);

        write(&mut r, &[REG_IO_FRAME, 2, 0x08, 7]);
        assert_eq!(read(&mut r, REG_IO_FRAME, 5), [4, b'c', b'a', b'r', b'r']);
        write(&mut r, &[REG_IO_FRAME, 6, 0x09, 8, 1, 2, 3, 4]);
        assert_eq!(r.tags[0].blocks[8], [1, 2, 3, 4]);
    }

    #[test]
    fn several_tags_each_get_their_own_slot() {
        let mut r = Reader::default();
        for last in [0x10, 0x20, 0x30] {
            let mut uid = UID;
            uid[7] = last;
            r.tags.push(Tag::new(uid));
        }
        write(&mut r, &[REG_PARAMETER, CARRIER_ON]);
        write(&mut r, &[REG_IO_FRAME, 2, 0x06, 0x00]);
        assert_eq!(read(&mut r, REG_IO_FRAME, 1), [0xFF]);
        write(&mut r, &[REG_SLOT_MARKER]);
        let slots = read(&mut r, REG_IO_FRAME, 19);
        assert_eq!(u16::from_le_bytes([slots[1], slots[2]]).count_ones(), 3);
    }
}
