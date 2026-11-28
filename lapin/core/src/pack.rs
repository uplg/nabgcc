//! The application packed, for the first flash from the C firmware
//! (`lapin-first.bin`, see `lapin/fw/src/boot.rs`): the C firmware's
//! routine writes the flash with the watchdog unfed, so the image it
//! writes must be short. The rescue core unpacks it, once, into the
//! external RAM.
//!
//! LZ77 with an adaptive binary coder (rANS, 12-bit probabilities),
//! after a filter that turns the offsets of Thumb's BL pairs into
//! their targets (two calls to one function then look alike). The
//! history the copies reach into starts with the rescue core: the
//! application shares much of its code.
//!
//! The stream is a sequence of items, each one bit first (its context:
//! the parity of the position, whether the item before was a copy):
//!
//! - 0: a literal, eight bits from the highest down a tree of
//!   contexts, chosen by the parity of the position and the top bit of
//!   the byte before;
//! - 1: a copy. After a literal, one more bit: 1 copies from as far
//!   back as the last copy did, 0 (and always after a copy) reads a new
//!   distance. Then its length minus one.
//!
//! Distances and lengths are Elias gamma codes, their bits from the
//! lowest, each with its own context. The unpacked length is known
//! beforehand: the stream has no end marker.

/// The coder's probabilities: 12 bits, out of [`ONE`].
const BITS: u32 = 12;
const ONE: u32 = 1 << BITS;
/// The coder's state stays in [`LOW`, `LOW` << 8) between bits.
const LOW: u32 = 1 << 16;
/// How fast a probability adapts: by 1/32 of the way.
const RATE: u32 = 5;

const IS_COPY: usize = 0;
const REPEAT: usize = 4;
const LITERAL: usize = 8;
/// Up to 2^20 for a distance or a length: 20 bits, two contexts each.
const GAMMA_BITS: usize = 20;
const TREES: usize = 4;
const DISTANCE: usize = LITERAL + TREES * 256;
const LENGTH: usize = DISTANCE + 2 * GAMMA_BITS;
const CONTEXTS: usize = LENGTH + 2 * GAMMA_BITS;

/// "LAPP", little-endian: the packed application's header. Its words:
/// the magic, the packed stream's length in bytes, the unpacked
/// application's length, the CRC-32 of the unpacked application (all
/// of it), the CRC-32 of the packed stream, which follows.
pub const MAGIC: u32 = 0x5050_414C;
pub const HEADER_LEN: usize = 20;

/// The literal's tree of contexts at `n`: by the parity of the position
/// and the top bit of the byte before.
fn tree(buf: &[u8], n: usize) -> usize {
    let before = if n > 0 { buf[n - 1] as usize } else { 0 };
    LITERAL + 256 * ((n & 1) | (2 * (before >> 7)))
}

/// A literal's eight bits from the highest, each through `bit` with its
/// context, the node of its `tree`. (Coding them against the byte a copy
/// would have brought next, as LZMA does, gained 39 bytes here.)
fn literal(tree: usize, mut bit: impl FnMut(usize) -> usize) -> u8 {
    let mut node = 1;
    while node < 256 {
        node = 2 * node + bit(tree + node);
    }
    node as u8
}

struct Decoder<'a> {
    input: &'a [u8],
    at: usize,
    state: u32,
    probs: [u16; CONTEXTS],
}

impl Decoder<'_> {
    fn bit(&mut self, ctx: usize) -> usize {
        while self.state < LOW {
            let byte = *self.input.get(self.at).unwrap_or(&0);
            self.at += 1;
            self.state = self.state << 8 | byte as u32;
        }
        let p = &mut self.probs[ctx];
        let prob = *p as u32;
        let slot = self.state & (ONE - 1);
        let high = self.state >> BITS;
        if slot < prob {
            self.state = prob * high + slot;
            *p += ((ONE - prob) >> RATE) as u16;
            1
        } else {
            self.state = (ONE - prob) * high + slot - prob;
            *p -= (prob >> RATE) as u16;
            0
        }
    }

    fn gamma(&mut self, mut ctx: usize) -> usize {
        let (mut value, mut shift) = (0, 0);
        while self.bit(ctx) != 0 {
            value |= self.bit(ctx + 1) << shift;
            shift += 1;
            ctx += 2;
        }
        value | 1 << shift
    }
}

/// Unpack `packed` into `buf` from `start` to its end; what is before
/// `start` is the history copies may reach into. `tick` is called at
/// every item (the watchdog). False if the stream reaches outside the
/// buffer.
pub fn unpack(packed: &[u8], buf: &mut [u8], start: usize, mut tick: impl FnMut()) -> bool {
    let mut d = Decoder {
        input: packed,
        at: 0,
        state: 0,
        probs: [(ONE / 2) as u16; CONTEXTS],
    };
    let (mut n, mut distance, mut after_copy) = (start, 0, 0);
    while n < buf.len() {
        tick();
        let parity = n & 1;
        if d.bit(IS_COPY + parity + 2 * after_copy) != 0 {
            if after_copy != 0 || d.bit(REPEAT) == 0 {
                distance = d.gamma(DISTANCE);
            }
            let len = d.gamma(LENGTH) + 1;
            if distance == 0 || distance > n || len > buf.len() - n {
                return false;
            }
            for _ in 0..len {
                buf[n] = buf[n - distance];
                n += 1;
            }
            after_copy = 1;
        } else {
            buf[n] = literal(tree(buf, n), |ctx| d.bit(ctx));
            n += 1;
            after_copy = 0;
        }
    }
    true
}

/// The filter on Thumb code: each BL pair's offset (to the halfword
/// after it) made the call's target, from the start of `code`, or back.
pub fn thumb_calls(code: &mut [u8], back: bool) {
    let mut i = 0;
    while i + 4 <= code.len() {
        if code[i + 1] & 0xF8 != 0xF0 || code[i + 3] & 0xF8 != 0xF8 {
            i += 2;
            continue;
        }
        let v = (code[i + 1] as u32 & 7) << 19
            | (code[i] as u32) << 11
            | (code[i + 3] as u32 & 7) << 8
            | code[i + 2] as u32;
        let at = (i as u32 + 4) >> 1;
        let v = if back {
            v.wrapping_sub(at)
        } else {
            v.wrapping_add(at)
        };
        code[i] = (v >> 11) as u8;
        code[i + 1] = 0xF0 | (v >> 19 & 7) as u8;
        code[i + 2] = v as u8;
        code[i + 3] = 0xF8 | (v >> 8 & 7) as u8;
        i += 4;
    }
}

/// CRC-32 (IEEE 802.3, as zlib's), `tick` called every 4 KB (the
/// firmware feeds its watchdog; it reads the flash a word at a time,
/// `lapin_fw::boot::crc32`).
pub fn crc32(data: &[u8], mut tick: impl FnMut()) -> u32 {
    let table = crc_table();
    let mut c = !0u32;
    for chunk in data.chunks(4096) {
        tick();
        c = crc_bytes(&table, c, chunk);
    }
    !c
}

/// The remainders of the 256 bytes, for [`crc_bytes`] and
/// [`crc_words`]. Built at each check, on the stack: the rescue core,
/// which checks the whole application at every power-on, has no room
/// left for it in its flash, nor the internal RAM to keep it. Building
/// it takes a fraction of a millisecond; four bits at a time, from a
/// table of 16 in the flash, the check took the rescue core 83 ms.
pub fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (i, t) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = (c >> 1) ^ (0xEDB8_8320 & (c & 1).wrapping_neg());
        }
        *t = c;
    }
    table
}

/// The CRC register `c` (inverted, as it runs) carried over `data`.
/// This and [`crc_words`] are ARM code, whose shifts come with the
/// operation that takes them; plain operators and no call, which the
/// compiler would not inline into them from Thumb.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
pub fn crc_bytes(table: &[u32; 256], mut c: u32, data: &[u8]) -> u32 {
    let mut i = 0;
    while i < data.len() {
        c = table[((c ^ data[i] as u32) & 0xFF) as usize] ^ (c >> 8);
        i += 1;
    }
    c
}

/// The same over the bytes of `words` as a little-endian processor
/// holds them (the rabbit's): one load for four bytes.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
pub fn crc_words(table: &[u32; 256], mut c: u32, words: &[u32]) -> u32 {
    let mut i = 0;
    while i < words.len() {
        c ^= words[i];
        c = table[(c & 0xFF) as usize] ^ (c >> 8);
        c = table[(c & 0xFF) as usize] ^ (c >> 8);
        c = table[(c & 0xFF) as usize] ^ (c >> 8);
        c = table[(c & 0xFF) as usize] ^ (c >> 8);
        i += 1;
    }
    c
}

#[cfg(any(test, feature = "std"))]
pub use packer::pack;

#[cfg(any(test, feature = "std"))]
mod packer {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// What the packer decides at a position.
    #[derive(Clone, Copy)]
    enum Item {
        Literal,
        Copy { distance: usize, len: usize },
    }

    /// The items as bits, each in its context, in the order the decoder
    /// reads them: the encoder records them, the parse prices them.
    trait Bits {
        fn bit(&mut self, ctx: usize, one: bool);

        /// `value`'s Elias gamma code, from `ctx` on.
        fn gamma(&mut self, mut ctx: usize, value: usize) {
            let top = usize::BITS - 1 - value.leading_zeros();
            for shift in 0..top {
                self.bit(ctx, true);
                self.bit(ctx + 1, value >> shift & 1 != 0);
                ctx += 2;
            }
            self.bit(ctx, false);
        }

        /// The literal `buf[n]`, after the bit that says it is one.
        fn literal(&mut self, buf: &[u8], n: usize, after_copy: usize) {
            self.bit(IS_COPY + (n & 1) + 2 * after_copy, false);
            let mut k = 8;
            literal(tree(buf, n), |ctx| {
                k -= 1;
                let b = buf[n] as usize >> k & 1;
                self.bit(ctx, b != 0);
                b
            });
        }
    }

    /// The model's bits as the coder will take them, recorded with their
    /// probability at that point.
    struct Model {
        probs: Vec<u16>,
        bits: Vec<(bool, u16)>,
        /// How often each context saw a 1 and a 0, for the next parse.
        seen: Vec<[u32; 2]>,
    }

    impl Model {
        fn new() -> Model {
            Model {
                probs: vec![(ONE / 2) as u16; CONTEXTS],
                bits: Vec::new(),
                seen: vec![[0; 2]; CONTEXTS],
            }
        }
    }

    impl Bits for Model {
        fn bit(&mut self, ctx: usize, one: bool) {
            let p = &mut self.probs[ctx];
            self.bits.push((one, *p));
            self.seen[ctx][one as usize] += 1;
            let prob = *p as u32;
            if one {
                *p += ((ONE - prob) >> RATE) as u16;
            } else {
                *p -= (prob >> RATE) as u16;
            }
        }
    }

    impl Model {
        /// `gamma`, of a value the decoder reads.
        fn coded(&mut self, ctx: usize, value: usize) {
            assert!((1..1 << GAMMA_BITS).contains(&value));
            self.gamma(ctx, value);
        }

        /// rANS: the bits taken in reverse, the bytes put out reversed.
        fn finish(&self) -> Vec<u8> {
            let mut out = Vec::new();
            let mut x = LOW;
            for &(one, p) in self.bits.iter().rev() {
                let p = p as u32;
                let (start, size) = if one { (0, p) } else { (p, ONE - p) };
                while x >= ((LOW >> BITS) << 8) * size {
                    out.push(x as u8);
                    x >>= 8;
                }
                x = ((x / size) << BITS) + x % size + start;
            }
            while x != 0 {
                out.push(x as u8);
                x >>= 8;
            }
            out.reverse();
            out
        }
    }

    /// Bits a 1 or a 0 costs in each context (in 1/256 of a bit), from
    /// what the last parse saw.
    struct Costs(Vec<[u32; 2]>);

    impl Costs {
        fn from(seen: Option<&[[u32; 2]]>) -> Costs {
            let cost = |p: f64| (-p.log2() * 256.0) as u32;
            Costs(
                (0..CONTEXTS)
                    .map(|c| {
                        let [zeros, ones] = seen.map_or([1, 1], |s| s[c]);
                        let p1 = (ones as f64 + 0.4) / ((zeros + ones) as f64 + 0.8);
                        [cost(1.0 - p1), cost(p1)]
                    })
                    .collect(),
            )
        }

        fn bit(&self, ctx: usize, one: bool) -> u32 {
            self.0[ctx][one as usize]
        }

        /// What `code` costs, the bits it gives `Bits` priced.
        fn price(&self, code: impl FnOnce(&mut Price)) -> u32 {
            let mut p = Price(self, 0);
            code(&mut p);
            p.1
        }

        fn gamma(&self, ctx: usize, value: usize) -> u32 {
            self.price(|p| p.gamma(ctx, value))
        }

        fn literal(&self, buf: &[u8], n: usize, after_copy: usize) -> u32 {
            self.price(|p| p.literal(buf, n, after_copy))
        }
    }

    /// The bits priced by `Costs`, summed.
    struct Price<'a>(&'a Costs, u32);

    impl Bits for Price<'_> {
        fn bit(&mut self, ctx: usize, one: bool) {
            self.1 += self.0.bit(ctx, one);
        }
    }

    /// The model run over the items: the stream.
    fn encode(buf: &[u8], start: usize, items: &[(usize, Item)]) -> Model {
        let mut m = Model::new();
        let (mut distance, mut after_copy) = (0, 0);
        for &(n, item) in items {
            let parity = n & 1;
            match item {
                Item::Literal => {
                    m.literal(buf, n, after_copy);
                    after_copy = 0;
                }
                Item::Copy { distance: d, len } => {
                    m.bit(IS_COPY + parity + 2 * after_copy, true);
                    if after_copy == 0 {
                        m.bit(REPEAT, d == distance);
                    }
                    if after_copy != 0 || d != distance {
                        m.coded(DISTANCE, d);
                    }
                    m.coded(LENGTH, len - 1);
                    distance = d;
                    after_copy = 1;
                }
            }
        }
        let _ = start;
        m
    }

    fn common(buf: &[u8], a: usize, b: usize) -> usize {
        let mut k = 0;
        while b + k < buf.len() && buf[a + k] == buf[b + k] {
            k += 1;
        }
        k
    }

    /// For each position from `start`, the copies worth trying: each the
    /// nearest distance for its length, lengths growing.
    fn candidates(buf: &[u8], start: usize) -> Vec<Vec<(usize, usize)>> {
        const DEPTH: usize = 256;
        let hash = |i: usize| {
            (buf[i] as usize | (buf[i + 1] as usize) << 8 | (buf[i + 2] as usize) << 16)
                .wrapping_mul(2_654_435_761)
                >> 8
                & 0xFFFF
        };
        let mut head = vec![usize::MAX; 0x10000];
        let mut prev = vec![usize::MAX; buf.len()];
        let mut found = vec![Vec::new(); buf.len()];
        for i in 0..buf.len().saturating_sub(2) {
            let h = hash(i);
            if i >= start {
                let mut best = 2;
                let mut j = head[h];
                let mut depth = 0;
                while j != usize::MAX && depth < DEPTH {
                    let k = common(buf, j, i);
                    if k > best {
                        best = k;
                        found[i].push((i - j, k));
                    }
                    j = prev[j];
                    depth += 1;
                }
            }
            prev[i] = head[h];
            head[h] = i;
        }
        found
    }

    /// The cheapest items from `start` to the end of `buf` by `costs`:
    /// the cheapest path to each position, ending on a literal and
    /// ending on a copy (their contexts differ), each with the distance
    /// carried along it.
    fn parse(
        buf: &[u8],
        start: usize,
        found: &[Vec<(usize, usize)>],
        costs: &Costs,
    ) -> Vec<(usize, Item)> {
        let n = buf.len();
        // By position and how the path to it ended (0 a literal, 1 a
        // copy): its price, its last item, the lane it came from, the
        // distance in effect.
        let mut price = vec![[u32::MAX; 2]; n + 1];
        let mut how = vec![[(Item::Literal, 0u8); 2]; n + 1];
        let mut distance_at = vec![[0usize; 2]; n + 1];
        price[start][0] = 0;
        for i in start..n {
            for after_copy in 0..2 {
                let here = price[i][after_copy];
                if here == u32::MAX {
                    continue;
                }
                let distance = distance_at[i][after_copy];
                let mut offer = |to: usize, cost: u32, item: Item, d: usize| {
                    let lane = matches!(item, Item::Copy { .. }) as usize;
                    if here + cost < price[to][lane] {
                        price[to][lane] = here + cost;
                        how[to][lane] = (item, after_copy as u8);
                        distance_at[to][lane] = d;
                    }
                };
                let literal = costs.literal(buf, i, after_copy);
                offer(i + 1, literal, Item::Literal, distance);
                let copy = costs.bit(IS_COPY + (i & 1) + 2 * after_copy, true);
                // The last distance again, after a literal.
                if after_copy == 0 && distance != 0 && distance <= i {
                    let k = common(buf, i - distance, i);
                    let base = copy + costs.bit(REPEAT, true);
                    for len in lengths(2, k) {
                        let c = base + costs.gamma(LENGTH, len - 1);
                        offer(i + len, c, Item::Copy { distance, len }, distance);
                    }
                }
                let base = copy
                    + if after_copy == 0 {
                        costs.bit(REPEAT, false)
                    } else {
                        0
                    };
                let mut shorter = 2;
                for &(d, k) in &found[i] {
                    let dc = base + costs.gamma(DISTANCE, d);
                    for len in lengths(shorter + 1, k) {
                        let c = dc + costs.gamma(LENGTH, len - 1);
                        offer(i + len, c, Item::Copy { distance: d, len }, d);
                    }
                    shorter = k;
                }
            }
        }
        let mut items = Vec::new();
        let mut at = n;
        let mut lane = (price[n][1] < price[n][0]) as usize;
        while at > start {
            let (item, from) = how[at][lane];
            let len = match item {
                Item::Literal => 1,
                Item::Copy { len, .. } => len,
            };
            at -= len;
            lane = from as usize;
            items.push((at, item));
        }
        items.reverse();
        items
    }

    /// The lengths worth pricing from `from` to `to`: all of them up to
    /// a point, then the longest only.
    fn lengths(from: usize, to: usize) -> impl Iterator<Item = usize> {
        let all = to.min(from + 48);
        (from..=all).chain((to > all).then_some(to))
    }

    /// Pack `data`, the history starting with `dict` (which the unpacker
    /// finds in its buffer before the data).
    pub fn pack(dict: &[u8], data: &[u8]) -> Vec<u8> {
        let mut buf = dict.to_vec();
        buf.extend_from_slice(data);
        let start = dict.len();
        let found = candidates(&buf, start);
        let mut seen: Option<Vec<[u32; 2]>> = None;
        let mut best: Option<Vec<u8>> = None;
        for _ in 0..4 {
            let costs = Costs::from(seen.as_deref());
            let items = parse(&buf, start, &found, &costs);
            let model = encode(&buf, start, &items);
            let out = model.finish();
            if best.as_ref().is_none_or(|b| out.len() < b.len()) {
                best = Some(out);
            }
            seen = Some(model.seen);
        }
        best.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn round_trip(dict: &[u8], data: &[u8]) -> usize {
        let packed = pack(dict, data);
        let mut buf = dict.to_vec();
        buf.resize(dict.len() + data.len(), 0xA5);
        let mut ticks = 0;
        assert!(unpack(&packed, &mut buf, dict.len(), || ticks += 1));
        assert_eq!(&buf[dict.len()..], data);
        assert!(ticks > 0 || data.is_empty());
        packed.len()
    }

    /// Bytes that look a little like code: a few patterns, repeated with
    /// changes, and some noise.
    fn sample(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        let mut out = Vec::new();
        while out.len() < len {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            match x >> 29 {
                0..=3 => out.push((x >> 16) as u8 & 0x3F),
                4 | 5 => out.extend_from_slice(&[0x70, 0xB5, (x >> 20) as u8, 0x46]),
                _ => {
                    let back = (x >> 8) as usize % 300 + 1;
                    for _ in 0..(x >> 4) as usize % 20 {
                        if back <= out.len() {
                            out.push(out[out.len() - back]);
                        }
                    }
                }
            }
        }
        out.truncate(len);
        out
    }

    /// zlib's check values, and the watchdog fed every 4 KB.
    #[test]
    fn crc32_is_zlib_s() {
        let mut ticks = 0;
        assert_eq!(crc32(b"123456789", || ticks += 1), 0xCBF4_3926);
        assert_eq!(crc32(&[0; 8193], || ticks += 1), 0x25B8_4C49);
        assert_eq!(ticks, 4);
    }

    /// Four bytes at a time from words, as the firmware reads the flash:
    /// the same CRC.
    #[test]
    fn crc_of_words_is_that_of_their_bytes() {
        let table = crc_table();
        let words: Vec<u32> = (0..1000u32).map(|i| i.wrapping_mul(0x9E37_79B9)).collect();
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(crc_words(&table, !0, &words), crc_bytes(&table, !0, &bytes));
        assert_eq!(!crc_bytes(&table, !0, &bytes), crc32(&bytes, || {}));
    }

    #[test]
    fn round_trips() {
        assert_eq!(round_trip(&[], &[]), 3);
        round_trip(&[], b"a");
        round_trip(&[1, 2, 3], &[7; 1000]);
        let d = sample(30_000, 1);
        let n = round_trip(&[], &d);
        assert!(n < d.len() / 2, "{n}");
        // The history before the data is used.
        let dict = sample(8000, 2);
        let mut data = dict[1000..5000].to_vec();
        data.extend(sample(2000, 3));
        let with = round_trip(&dict, &data);
        let without = round_trip(&[], &data);
        assert!(with + 1000 < without, "{with} {without}");
    }

    #[test]
    fn a_damaged_stream_stays_inside_the_buffer() {
        let d = sample(5000, 4);
        let packed = pack(&[], &d);
        for i in (0..packed.len()).step_by(7) {
            let mut bad = packed.clone();
            bad[i] ^= 0x5A;
            let mut buf = std::vec![0; d.len()];
            // Whatever comes out, nothing is read or written outside.
            let _ = unpack(&bad, &mut buf, 0, || {});
        }
        // A stream of ones: a copy first, from before the buffer.
        let mut buf = std::vec![0; 100];
        assert!(!unpack(&[0xFF; 64], &mut buf, 0, || {}));
    }

    #[test]
    fn the_call_filter_goes_back() {
        let code = sample(4000, 5);
        let mut calls = code.clone();
        // Some BL pairs among it.
        for at in (0..3990).step_by(50) {
            calls[at + 1] = 0xF0 | calls[at + 1] & 7;
            calls[at + 3] = 0xF8 | calls[at + 3] & 7;
        }
        let mut f = calls.clone();
        thumb_calls(&mut f, false);
        assert_ne!(f, calls);
        thumb_calls(&mut f, true);
        assert_eq!(f, calls);
        // Two calls to one target come out the same.
        let mut two = [0u8; 8];
        let bl = |at: u32, target: u32| {
            let v = (target - at - 4) >> 1;
            [
                (v >> 11) as u8,
                0xF0 | (v >> 19 & 7) as u8,
                v as u8,
                0xF8 | (v >> 8 & 7) as u8,
            ]
        };
        two[..4].copy_from_slice(&bl(0, 0x400));
        two[4..].copy_from_slice(&bl(4, 0x400));
        thumb_calls(&mut two, false);
        assert_eq!(two[..4], two[4..]);
    }
}
