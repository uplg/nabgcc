//! Sound (`src/vm/vaudio.c`, and the half of `src/hal/audio.c` that
//! feeds the codec from the bytecode).
//!
//! Playing, the bytecode fills a 4 KB ring buffer through its play
//! callback; the machine empties it into the codec whenever the codec
//! asks for data. Recording, the codec's ADPCM words go to the record
//! callback as they come.

use crate::{AUDIO_FIFOPLAY, Host, NIL, SYS_CBPLAY, SYS_CBREC, Vm, int, pnt, val};

const VS1003_MODE: u8 = 0x00;
const VS1003_DECODE_TIME: u8 = 0x04;
const VS1003_HDAT0: u8 = 0x08;
const VS1003_HDAT1: u8 = 0x09;
const VS1003_VOLUME: u8 = 0x0B;
const VS1003_AICTRL0: u8 = 0x0C;
const VS1003_AICTRL1: u8 = 0x0D;

const SM_RESET: u16 = 0x04;
const SM_SDISHARE: u16 = 0x04;
const SM_SDINEW: u16 = 0x08;
const SM_ADPCM: u16 = 0x10;
const SM_ADPCM_HP: u16 = 0x20;
/// The mode of the codec on the LLC2-4c board.
const MODE_H: u16 = SM_SDISHARE | SM_SDINEW;
const MODE_L: u16 = 0;

/// The WMA patch the C loads before every sound (`patchwma`).
const PATCH_WMA: [u32; 10] = [
    0x0207800e, 0x02062801, 0x02063f80, 0x02060006, 0x020653d7, 0x020784fe, 0x02062000, 0x02060000,
    0x02063f05, 0x0206c024,
];

const STEPS: [u16; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272,
    2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493,
    10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
];
const INDEX: [i32; 8] = [-1, -1, -1, -1, 2, 4, 6, 8];

#[rustfmt::skip]
const ALAW: [i16; 256] = [
-5504,-5248,-6016,-5760,-4480,-4224,-4992,-4736,-7552,-7296,-8064,-7808,-6528,-6272,-7040,-6784,-2752,-2624,-3008,-2880,-2240,-2112,-2496,-2368,-3776,-3648,-4032,-3904,-3264,-3136,-3520,-3392,
-22016,-20992,-24064,-23040,-17920,-16896,-19968,-18944,-30208,-29184,-32256,-31232,-26112,-25088,-28160,-27136,-11008,-10496,-12032,-11520,-8960,-8448,-9984,-9472,-15104,-14592,-16128,-15616,-13056,-12544,-14080,-13568,
-344,-328,-376,-360,-280,-264,-312,-296,-472,-456,-504,-488,-408,-392,-440,-424,-88,-72,-120,-104,-24,-8,-56,-40,-216,-200,-248,-232,-152,-136,-184,-168,
-1376,-1312,-1504,-1440,-1120,-1056,-1248,-1184,-1888,-1824,-2016,-1952,-1632,-1568,-1760,-1696,-688,-656,-752,-720,-560,-528,-624,-592,-944,-912,-1008,-976,-816,-784,-880,-848,
5504,5248,6016,5760,4480,4224,4992,4736,7552,7296,8064,7808,6528,6272,7040,6784,2752,2624,3008,2880,2240,2112,2496,2368,3776,3648,4032,3904,3264,3136,3520,3392,
22016,20992,24064,23040,17920,16896,19968,18944,30208,29184,32256,31232,26112,25088,28160,27136,11008,10496,12032,11520,8960,8448,9984,9472,15104,14592,16128,15616,13056,12544,14080,13568,
344,328,376,360,280,264,312,296,472,456,504,488,408,392,440,424,88,72,120,104,24,8,56,40,216,200,248,232,152,136,184,168,
1376,1312,1504,1440,1120,1056,1248,1184,1888,1824,2016,1952,1632,1568,1760,1696,688,656,752,720,560,528,624,592,944,912,1008,976,816,784,880,848];

#[rustfmt::skip]
const MULAW: [i16; 256] = [
-32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,-23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,-15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,-11900,-11388,-10876,-10364,-9852,-9340,-8828,-8316,
-7932,-7676,-7420,-7164,-6908,-6652,-6396,-6140,-5884,-5628,-5372,-5116,-4860,-4604,-4348,-4092,-3900,-3772,-3644,-3516,-3388,-3260,-3132,-3004,-2876,-2748,-2620,-2492,-2364,-2236,-2108,-1980,
-1884,-1820,-1756,-1692,-1628,-1564,-1500,-1436,-1372,-1308,-1244,-1180,-1116,-1052,-988,-924,-876,-844,-812,-780,-748,-716,-684,-652,-620,-588,-556,-524,-492,-460,-428,-396,
-372,-356,-340,-324,-308,-292,-276,-260,-244,-228,-212,-196,-180,-164,-148,-132,-120,-112,-104,-96,-88,-80,-72,-64,-56,-48,-40,-32,-24,-16,-8,0,
32124,31100,30076,29052,28028,27004,25980,24956,23932,22908,21884,20860,19836,18812,17788,16764,15996,15484,14972,14460,13948,13436,12924,12412,11900,11388,10876,10364,9852,9340,8828,8316,
7932,7676,7420,7164,6908,6652,6396,6140,5884,5628,5372,5116,4860,4604,4348,4092,3900,3772,3644,3516,3388,3260,3132,3004,2876,2748,2620,2492,2364,2236,2108,1980,
1884,1820,1756,1692,1628,1564,1500,1436,1372,1308,1244,1180,1116,1052,988,924,876,844,812,780,748,716,684,652,620,588,556,524,492,460,428,396,
372,356,340,324,308,292,276,260,244,228,212,196,180,164,148,132,120,112,104,96,88,80,72,64,56,48,40,32,24,16,8,0];

/// The exponent of an A-law or mu-law sample, by its top byte.
fn exponent(top: i32) -> i32 {
    match top {
        0 => 0,
        1 => 1,
        2..=3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=63 => 6,
        64..=127 => 7,
        _ => 8,
    }
}

/// The sign bit both laws keep, and the magnitude they encode, cut at
/// 32635.
fn sign_magnitude(pcm: i16) -> (i32, i32) {
    let mut pcm = pcm as i32;
    let sign = (pcm & 0x8000) >> 8;
    if sign != 0 {
        pcm = -pcm;
    }
    (sign, pcm.min(32635))
}

fn alaw_encode(pcm: i16) -> u8 {
    let (sign, pcm) = sign_magnitude(pcm);
    let e = exponent(pcm >> 8);
    let mantissa = (pcm >> if e == 0 { 4 } else { e + 3 }) & 0x0f;
    ((sign | e << 4 | mantissa) as u8) ^ 0xD5
}

fn mulaw_encode(pcm: i16) -> u8 {
    let (sign, pcm) = sign_magnitude(pcm);
    let pcm = pcm + 0x84;
    let e = exponent(pcm >> 8);
    let mantissa = (pcm >> (e + 3)) & 0x0f;
    !((sign | e << 4 | mantissa) as u8)
}

pub(crate) struct Audio {
    play_w: i32,
    play_r: i32,
    play_state: u8,
    rec_state: u8,
    try_to_feed: i32,
    predicted: i16,
    step_index: u8,
    vol: i32,
}

impl Audio {
    pub(crate) const fn new() -> Self {
        Audio {
            play_w: 0,
            play_r: 0,
            play_state: 0,
            rec_state: 0,
            try_to_feed: 2048,
            predicted: 0,
            step_index: 0,
            vol: 0,
        }
    }

    fn decode_init(&mut self, s0: i32, st: i32) {
        self.predicted = s0 as i16;
        self.step_index = st as u8;
        self.vol = 0;
    }

    /// The step the index points at. The C indexes its table with the
    /// saved byte, unchecked: a bad block header reads past it.
    fn step(&self) -> i32 {
        STEPS.get(self.step_index as usize).copied().unwrap_or(0) as i32
    }

    /// What decoding and encoding share once a nibble's difference is
    /// known: the new prediction, and the step index the nibble moves.
    fn advance(&mut self, nibble: u32, diff: i32) -> i32 {
        let p = self.predicted as i32;
        let v = if nibble & 8 != 0 { p - diff } else { p + diff };
        let v = v.clamp(-0x8000, 0x7fff);
        self.predicted = v as i16;
        let index = self.step_index as i32 + INDEX[(nibble & 7) as usize];
        self.step_index = index.clamp(0, 88) as u8;
        v
    }

    /// `mydecode`: one IMA ADPCM nibble.
    fn decode(&mut self, adpcm: u32) -> i16 {
        let step = self.step();
        let mut diff = step >> 3;
        if adpcm & 4 != 0 {
            diff += step;
        }
        if adpcm & 2 != 0 {
            diff += step >> 1;
        }
        if adpcm & 1 != 0 {
            diff += step >> 2;
        }
        let v = self.advance(adpcm, diff);
        self.vol = self.vol.wrapping_add((v * v) >> 16);
        v as i16
    }

    /// `myencode`.
    fn encode(&mut self, pcm: i16) -> u8 {
        let mut delta = pcm as i32 - self.predicted as i32;
        let mut value: u32 = if delta >= 0 { 0 } else { 8 };
        delta = delta.abs();
        let mut step = self.step();
        let mut diff = step >> 3;
        for bit in [4, 2, 1] {
            if delta > step {
                value |= bit;
                delta -= step;
                diff += step;
            }
            step >>= 1;
        }
        self.advance(value, diff);
        (value & 15) as u8
    }
}

impl<H: Host> Vm<'_, H> {
    /// `clear_vlsi_fifo`: a soft reset of the codec.
    fn codec_reset(&mut self) {
        self.host
            .codec_write(VS1003_MODE, (MODE_H << 8) | MODE_L | SM_RESET);
    }

    /// `audioPlayStart` and `play_start`.
    pub(crate) fn play_start(&mut self, mut try_to_feed: i32) {
        self.audio.play_w = 0;
        self.audio.play_r = 0;
        if self.audio.rec_state != 0 {
            return;
        }
        self.codec_reset();
        for k in PATCH_WMA {
            self.host.codec_write((k >> 16) as u8, k as u16);
        }
        if try_to_feed <= 0 {
            try_to_feed = 1024;
        }
        self.audio.try_to_feed = try_to_feed;
        self.host.amplifier(true);
        self.audio.play_state = 1;
    }

    /// `play_stop`.
    pub(crate) fn play_stop(&mut self) {
        if self.audio.play_state == 0 {
            return;
        }
        self.host.amplifier(false);
        self.codec_reset();
        self.audio.play_state = 0;
    }

    /// `audioPlayFeed`: as much of the bytes as the ring takes. Without
    /// bytes, the sound ends once the ring is empty.
    pub(crate) fn play_feed(&mut self, src: Option<(i32, i32)>) -> i32 {
        let Some((src, len)) = src else {
            if self.audio.play_state == 1 {
                self.audio.play_state = 2;
            }
            return 0;
        };
        let (w, r) = (self.audio.play_w, self.audio.play_r);
        let size = AUDIO_FIFOPLAY as i32;
        let mut i_end = r - 1;
        if w >= r {
            i_end = size + r - 1;
        }
        if w + len < i_end {
            i_end = w + len;
        }
        if i_end <= w {
            return 0;
        }
        if i_end < size {
            let len = i_end - w;
            self.fifo_copy(w, src, len);
            self.audio.play_w = i_end;
            return len;
        }
        let len = size - w;
        self.fifo_copy(w, src, len);
        let i_end = i_end - size;
        if i_end != 0 {
            self.fifo_copy(0, src + len, i_end);
        }
        self.audio.play_w = i_end;
        len + i_end
    }

    fn fifo_copy(&mut self, at: i32, src: i32, len: i32) {
        for k in 0..len.max(0) {
            let v = self.b(src + k);
            if let Some(d) = self.mem.fifo.get_mut((at + k) as usize) {
                *d = v;
            }
        }
    }

    /// `audioPlayTryFeed`: ask the bytecode for more until the ring holds
    /// `ask` bytes or it stops giving. True if it gave anything.
    fn play_try_feed(&mut self, ask: i32) -> bool {
        let w0 = self.audio.play_w;
        if self.fifo_level() >= ask {
            return false;
        }
        loop {
            let lastw = self.audio.play_w;
            self.push(int(AUDIO_FIFOPLAY as i32 - self.fifo_level()));
            self.push(self.cget(self.sys_start, SYS_CBPLAY));
            if self.sget(0) == NIL {
                self.pull();
                self.pull();
                return false;
            }
            self.interp_go();
            self.pull();
            if self.audio.play_w == lastw {
                break;
            }
        }
        self.audio.play_w != w0
    }

    /// How many bytes the ring holds.
    fn fifo_level(&self) -> i32 {
        let level = self.audio.play_w - self.audio.play_r;
        if level < 0 {
            level + AUDIO_FIFOPLAY as i32
        } else {
            level
        }
    }

    /// `audioPlayFetchByte`.
    fn play_fetch_byte(&mut self) -> i32 {
        if self.audio.play_w == self.audio.play_r {
            return -1;
        }
        let v = self.mem.fifo[self.audio.play_r as usize % AUDIO_FIFOPLAY] as i32;
        self.audio.play_r += 1;
        if self.audio.play_r >= AUDIO_FIFOPLAY as i32 {
            self.audio.play_r -= AUDIO_FIFOPLAY as i32;
        }
        v
    }

    /// `play_check`: feed the codec while it asks, refilling the ring
    /// from the bytecode unless `nocb`.
    pub(crate) fn play_check(&mut self, nocb: bool) {
        if self.audio.play_state == 0 || !self.host.codec_ready() {
            return;
        }
        let mut nocb = nocb;
        if !nocb {
            nocb = !self.play_try_feed(self.audio.try_to_feed);
        }
        let mut nb = 0;
        loop {
            if !self.host.codec_ready() {
                break;
            }
            self.host.watchdog();
            let mut v = self.play_fetch_byte();
            if v < 0 && nb + nb >= self.audio.try_to_feed && !nocb {
                nocb = !self.play_try_feed(self.audio.try_to_feed);
                self.play_try_feed(self.audio.try_to_feed);
                v = self.play_fetch_byte();
            }
            if v >= 0 {
                nb += 1;
                self.host.codec_feed(&[v as u8]);
            } else {
                if self.audio.play_state == 2 {
                    self.audio.play_state = 0;
                }
                break;
            }
        }
    }

    /// `audioVol` (`set_vlsi_volume`).
    pub(crate) fn volume(&mut self, vol: i32) {
        let v = ((vol & 255) / 2) as u16;
        self.host.codec_write(VS1003_VOLUME, (v << 8) | v);
        self.host.amplifier(v < 0x7f);
    }

    /// `check_decode_time`.
    pub(crate) fn play_time(&mut self) -> i32 {
        self.host.codec_read(VS1003_DECODE_TIME) as i32
    }

    /// `rec_start`.
    pub(crate) fn rec_start(&mut self, freq: i32, gain: i32) {
        if self.audio.play_state != 0 {
            return;
        }
        self.codec_reset();
        self.host.amplifier(false);
        let freq = freq as u16;
        // A zero frequency divides by zero; the ARM's division gives
        // the largest number, cut to 16 bits.
        let config = if freq == 0 {
            0xFFFF
        } else {
            (192000 / freq as u32) as u16
        };
        self.host.codec_write(VS1003_AICTRL0, config);
        self.host.codec_write(VS1003_AICTRL1, gain as u16);
        self.host.codec_write(
            VS1003_MODE,
            ((MODE_H | SM_ADPCM_HP | SM_ADPCM) << 8) | MODE_L | SM_RESET,
        );
        self.audio.rec_state = 1;
    }

    /// `rec_stop`.
    pub(crate) fn rec_stop(&mut self) {
        if self.audio.rec_state == 0 {
            return;
        }
        self.codec_reset();
        self.host.amplifier(false);
        self.codec_reset();
        self.audio.rec_state = 0;
    }

    /// `rec_check`: hand what the codec recorded to the bytecode.
    pub(crate) fn rec_check(&mut self) {
        if self.audio.rec_state == 0 {
            return;
        }
        let mut words = self.host.codec_read(VS1003_HDAT1) & 0xFF80;
        if words == 0 {
            return;
        }
        let p = self.alloc_bin((words as i32) << 1);
        self.push(pnt(p));
        // The push may have collected and moved the block: from the
        // stack, as the C's VSTACKGET(0).
        let mut at = Self::start_bin(val(self.sget(0)));
        while words > 0 {
            words -= 1;
            let v = self.host.codec_read(VS1003_HDAT0);
            self.set_b(at, (v >> 8) as u8);
            self.set_b(at + 1, v as u8);
            at += 2;
        }
        self.push(self.cget(self.sys_start, SYS_CBREC));
        if self.sget(0) != NIL {
            self.interp_go();
        } else {
            self.pull();
        }
        self.pull();
    }

    /// `audioRecVol`: the loudness of a 256-byte ADPCM block.
    pub(crate) fn rec_vol(&mut self, src: i32, len: i32, start: i32) -> i32 {
        if start.wrapping_add(256) > len {
            return 0;
        }
        self.decode_block(src + start, None);
        self.audio.vol >> 8
    }

    /// `AudioAdp2wav`: 256-byte ADPCM blocks to 505 16-bit samples each.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn adp2wav(
        &mut self,
        dst: i32,
        idst: i32,
        ldst: i32,
        src: i32,
        isrc: i32,
        lsrc: i32,
        mut len: i32,
    ) {
        if !starts_inside(idst, ldst, isrc, lsrc) || len & 255 != 0 {
            return;
        }
        if len > lsrc - isrc || (len >> 8) * 505 * 2 > ldst - idst {
            return;
        }
        let (mut s, mut d) = (src + isrc, dst + idst);
        while len > 0 {
            self.decode_block(s, Some(d));
            s += 256;
            d += 505 * 2;
            len -= 256;
        }
    }

    /// A 256-byte ADPCM block: its first sample and step index, then 252
    /// bytes of two nibbles. The 505 samples go to `dst` if there is one.
    fn decode_block(&mut self, src: i32, dst: Option<i32>) {
        let s0 = self.short(src);
        self.audio.decode_init(s0, self.short(src + 2));
        if let Some(d) = dst {
            self.put16(d, s0 as i16);
        }
        for i in 0..252 {
            let c = self.b(src + 4 + i) as u32;
            let a = self.audio.decode(c & 15);
            let b = self.audio.decode((c >> 4) & 15);
            if let Some(d) = dst {
                self.put16(d + 2 + 4 * i, a);
                self.put16(d + 4 + 4 * i, b);
            }
        }
    }

    /// `AudioWav2adp`: blocks of 505 16-bit samples to 256 bytes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn wav2adp(
        &mut self,
        dst: i32,
        idst: i32,
        ldst: i32,
        src: i32,
        isrc: i32,
        lsrc: i32,
        mut len: i32,
    ) {
        if !starts_inside(idst, ldst, isrc, lsrc) {
            return;
        }
        let mut n = 0;
        let mut l = len;
        while l > 0 {
            l -= 505 * 2;
            n += 1;
        }
        if l != 0 {
            return;
        }
        if len > lsrc - isrc || (n << 8) > ldst - idst {
            return;
        }
        let (mut s, mut d) = (src + isrc, dst + idst);
        while len > 0 {
            self.adpcm_encode_block(s, d);
            s += 505 * 2;
            d += 256;
            len -= 505 * 2;
        }
    }

    /// `adpcmencode`.
    fn adpcm_encode_block(&mut self, src: i32, dst: i32) {
        let sample = |vm: &Self, i: i32| vm.get16(src + 2 * i);
        let s1 = sample(self, 0);
        let s2 = sample(self, 1);
        self.audio.predicted = s1;
        let delta = (s2 as i32 - s1 as i32).abs().min(32767);
        let mut index = 0;
        // The C walks the table unchecked; 32767 is its last entry.
        while (STEPS[index] as u32) < delta as u32 {
            index += 1;
        }
        self.audio.step_index = index as u8;
        self.put16(dst, s1);
        self.put16(dst + 2, index as i16);
        let mut o = dst + 4;
        let mut i = 1;
        while i < 505 {
            let a = self.audio.encode(sample(self, i));
            let b = self.audio.encode(sample(self, i + 1));
            self.set_b(o, a + (b << 4));
            o += 1;
            i += 2;
        }
    }

    /// `AudioWav2alaw`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn wav2alaw(
        &mut self,
        dst: i32,
        idst: i32,
        ldst: i32,
        src: i32,
        isrc: i32,
        lsrc: i32,
        len: i32,
        mu: bool,
    ) {
        if !starts_inside(idst, ldst, isrc, lsrc) || len & 1 != 0 {
            return;
        }
        if len > lsrc - isrc || (len >> 1) > ldst - idst {
            return;
        }
        let (s, d) = (src + isrc, dst + idst);
        for k in 0..len >> 1 {
            let v = self.get16(s + 2 * k);
            self.set_b(d + k, if mu { mulaw_encode(v) } else { alaw_encode(v) });
        }
    }

    /// `AudioAlaw2wav`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn alaw2wav(
        &mut self,
        dst: i32,
        idst: i32,
        ldst: i32,
        src: i32,
        isrc: i32,
        lsrc: i32,
        len: i32,
        mu: bool,
    ) {
        if !starts_inside(idst, ldst, isrc, lsrc) {
            return;
        }
        if len > lsrc - isrc || len + len > ldst - idst {
            return;
        }
        let (s, d) = (src + isrc, dst + idst);
        for k in 0..len.max(0) {
            let c = self.b(s + k) as usize;
            self.put16(d + 2 * k, if mu { MULAW[c] } else { ALAW[c] });
        }
    }

    /// An `int16_t` read as the C's `ldrsh` does on the ARM7TDMI: from
    /// an odd address the core loads the one byte there, sign-extended.
    fn get16(&self, at: i32) -> i16 {
        if at & 1 != 0 {
            return self.b(at) as i8 as i16;
        }
        (self.b(at) as u16 | (self.b(at + 1) as u16) << 8) as i16
    }

    /// An `int16_t` written as the C's `strh` does on the ARM7TDMI: the
    /// low bit of the address ignored.
    fn put16(&mut self, at: i32, v: i16) {
        let at = at & !1;
        self.set_b(at, v as u8);
        self.set_b(at + 1, (v >> 8) as u8);
    }
}

/// The check every conversion starts with: both indexes inside their
/// strings.
fn starts_inside(idst: i32, ldst: i32, isrc: i32, lsrc: i32) -> bool {
    idst >= 0 && isrc >= 0 && idst < ldst && isrc < lsrc
}
