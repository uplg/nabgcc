//! The machine's library (`src/vm/vlog.c` and `src/vm/vnet.c`): strings,
//! numbers, the board.

use crate::{Auth, Host, Motor, NIL, SYS_CBTCP, Vm, int, pnt, val};

/// Multiplicative inverses modulo 256 of the odd bytes, for `crypt`.
const INV8: [u8; 128] = [
    1, 171, 205, 183, 57, 163, 197, 239, 241, 27, 61, 167, 41, 19, 53, 223, 225, 139, 173, 151, 25,
    131, 165, 207, 209, 251, 29, 135, 9, 243, 21, 191, 193, 107, 141, 119, 249, 99, 133, 175, 177,
    219, 253, 103, 233, 211, 245, 159, 161, 75, 109, 87, 217, 67, 101, 143, 145, 187, 221, 71, 201,
    179, 213, 127, 129, 43, 77, 55, 185, 35, 69, 111, 113, 155, 189, 39, 169, 147, 181, 95, 97, 11,
    45, 23, 153, 3, 37, 79, 81, 123, 157, 7, 137, 115, 149, 63, 65, 235, 13, 247, 121, 227, 5, 47,
    49, 91, 125, 231, 105, 83, 117, 31, 33, 203, 237, 215, 89, 195, 229, 15, 17, 59, 93, 199, 73,
    51, 85, 255,
];

/// The size of the settings sector.
const SETTINGS: i32 = 4096;

/// How many times the C asks an I2C device before it gives up.
const TRIES: u32 = 1000;

const ITOA: [i32; 10] = [
    1_000_000_000,
    100_000_000,
    10_000_000,
    1_000_000,
    100_000,
    10_000,
    1000,
    100,
    10,
    1,
];

/// A digit of a number in base 16, small letters past 9.
pub(crate) fn hex_digit(v: i32) -> u8 {
    if v < 10 {
        b'0' + v as u8
    } else {
        b'a' + (v - 10) as u8
    }
}

impl<H: Host> Vm<'_, H> {
    /// `logSecho`.
    pub(crate) fn secho(&mut self, p: i32, nl: bool) {
        self.echo(p, nl, |vm, p| {
            let q = val(p);
            let (at, len) = (Self::start_bin(q), vm.size_bin(q));
            let text = clip(crate::bytes(&vm.mem.heap), at, len);
            vm.host.console(text);
        });
    }

    /// `logIecho`.
    pub(crate) fn iecho(&mut self, i: i32, nl: bool) {
        self.echo(i, nl, |vm, i| vm.console_int(val(i)));
    }

    /// What the two echoes share: nil printed as such, then the end of
    /// the line if asked.
    fn echo(&mut self, v: i32, nl: bool, show: impl FnOnce(&mut Self, i32)) {
        if v == NIL {
            self.host.console(b"NIL");
        } else {
            show(self, v);
        }
        if nl {
            self.host.console(b"\r\n");
        }
    }

    /// `sysCpy`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sys_cpy(
        &mut self,
        dst: i32,
        i: i32,
        ldst: i32,
        src: i32,
        j: i32,
        lsrc: i32,
        len: i32,
    ) {
        if let Some(len) = fit(i, ldst, j, lsrc, len) {
            self.copy_bytes(dst.wrapping_add(i), src.wrapping_add(j), len);
        }
    }

    /// `sysCmp`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sys_cmp(
        &self,
        dst: i32,
        i: i32,
        ldst: i32,
        src: i32,
        j: i32,
        lsrc: i32,
        mut len: i32,
    ) -> i32 {
        if i < 0 || j < 0 || len <= 0 {
            return 0;
        }
        if i.wrapping_add(len) > ldst && j.wrapping_add(len) > lsrc {
            len = (ldst - i).max(lsrc - j);
        }
        self.memcmp(dst.wrapping_add(i), src.wrapping_add(j), len)
            .signum()
    }

    /// `sysFind` going `forward` from `i`, `sysFindrev` going back: where
    /// the `len` bytes from `j` in `src` are in `dst`, as an integer, or
    /// nil.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn sys_find(
        &self,
        dst: i32,
        mut i: i32,
        ldst: i32,
        src: i32,
        j: i32,
        lsrc: i32,
        len: i32,
        forward: bool,
    ) -> i32 {
        if j < 0 || j.wrapping_add(len) > lsrc {
            return NIL;
        }
        let src = src.wrapping_add(j);
        if forward {
            i = i.max(0);
        } else if i.wrapping_add(len) > ldst {
            i = ldst - len;
        }
        let inside = |i: i32| {
            if forward {
                i.wrapping_add(len) <= ldst
            } else {
                i >= 0
            }
        };
        while inside(i) {
            if self.memcmp(dst.wrapping_add(i), src, len) == 0 {
                return int(i);
            }
            i += if forward { 1 } else { -1 };
        }
        NIL
    }

    /// `memcmp` as newlib returns it: the difference of the first bytes
    /// that differ.
    pub(crate) fn memcmp(&self, a: i32, b: i32, len: i32) -> i32 {
        let mut i = 0;
        while i < len {
            let (x, y) = (self.b(a.wrapping_add(i)), self.b(b.wrapping_add(i)));
            if x != y {
                return x as i32 - y as i32;
            }
            i += 1;
        }
        0
    }

    /// `sysStrgetword`: a big-endian 16-bit word.
    pub(crate) fn strgetword(&self, src: i32, len: i32, ind: i32) -> i32 {
        if ind < 0 || ind.wrapping_add(2) > len {
            return -1;
        }
        ((self.b(src.wrapping_add(ind)) as i32) << 8)
            + self.b(src.wrapping_add(ind).wrapping_add(1)) as i32
    }

    /// `sysStrputword`.
    pub(crate) fn strputword(&mut self, src: i32, len: i32, ind: i32, v: i32) {
        if ind < 0 || ind.wrapping_add(2) > len {
            return;
        }
        self.set_b(src + ind + 1, v as u8);
        self.set_b(src + ind, (v >> 8) as u8);
    }

    /// `sysAtoi`: decimal, up to the first character that is not a digit.
    pub(crate) fn atoi(&self, mut src: i32) -> i32 {
        let mut x: i32 = 0;
        let mut s = false;
        if self.b(src) == b'-' {
            s = true;
            src += 1;
        }
        loop {
            let c = self.b(src);
            src = src.wrapping_add(1);
            if c == 0 || !c.is_ascii_digit() {
                break;
            }
            x = x.wrapping_mul(10).wrapping_add((c - b'0') as i32);
        }
        if s { x.wrapping_neg() } else { x }
    }

    /// `sysHtoi`.
    pub(crate) fn htoi(&self, mut src: i32) -> i32 {
        let mut x: i32 = 0;
        loop {
            let c = self.b(src);
            src = src.wrapping_add(1);
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'A'..=b'F' => c - b'A' + 10,
                b'a'..=b'f' => c - b'a' + 10,
                _ => return x,
            };
            x = (x << 4).wrapping_add(d as i32);
        }
    }

    /// `sysCtoa`.
    pub(crate) fn ctoa(&mut self, c: i32) {
        self.push_str(&[c as u8]);
    }

    /// `sysItoa`.
    pub(crate) fn itoa(&mut self, v: i32) {
        // The most negative number stays negative: no digit, as in the C.
        let mut rest = if v < 0 { v.wrapping_neg() } else { v };
        let digits = ITOA.iter().map(move |&unit| {
            let mut k = 0;
            while rest >= unit {
                k += 1;
                rest -= unit;
            }
            k
        });
        self.push_number(v < 0, digits);
    }

    /// `sysItoh`.
    pub(crate) fn itoh(&mut self, v: i32) {
        self.push_number(false, (0..8).rev().map(|d| (v >> (4 * d)) & 15));
    }

    /// What `sysItoa` and `sysItoh` share: the sign, then the digits
    /// without their leading zeros, "0" if nothing is left, pushed as a
    /// string.
    fn push_number(&mut self, minus: bool, digits: impl Iterator<Item = i32>) {
        let mut res = [0u8; 16];
        let mut n = 0;
        if minus {
            res[n] = b'-';
            n += 1;
        }
        for d in digits.skip_while(|&d| d == 0) {
            res[n] = hex_digit(d);
            n += 1;
        }
        if n == 0 {
            res[n] = b'0';
            n += 1;
        }
        self.push_str(&res[..n]);
    }

    /// `sysCtoh`.
    pub(crate) fn ctoh(&mut self, c: i32) {
        self.push_str(&[hex_digit((c >> 4) & 15), hex_digit(c & 15)]);
    }

    /// `sysItobin2`.
    pub(crate) fn itobin2(&mut self, c: i32) {
        self.push_str(&[(c >> 8) as u8, c as u8]);
    }

    /// `sysListswitch`: the value paired with `key` in a list of pairs.
    pub(crate) fn listswitch(&self, mut p: i32, key: i32) -> i32 {
        while p != NIL {
            let q = val(self.fetch(p, 0));
            if q != NIL && self.fetch(q, 0) == key {
                return self.fetch(q, 1);
            }
            p = val(self.fetch(p, 1));
        }
        NIL
    }

    /// `sysListswitchstr`: the same, keys compared as C strings.
    pub(crate) fn listswitchstr(&self, mut p: i32, key: i32) -> i32 {
        while p != NIL {
            let q = val(self.fetch(p, 0));
            if q != NIL {
                let r = val(self.fetch(q, 0));
                if r != NIL && self.cstr(Self::start_bin(r)) == self.cstr(key) {
                    return self.fetch(q, 1);
                }
            }
            p = val(self.fetch(p, 1));
        }
        NIL
    }

    /// `sysMotorset`.
    pub(crate) fn motor_set(&mut self, motor: i32, sens: i32) {
        let motor = 1 + (motor & 1) as u8;
        let run = match sens {
            0 => Motor::Stop,
            s if s > 0 => Motor::Reverse,
            _ => Motor::Forward,
        };
        self.host.motor(motor, run);
    }

    /// `sysLoad`. As in the C, the bytes land at the start of the
    /// string, whatever the index says.
    pub(crate) fn sys_load(&mut self, dst: i32, i: i32, ldst: i32, j: i32, len: i32) -> i32 {
        let Some(len) = fit(i, ldst, j, SETTINGS, len) else {
            return 0;
        };
        if let Some(d) = span_mut(crate::bytes_mut(&mut self.mem.heap), dst, len as usize) {
            self.host.settings_read(j as u32, d);
        }
        len
    }

    /// `sysSave`, with the same quirk.
    pub(crate) fn sys_save(&mut self, dst: i32, i: i32, ldst: i32, j: i32, len: i32) -> i32 {
        let Some(len) = fit(i, ldst, j, SETTINGS, len) else {
            return 0;
        };
        let data = clip(crate::bytes(&self.mem.heap), dst, len);
        self.host.settings_write(j as u32, data);
        len
    }

    /// `sysRand`: a value between 0 and 65535.
    pub(crate) fn rand(&mut self) -> i32 {
        self.rndval = self.rndval.wrapping_mul(0x1234567).wrapping_add(11);
        (self.rndval >> 8) & 0xffff
    }

    pub(crate) fn srand(&mut self, seed: i32) {
        self.rndval = seed;
    }

    /// `sysCrypt` (`encode8`), or `sysUncrypt` (`decode8`) to `decode`:
    /// each byte changed by the key the clear byte before it leaves.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn crypt(
        &mut self,
        src: i32,
        index: i32,
        len: i32,
        lsrc: i32,
        key: i32,
        alpha: i32,
        decode: bool,
    ) -> i32 {
        if index < 0 || index.wrapping_add(len) > lsrc || len <= 0 {
            return -1;
        }
        let (mut key, alpha) = (key as u8, alpha as u8);
        for k in 0..len {
            let at = src + index + k;
            let v = self.b(at);
            let (out, clear) = if decode {
                let d = v.wrapping_sub(alpha).wrapping_mul(key);
                (d, d)
            } else {
                (
                    alpha.wrapping_add(v.wrapping_mul(INV8[(key >> 1) as usize])),
                    v,
                )
            };
            self.set_b(at, out);
            key = clear.wrapping_add(clear).wrapping_add(1);
        }
        key as i32
    }

    /// `netChk`: the Internet checksum, carried on from `v`. Words are
    /// read little-endian as the ARM7 loads them; from an odd address it
    /// loads the halfword below, rotated by a byte across the register.
    pub(crate) fn net_chk(&self, src: i32, index: i32, mut len: i32, lsrc: i32, v: u32) -> u32 {
        if index < 0 {
            return v;
        }
        if index.wrapping_add(len) > lsrc {
            len = lsrc - index;
        }
        if len <= 0 {
            return v;
        }
        let mut p = src + index;
        let mut v = ((v << 8) & 0xff00).wrapping_add((v >> 8) & 0xff);
        while len > 1 {
            let even = p & !1;
            let half = self.b(even) as u32 | (self.b(even + 1) as u32) << 8;
            v = v.wrapping_add(half.rotate_right((p as u32 & 1) * 8));
            p += 2;
            len -= 2;
        }
        if len != 0 {
            v = v.wrapping_add(self.b(p) as u32);
        }
        v = (v >> 16).wrapping_add(v & 0xffff);
        v = (v >> 16).wrapping_add(v & 0xffff);
        ((v << 8) & 0xff00).wrapping_add((v >> 8) & 0xff)
    }

    /// `netSend`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn net_send(
        &mut self,
        src: i32,
        index: i32,
        mut len: i32,
        lsrc: i32,
        mac: i32,
        imac: i32,
        lmac: i32,
        speed: i32,
    ) -> i32 {
        if index < 0 {
            return -1;
        }
        if index.wrapping_add(len) > lsrc {
            len = lsrc - index;
        }
        if len <= 0 || imac < 0 || imac.wrapping_add(6) > lmac {
            return -1;
        }
        let mut dest = [0u8; 6];
        dest.copy_from_slice(&self.slice_padded::<6>(mac + imac));
        let heap = crate::bytes(&self.mem.heap);
        let frame = clip(heap, src + index, len);
        self.host.net_send(frame, &dest, speed)
    }

    /// `N` bytes from `off`, zero where the heap ends.
    pub(crate) fn slice_padded<const N: usize>(&self, off: i32) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = self.b(off.wrapping_add(i as i32));
        }
        out
    }

    /// `netCb`: hand a received frame to the bytecode.
    pub(crate) fn net_callback(&mut self, len: usize) {
        let p = self.alloc_bin(len as i32);
        let mut source = [0u8; 6];
        let heap = crate::bytes_mut(&mut self.mem.heap);
        match span_mut(heap, Self::start_bin(p), len) {
            Some(dst) if p >= 0 => self.host.net_take(dst, &mut source),
            _ => self.host.net_take(&mut [], &mut source),
        }
        self.push(pnt(p));
        self.push_str(&source);
        self.push(self.cget(self.sys_start, SYS_CBTCP));
        if self.sget(0) != NIL {
            self.interp_go();
        } else {
            self.pull();
            self.pull();
        }
        self.pull();
    }

    /// `netScan`: a list of `[ssid mac bssid rssi channel rateset
    /// encryption]`.
    pub(crate) fn net_scan(&mut self, ssid: i32) {
        let mut name = [0u8; 64];
        let filter = if ssid == NIL {
            None
        } else {
            let s = self.cstr(Self::start_bin(ssid));
            let n = s.len().min(name.len());
            name[..n].copy_from_slice(&s[..n]);
            Some(n)
        };
        let found = self.host.net_scan(filter.map(|n| &name[..n]));
        for i in 0..found {
            let r = self.host.net_scan_result(i);
            let n = r.ssid.iter().position(|&c| c == 0).unwrap_or(r.ssid.len());
            self.push_str(&r.ssid[..n]);
            self.push_str(&r.mac);
            self.push_str(&r.bssid);
            self.push(int(r.rssi as i32));
            self.push(int(r.channel as i32));
            self.push(int(r.rateset as i32));
            self.push(int(r.encryption as i32));
            self.stack_to_tab(7);
        }
        self.stack_to_list(found as i32);
    }

    /// `netAuth`, with the C firmware's check that what the person chose
    /// agrees with what the access point advertises.
    pub(crate) fn net_auth(&mut self, scan: i32, authmode: i32, encrypt: i32, key: i32) {
        if scan == NIL {
            return;
        }
        let ssid = val(self.fetch(scan, 0));
        let mac = val(self.fetch(scan, 1));
        let bssid = val(self.fetch(scan, 2));
        let chn = val(self.fetch(scan, 4));
        let rate = val(self.fetch(scan, 5));
        let crypt = val(self.fetch(scan, 6));
        let wpa_family =
            (crypt & 0xF0 == 0x20 || crypt & 0xF0 == 0x40) && (encrypt == 0x20 || encrypt == 0x40);
        if mac == NIL || bssid == NIL || crypt == 0xFF || !(wpa_family || crypt & 0xF0 == encrypt) {
            return;
        }
        let (ssid, key) = (
            (ssid != NIL).then(|| Self::start_bin(ssid)),
            (key != NIL).then(|| (Self::start_bin(key), self.size_bin(key))),
        );
        let (mac, bssid) = (
            self.slice_padded(Self::start_bin(mac)),
            self.slice_padded(Self::start_bin(bssid)),
        );
        let heap = crate::bytes(&self.mem.heap);
        let auth = Auth {
            ssid: ssid.map(|at| cstr(heap, at)),
            mac,
            bssid,
            channel: chn as u8,
            rateset: rate as u16,
            authmode: authmode as u8,
            encryption: crypt as u8,
            key: key.map(|(at, len)| clip(heap, at, len)),
        };
        self.host.net_auth(&auth);
    }

    /// `netSeqAdd`: a 32-bit big-endian sequence number plus `n`.
    pub(crate) fn net_seq_add(&mut self, seq: i32, n: i32) {
        let s = self.slice_padded::<4>(seq);
        let v = u32::from_be_bytes(s).wrapping_add(n as u32);
        self.push_str(&v.to_be_bytes());
    }

    /// `sysRfidgetList`.
    pub(crate) fn rfid_list(&mut self) {
        let n = self.host.rfid_count();
        for i in 0..n {
            let id = self.host.rfid_nth(i);
            self.push_str(&id);
        }
        self.stack_to_list(n);
    }

    /// The top `n` words, the deepest first, become a list of pairs
    /// ended by nil.
    fn stack_to_list(&mut self, n: i32) {
        self.push(NIL);
        for _ in 0..n {
            self.stack_to_tab(2);
        }
    }

    /// `sysRfidread`.
    pub(crate) fn rfid_read(&mut self, id: i32, block: i32) {
        let id = self.slice_padded::<8>(id);
        let mut data = [0u8; 4];
        if self.host.rfid_read(&id, block, &mut data) != 0 {
            self.push(NIL);
            return;
        }
        self.push_str(&data);
    }

    /// `sysI2cRead`. The C reads into a null pointer and returns the
    /// first bytes of the flash; this one returns what the device said.
    pub(crate) fn i2c_read(&mut self, address: u8, size: i32) {
        let p = self.alloc_bin(size);
        let at = Self::start_bin(p);
        // The allocation takes the whole size, the device the low byte.
        let len = (size.max(0) as usize).min(size as u8 as usize);
        if let Some(data) = span_mut(crate::bytes_mut(&mut self.mem.heap), at, len) {
            (0..TRIES).any(|_| self.host.i2c_read(address, data));
        }
        self.push(pnt(p));
    }

    /// `sysI2cWrite`.
    pub(crate) fn i2c_write(&mut self, address: u8, data: i32, len: i32) {
        let heap = crate::bytes(&self.mem.heap);
        let data = clip(heap, data, len as u8 as i32);
        (0..TRIES).any(|_| self.host.i2c_write(address, data));
    }

    /// `sysFlash`: the last checks before the flash erases itself. There
    /// is no bootloader, so an image that is not a firmware costs a JTAG
    /// session: it must fit below the settings sector and open on five
    /// `ldr pc, [pc, #n]`.
    pub(crate) fn flash_firmware(&mut self, image: i32, len: i32) {
        if !(0x1000..=0x1F000).contains(&len) {
            return;
        }
        for i in 0..5 {
            let at = image + 4 * i;
            if self.b(at + 3) != 0xE5 || self.b(at + 2) != 0x9F || self.b(at + 1) & 0xF0 != 0xF0 {
                return;
            }
        }
        let heap = crate::bytes(&self.mem.heap);
        self.host.flash_firmware(clip(heap, image, len));
    }
}

/// The bytes from `at` up to the first zero, as C reads a string.
pub(crate) fn cstr(heap: &[u8], at: i32) -> &[u8] {
    let Ok(start) = usize::try_from(at) else {
        return &[];
    };
    let rest = heap.get(start..).unwrap_or(&[]);
    let n = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    &rest[..n]
}

/// The bytes `[at, at + len)` of the heap, if they all are in it.
fn span_mut(heap: &mut [u8], at: i32, len: usize) -> Option<&mut [u8]> {
    usize::try_from(at)
        .ok()
        .and_then(|at| heap.get_mut(at..at + len))
}

/// The bounds `sysCpy`, `sysLoad` and `sysSave` share: `len` bytes from
/// `i` in `ldst` and from `j` in `lsrc`, cut to what fits in both. None
/// when nothing is left.
fn fit(i: i32, ldst: i32, j: i32, lsrc: i32, mut len: i32) -> Option<i32> {
    if i < 0 || j < 0 || len <= 0 {
        return None;
    }
    if i.wrapping_add(len) > ldst {
        len = ldst - i;
    }
    if len <= 0 {
        return None;
    }
    if j.wrapping_add(len) > lsrc {
        len = lsrc - j;
    }
    if len <= 0 {
        return None;
    }
    Some(len)
}

/// The bytes `[at, at + len)` of the heap, cut where it ends.
pub(crate) fn clip(heap: &[u8], at: i32, len: i32) -> &[u8] {
    let (Ok(start), Ok(len)) = (usize::try_from(at), usize::try_from(len)) else {
        return &[];
    };
    let start = start.min(heap.len());
    let end = start.saturating_add(len).min(heap.len());
    &heap[start..end]
}
