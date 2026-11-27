//! The Metal virtual machine: what runs the rabbit's bytecode.
//!
//! A port of the C firmware's machine (`src/vm/` and the half of
//! `src/hal/audio.c` that calls back into the bytecode), kept faithful
//! down to its accidents, because the boot bytecode and the programs
//! served to rabbits were written against that machine and nothing
//! else. The memory is laid out as the C lays it out, word for word,
//! and its collector moves things exactly when the C one does. Where
//! the C reads or writes outside its memory, this one reads zero and
//! writes nothing; everything that stays inside the heap, harmful or
//! not, happens as it did.
//!
//! The hardware is the firmware's business: everything the machine
//! asks of the board goes through [`Host`].

#![no_std]

#[cfg(target_endian = "big")]
compile_error!(
    "the bytecode's strings live in the words of the heap, little-endian as on the rabbit"
);

mod audio;
mod gc;
mod interp;
mod loader;
mod natives;
pub mod op;

/// Size of the machine's memory in 32-bit words: heap and stack share it
/// (`VMEM_LENGTH`, 800 KB).
pub const VMEM_LENGTH: usize = 1024 * 200;
/// A collection runs when fewer words than this would stay free.
const GC_THRESHOLD: i32 = 16;
/// The ring buffer between the bytecode and the audio codec.
pub const AUDIO_FIFOPLAY: usize = 4096;

/// The machine's nil.
pub const NIL: i32 = -1;

const HEADER_LENGTH: i32 = 3;
const HEADER_GC: i32 = 1;
const HEADER_LIST: i32 = 2;
const TYPE_BINARY: i32 = 0;
const TYPE_TAB: i32 = 1;

/// The callbacks the bytecode registers, at the bottom of the stack.
pub const SYS_CBPLAY: i32 = 0;
pub const SYS_CBUDP: i32 = 1;
pub const SYS_CBTCP: i32 = 2;
pub const SYS_CBLOOP: i32 = 3;
pub const SYS_ENV: i32 = 4;
pub const SYS_CBREC: i32 = 5;
const SYS_NB: i32 = 6;

/// A machine word holding an integer.
pub const fn int(i: i32) -> i32 {
    i << 1
}

/// A machine word holding a pointer to the block at word `p`.
pub const fn pnt(p: i32) -> i32 {
    1i32.wrapping_add(p << 1)
}

/// The integer, or the block, a word holds.
pub const fn val(v: i32) -> i32 {
    v >> 1
}

/// The memory the machine runs in, 804 KB: on the rabbit it lives in
/// the external RAM, where the C firmware put it.
#[repr(C, align(4))]
pub struct Memory {
    /// Bytecode, then heap growing up, then stack growing down from the
    /// end (`_vmem_heap`).
    pub heap: [i32; VMEM_LENGTH],
    /// The audio ring buffer (`audioFifoPlay`), which also carries the
    /// environment across a change of bytecode.
    pub fifo: [u8; AUDIO_FIFOPLAY],
}

impl Memory {
    pub const fn new() -> Self {
        Memory {
            heap: [0; VMEM_LENGTH],
            fifo: [0; AUDIO_FIFOPLAY],
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

/// What `motorset` asks of an ear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Motor {
    Stop,
    /// A negative direction from the bytecode.
    Forward,
    /// A positive direction from the bytecode.
    Reverse,
}

/// A network heard by a scan (`struct rt2501_scan_result`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult {
    /// The name, ended by a zero byte unless it takes all 32.
    pub ssid: [u8; 33],
    pub mac: [u8; 6],
    pub bssid: [u8; 6],
    pub rssi: i16,
    pub channel: u8,
    pub rateset: u16,
    pub encryption: u8,
}

/// What `netAuth` hands the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth<'a> {
    /// The bytes before the first zero, as the driver reads them.
    pub ssid: Option<&'a [u8]>,
    pub mac: [u8; 6],
    pub bssid: [u8; 6],
    pub channel: u8,
    pub rateset: u16,
    pub authmode: u8,
    pub encryption: u8,
    /// The whole key string: 5 or 13 bytes for WEP, the 32 of the PMK
    /// for WPA. The driver takes what it needs from the start.
    pub key: Option<&'a [u8]>,
}

/// The board, as the machine sees it. Each method is one of the C
/// firmware's functions, named in its documentation.
pub trait Host {
    /// Text for the serial console (`putbin_uart`).
    fn console(&mut self, text: &[u8]);
    /// Called before every instruction, as the C clears the watchdog.
    fn watchdog(&mut self) {}
    /// Milliseconds since boot (`counter_timer`).
    fn time_ms(&mut self) -> u32;
    /// Seconds since boot (`counter_timer_s`).
    fn time_s(&mut self) -> u32;

    /// `set_led`.
    fn led(&mut self, led: u8, color: u32);
    /// `run_motor` or `stop_motor`; `motor` is 1 or 2.
    fn motor(&mut self, motor: u8, run: Motor);
    /// `get_motor_position`; `motor` is 1 or 2.
    fn motor_position(&mut self, motor: u8) -> u16;
    /// `push_button_value`.
    fn button(&mut self) -> u8;
    /// `get_adc_value`: the wheel, read as `255 - adc`.
    fn adc(&mut self) -> u8;

    /// `get_rfid_first_device`.
    fn rfid_first(&mut self) -> Option<[u8; 8]>;
    /// `check_rfid_n`.
    fn rfid_count(&mut self) -> i32;
    /// `get_nth_rfid`.
    fn rfid_nth(&mut self, i: i32) -> [u8; 8];
    /// `rfid_read`: zero when the block was read.
    fn rfid_read(&mut self, id: &[u8; 8], block: i32, data: &mut [u8; 4]) -> i32;
    /// `rfid_write`.
    fn rfid_write(&mut self, id: &[u8; 8], block: i32, data: &[u8; 4]) -> i32;
    /// `read_i2c`: false when the device did not answer. At most 255
    /// bytes, as the C's length is a byte.
    fn i2c_read(&mut self, address: u8, data: &mut [u8]) -> bool;
    /// `write_i2c`.
    fn i2c_write(&mut self, address: u8, data: &[u8]) -> bool;

    /// `read_uc_flash`: bytes of the 4 KB settings sector.
    fn settings_read(&mut self, offset: u32, data: &mut [u8]);
    /// `write_uc_flash`: the sector is rewritten with these bytes at
    /// `offset`.
    fn settings_write(&mut self, offset: u32, data: &[u8]);
    /// `flash_uc`: write a new firmware over the old one and reset; it
    /// does not come back.
    /// Called only for an image that passed the C firmware's checks.
    fn flash_firmware(&mut self, image: &[u8]) -> !;
    /// `reset_uc`: it does not come back.
    fn reboot(&mut self) -> !;

    /// `vlsi_read_sci`.
    fn codec_read(&mut self, register: u8) -> u16;
    /// `vlsi_write_sci`.
    fn codec_write(&mut self, register: u8, value: u16);
    /// `vlsi_fifo_ready`: the codec takes data (DREQ).
    fn codec_ready(&mut self) -> bool;
    /// `vlsi_feed_sdi`: send bytes while the codec takes them; how many
    /// it took.
    fn codec_feed(&mut self, data: &[u8]) -> usize;
    /// `vlsi_ampli`.
    fn amplifier(&mut self, on: bool);

    /// `rt2501_state`.
    fn net_state(&mut self) -> i32;
    /// `rt2501_send(frame, length, dest, lowrate, 1)`.
    fn net_send(&mut self, frame: &[u8], dest: &[u8; 6], low_rate: i32) -> i32;
    /// `rt2501_mac`.
    fn net_mac(&mut self) -> [u8; 6];
    /// `rt2501_setmode`.
    fn net_set_mode(&mut self, mode: i32, ssid: Option<&[u8]>, channel: u8);
    /// `rt2501_scan`: scan, keep what was heard, say how many.
    fn net_scan(&mut self, ssid: Option<&[u8]>) -> usize;
    /// The scan's results, in the order the driver reported them.
    fn net_scan_result(&mut self, i: usize) -> ScanResult;
    /// `rt2501_auth`.
    fn net_auth(&mut self, auth: &Auth<'_>);
    /// `mypassword_to_pmk`: the WPA key from a passphrase.
    fn net_pmk(&mut self, ssid: &[u8], passphrase: &[u8]) -> [u8; 32];
    /// `rt2501_rssi_average`.
    fn net_rssi(&mut self) -> i32;
    /// `rt2501_receive`: the length of the next received frame, if any.
    fn net_pending(&mut self) -> Option<usize>;
    /// Hand over that frame (from its LLC header) and its source, and
    /// let it go (`hcd_free`).
    fn net_take(&mut self, data: &mut [u8], source: &mut [u8; 6]);
    /// `usbhost_events`.
    fn usb_events(&mut self) {}
    /// `rt2501_timer`, about every 200 ms of the main loop.
    fn net_timer(&mut self) {}
}

/// The machine.
pub struct Vm<'m, H: Host> {
    pub host: H,
    mem: &'m mut Memory,
    /// Where the heap is, as the collector's report prints it.
    pub heap_address: u32,
    heapindex: i32,
    stack: i32,
    start: i32,
    broken: bool,
    sys_start: i32,
    global_start: i32,
    /// Byte offset of the function table in the heap.
    tabfun: i32,
    nbfun: u16,
    currentop: i32,
    rndval: i32,
    audio: audio::Audio,
    counttimer: u8,
}

impl<'m, H: Host> Vm<'m, H> {
    pub fn new(host: H, mem: &'m mut Memory) -> Self {
        let heap_address = mem.heap.as_ptr() as usize as u32;
        let mut vm = Vm {
            host,
            mem,
            heap_address,
            heapindex: 0,
            stack: 0,
            start: 0,
            broken: false,
            sys_start: 0,
            global_start: 0,
            tabfun: 0,
            nbfun: 0,
            currentop: -1,
            rndval: 0,
            audio: audio::Audio::new(),
            counttimer: 0,
        };
        vm.vmem_init(0);
        vm
    }

    /// Boot `bytecode` as `main` does: load it, run its main function.
    pub fn boot(&mut self, bytecode: &[u8]) {
        self.vmem_init(0);
        self.load_external(bytecode);
        self.push(int(0));
        self.interp_go();
        self.pull();
    }

    /// One turn of the C firmware's main loop: the loop callback, then
    /// 50 ms of audio and received frames, and the driver's timer every
    /// fourth turn.
    pub fn main_loop_once(&mut self) {
        self.host.watchdog();
        self.push(self.cget(self.sys_start, SYS_CBLOOP));
        if self.sget(0) != NIL {
            self.interp_go();
        }
        self.pull();
        let t = self.host.time_ms();
        loop {
            self.play_check(false);
            self.rec_check();
            self.host.watchdog();
            self.host.usb_events();
            while self.host.time_ms().wrapping_sub(t) < 1000 {
                let Some(len) = self.host.net_pending() else {
                    break;
                };
                self.host.watchdog();
                self.net_callback(len);
                self.play_check(false);
                self.rec_check();
            }
            if self.host.time_ms().wrapping_sub(t) >= 50 {
                break;
            }
        }
        self.counttimer = (self.counttimer + 1) & 3;
        if self.counttimer == 0 {
            self.host.net_timer();
        }
    }

    /// Give the board back.
    pub fn into_host(self) -> H {
        self.host
    }

    /// The memory's bookkeeping: stack pointer (negative, from the end),
    /// next free word, first heap word.
    pub fn registers(&self) -> (i32, i32, i32) {
        (self.stack, self.heapindex, self.start)
    }

    /// The memory, word by word.
    pub fn memory(&self) -> &Memory {
        self.mem
    }

    /// True once the machine ran out of memory: it then runs nothing
    /// more, as the C one, until a new bytecode is loaded.
    pub fn broken(&self) -> bool {
        self.broken
    }

    /// The words in use, heap and stack, in percent, as `gc` reports.
    pub fn used_percent(&self) -> i32 {
        (self.heapindex - self.stack) * 100 / VMEM_LENGTH as i32
    }

    // The memory, word by word. Outside the heap, reads give zero and
    // writes are dropped.

    #[inline(never)]
    fn w(&self, i: i32) -> i32 {
        match self.mem.heap.get(i as usize) {
            Some(v) => *v,
            None => 0,
        }
    }

    #[inline(never)]
    fn set(&mut self, i: i32, v: i32) {
        if let Some(w) = self.mem.heap.get_mut(i as usize) {
            *w = v;
        }
    }

    /// [`Self::w`] and [`Self::set`] inline, for the collector's loops.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn wf(&self, i: i32) -> i32 {
        match self.mem.heap.get(i as usize) {
            Some(v) => *v,
            None => 0,
        }
    }

    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn setf(&mut self, i: i32, v: i32) {
        if let Some(w) = self.mem.heap.get_mut(i as usize) {
            *w = v;
        }
    }

    /// `VSIZE`, inline.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn size_tab_f(&self, p: i32) -> i32 {
        ((self.wf(p) >> 8) + 4) >> 2
    }

    /// `_vmem_top[i]`: the stack counts down from the end of the heap.
    #[inline]
    fn top(&self, i: i32) -> i32 {
        self.w((VMEM_LENGTH as i32).wrapping_add(i))
    }

    #[inline]
    fn set_top(&mut self, i: i32, v: i32) {
        self.set((VMEM_LENGTH as i32).wrapping_add(i), v)
    }

    /// `VSTACKGET`.
    #[inline]
    fn sget(&self, n: i32) -> i32 {
        self.top(self.stack.wrapping_add(n))
    }

    /// `VSTACKSET`.
    #[inline]
    fn sset(&mut self, n: i32, v: i32) {
        self.set_top(self.stack.wrapping_add(n), v)
    }

    /// `VPULL`.
    #[inline]
    fn pull(&mut self) -> i32 {
        let v = self.top(self.stack);
        self.stack = self.stack.wrapping_add(1);
        v
    }

    /// `VDROPN`.
    #[inline]
    fn drop_n(&mut self, n: i32) {
        self.stack = self.stack.wrapping_add(n);
    }

    /// `VCALLSTACKGET`.
    #[inline]
    fn cget(&self, off: i32, n: i32) -> i32 {
        self.top(off.wrapping_sub(n))
    }

    /// `VCALLSTACKSET`.
    #[inline]
    fn cset(&mut self, off: i32, n: i32, v: i32) {
        self.set_top(off.wrapping_sub(n), v)
    }

    /// `VSIZE`: words in a table.
    #[inline]
    fn size_tab(&self, p: i32) -> i32 {
        ((self.w(p) >> 8) + 4) >> 2
    }

    /// `VSIZEBIN`: bytes in a string.
    #[inline]
    fn size_bin(&self, p: i32) -> i32 {
        self.w(p) >> 8
    }

    /// `VFETCH`.
    #[inline]
    fn fetch(&self, p: i32, i: i32) -> i32 {
        self.w(p.wrapping_add(HEADER_LENGTH).wrapping_add(i))
    }

    /// `VSTORE`.
    #[inline]
    fn store(&mut self, p: i32, i: i32, v: i32) {
        self.set(p.wrapping_add(HEADER_LENGTH).wrapping_add(i), v)
    }

    // The memory, byte by byte: strings and the bytecode.

    #[inline]
    fn bytes(&self) -> &[u8] {
        bytes(&self.mem.heap)
    }

    #[inline]
    fn bytes_mut(&mut self) -> &mut [u8] {
        bytes_mut(&mut self.mem.heap)
    }

    #[inline(never)]
    fn b(&self, off: i32) -> u8 {
        match self.bytes().get(off as usize) {
            Some(v) => *v,
            None => 0,
        }
    }

    #[inline(never)]
    fn set_b(&mut self, off: i32, v: u8) {
        if let Some(b) = self.bytes_mut().get_mut(off as usize) {
            *b = v;
        }
    }

    /// `loaderGetShort`.
    #[inline(never)]
    fn short(&self, off: i32) -> i32 {
        let bytes = self.bytes();
        let o = off as usize;
        // One check for both bytes; at the edge of the memory, the slow
        // way, byte by byte.
        if o < bytes.len() - 1 {
            bytes[o] as i32 | (bytes[o + 1] as i32) << 8
        } else {
            self.b(off) as i32 | (self.b(off.wrapping_add(1)) as i32) << 8
        }
    }

    /// `loaderGetInt`.
    #[inline]
    fn int32(&self, off: i32) -> i32 {
        (self.short(off.wrapping_add(2)) << 16) | self.short(off)
    }

    /// The bytes from `off` up to the first zero, as C reads a string.
    fn cstr(&self, off: i32) -> &[u8] {
        natives::cstr(self.bytes(), off)
    }

    /// Copy `len` bytes forward, one at a time, as `mystrcpy` does.
    fn copy_bytes(&mut self, dst: i32, src: i32, len: i32) {
        // Past twice the memory, every byte left is out of it.
        let len = len.min(2 * 4 * VMEM_LENGTH as i32);
        let mut i = 0;
        while i < len {
            let v = self.b(src.wrapping_add(i));
            self.set_b(dst.wrapping_add(i), v);
            i += 1;
        }
    }

    /// Byte offset of a string's first character (`VSTARTBIN`).
    #[inline]
    fn start_bin(p: i32) -> i32 {
        p.wrapping_add(HEADER_LENGTH).wrapping_mul(4)
    }

    fn console_int(&mut self, v: i32) {
        let mut buf = [0u8; 12];
        let s = fmt_dec(v, &mut buf);
        self.host.console(s);
    }

    fn console_hex(&mut self, v: u32) {
        let mut buf = [0u8; 10];
        buf[0] = b'0';
        buf[1] = b'x';
        let mut n = 2;
        let mut started = false;
        for shift in (0..8).rev() {
            let d = (v >> (shift * 4)) & 15;
            if d != 0 || started || shift == 0 {
                started = true;
                buf[n] = b"0123456789abcdef"[d as usize];
                n += 1;
            }
        }
        self.host.console(&buf[..n]);
    }
}

fn bytes(heap: &[i32]) -> &[u8] {
    // SAFETY: any i32 is four valid bytes, and u8 has no alignment.
    unsafe { core::slice::from_raw_parts(heap.as_ptr().cast(), heap.len() * 4) }
}

fn bytes_mut(heap: &mut [i32]) -> &mut [u8] {
    // SAFETY: as above, and the borrow is exclusive.
    unsafe { core::slice::from_raw_parts_mut(heap.as_mut_ptr().cast(), heap.len() * 4) }
}

/// `%ld`.
fn fmt_dec(v: i32, buf: &mut [u8; 12]) -> &[u8] {
    let mut n = buf.len();
    let mut u = v.unsigned_abs();
    loop {
        n -= 1;
        buf[n] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if v < 0 {
        n -= 1;
        buf[n] = b'-';
    }
    &buf[n..]
}
