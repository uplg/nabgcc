//! Loading a bytecode (`src/vm/vloader.c`).
//!
//! A bytecode is: the size of the globals, then the globals as a tree
//! of integers, strings and tuples; the size of the code and the code;
//! the number of functions and their start offsets. It is copied to the
//! bottom of the memory, its globals are built on the stack, then the
//! code and the function table are moved down over the globals' source
//! and the room left behind becomes heap.

use crate::{Host, NIL, SYS_NB, Vm};

/// `loaderSizeBC`: how many bytes of `src` the bytecode takes.
pub fn size(src: &[u8]) -> usize {
    let short = |o: usize| {
        src.get(o).copied().unwrap_or(0) as u32 | (src.get(o + 1).copied().unwrap_or(0) as u32) << 8
    };
    let int = |o: usize| short(o) | short(o + 2) << 16;
    let n = int(0);
    let b = int(n as usize);
    let total = n.wrapping_add(4).wrapping_add(b);
    let fun = short(total as usize);
    total.wrapping_add(2).wrapping_add(fun << 2) as usize
}

impl<H: Host> Vm<'_, H> {
    /// `loaderInit` for a bytecode outside the machine's memory, such as
    /// the boot bytecode in flash.
    pub(crate) fn load_external(&mut self, src: &[u8]) {
        let n = size(src);
        let dst = self.bytes_mut();
        let room = n.min(dst.len());
        let have = room.min(src.len());
        dst[..have].copy_from_slice(&src[..have]);
        dst[have..room].fill(0);
        self.load_rest(n as i32);
    }

    /// `loaderInit` for a bytecode the machine holds as a string at byte
    /// `src`: copied down byte by byte, as the C does.
    pub(crate) fn load_heap(&mut self, src: i32) {
        let globals = self.int32(src);
        let code = self.int32(src.wrapping_add(globals));
        let total = globals.wrapping_add(4).wrapping_add(code);
        let fun = self.short(src.wrapping_add(total));
        let n = total.wrapping_add(2).wrapping_add(fun << 2);
        self.copy_bytes(0, src, n);
        self.load_rest(n);
    }

    fn load_rest(&mut self, n: i32) {
        // The C's sizes are unsigned: a huge one gives a start far up,
        // never below 0.
        self.vmem_init(words(n));
        self.sys_start = self.stack - 1;
        for _ in 0..SYS_NB {
            self.push(NIL);
        }
        let n = self.int32(0);
        let mut src = 4;
        self.global_start = self.stack - 1;
        while (src as u32) < n as u32 {
            src = self.load_rec(src);
        }
        let n = self.int32(src);
        src = src.wrapping_add(4);
        self.tabfun = n.wrapping_add(2);
        self.nbfun = self.short(src.wrapping_add(n)) as u16;
        let n = n.wrapping_add(2).wrapping_add((self.nbfun as i32) << 2);
        self.copy_bytes(0, src, n);
        self.set_start(words(n));
    }

    /// `loaderInitRec`: one global value, pushed.
    fn load_rec(&mut self, mut src: i32) -> i32 {
        let mut l = self.int32(src);
        src += 4;
        if l == -1 {
            self.push(NIL);
        } else if l & 1 != 0 {
            l >>= 1;
            if l & 1 != 0 {
                l >>= 1;
                for _ in 0..l {
                    src = self.load_rec(src);
                }
                self.stack_to_tab(l);
            } else {
                l >>= 1;
                let p = self.alloc_str_heap(src, l);
                self.push(crate::pnt(p));
                src = src.wrapping_add(l);
            }
        } else {
            self.push(l);
        }
        src
    }

    /// `loaderFunstart`.
    pub(crate) fn fun_start(&self, fun: i32) -> i32 {
        self.int32(self.tabfun.wrapping_add(fun << 2))
    }
}

/// `(n + 3) >> 2` on the C's `uint32_t`.
fn words(n: i32) -> i32 {
    ((n as u32).wrapping_add(3) >> 2) as i32
}
