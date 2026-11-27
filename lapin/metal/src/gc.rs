//! The memory: allocation, the stack and the compacting collector
//! (`src/vm/vmem.c`).
//!
//! A block is three header words then its contents. The first word
//! holds the size (bytes for a string, words × 4 − 1 for a table)
//! above bit 8, an external type in bits 1 to 7 and the kind in bit 0.
//! The second is the collector's: mark in bit 0, new place above it.
//! The third chains the blocks still to scan.

use crate::{
    GC_THRESHOLD, HEADER_GC, HEADER_LENGTH, HEADER_LIST, Host, NIL, TYPE_BINARY, TYPE_TAB,
    VMEM_LENGTH, Vm, pnt, val,
};

impl<H: Host> Vm<'_, H> {
    /// `vmemInit`.
    pub(crate) fn vmem_init(&mut self, start: i32) {
        self.stack = 0;
        self.start = start;
        self.heapindex = start;
        self.broken = false;
    }

    /// `vmemSetstart`: give the words between `start` and the first
    /// block back to the heap, as one string nobody points to.
    pub(crate) fn set_start(&mut self, start: i32) {
        if start >= self.start - HEADER_LENGTH {
            return;
        }
        let size = ((self.start - HEADER_LENGTH - start) << 2) - 1;
        self.set(start, (size << 8) + TYPE_BINARY);
        self.set(start + HEADER_GC, 0);
        self.set(start + HEADER_LIST, 0);
        self.start = start;
    }

    #[inline]
    fn used(&self, p: i32) -> bool {
        self.w(p.wrapping_add(HEADER_GC)) & 1 != 0
    }

    #[inline]
    fn mark(&mut self, p: i32) {
        let i = p.wrapping_add(HEADER_GC);
        self.set(i, self.w(i) | 1);
    }

    /// Mark `k`, if it points to a block not marked yet, and chain it.
    #[inline]
    fn reach(&mut self, k: i32, first: &mut i32) {
        if k & 1 != 0 && k != NIL {
            let k = val(k);
            if !self.used(k) {
                self.mark(k);
                self.set(k.wrapping_add(HEADER_LIST), *first);
                *first = k;
            }
        }
    }

    /// Mark everything reachable from the stack. With `relocate`, also
    /// rewrite every pointer met to where its block is going
    /// (`vmemGCfirst` and `vmemGCthird`).
    fn gc_mark(&mut self, relocate: bool) {
        let mut first = -1;
        let mut i = self.stack;
        while i < 0 {
            let k = self.top(i);
            if relocate && k & 1 != 0 && k != NIL {
                let to = self.w(val(k).wrapping_add(HEADER_GC)) | 1;
                self.set_top(i, to);
            }
            self.reach(k, &mut first);
            i += 1;
        }
        while first != -1 {
            let k = first;
            first = self.w(k.wrapping_add(HEADER_LIST));
            if self.w(k) & 1 != 0 {
                let n = self.size_tab(k);
                let j = k.wrapping_add(HEADER_LENGTH);
                for i in 0..n.max(0) {
                    let at = j.wrapping_add(i);
                    let v = self.w(at);
                    if relocate && v & 1 != 0 && v != NIL {
                        let to = self.w(val(v).wrapping_add(HEADER_GC)) | 1;
                        self.set(at, to);
                    }
                    self.reach(v, &mut first);
                }
            }
        }
    }

    /// The size of the block at `pos`, header included.
    #[inline]
    fn real_size(&self, pos: i32) -> i32 {
        self.size_tab(pos) + HEADER_LENGTH
    }

    /// `vmemGCsecond`: give every marked block its new place, and
    /// unmark it.
    fn gc_place(&mut self) {
        let mut pos = self.start;
        let mut newpos = self.start;
        while pos < self.heapindex {
            let realsize = self.real_size(pos);
            if self.used(pos) {
                self.set(pos + HEADER_GC, newpos << 1);
                newpos = newpos.wrapping_add(realsize);
            }
            pos = pos.wrapping_add(realsize);
            if realsize <= 0 {
                // The C loops forever on a broken header; the watchdog
                // ends it. Stop instead.
                break;
            }
        }
    }

    /// `vmemGCfourth`: move the marked blocks down.
    fn gc_move(&mut self) {
        let mut pos = self.start;
        let mut newpos = self.start;
        while pos < self.heapindex {
            let realsize = self.real_size(pos);
            if realsize <= 0 {
                break;
            }
            if self.used(pos) {
                self.set(pos + HEADER_GC, 0);
                if newpos != pos {
                    let (from, to, n) = (pos as usize, newpos as usize, realsize as usize);
                    if from.saturating_add(n) <= VMEM_LENGTH {
                        self.mem.heap.copy_within(from..from + n, to);
                    }
                    newpos += realsize;
                    pos += realsize;
                } else {
                    pos += realsize;
                    newpos = pos;
                }
            } else {
                pos += realsize;
            }
        }
        self.heapindex = newpos;
    }

    /// `vmemGC`.
    pub(crate) fn gc(&mut self) {
        self.play_check(true);
        self.gc_mark(false);
        self.play_check(true);
        self.gc_place();
        self.play_check(true);
        self.gc_mark(true);
        self.play_check(true);
        self.gc_move();
        self.play_check(true);
        self.log_gc();
    }

    /// `logGC`.
    fn log_gc(&mut self) {
        self.host.console(b"#GC : sp=");
        self.console_int(-self.stack);
        self.host.console(b" hp=");
        self.console_int(self.heapindex);
        self.host.console(b" used=");
        self.console_int(self.used_percent());
        self.host.console(b"%\r\n b:");
        self.console_hex(self.heap_address);
        self.host.console(b" bc:");
        self.console_hex(self.heap_address);
        self.host.console(b" st:");
        self.console_hex(self.start as u32);
        self.host.console(b" op:");
        self.console_hex(self.currentop as u32);
        self.host.console(b"\r\n");
    }

    /// `vmem_check`: room for `wsize` more words, collecting if need be.
    /// Out of memory, the machine breaks and the board reboots.
    #[inline(always)]
    fn check(&mut self, wsize: i32) -> bool {
        let free = (VMEM_LENGTH as i32)
            .wrapping_add(self.stack)
            .wrapping_sub(self.heapindex)
            .wrapping_sub(wsize);
        if free >= GC_THRESHOLD {
            return true;
        }
        self.check_slow(wsize)
    }

    /// The rare case of `check`: collect, and break if still short.
    #[cold]
    #[inline(never)]
    pub(crate) fn check_slow(&mut self, wsize: i32) -> bool {
        let free = |vm: &Self| {
            (VMEM_LENGTH as i32)
                .wrapping_add(vm.stack)
                .wrapping_sub(vm.heapindex)
                .wrapping_sub(wsize)
        };
        if free(self) < GC_THRESHOLD {
            self.gc();
            if free(self) < GC_THRESHOLD {
                self.broken = true;
                self.host.reboot();
            }
        }
        true
    }

    /// `vmemAllocBin`: a string of `size` bytes, its last word zeroed.
    pub(crate) fn alloc_bin(&mut self, size: i32) -> i32 {
        let wsize = HEADER_LENGTH.wrapping_add(size.wrapping_add(4) >> 2);
        if !self.check(wsize) {
            return -1;
        }
        let p = self.heapindex;
        self.heapindex = self.heapindex.wrapping_add(wsize);
        self.set(p, (size << 8) + TYPE_BINARY);
        self.set(p + HEADER_GC, 0);
        self.set(p + HEADER_LIST, 0);
        self.set(p.wrapping_add(wsize).wrapping_sub(1), 0);
        p
    }

    /// `vmemAllocString` from bytes outside the heap.
    pub(crate) fn alloc_str(&mut self, src: &[u8]) -> i32 {
        let p = self.alloc_bin(src.len() as i32);
        if p < 0 {
            return p;
        }
        let at = Self::start_bin(p) as usize;
        if let Some(dst) = self.bytes_mut().get_mut(at..at + src.len()) {
            dst.copy_from_slice(src);
        }
        p
    }

    /// `vmemAllocString` from bytes of the heap, read after the
    /// allocation as the C reads them.
    pub(crate) fn alloc_str_heap(&mut self, src: i32, len: i32) -> i32 {
        let p = self.alloc_bin(len);
        if p < 0 {
            return p;
        }
        self.copy_bytes(Self::start_bin(p), src, len);
        p
    }

    /// `vmemAllocTab`: a table of `size` words, the last one zeroed.
    pub(crate) fn alloc_tab(&mut self, size: i32) -> i32 {
        let wsize = HEADER_LENGTH.wrapping_add(size);
        if !self.check(wsize) {
            return -1;
        }
        let p = self.heapindex;
        self.heapindex = self.heapindex.wrapping_add(wsize);
        let bytes = (size << 2) - 1;
        self.set(p, (bytes << 8) + TYPE_TAB);
        self.set(p + HEADER_GC, 0);
        self.set(p + HEADER_LIST, 0);
        self.set(p.wrapping_add(wsize).wrapping_sub(1), 0);
        p
    }

    /// `vmemAllocTabClear`: the same, all nil.
    pub(crate) fn alloc_tab_clear(&mut self, size: i32) -> i32 {
        let p = self.alloc_tab(size);
        if p >= 0 {
            for i in 0..size {
                self.set(p + HEADER_LENGTH + i, NIL);
            }
        }
        p
    }

    /// `vmemPush`.
    #[inline(never)]
    pub(crate) fn push(&mut self, v: i32) -> bool {
        self.stack = self.stack.wrapping_sub(1);
        self.set_top(self.stack, v);
        self.check(0)
    }

    /// `vmemStacktotab`: the top `n` words become a table.
    pub(crate) fn stack_to_tab(&mut self, mut n: i32) {
        let p = self.alloc_tab(n);
        let q = p.wrapping_add(HEADER_LENGTH);
        while n > 0 {
            n -= 1;
            let v = self.pull();
            self.set(q.wrapping_add(n), v);
        }
        self.push(pnt(p));
    }
}
