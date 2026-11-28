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
        self.header(start, (size << 8) + TYPE_BINARY);
        self.start = start;
    }

    /// A block's three header words: its size and kind, the collector's
    /// two cleared.
    #[inline(always)]
    fn header(&mut self, p: i32, first: i32) {
        self.set_in(p, first);
        self.set_in(p + HEADER_GC, 0);
        self.set_in(p + HEADER_LIST, 0);
    }

    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn used(&self, p: i32) -> bool {
        self.wf(p.wrapping_add(HEADER_GC)) & 1 != 0
    }

    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn mark(&mut self, p: i32) {
        let i = p.wrapping_add(HEADER_GC);
        self.setf(i, self.wf(i) | 1);
    }

    /// Mark `k`, if it points to a block not marked yet, and chain it.
    // ARM like its callers, or it could not be inlined into them.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn reach(&mut self, k: i32, first: &mut i32) {
        if k & 1 != 0 && k != NIL {
            let k = val(k);
            // A word that only looks like a pointer, outside the memory:
            // the C marks and chains it in the RAM next to the heap,
            // where the bytecode never looks. Here the chaining word
            // would read back 0 and send the walk through the bytecode:
            // skip it, which leaves what the bytecode sees the same.
            if !inside(k) {
                return;
            }
            if !self.used(k) {
                self.mark(k);
                self.setf(k.wrapping_add(HEADER_LIST), *first);
                *first = k;
            }
        }
    }

    /// Mark everything reachable from the stack. With `relocate`, also
    /// rewrite every pointer met to where its block is going
    /// (`vmemGCfirst` and `vmemGCthird`).
    // A collection walks every word of the heap: ARM code, accessors
    // inline, as the hot loop of the interpreter.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(never)]
    fn gc_mark(&mut self, relocate: bool) {
        let mut first = -1;
        let mut i = self.stack;
        while i < 0 {
            let k = self.wf((VMEM_LENGTH as i32).wrapping_add(i));
            if relocate && k & 1 != 0 && k != NIL {
                let to = self.wf(val(k).wrapping_add(HEADER_GC)) | 1;
                self.setf((VMEM_LENGTH as i32).wrapping_add(i), to);
            }
            self.reach(k, &mut first);
            i += 1;
        }
        while first != -1 {
            let k = first;
            first = self.wf(k.wrapping_add(HEADER_LIST));
            if self.wf(k) & 1 != 0 {
                let n = self.size_tab_f(k);
                let j = k.wrapping_add(HEADER_LENGTH);
                for i in 0..n.max(0) {
                    let at = j.wrapping_add(i);
                    let v = self.wf(at);
                    if relocate && v & 1 != 0 && v != NIL {
                        let to = self.wf(val(v).wrapping_add(HEADER_GC)) | 1;
                        self.setf(at, to);
                    }
                    self.reach(v, &mut first);
                }
            }
        }
    }

    /// The size of the block at `pos`, header included.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(always)]
    fn real_size(&self, pos: i32) -> i32 {
        self.size_tab_f(pos) + HEADER_LENGTH
    }

    /// `vmemGCsecond`: give every marked block its new place, and
    /// unmark it.
    // A collection walks every word of the heap: ARM code, accessors
    // inline, as the hot loop of the interpreter.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(never)]
    fn gc_place(&mut self) {
        let mut pos = self.start;
        let mut newpos = self.start;
        while pos < self.heapindex {
            let realsize = self.real_size(pos);
            if self.used(pos) {
                self.setf(pos + HEADER_GC, newpos << 1);
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
    // A collection walks every word of the heap: ARM code, accessors
    // inline, as the hot loop of the interpreter.
    #[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
    #[inline(never)]
    fn gc_move(&mut self) {
        let mut pos = self.start;
        let mut newpos = self.start;
        while pos < self.heapindex {
            let realsize = self.real_size(pos);
            if realsize <= 0 {
                break;
            }
            if self.used(pos) {
                self.setf(pos + HEADER_GC, 0);
                if newpos != pos {
                    let (from, to, n) = (pos as usize, newpos as usize, realsize as usize);
                    // `to` is below `from` (`newpos` never passes `pos`),
                    // and not below 0: the loader's start is unsigned.
                    if newpos >= 0 && from.saturating_add(n) <= VMEM_LENGTH {
                        // Down the heap, word by word from the start: the
                        // block never lands above where it was (a call to
                        // `memcpy` costs more than this loop, measured).
                        let heap = self.mem.heap.as_mut_ptr();
                        for k in 0..n {
                            // SAFETY: `from + n` is inside the heap and
                            // `0 <= to <= from`, checked above.
                            unsafe { *heap.add(to + k) = *heap.add(from + k) };
                        }
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
        self.alloc(wsize, (size << 8) + TYPE_BINARY)
    }

    /// What both allocations do: room for `wsize` words, the header, the
    /// last word zeroed. -1 when there is no room.
    // Inline, as the header: called, they cost a program that allocates
    // much 2% of its time (measured).
    #[inline(always)]
    fn alloc(&mut self, wsize: i32, first: i32) -> i32 {
        if !self.check(wsize) {
            return -1;
        }
        let p = self.heapindex;
        self.heapindex = self.heapindex.wrapping_add(wsize);
        self.header(p, first);
        self.set_in(p.wrapping_add(wsize).wrapping_sub(1), 0);
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

    /// The same, pushed.
    pub(crate) fn push_str(&mut self, src: &[u8]) {
        let p = self.alloc_str(src);
        self.push(pnt(p));
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
        let bytes = (size << 2) - 1;
        self.alloc(HEADER_LENGTH.wrapping_add(size), (bytes << 8) + TYPE_TAB)
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
        self.set_in((VMEM_LENGTH as i32).wrapping_add(self.stack), v);
        self.check(0)
    }

    /// `vmemStacktotab`: the top `n` words become a table.
    pub(crate) fn stack_to_tab(&mut self, mut n: i32) {
        let p = self.alloc_tab(n);
        let q = p.wrapping_add(HEADER_LENGTH);
        while n > 0 {
            n -= 1;
            let v = self.w_in((VMEM_LENGTH as i32).wrapping_add(self.stack));
            self.stack = self.stack.wrapping_add(1);
            self.set_in(q.wrapping_add(n), v);
        }
        self.push(pnt(p));
    }
}

/// Whether a block at `k` has its header (and so the collector's two
/// words) inside the memory.
#[cfg_attr(target_arch = "arm", instruction_set(arm::a32))]
#[inline(always)]
fn inside(k: i32) -> bool {
    (k as u32) < (VMEM_LENGTH as u32 - HEADER_LIST as u32)
}
