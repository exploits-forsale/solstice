use core::alloc::{AllocError, Allocator};
use core::ptr;

use crate::{
    functions::{fetch_global_alloc, fetch_global_free, GlobalAllocFn, GlobalFreeFn},
    PVOID,
};

pub struct WinGlobalAlloc {
    global_alloc_fn: GlobalAllocFn,
    global_free_fn: GlobalFreeFn,
}

impl WinGlobalAlloc {
    pub fn new(kernel32_ptr: PVOID) -> Self {
        Self {
            global_alloc_fn: fetch_global_alloc(kernel32_ptr),
            global_free_fn: fetch_global_free(kernel32_ptr),
        }
    }
}

// TODO: Update if we ever support other architectures like 32-bit. See:
// https://github.com/rust-lang/rust/blob/aabbf84b45a5e7b868c33e959d7e5cc985097d19/library/std/src/sys/pal/common/alloc.rs#L22
const MIN_ALIGN: usize = 8;

const MEM_FIXED: u32 = 0x0;
const ZERO_INIT: u32 = 0x40;

// Repurposed from https://github.com/rust-lang/rust/blob/aabbf84b45a5e7b868c33e959d7e5cc985097d19/library/std/src/sys/pal/windows/alloc.rs#L162
unsafe fn allocate(
    global_alloc_fn: GlobalAllocFn,
    layout: core::alloc::Layout,
    zeroed: bool,
) -> *mut u8 {
    let flags = if zeroed { ZERO_INIT } else { MEM_FIXED };

    if layout.align() <= MIN_ALIGN {
        // The returned pointer points to the start of an allocated block.
        (global_alloc_fn)(flags, layout.size()) as *mut u8
    } else {
        // Allocate extra padding in order to be able to satisfy the alignment.
        let total = layout.align() + layout.size();

        let ptr = (global_alloc_fn)(flags, total) as *mut u8;
        if ptr.is_null() {
            // Allocation has failed.
            return ptr::null_mut();
        }

        // Create a correctly aligned pointer offset from the start of the allocated block,
        // and write a header before it.

        let offset = layout.align() - (ptr.addr() & (layout.align() - 1));
        // SAFETY: `MIN_ALIGN` <= `offset` <= `layout.align()` and the size of the allocated
        // block is `layout.align() + layout.size()`. `aligned` will thus be a correctly aligned
        // pointer inside the allocated block with at least `layout.size()` bytes after it and at
        // least `MIN_ALIGN` bytes of padding before it.
        let aligned = unsafe { ptr.add(offset) };
        // SAFETY: Because the size and alignment of a header is <= `MIN_ALIGN` and `aligned`
        // is aligned to at least `MIN_ALIGN` and has at least `MIN_ALIGN` bytes of padding before
        // it, it is safe to write a header directly before it.
        unsafe { ptr::write((aligned as *mut Header).sub(1), Header(ptr)) };

        // SAFETY: The returned pointer does not point to the to the start of an allocated block,
        // but there is a header readable directly before it containing the location of the start
        // of the block.
        aligned
    }
}

// Header containing a pointer to the start of an allocated block.
// SAFETY: Size and alignment must be <= `MIN_ALIGN`.
#[repr(C)]
struct Header(*mut u8);

unsafe impl Allocator for WinGlobalAlloc {
    fn allocate(
        &self,
        layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        let raw_ptr = unsafe { allocate(self.global_alloc_fn, layout, false) };
        let ptr = ptr::NonNull::new(raw_ptr).ok_or(AllocError)?;
        Ok(ptr::NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, layout: core::alloc::Layout) {
        let raw_ptr = ptr.as_ptr();
        let block = {
            if layout.align() <= MIN_ALIGN {
                raw_ptr
            } else {
                // The location of the start of the block is stored in the padding before `ptr`.

                // SAFETY: Because of the contract of `System`, `ptr` is guaranteed to be non-null
                // and have a header readable directly before it.
                unsafe { ptr::read((raw_ptr as *mut Header).sub(1)).0 }
            }
        };

        // SAFETY: `heap` is a non-null handle returned by `GetProcessHeap`,
        // `block` is a pointer to the start of an allocated block.

        // TODO: mark as unsafe
        (self.global_free_fn)(block as _);
    }

    fn allocate_zeroed(
        &self,
        layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        let raw_ptr = unsafe { allocate(self.global_alloc_fn, layout, true) };
        let ptr = ptr::NonNull::new(raw_ptr).ok_or(AllocError)?;
        Ok(ptr::NonNull::slice_from_raw_parts(ptr, layout.size()))
    }
}
