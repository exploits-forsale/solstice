use core::alloc::{AllocError, Allocator, GlobalAlloc};
use core::ptr;

use crate::functions::{fetch_virtual_alloc, fetch_virtual_free, VirtualAllocFn, VirtualFreeFn};
use crate::{
    functions::{fetch_global_alloc, fetch_global_free, GlobalAllocFn, GlobalFreeFn},
    PVOID,
};

#[global_allocator]
static DO_NOT_USE_ALLOCATOR: DummyGlobalAlloc = DummyGlobalAlloc {};

// This hack taken from: https://github.com/microsoft/windows-drivers-rs/blob/27309815433e0a550902e835220d7d6a24822477/crates/wdk-sys/src/lib.rs#L30C1-L36C2
// FIXME: Is there any way to avoid this stub? See https://github.com/rust-lang/rust/issues/101134
#[allow(missing_docs)]
#[allow(clippy::missing_const_for_fn)] // const extern is not yet supported: https://github.com/rust-lang/rust/issues/64926
#[no_mangle]
pub extern "system" fn __CxxFrameHandler3() -> i32 {
    0
}

pub struct DummyGlobalAlloc {}

unsafe impl GlobalAlloc for DummyGlobalAlloc {
    unsafe fn alloc(&self, _layout: core::alloc::Layout) -> *mut u8 {
        panic!("this should never be used");
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: core::alloc::Layout) {
        panic!("this should never be used");
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct WinVirtualAlloc {
    virtual_alloc_fn: VirtualAllocFn,
    virtual_free_fn: VirtualFreeFn,
}

impl WinVirtualAlloc {
    pub fn new(kernelbase_ptr: PVOID) -> Self {
        Self {
            virtual_alloc_fn: fetch_virtual_alloc(kernelbase_ptr),
            virtual_free_fn: fetch_virtual_free(kernelbase_ptr),
        }
    }
}

// TODO: Update if we ever support other architectures like 32-bit. See:
// https://github.com/rust-lang/rust/blob/aabbf84b45a5e7b868c33e959d7e5cc985097d19/library/std/src/sys/pal/common/alloc.rs#L22
const MIN_ALIGN: usize = 8;

const MEM_FIXED: u32 = 0x0;
const ZERO_INIT: u32 = 0x40;

#[inline(always)]
unsafe fn virtual_allocate(
    virtual_alloc_fn: VirtualAllocFn,
    layout: core::alloc::Layout,
    _zeroed: bool,
) -> *mut u8 {
    // VirtualAlloc always returns an aligned pointer
    (virtual_alloc_fn)(core::ptr::null_mut(), layout.size(), 0x3000, 4) as *mut _
}

unsafe impl Allocator for WinVirtualAlloc {
    #[inline(always)]
    fn allocate(
        &self,
        layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        let raw_ptr = unsafe { virtual_allocate(self.virtual_alloc_fn, layout, false) };
        let ptr = ptr::NonNull::new(raw_ptr).ok_or(AllocError)?;
        Ok(ptr::NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    #[inline(always)]
    unsafe fn deallocate(&self, ptr: core::ptr::NonNull<u8>, _layout: core::alloc::Layout) {
        let raw_ptr = ptr.as_ptr();

        (self.virtual_free_fn)(raw_ptr as _, 0x0, 0x00008000);
    }

    #[inline(always)]
    fn allocate_zeroed(
        &self,
        layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        let raw_ptr = unsafe { virtual_allocate(self.virtual_alloc_fn, layout, true) };
        let ptr = ptr::NonNull::new(raw_ptr).ok_or(AllocError)?;
        Ok(ptr::NonNull::slice_from_raw_parts(ptr, layout.size()))
    }
}

// Most of the below is repurposed from https://github.com/rust-lang/rust/blob/aabbf84b45a5e7b868c33e959d7e5cc985097d19/library/std/src/sys/pal/windows/alloc.rs#L162

// Header containing a pointer to the start of an allocated block.
// SAFETY: Size and alignment must be <= `MIN_ALIGN`.
#[repr(C)]
struct Header(*mut u8);

#[inline(always)]
unsafe fn allocate(
    global_alloc_fn: GlobalAllocFn,
    layout: core::alloc::Layout,
    zeroed: bool,
) -> *mut u8 {
    let flags = if zeroed { ZERO_INIT } else { MEM_FIXED };

    if layout.align() <= MIN_ALIGN {
        // The returned pointer points to the start of an allocated block.
        let ptr = (global_alloc_fn)(flags, layout.size()) as *mut u8;
        ptr
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

unsafe impl Allocator for WinGlobalAlloc {
    #[inline(always)]
    fn allocate(
        &self,
        layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        let raw_ptr = unsafe { allocate(self.global_alloc_fn, layout, false) };
        let ptr = ptr::NonNull::new(raw_ptr).ok_or(AllocError)?;
        Ok(ptr::NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    #[inline(always)]
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

        (self.global_free_fn)(block as _);
    }

    #[inline(always)]
    fn allocate_zeroed(
        &self,
        layout: core::alloc::Layout,
    ) -> Result<core::ptr::NonNull<[u8]>, core::alloc::AllocError> {
        let raw_ptr = unsafe { allocate(self.global_alloc_fn, layout, true) };
        let ptr = ptr::NonNull::new(raw_ptr).ok_or(AllocError)?;
        Ok(ptr::NonNull::slice_from_raw_parts(ptr, layout.size()))
    }
}
