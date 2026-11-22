//! Memory routines that LLVM emits calls to. The stages link no C runtime, so
//! they provide their own. The copy and fill routines use string instructions
//! so LLVM cannot turn them back into calls to themselves.

use core::ffi::c_int;
use core::ffi::c_void;

#[no_mangle]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    unsafe {
        core::arch::asm!(
            "rep movsb",
            inout("rcx") count => _,
            inout("rdi") dest => _,
            inout("rsi") src => _,
            options(nostack, preserves_flags),
        );
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, count: usize) -> *mut c_void {
    if count == 0 {
        return dest;
    }

    // A forward copy is safe unless `dest` starts inside the source range.
    let overlaps_forward = (dest as usize) > (src as usize) && (dest as usize) < (src as usize) + count;
    if !overlaps_forward {
        return unsafe { memcpy(dest, src, count) };
    }

    unsafe {
        core::arch::asm!(
            "std",
            "rep movsb",
            "cld",
            inout("rcx") count => _,
            inout("rdi") dest.byte_add(count - 1) => _,
            inout("rsi") src.byte_add(count - 1) => _,
            options(nostack),
        );
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut c_void, value: c_int, count: usize) -> *mut c_void {
    unsafe {
        core::arch::asm!(
            "rep stosb",
            inout("rcx") count => _,
            inout("rdi") dest => _,
            in("al") value as u8,
            options(nostack, preserves_flags),
        );
    }

    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, count: usize) -> c_int {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();

    let mut idx = 0;
    while idx < count {
        let (a, b) = unsafe { (*left.add(idx), *right.add(idx)) };
        if a != b {
            return c_int::from(a) - c_int::from(b);
        }

        idx += 1;
    }

    0
}
