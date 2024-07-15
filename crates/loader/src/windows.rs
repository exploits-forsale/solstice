#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::{c_char, c_void};

use windows_sys::Win32;

pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;
pub const DLL_PROCESS_ATTACH: u32 = 1;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const IMAGE_ORDINAL_FLAG: usize = 0x80000000_00000000;

#[cfg(not(feature = "shellcode_compat"))]
pub(crate) mod ffi {
    use windows_sys::Win32::{
        self,
        System::Memory::{PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE},
    };

    use super::*;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn VirtualAlloc(
            lpaddress: *const c_void,
            dwsize: usize,
            flallocationtype: VIRTUAL_ALLOCATION_TYPE,
            flprotect: PAGE_PROTECTION_FLAGS,
        ) -> *mut c_void;

        pub fn VirtualProtect(
            lpAddress: *const c_void,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> c_char;

        pub fn GetProcAddress(hmodule: *mut c_void, lpprocname: *const u8) -> *mut c_void;

        pub fn LoadLibraryA(lplibfilename: *const u8) -> *mut c_void;

        pub fn CreateThread(
            lpThreadAttributes: *const c_void,
            dwStackSize: usize,
            lpStartAddress: *const c_void,
            lpParameter: *const c_void,
            dwCreationFlags: u32,
            lpThreadId: *mut u32,
        ) -> *mut c_void;

        pub fn RtlAddFunctionTable(
            FunctionTable: *const c_void,
            EntryCount: u32,
            BaseAddress: u64,
        ) -> u32;

        pub fn GetModuleHandleA(lpModuleName: *const i8) -> *mut c_void;

        pub fn NtCurrentTeb() -> *mut Win32::System::Threading::TEB;
    }
}

pub type NtCurrentTebFn = unsafe extern "system" fn() -> *mut Win32::System::Threading::TEB;

pub type VirtualAllocFn = unsafe extern "system" fn(
    lpAddress: *const c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> *mut c_void;

pub type VirtualProtectFn = unsafe extern "system" fn(
    lpAddress: *const c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> c_char;

pub type GetProcAddressFn =
    unsafe extern "system" fn(hModule: *mut c_void, name: *const u8) -> *mut c_void;
pub type LoadLibraryAFn = unsafe extern "system" fn(lpFileName: *const u8) -> *mut c_void;

pub type CreateThreadFn = unsafe extern "system" fn(
    lpThreadAttributes: *const c_void,
    dwStackSize: usize,
    lpStartAddress: *const c_void,
    lpParameter: *const c_void,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> *mut c_void;

pub type ImageTlsCallbackFn =
    unsafe extern "system" fn(dllHandle: *const c_void, reason: u32, reserved: *const c_void);

pub type RtlAddFunctionTableFn = unsafe extern "system" fn(
    FunctionTable: *const c_void,
    EntryCount: u32,
    BaseAddress: u64,
) -> u32;

pub type GetModuleHandleAFn = unsafe extern "system" fn(lpModuleName: *const i8) -> *mut c_void;
