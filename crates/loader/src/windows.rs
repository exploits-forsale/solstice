#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::{c_char, c_void};

pub type VIRTUAL_ALLOCATION_TYPE = u32;
pub type PAGE_PROTECTION_FLAGS = u32;
pub const MEM_COMMIT: VIRTUAL_ALLOCATION_TYPE = 0x1000;
pub const PAGE_READWRITE: PAGE_PROTECTION_FLAGS = 0x04;
pub const PAGE_EXECUTE_READ: PAGE_PROTECTION_FLAGS = 0x20;
pub const PAGE_EXECUTE_READWRITE: PAGE_PROTECTION_FLAGS = 0x40;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
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
    }
}

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

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct RUNTIME_FUNCTION {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub UnwindData: u32,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY64 {
    pub StartAddressOfRawData: u64,
    pub EndAddressOfRawData: u64,
    pub AddressOfIndex: u64,
    pub AddressOfCallBacks: u64,
    pub SizeOfZeroFill: u32,
    pub Characteristics: u32,
}

#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct IMAGE_TLS_DIRECTORY32 {
    pub StartAddressOfRawData: u32,
    pub EndAddressOfRawData: u32,
    pub AddressOfIndex: u32,
    pub AddressOfCallBacks: u32,
    pub SizeOfZeroFill: u32,
    pub Characteristics: u32,
}

#[derive(Default)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER32,
}

#[derive(Default)]
#[repr(C)]
#[cfg(target_arch = "x86_64")]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
#[cfg(target_arch = "x86")]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Default)]
#[repr(C, packed(4))]
#[cfg(target_arch = "x86_64")]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_BASE_RELOCATION {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union IMAGE_RELOCATION_UNION {
    pub VirtualAddress: u32,
    pub RelocCount: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_RELOCATION {
    pub va_union: IMAGE_RELOCATION_UNION,
    pub SymbolTableIndex: u32,
    pub Typ: u16,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub Misc: IMAGE_SECTION_HEADER_0,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}
#[derive(Clone, Copy)]
#[repr(C)]
pub union IMAGE_SECTION_HEADER_0 {
    pub PhysicalAddress: u32,
    pub VirtualSize: u32,
}

#[derive(Clone, Copy)]
#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct IMAGE_IMPORT_DESCRIPTOR {
    pub Anonymous: IMAGE_IMPORT_DESCRIPTOR_0,
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,
    pub FirstThunk: u32,
}

#[repr(C)]
pub union IMAGE_IMPORT_DESCRIPTOR_0 {
    pub Characteristics: u32,
    pub OriginalFirstThunk: u32,
}
