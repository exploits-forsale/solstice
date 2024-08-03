use core::cell::LazyCell;
use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_void;

use const_str::equal;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Networking::WinSock::QOS;
use windows_sys::Win32::Networking::WinSock::SOCKET;
use windows_sys::Win32::Networking::WinSock::WSABUF;
use windows_sys::Win32::Networking::WinSock::WSADATA;
use windows_sys::Win32::Networking::WinSock::WSAPROTOCOL_INFOA;
use windows_sys::Win32::System::Diagnostics::ToolHelp::THREADENTRY32;
use windows_sys::Win32::System::Threading::TEB;

use crate::binds::*;
use crate::resolve_func;

#[repr(transparent)]
struct CachedPtr<T, F = fn() -> T>(LazyCell<T, F>);
unsafe impl<T, F> Sync for CachedPtr<T, F> {}

impl<T, F: FnOnce() -> T> CachedPtr<T, F> {
    #[inline]
    pub const fn new(f: F) -> CachedPtr<T, F> {
        CachedPtr(LazyCell::new(f))
    }
}

pub const GetProcAddress_: &str = concat!("GetProcAddress", "\0");
pub const MessageBoxA_: &str = concat!("MessageBoxA", "\0");
pub const GlobalAlloc_: &str = concat!("GlobalAlloc", "\0");

pub type LoadLibraryAFn = unsafe extern "system" fn(lpFileName: *const u8) -> PVOID;
pub type GetProcAddressFn = unsafe extern "system" fn(hmodule: PVOID, name: *const u8) -> PVOID;
pub type MessageBoxAFn =
    unsafe extern "system" fn(h: PVOID, text: LPCSTR, cation: LPCSTR, t: u32) -> u32;
pub type OutputDebugStringAFn = unsafe extern "C" fn(*const i8);
pub type DbgPrintFn = unsafe extern "C" fn(Format: *const u8, ...) -> NTSTATUS;
pub type GetModuleHandleAFn = unsafe extern "system" fn(lpModuleName: LPCSTR) -> PVOID;
pub type CreateFileAFn = unsafe extern "system" fn(
    lpFileName: LPCSTR,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: PVOID,
    dwCreationDisposition: u32,
    dwFlagsAndATtributes: u32,
    hTemplateFile: PVOID,
) -> HANDLE;
pub type wsprintfaFn = unsafe extern "system" fn(outbuf: LPSTR, inbuf: LPCSTR, ...);
pub type ReadFileFn = unsafe extern "system" fn(
    hFile: HANDLE,
    lpBuf: PVOID,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: *mut u32,
    lpOverlapped: PVOID,
) -> c_int;
pub type GlobalAllocFn = unsafe extern "system" fn(flags: u32, byte_count: usize) -> PVOID;
pub type GlobalFreeFn = unsafe extern "system" fn(addr: PVOID);
pub type VirtualAllocFn = unsafe extern "system" fn(
    lpAddress: *const c_void,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) -> PVOID;
pub type VirtualFreeFn =
    unsafe extern "system" fn(lpAddress: PVOID, dwSize: usize, dwFreeType: u32) -> bool;

pub type VirtualProtectFn = unsafe extern "system" fn(
    lpAddress: *const c_void,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *mut u32,
) -> c_char;
pub type GetFileSizeFn = unsafe extern "system" fn(hFile: HANDLE, lpHighFileSize: *mut u32) -> u32;
pub type CreateThreadFn = unsafe extern "system" fn(
    lpThreadAttributes: *const c_void,
    dwStackSize: usize,
    lpStartAddress: *const c_void,
    lpParameter: *const c_void,
    dwCreationFlags: u32,
    lpThreadId: *mut u32,
) -> *mut c_void;

pub type RtlAddFunctionTableFn = unsafe extern "system" fn(
    FunctionTable: *const c_void,
    EntryCount: u32,
    BaseAddress: u64,
) -> u32;

pub type CloseHandleFn = unsafe extern "system" fn(hObject: HANDLE);

pub type ExpandEnvironmentStringsAFn =
    unsafe extern "system" fn(lpSrc: *const u8, lpDst: *mut u8, size: u32) -> u32;

pub type GetFullPathNameAFn = unsafe extern "system" fn(
    lpFileName: *const u8,
    nBufferLength: u32,
    lpBuffer: *mut u8,
    lpFilePart: *mut *const u8,
) -> u32;

pub type WSAStartupFn = unsafe extern "system" fn(wVersionRequired: u16, lpsWSAData: *mut WSADATA);

pub type WSASocketAFn = unsafe extern "system" fn(
    af: c_int,
    typ: c_int,
    protocol: c_int,
    lpProtocolInfo: *const WSAPROTOCOL_INFOA,
    group: *const c_void, // we won't use, no need to bring in the feature for the appropriate type
    dwFlags: u32,
) -> SOCKET;

pub type WSAConnectFn = unsafe extern "system" fn(
    socket: SOCKET,
    sockaddr: *const c_char,
    namelen: c_int,
    lpCallerData: *const WSABUF,
    lpCalleeData: *mut WSABUF,
    lpSQOS: *const QOS,
    lpGQOS: *const QOS,
);

pub type WriteFileFn = unsafe extern "system" fn(
    hFile: HANDLE,
    lpBuffer: *const c_void,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: *mut u32,
    lpOverlapped: *mut c_void,
);

pub type GetLastErrorFn = unsafe extern "system" fn() -> u32;

pub type inet_addrFn = unsafe extern "system" fn(cp: *const c_char) -> u32;

pub type CreateToolhelp32SnapshotFn =
    unsafe extern "system" fn(dwFlags: u32, th32ProcessId: u32) -> HANDLE;
pub type GetCurrentProcessIdFn = unsafe extern "system" fn() -> u32;
pub type GetCurrentThreadIdFn = unsafe extern "system" fn() -> u32;
pub type OpenThreadFn = unsafe extern "system" fn(
    dwDesiredAccess: u32,
    bInheritHandle: bool,
    dwThreadId: u32,
) -> HANDLE;
pub type SuspendThreadFn = unsafe extern "system" fn(hThread: HANDLE) -> u32;
pub type Thread32NextFn =
    unsafe extern "system" fn(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> c_int;
pub type Thread32FirstFn =
    unsafe extern "system" fn(hSnapshot: HANDLE, lpte: *mut THREADENTRY32) -> c_int;

pub type NtCurrentTebFn = unsafe extern "system" fn() -> *mut TEB;

pub type ImageTlsCallbackFn =
    unsafe extern "system" fn(dllHandle: *const c_void, reason: u32, reserved: *const c_void);

// pub fn get_kernel32_test() -> PVOID {
//     static KERNEL32: CachedPtr<PVOID> = CachedPtr::new(|| {
//         let KERNEL32_STR: [u16; 13] = [75, 69, 82, 78, 69, 76, 51, 50, 46, 68, 76, 76, 0];
//         crate::get_module_by_name(KERNEL32_STR.as_ptr())
//     });

//     *KERNEL32.0
// }

// NOTE: These are not stable across versions.
pub const fn func_to_ordinal(func: &'static str) -> Option<u32> {
    // We cannot match on strings in a const context, so we use const_str::equal!()

    // ws2_32.dll
    if equal!(func, "WSAConnect") {
        Some(0x2f)
    } else if equal!(func, "WSAStartup") {
        Some(0x73)
    } else if equal!(func, "inet_addr") {
        Some(0xB)
    } else if equal!(func, "WSASocketA") {
        Some(0x78)
    }
    // KernelBase.dll
    else if equal!(func, "VirtualAlloc") {
        Some(0x749)
    } else if equal!(func, "VirtualFree") {
        Some(0x7F4)
    } else if equal!(func, "VirtualProtect") {
        Some(0x752)
    } else if equal!(func, "ReadFile") {
        Some(0x574)
    } else if equal!(func, "WriteFile") {
        Some(0x797)
    } else if equal!(func, "CloseHandle") {
        Some(0x90)
    } else if equal!(func, "ExpandEnvironmentStringsA") {
        Some(0x179)
    } else {
        None
    }
}

pub fn get_kernelbase() -> Option<PVOID> {
    let KERNEL32_STR: [u16; 15] = [
        'K' as u16, 'E' as u16, 'R' as u16, 'N' as u16, 'E' as u16, 'L' as u16, 'B' as u16,
        'A' as u16, 'S' as u16, 'E' as u16, '.' as u16, 'D' as u16, 'L' as u16, 'L' as u16, 0,
    ];
    crate::get_module_by_name(KERNEL32_STR.as_ptr())
}

pub fn get_kernel32(kernelbase_ptr: PVOID) -> Option<PVOID> {
    let KERNEL32_STR: [u16; 13] = [
        'K' as u16, 'E' as u16, 'R' as u16, 'N' as u16, 'E' as u16, 'L' as u16, '3' as u16,
        '2' as u16, '.' as u16, 'D' as u16, 'L' as u16, 'L' as u16, 0,
    ];

    crate::get_module_by_name(KERNEL32_STR.as_ptr()).or_else(|| {
        let kernel32 = concat!("kernel32.dll", "\0");
        let kernel32_ptr = unsafe { (fetch_load_library(kernelbase_ptr))(kernel32.as_ptr()) };
        if kernel32_ptr.is_null() {
            None
        } else {
            Some(kernel32_ptr)
        }
    })
}

pub fn get_kernel32_legacy(kernelbase_ptr: PVOID) -> Option<PVOID> {
    let KERNEL32_STR: [u16; 19] = [
        'k' as u16, 'e' as u16, 'r' as u16, 'n' as u16, 'e' as u16, 'l' as u16, '3' as u16,
        '2' as u16, 'l' as u16, 'e' as u16, 'g' as u16, 'a' as u16, 'c' as u16, 'y' as u16,
        '.' as u16, 'D' as u16, 'L' as u16, 'L' as u16, 0,
    ];

    crate::get_module_by_name(KERNEL32_STR.as_ptr()).or_else(|| {
        let kernel32 = concat!("kernel32legacy.dll", "\0");
        let kernel32_ptr = unsafe { (fetch_load_library(kernelbase_ptr))(kernel32.as_ptr()) };
        if kernel32_ptr.is_null() {
            None
        } else {
            Some(kernel32_ptr)
        }
    })
}

pub fn fetch_get_current_process_id(kernelbase_ptr: PVOID) -> GetCurrentProcessIdFn {
    resolve_func!(kernelbase_ptr, "GetCurrentProcessId")
}

pub fn fetch_create_tool_help32(kernelbase_ptr: PVOID) -> CreateToolhelp32SnapshotFn {
    resolve_func!(kernelbase_ptr, "CreateToolhelp32Snapshot")
}

pub fn fetch_get_current_thread_id(kernelbase_ptr: PVOID) -> GetCurrentThreadIdFn {
    resolve_func!(kernelbase_ptr, "GetCurrentThreadId")
}

pub fn fetch_open_thread(kernelbase_ptr: PVOID) -> OpenThreadFn {
    resolve_func!(kernelbase_ptr, "OpenThread")
}

pub fn fetch_suspend_thread(kernelbase_ptr: PVOID) -> SuspendThreadFn {
    resolve_func!(kernelbase_ptr, "SuspendThread")
}

pub fn fetch_thread_32_first(kernelbase_ptr: PVOID) -> Thread32FirstFn {
    resolve_func!(kernelbase_ptr, "Thread32First")
}

pub fn fetch_thread_32_next(kernelbase_ptr: PVOID) -> Thread32NextFn {
    resolve_func!(kernelbase_ptr, "Thread32Next")
}

pub fn fetch_ws2_32(kernelbase_ptr: PVOID) -> Option<PVOID> {
    let WS2_32_WSTR: [u16; 11] = [
        'W' as u16, 'S' as u16, '2' as u16, '_' as u16, '3' as u16, '2' as u16, '.' as u16,
        'd' as u16, 'l' as u16, 'l' as u16, 0,
    ];

    crate::get_module_by_name(WS2_32_WSTR.as_ptr()).or_else(|| {
        let ws2_32_str = concat!("WS2_32.dll", "\0");
        let ws2_32_ptr = unsafe { (fetch_load_library(kernelbase_ptr))(ws2_32_str.as_ptr()) };
        if ws2_32_ptr.is_null() {
            None
        } else {
            Some(ws2_32_ptr)
        }
    })
}

pub fn get_user32(kernelbase_ptr: PVOID) -> PVOID {
    let user32 = concat!("user32.dll", "\0");
    let mut u32_ptr = unsafe { (fetch_load_library(kernelbase_ptr))(user32.as_ptr()) };
    if u32_ptr.is_null() {
        u32_ptr = unsafe { (fetch_get_module_handle(kernelbase_ptr))(user32.as_ptr()) };
    }

    u32_ptr
}

pub fn fetch_get_last_error(kernelbase_ptr: PVOID) -> GetLastErrorFn {
    resolve_func!(kernelbase_ptr, "GetLastError")
}

pub fn fetch_wsa_startup(ws2_32_ptr: PVOID) -> WSAStartupFn {
    resolve_func!(ws2_32_ptr, "WSAStartup")
}

pub fn fetch_wsa_connect(ws2_32_ptr: PVOID) -> WSAConnectFn {
    resolve_func!(ws2_32_ptr, "WSAConnect")
}

pub fn fetch_wsa_socket(ws2_32_ptr: PVOID) -> WSASocketAFn {
    resolve_func!(ws2_32_ptr, "WSASocketA")
}

pub fn fetch_inet_addr(ws2_32_ptr: PVOID) -> inet_addrFn {
    resolve_func!(ws2_32_ptr, "inet_addr")
}

pub fn fetch_get_full_path_name(kernelbase_ptr: PVOID) -> GetFullPathNameAFn {
    resolve_func!(kernelbase_ptr, "GetFullPathNameA")
}

pub fn fetch_wsprintf(user32_ptr: PVOID) -> wsprintfaFn {
    resolve_func!(user32_ptr, "wsprintfA")
}

pub fn fetch_expand_environment_strings(kernelbase_ptr: PVOID) -> ExpandEnvironmentStringsAFn {
    resolve_func!(kernelbase_ptr, "ExpandEnvironmentStringsA")
}

pub fn fetch_rtl_add_fn_table(kernel32_ptr: PVOID) -> RtlAddFunctionTableFn {
    resolve_func!(kernel32_ptr, "RtlAddFunctionTable")
}

pub fn fetch_create_thread(kernelbase_ptr: PVOID) -> CreateThreadFn {
    resolve_func!(kernelbase_ptr, "CreateThread")
}

pub fn fetch_global_alloc(kernelbase_ptr: PVOID) -> GlobalAllocFn {
    resolve_func!(kernelbase_ptr, "GlobalAlloc")
}

pub fn fetch_global_free(kernelbase_ptr: PVOID) -> GlobalFreeFn {
    resolve_func!(kernelbase_ptr, "GlobalFree")
}

pub fn fetch_get_file_size(kernelbase_ptr: PVOID) -> GetFileSizeFn {
    resolve_func!(kernelbase_ptr, "GetFileSize")
}

pub fn fetch_output_debug_string(kernelbase_ptr: PVOID) -> OutputDebugStringAFn {
    resolve_func!(kernelbase_ptr, "OutputDebugStringA")
}

pub fn fetch_get_module_handle(kernelbase_ptr: PVOID) -> GetModuleHandleAFn {
    resolve_func!(kernelbase_ptr, "GetModuleHandleA")
}

pub fn fetch_get_proc_address(kernelbase_ptr: PVOID) -> GetProcAddressFn {
    resolve_func!(kernelbase_ptr, "GetProcAddress")
}

pub fn fetch_load_library(kernelbase_ptr: PVOID) -> LoadLibraryAFn {
    resolve_func!(kernelbase_ptr, "LoadLibraryA")
}

pub fn fetch_create_file(kernelbase_ptr: PVOID) -> CreateFileAFn {
    resolve_func!(kernelbase_ptr, "CreateFileA")
}

pub fn fetch_write_file(kernelbase_ptr: PVOID) -> WriteFileFn {
    resolve_func!(kernelbase_ptr, "WriteFile")
}

pub fn fetch_read_file(kernelbase_ptr: PVOID) -> ReadFileFn {
    resolve_func!(kernelbase_ptr, "ReadFile")
}

pub fn fetch_virtual_alloc(kernelbase_ptr: PVOID) -> VirtualAllocFn {
    resolve_func!(kernelbase_ptr, "VirtualAlloc")
}

pub fn fetch_virtual_free(kernelbase_ptr: PVOID) -> VirtualFreeFn {
    resolve_func!(kernelbase_ptr, "VirtualFree")
}

pub fn fetch_virtual_protect(kernelbase_ptr: PVOID) -> VirtualProtectFn {
    resolve_func!(kernelbase_ptr, "VirtualProtect")
}

pub fn fetch_close_handle(kernelbase_ptr: PVOID) -> CloseHandleFn {
    resolve_func!(kernelbase_ptr, "CloseHandle")
}
