#![no_std]
#![no_main]

#[cfg(not(feature = "shellcode_compat"))]
extern crate alloc;

#[cfg(feature = "shellcode_compat")]
extern crate compiler_builtins;

pub mod pelib;
pub mod test;
pub mod utils;
pub mod windows;

use pelib::fix_base_relocations;
use pelib::fix_section_permissions;
use pelib::get_dos_header;
use pelib::get_headers_size;
use pelib::get_image_size;
use pelib::get_nt_header;
use pelib::patch_kernelbase;
use pelib::patch_module_list;
use pelib::patch_peb;
use pelib::teb;
use pelib::write_import_table;
use pelib::write_sections;
use shellcode_utils::prelude::CreateThreadFn;
use shellcode_utils::prelude::GetModuleHandleAFn;
use shellcode_utils::prelude::GetProcAddressFn;
use shellcode_utils::prelude::ImageTlsCallbackFn;
use shellcode_utils::prelude::LoadLibraryAFn;
use shellcode_utils::prelude::RtlAddFunctionTableFn;
use shellcode_utils::prelude::VirtualAllocFn;
use shellcode_utils::prelude::VirtualProtectFn;
use utils::detect_platform;

#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::Diagnostics::Debug::RtlAddFunctionTable;
#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::Memory::VirtualAlloc;
#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::Memory::VirtualProtect;
#[cfg(not(feature = "shellcode_compat"))]
use windows_sys::Win32::System::Threading::CreateThread;

use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_EXCEPTION;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_DIRECTORY_ENTRY_TLS;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY;
use windows_sys::Win32::System::Memory::MEM_COMMIT;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::SystemServices::DLL_THREAD_ATTACH;
use windows_sys::Win32::System::SystemServices::IMAGE_TLS_DIRECTORY64;

use core::arch;
use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_void;
use core::ptr;

#[used]
#[no_mangle]
#[cfg(feature = "shellcode_compat")]
// Required because compiler_builtins expects this symbol to be present
// and they only define it for UEFI environments
pub static _fltused: i32 = 0;

pub struct DependentModules {
    pub kernelbase: *mut u8,
}

pub struct RuntimeFns {
    pub virtual_alloc: VirtualAllocFn,
    pub virtual_protect: VirtualProtectFn,
    pub get_proc_address_fn: GetProcAddressFn,
    pub load_library_fn: LoadLibraryAFn,
    pub create_thread_fn: CreateThreadFn,
    pub rtl_add_function_table_fn: Option<RtlAddFunctionTableFn>,
    pub get_module_handle_fn: GetModuleHandleAFn,
}

pub struct LoaderContext<'a, 'b> {
    pub buffer: &'a [u8],
    pub image_name: Option<&'b [u16]>,
    pub args: Option<&'b [u16]>,
    pub modules: DependentModules,
    pub fns: RuntimeFns,
}

/// Compares the platform of the imported Portable Executable (PE) file with the platform of the compiled binary.
/// Panic if not same platforms
///
/// # Arguments
///
/// * `data` - A vector containing the bytes of the PE file to be loaded.
fn is_platforms_same(data: &[u8]) {
    let platform = detect_platform(&data).unwrap();

    let target_arch = if cfg!(target_arch = "x86_64") { 64 } else { 32 };

    if platform != target_arch {
        panic!("The platform not the same as the imported pe.")
    }
}

unsafe fn reflective_loader_impl(context: LoaderContext) {
    unsafe { core::arch::asm!("and rsp, ~0xf") };

    is_platforms_same(context.buffer);

    // Get the size of the headers and the image
    let headerssize = get_headers_size(context.buffer);
    let imagesize = get_image_size(context.buffer);

    // Get the DOS header
    let dosheader = get_dos_header(context.buffer.as_ptr() as *const c_void);

    // Get the NT header IMAGE_NT_HEADERS64|IMAGE_NT_HEADERS32
    let ntheader = get_nt_header(context.buffer.as_ptr() as *const c_void, dosheader);

    #[cfg(target_arch = "x86_64")]
    let ntheader_ref: &IMAGE_NT_HEADERS64 = unsafe { core::mem::transmute(ntheader) };
    #[cfg(target_arch = "x86")]
    let ntheader_ref: &IMAGE_NT_HEADERS32 = unsafe { core::mem::transmute(ntheader) };

    // Allocate memory for the image
    let preferred_load_addr = ntheader_ref.OptionalHeader.ImageBase as *mut c_void;
    let baseptr = (context.fns.virtual_alloc)(
        preferred_load_addr, // lpAddress: A pointer to the starting address of the region to allocate.
        imagesize,           // dwSize: The size of the region, in bytes.
        MEM_COMMIT,          // flAllocationType: The type of memory allocation.
        PAGE_READWRITE, // flProtect: The memory protection for the region of pages to be allocated.
    );

    // If we failed to get our preferred address, allocate anywhere
    let baseptr = if baseptr.is_null() {
        (context.fns.virtual_alloc)(
            ptr::null_mut(), // lpAddress: A pointer to the starting address of the region to allocate.
            imagesize,       // dwSize: The size of the region, in bytes.
            MEM_COMMIT,      // flAllocationType: The type of memory allocation.
            PAGE_READWRITE, // flProtect: The memory protection for the region of pages to be allocated.
        )
    } else {
        baseptr
    };

    let base_offset = baseptr.offset_from(preferred_load_addr);

    // Write the headers to the allocated memory
    core::ptr::copy_nonoverlapping(
        context.buffer.as_ptr() as *const c_void,
        baseptr,
        headerssize,
    );

    // Write each section to the allocated memory
    write_sections(
        baseptr,        // The base address of the image.
        context.buffer, // The buffer containing the image.
        ntheader,       // The NT header of the image.
        dosheader,      // The DOS header of the image.
    );

    // Write the import table to the allocated memory
    write_import_table(
        baseptr,
        ntheader,
        context.fns.get_proc_address_fn,
        context.fns.load_library_fn,
        context.fns.get_module_handle_fn,
    );

    // Fix the base relocations
    if base_offset != 0 {
        fix_base_relocations(baseptr, ntheader);
    }

    // Ensure each section has the proper permissions set
    fix_section_permissions(baseptr, ntheader, dosheader, context.fns.virtual_protect);

    // Patch data in kernelbase
    patch_kernelbase(context.args.clone(), context.modules.kernelbase);

    // Patch the PEB
    patch_peb(
        context.args,
        context.image_name,
        context.fns.virtual_protect,
    );

    #[cfg(target_arch = "x86_64")]
    let entrypoint = (baseptr as usize
        + (*(ntheader as *const IMAGE_NT_HEADERS64))
            .OptionalHeader
            .AddressOfEntryPoint as usize) as *const c_void;
    #[cfg(target_arch = "x86")]
    let entrypoint = (baseptr as usize
        + (*(ntheader as *const IMAGE_NT_HEADERS32))
            .OptionalHeader
            .AddressOfEntryPoint as usize) as *const c_void;

    let tls_directory =
        &ntheader_ref.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];

    // Grab the TLS data from the PE we're loading
    let tls_data_addr = if tls_directory.Size == 0 {
        core::ptr::null()
    } else {
        baseptr.offset(tls_directory.VirtualAddress as isize) as *mut IMAGE_TLS_DIRECTORY64
    };

    // TODO: Patch the module list
    let tls_index = patch_module_list(
        context.image_name,
        baseptr,
        imagesize,
        context.fns.get_module_handle_fn,
        tls_data_addr,
        context.fns.virtual_protect,
        entrypoint,
    );

    if tls_directory.Size > 0 {
        // Grab the TLS data from the PE we're loading
        let tls_data_addr =
            baseptr.offset(tls_directory.VirtualAddress as isize) as *mut IMAGE_TLS_DIRECTORY64;

        let tls_data: &mut IMAGE_TLS_DIRECTORY64 = unsafe { core::mem::transmute(tls_data_addr) };

        // Grab the TLS start from the TEB
        let tls_start: *mut *mut c_void;
        unsafe { core::arch::asm!("mov {}, gs:[0x58]", out(reg) tls_start) }

        let tls_slot = tls_start.offset(tls_index as isize);
        let raw_data_size = tls_data.EndAddressOfRawData - tls_data.StartAddressOfRawData;
        let tls_data_addr = (context.fns.virtual_alloc)(
            ptr::null(),
            raw_data_size as usize, // + tls_data.SizeOfZeroFill as usize,
            MEM_COMMIT,
            PAGE_READWRITE,
        );

        core::ptr::copy_nonoverlapping(
            tls_data.StartAddressOfRawData as *const _,
            tls_data_addr,
            raw_data_size as usize,
        );

        // Update the TLS index
        core::ptr::write(tls_data.AddressOfIndex as *mut u32, tls_index);
        *tls_slot = tls_data_addr;

        let mut callbacks_addr = tls_data.AddressOfCallBacks as *const *const c_void;
        if !callbacks_addr.is_null() {
            let mut callback = unsafe { *callbacks_addr };

            while !callback.is_null() {
                execute_tls_callback(baseptr, callback);
                callbacks_addr = callbacks_addr.add(1);
                callback = unsafe { *callbacks_addr };
            }
        }
    }

    // Set exception handler
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(rtl_add_function_table_fn) = context.fns.rtl_add_function_table_fn {
            let exception_dir = &ntheader_ref.OptionalHeader.DataDirectory
                [IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];

            if exception_dir.Size != 0 {
                let runtime_functions: *const IMAGE_RUNTIME_FUNCTION_ENTRY =
                    core::mem::transmute(baseptr.offset(exception_dir.VirtualAddress as isize));

                (rtl_add_function_table_fn)(
                    runtime_functions as *const _,
                    ((exception_dir.Size as usize)
                        / core::mem::size_of::<IMAGE_RUNTIME_FUNCTION_ENTRY>())
                        as u32,
                    baseptr as u64,
                );
            }
        }
    }

    // Create a new thread to execute the image
    execute_image(baseptr, entrypoint, context.fns.create_thread_fn);

    // Free the allocated memory of baseptr
    let _ = baseptr;
}

/// Loads a Portable Executable (PE) file into memory using reflective loading.
///
/// # Arguments
///
/// * `buffer` - A vector containing the bytes of the PE file to be loaded.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API and modifies memory
/// in the target process.
#[cfg(not(feature = "shellcode_compat"))]
pub unsafe fn reflective_loader(buffer: &[u8], image_name: Option<&[u16]>, args: Option<&[u16]>) {
    let context = LoaderContext {
        buffer,
        image_name,
        args,
        modules: DependentModules {
            // TODO
            kernelbase: core::ptr::null_mut(),
        },
        fns: RuntimeFns {
            virtual_alloc: VirtualAlloc,
            virtual_protect: VirtualProtect,
            get_proc_address_fn: unsafe {
                core::mem::transmute(GetProcAddress as unsafe extern "system" fn(_, _) -> _)
            },
            load_library_fn: unsafe {
                core::mem::transmute(LoadLibraryA as unsafe extern "system" fn(_) -> _)
            },
            // TODO
            create_thread_fn: unsafe { core::mem::transmute(core::ptr::null::<CreateThreadFn>()) },
            get_module_handle_fn: unsafe {
                core::mem::transmute(GetModuleHandleA as unsafe extern "system" fn(_) -> _)
            },
            rtl_add_function_table_fn: None,
        },
    };
    reflective_loader_impl(context);
}

/// Loads a Portable Executable (PE) file into memory using reflective loading.
///
/// # Arguments
///
/// * `buffer` - A vector containing the bytes of the PE file to be loaded.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API and modifies memory
/// in the target process.
#[cfg(feature = "shellcode_compat")]
pub unsafe fn reflective_loader(context: LoaderContext) {
    reflective_loader_impl(context);
}

/// Executes the image by calling its entry point and waiting for the thread to finish executing.
///
/// # Arguments
///
/// * `entrypoint` - A pointer to the PE file entrypoint.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API and modifies memory
/// in the target process.
unsafe fn execute_image(
    dll_base: *const c_void,
    entrypoint: *const c_void,
    create_thread_fn: CreateThreadFn,
) {
    // if let Some(create_thread_fn) = create_thread_fn {
    //     unsafe {
    //         let handle = (create_thread_fn)(
    //             ptr::null(),     // default security attributes
    //             0,               // default stack size
    //             entrypoint,      // thread start fn
    //             ptr::null(),     // args
    //             0,               // default creation flags
    //             ptr::null_mut(), // thread id
    //         );

    //         core::arch::asm!("int 3");
    //     }
    // } else {
    // Call the entry point of the image
    // Load the DLL
    let func: extern "system" fn(*const c_void, u32, *const c_void) -> u32 =
        core::mem::transmute(entrypoint);
    func(dll_base, DLL_PROCESS_ATTACH, ptr::null());
    //}
}

/// Executes the image by calling its entry point and waiting for the thread to finish executing.
///
/// # Arguments
///
/// * `entrypoint` - A pointer to the PE file entrypoint.
///
/// # Safety
///
/// This function is unsafe because it directly interacts with the Windows API and modifies memory
/// in the target process.
unsafe fn execute_tls_callback(baseptr: *const c_void, entrypoint: *const c_void) {
    // if let Some(create_thread_fn) = create_thread_fn {
    //     unsafe {
    //         let handle = (create_thread_fn)(
    //             ptr::null(),     // default security n
    //             0,               // default stack size
    //             entrypoint,      // thread start fn
    //             ptr::null(),     // args
    //             0,               // default creation flags
    //             ptr::null_mut(), // thread id
    //         );

    //         core::arch::asm!("int 3");
    //     }
    // } else {
    // Call the entry point of the image
    let func: ImageTlsCallbackFn = core::mem::transmute(entrypoint);
    func(baseptr, DLL_THREAD_ATTACH, ptr::null_mut());
    //}
}
