use core::ffi::c_void;

use windows_sys::Win32::{
    self,
    Foundation::UNICODE_STRING,
    System::{
        Diagnostics::Debug::{
            IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
            IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER,
        },
        Kernel::LIST_ENTRY,
        Memory::{
            PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
            PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
        },
        SystemServices::{
            IMAGE_BASE_RELOCATION, IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_TLS_DIRECTORY64,
        },
        Threading::PEB,
        WindowsProgramming::LDR_DATA_TABLE_ENTRY,
    },
};

use crate::windows::{
    GetModuleHandleAFn, GetProcAddressFn, LoadLibraryAFn, VirtualAllocFn, VirtualProtectFn,
    IMAGE_NT_SIGNATURE, IMAGE_ORDINAL_FLAG,
};

/// Function to get the size of the headers
///
/// # Arguments
///
/// * `buffer` - A slice of bytes representing the buffer.
///
/// # Returns
///
/// The size of the headers.
pub fn get_headers_size(buffer: &[u8]) -> usize {
    // Check if the first two bytes of the buffer are "MZ"
    if buffer.len() >= 2 && buffer[0] == b'M' && buffer[1] == b'Z' {
        // Get the offset to the NT header
        if buffer.len() >= 64 {
            let offset =
                u32::from_le_bytes([buffer[60], buffer[61], buffer[62], buffer[63]]) as usize;
            // Check the bit version and return the size of the headers
            if buffer.len() >= offset + 4 + 20 + 2 {
                match u16::from_le_bytes([buffer[offset + 4 + 20], buffer[offset + 4 + 20 + 1]]) {
                    523 | 267 => {
                        let headerssize = u32::from_le_bytes([
                            buffer[offset + 24 + 60],
                            buffer[offset + 24 + 60 + 1],
                            buffer[offset + 24 + 60 + 2],
                            buffer[offset + 24 + 60 + 3],
                        ]);
                        return headerssize as usize;
                    }
                    _ => panic!("invalid bit version"),
                }
            } else {
                panic!("file size is less than required offset");
            }
        } else {
            panic!("file size is less than 64");
        }
    } else {
        panic!("it's not a PE file");
    }
}

// Function to get the size of the image
/// This function returns the size of the image.
///
/// # Arguments
///
/// * `buffer` - A slice of bytes representing the buffer.
///
/// # Returns
///
/// The size of the image.
pub fn get_image_size(buffer: &[u8]) -> usize {
    // Get the magic string from the buffer
    let magic = &buffer[0..2];
    // Convert the magic string to a string
    let magicstring = match core::str::from_utf8(magic) {
        Ok(s) => s,
        Err(_) => panic!("invalid magic string"),
    };
    // Check if the magic string is "MZ"
    assert_eq!(magicstring, "MZ", "it's not a PE file");
    // Get the offset to the NT header
    let offset = {
        let ntoffset = &buffer[60..64];
        let mut offset = [0u8; 4];
        offset.copy_from_slice(ntoffset);
        i32::from_le_bytes(offset) as usize
    };
    // Get the bit version from the buffer
    let bit = {
        let bitversion = &buffer[offset + 4 + 20..offset + 4 + 20 + 2];
        let mut bit = [0u8; 2];
        bit.copy_from_slice(bitversion);
        u16::from_le_bytes(bit)
    };
    // Check the bit version and return the size of the image
    match bit {
        523 | 267 => {
            let index = offset + 24 + 60 - 4;
            let size = {
                let headerssize = &buffer[index..index + 4];
                let mut size = [0u8; 4];
                size.copy_from_slice(headerssize);
                i32::from_le_bytes(size)
            };
            size as usize
        }
        _ => panic!("invalid bit version"),
    }
}

/// Function to get the DOS header
///
/// # Arguments
///
/// * `lp_image` - A pointer to the image.
///
/// # Returns
///
/// A pointer to the DOS header.
pub fn get_dos_header(lp_image: *const c_void) -> *const IMAGE_DOS_HEADER {
    lp_image as *const IMAGE_DOS_HEADER
}

/// Function to get the NT header
///
/// # Arguments
///
/// * `lp_image` - A pointer to the image.
/// * `lp_dos_header` - A pointer to the DOS header.
///
/// # Returns
///
/// A pointer to the NT header.
pub fn get_nt_header(
    lp_image: *const c_void,
    lp_dos_header: *const IMAGE_DOS_HEADER,
) -> *const c_void {
    // Calculate the address of the NT header
    #[cfg(target_arch = "x86_64")]
    let lp_nt_header = unsafe {
        (lp_image as usize + (*lp_dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64
    };
    #[cfg(target_arch = "x86")]
    let lp_nt_header = unsafe {
        (lp_image as usize + (*lp_dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS32
    };
    // Check if the NT header signature is valid
    if unsafe { (*lp_nt_header).Signature } != IMAGE_NT_SIGNATURE {
        return core::ptr::null_mut();
    }
    lp_nt_header as *const c_void
}

/// Returns the size of the NT header based on the target architecture.
///
/// # Returns
///
/// The size of the NT header.
fn get_nt_header_size() -> usize {
    #[cfg(target_arch = "x86")]
    {
        core::mem::size_of::<IMAGE_NT_HEADERS32>()
    }
    #[cfg(target_arch = "x86_64")]
    {
        core::mem::size_of::<IMAGE_NT_HEADERS64>()
    }
}

/// Returns the number of sections in the PE file based on the target architecture.
///
/// # Arguments
///
/// * `ntheader` - A pointer to the NT header of the PE file.
///
/// # Returns
///
/// The number of sections in the PE file.
fn get_number_of_sections(ntheader: *const c_void) -> u16 {
    #[cfg(target_arch = "x86_64")]
    return unsafe {
        (*(ntheader as *const IMAGE_NT_HEADERS64))
            .FileHeader
            .NumberOfSections
    };
    #[cfg(target_arch = "x86")]
    return unsafe {
        (*(ntheader as *const IMAGE_NT_HEADERS32))
            .FileHeader
            .NumberOfSections
    };
}

/// Writes each section of the PE file to the allocated memory in the target process.
///
/// # Arguments
///
/// * `baseptr` - A pointer to the base address of the allocated memory in the target process.
/// * `buffer` - A vector containing the bytes of the PE file to be loaded.
/// * `ntheader` - A pointer to the NT header of the PE file.
/// * `dosheader` - A pointer to the DOS header of the PE file.
pub fn write_sections(
    // A handle to the process into which the PE file will be loaded.
    // A pointer to the base address of the allocated memory in the target process.
    baseptr: *mut c_void,
    // A vector containing the bytes of the PE file to be loaded.
    buffer: &[u8],
    // A pointer to the NT header of the PE file.
    ntheader: *const c_void,
    // A pointer to the DOS header of the PE file.
    dosheader: *const IMAGE_DOS_HEADER,
) {
    let number_of_sections = get_number_of_sections(ntheader);
    let nt_header_size = get_nt_header_size();

    let e_lfanew = (unsafe { *dosheader }).e_lfanew as usize;
    let mut st_section_header =
        (baseptr as usize + e_lfanew + nt_header_size) as *const IMAGE_SECTION_HEADER;

    for _i in 0..number_of_sections {
        let header_ref: &IMAGE_SECTION_HEADER = unsafe { core::mem::transmute(st_section_header) };
        let dest = unsafe { baseptr.offset(header_ref.VirtualAddress as isize) };
        let len = header_ref.SizeOfRawData as usize;

        // Get the section data
        let section_data = buffer
            .get(header_ref.PointerToRawData as usize..(header_ref.PointerToRawData as usize + len))
            .unwrap_or_default();

        // Write the section data to the allocated memory
        unsafe {
            core::ptr::copy_nonoverlapping(section_data.as_ptr() as *const c_void, dest, len)
        };

        st_section_header = unsafe { st_section_header.add(1) };
    }
}

/// Writes each section of the PE file to the allocated memory in the target process.
///
/// # Arguments
///
/// * `baseptr` - A pointer to the base address of the allocated memory in the target process.
/// * `ntheader` - A pointer to the NT header of the PE file.
/// * `dosheader` - A pointer to the DOS header of the PE file.
pub fn fix_section_permissions(
    // A handle to the process into which the PE file will be loaded.
    // A pointer to the base address of the allocated memory in the target process.
    baseptr: *mut c_void,
    // A pointer to the NT header of the PE file.
    ntheader: *const c_void,
    // A pointer to the DOS header of the PE file.
    dosheader: *const IMAGE_DOS_HEADER,
    virtual_protect: VirtualProtectFn,
) {
    let number_of_sections = get_number_of_sections(ntheader);
    let nt_header_size = get_nt_header_size();

    let e_lfanew = (unsafe { *dosheader }).e_lfanew as usize;
    let mut st_section_header =
        (baseptr as usize + e_lfanew + nt_header_size) as *const IMAGE_SECTION_HEADER;

    for _i in 0..number_of_sections {
        let header_ref: &IMAGE_SECTION_HEADER = unsafe { core::mem::transmute(st_section_header) };
        let dest = unsafe { baseptr.offset(header_ref.VirtualAddress as isize) };
        let len = header_ref.SizeOfRawData as usize;

        // Assign this section the proper permissions
        let is_read = header_ref.Characteristics & IMAGE_SCN_MEM_READ != 0;
        let is_write = header_ref.Characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let is_exec = header_ref.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

        let perms = match (is_read, is_write, is_exec) {
            (false, false, false) => PAGE_NOACCESS,
            (false, false, true) => PAGE_EXECUTE,
            (true, false, false) => PAGE_READONLY,
            (true, true, false) => PAGE_READWRITE,
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (false, true, true) => PAGE_EXECUTE_WRITECOPY,
            (true, false, true) => PAGE_EXECUTE_READ,
            (false, true, false) => {
                unsafe {
                    core::arch::asm!("int 3");
                }
                0
            }
        };

        // Update this section's permissions
        let mut old_protection: u32 = 0;
        let succeeded = unsafe {
            (virtual_protect)(
                dest,                          // lpAddress,
                len,                           // dwSize,
                perms,                         // flNewProtect,
                &mut old_protection as *mut _, // lpflOldProtect,
            )
        };

        assert!(succeeded != 0);

        st_section_header = unsafe { st_section_header.add(1) };
    }
}

/// This function fixes the base relocations of the PE file in the allocated memory in the target process.
///
/// # Arguments
///
/// * `baseptr` - A pointer to the base address of the allocated memory in the target process.
/// * `ntheader` - A pointer to the NT header of the PE file.
pub fn fix_base_relocations(
    // Pointer to the base address of the allocated memory in the target process
    baseptr: *const c_void,
    // Pointer to the NT header of the PE file
    ntheader: *const c_void,
) {
    // Get the NT header
    #[cfg(target_arch = "x86_64")]
    let nt_header = unsafe { &(*(ntheader as *const IMAGE_NT_HEADERS64)).OptionalHeader };
    #[cfg(target_arch = "x86")]
    let nt_header = unsafe { &(*(ntheader as *const IMAGE_NT_HEADERS32)).OptionalHeader };

    // Get the base relocation directory
    let basereloc = &nt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
    if basereloc.Size == 0 {
        return;
    }

    // Calculate the difference between the image base and the allocated memory base
    let image_base = nt_header.ImageBase;
    let diffaddress = baseptr as usize - image_base as usize;

    // Get the pointer to the base relocation block
    let mut relocptr =
        (baseptr as usize + basereloc.VirtualAddress as usize) as *const IMAGE_BASE_RELOCATION;

    // Iterate through each block in the base relocation directory
    while unsafe { (*relocptr).SizeOfBlock } != 0 {
        // Get the number of entries in the current block
        let entries = (unsafe { (*relocptr).SizeOfBlock }
            - core::mem::size_of::<IMAGE_BASE_RELOCATION>() as u32)
            / 2;

        // Iterate through each entry in the current block
        for i in 0..entries {
            // Get the pointer to the current relocation offset
            let relocoffset_ptr = (relocptr as usize
                + core::mem::size_of::<IMAGE_BASE_RELOCATION>()
                + i as usize * 2) as *const u16;

            // Get the value of the current relocation offset
            let temp = unsafe { *relocoffset_ptr };

            // Check if the relocation type is not absolute
            if temp as u32 >> 12 as u32 != crate::windows::IMAGE_REL_BASED_ABSOLUTE as u32 {
                // Calculate the final address of the relocation
                let finaladdress = baseptr as usize
                    + unsafe { (*relocptr).VirtualAddress } as usize
                    + (temp & 0x0fff) as usize;

                // Read the original value at the final address
                let ogaddress = unsafe { core::ptr::read(finaladdress as *const usize) };

                // Calculate the fixed address of the relocation
                let fixedaddress = (ogaddress + diffaddress as usize) as usize;

                // Write the fixed address to the final address
                unsafe {
                    core::ptr::write(finaladdress as *mut usize, fixedaddress);
                }
            }
        }

        // Move to the next block in the base relocation directory
        relocptr = unsafe {
            (relocptr as *const u8).add((*relocptr).SizeOfBlock as usize)
                as *const IMAGE_BASE_RELOCATION
        };
    }
}

/// Gets the import directory from the NT header of the PE file.
///
/// # Arguments
///
/// * `ntheader` - A pointer to the NT header of the PE file.
///
/// # Returns
///
/// The import directory of the PE file.
fn get_import_directory(ntheader: *const c_void) -> IMAGE_DATA_DIRECTORY {
    #[cfg(target_arch = "x86_64")]
    return unsafe {
        (*(ntheader as *const IMAGE_NT_HEADERS64))
            .OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
    };

    #[cfg(target_arch = "x86")]
    return unsafe {
        (*(ntheader as *const crate::windows::IMAGE_NT_HEADERS32))
            .OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
    };
}

/// Writes the import table of the PE file to the allocated memory in the target process.
///
/// # Arguments
///
/// * `baseptr` - A pointer to the base address of the allocated memory in the target process.
/// * `ntheader` - A pointer to the NT header of the PE file.
fn write_import_table_impl(
    // A pointer to the base address of the allocated memory in the target process.
    baseptr: *const c_void,
    // A pointer to the NT header of the PE file.
    ntheader: *const c_void,
    get_proc_address_fn: GetProcAddressFn,
    load_library_fn: LoadLibraryAFn,
    get_module_handle_fn: GetModuleHandleAFn,
) {
    // Get the import directory
    let import_dir = get_import_directory(ntheader);

    // If the import directory is empty, return
    if import_dir.Size == 0 {
        return;
    }

    // Get the pointer to the first thunk
    let mut ogfirstthunkptr = baseptr as usize + import_dir.VirtualAddress as usize;

    // Loop through each import descriptor
    while unsafe { (*(ogfirstthunkptr as *const IMAGE_IMPORT_DESCRIPTOR)).Name } != 0
        && unsafe { (*(ogfirstthunkptr as *const IMAGE_IMPORT_DESCRIPTOR)).FirstThunk } != 0
    {
        // Get the import descriptor
        let mut import = unsafe { core::mem::zeroed::<IMAGE_IMPORT_DESCRIPTOR>() };
        //fill_structure_from_memory(&mut import, ogfirstthunkptr as *const c_void);
        unsafe {
            core::ptr::copy_nonoverlapping(
                ogfirstthunkptr as *const u8,
                &mut import as *mut IMAGE_IMPORT_DESCRIPTOR as *mut u8,
                core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
            );
        }
        // Get the name of the DLL
        let dllname = crate::utils::read_string_from_memory(
            (baseptr as usize + import.Name as usize) as *const u8,
        );

        let dllhandle = unsafe { (load_library_fn)(dllname.as_bytes().as_ptr() as *const u8) };
        let dllhandle = if dllhandle.is_null() || dllhandle == usize::MAX as *mut c_void {
            unsafe { (get_module_handle_fn)(dllname.as_bytes().as_ptr() as *const _) }
        } else {
            dllhandle
        };

        // Get the pointer to the first thunk for this import descriptor
        let mut thunkptr = unsafe {
            baseptr as usize
                + (import.Anonymous.OriginalFirstThunk as usize
                    | import.Anonymous.Characteristics as usize)
        };

        let mut i = 0;

        // Loop through each thunk for this import descriptor
        // and replace the function address with the address of the function in the DLL
        while unsafe { *(thunkptr as *const usize) } != 0 {
            // Get the thunk data
            let mut thunkdata: [u8; core::mem::size_of::<usize>()] =
                unsafe { core::mem::zeroed::<[u8; core::mem::size_of::<usize>()]>() };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    thunkptr as *const u8,
                    &mut thunkdata as *mut u8,
                    core::mem::size_of::<usize>(),
                );
            }
            // Get the offset of the function name
            let offset = usize::from_ne_bytes(thunkdata);

            // Check if this is imported by ordinal
            let func_addr = if offset & IMAGE_ORDINAL_FLAG != 0 {
                let val = unsafe {
                    (get_proc_address_fn)(
                        dllhandle,
                        (offset & (IMAGE_ORDINAL_FLAG - 1)) as *const u8,
                    )
                };

                // Putting this into two separate expressions is a little cleaner
                // and allows us to insert an int3 after the function if we want.
                Some(val)
            } else {
                // Get the function name
                let funcname = crate::utils::read_string_from_memory(
                    (baseptr as usize + offset as usize + 2) as *const u8,
                );

                // If the function name is not empty, replace the function address with the address of the function in the DLL
                if !funcname.len() > 1 {
                    let val = unsafe {
                        (get_proc_address_fn)(dllhandle, funcname.as_bytes().as_ptr() as *const u8)
                    };

                    Some(val)
                } else {
                    None
                }
            };
            if let Some(func_addr) = func_addr {
                let funcaddress_ptr = (baseptr as usize
                    + import.FirstThunk as usize
                    + i * core::mem::size_of::<usize>())
                    as *mut usize;
                unsafe { core::ptr::write(funcaddress_ptr, func_addr as usize) };
            }

            i += 1;
            // Move to the next thunk
            thunkptr += core::mem::size_of::<usize>();
        }
        ogfirstthunkptr += core::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();
    }
}

/// Writes the import table of the PE file to the allocated memory in the target process.
///
/// # Arguments
///
/// * `baseptr` - A pointer to the base address of the allocated memory in the target process.
/// * `ntheader` - A pointer to the NT header of the PE file.
pub fn write_import_table(
    // A pointer to the base address of the allocated memory in the target process.
    baseptr: *const c_void,
    // A pointer to the NT header of the PE file.
    ntheader: *const c_void,
    get_proc_address_func: GetProcAddressFn,
    load_library_fn: LoadLibraryAFn,
    get_module_handle_fn: GetModuleHandleAFn,
) {
    write_import_table_impl(
        baseptr,
        ntheader,
        get_proc_address_func,
        load_library_fn,
        get_module_handle_fn,
    )
}

/// Patches the PEB to reflect the new image command line arguments
pub unsafe fn patch_peb(
    args: Option<&[u16]>,
    image_name: Option<&[u16]>,
    virtual_protect: VirtualProtectFn,
) {
    let peb = (*teb()).ProcessEnvironmentBlock;
    let mut old_permissions = 0u32;
    (virtual_protect)(
        peb as *const _,
        core::mem::size_of::<PEB>(),
        PAGE_READWRITE,
        &mut old_permissions as *mut _,
    );

    if let Some(args) = args {
        let len = args.len() * core::mem::size_of::<u16>();
        (*(*peb).ProcessParameters).CommandLine.Buffer = (args.as_ptr() as *mut _);
        (*(*peb).ProcessParameters).CommandLine.Length = len as u16;
        (*(*peb).ProcessParameters).CommandLine.MaximumLength = len as u16;
    }

    if let Some(image_name) = image_name {
        let len = image_name.len() * core::mem::size_of::<u16>();
        (*(*peb).ProcessParameters).ImagePathName.Buffer = (image_name.as_ptr() as *mut _);
        (*(*peb).ProcessParameters).ImagePathName.Length = len as u16;
        (*(*peb).ProcessParameters).ImagePathName.MaximumLength = len as u16;
    }
}

/// For the given `module` and `name`, parses the PE headers and attempts to find
/// a section with the given `name`.
pub fn get_module_section(module: *mut u8, name: &[u8]) -> Option<&'static mut [u8]> {
    if name.len() > 8 {
        return None;
    }

    let dosheader = get_dos_header(module as *const c_void);
    let ntheader = get_nt_header(module as *const _, dosheader);

    let number_of_sections = get_number_of_sections(ntheader);
    let nt_header_size = get_nt_header_size();

    let e_lfanew = (unsafe { *dosheader }).e_lfanew as usize;
    let mut st_section_header =
        (module as usize + e_lfanew + nt_header_size) as *const IMAGE_SECTION_HEADER;

    for _i in 0..number_of_sections {
        let header_ref: &IMAGE_SECTION_HEADER = unsafe { core::mem::transmute(st_section_header) };
        if &header_ref.Name[..name.len()] == name {
            unsafe {
                return Some(core::slice::from_raw_parts_mut(
                    module.offset(header_ref.VirtualAddress as isize),
                    header_ref.Misc.VirtualSize as usize,
                ));
            }
        }

        st_section_header = unsafe { st_section_header.add(1) };
    }

    None
}

/// Patches kernelbase to reflect some of the new image's data, including:
///
/// - The command line arguments
pub unsafe fn patch_kernelbase(args: Option<&[u16]>, kernelbase_ptr: *mut u8) {
    if let Some(args) = args {
        let peb = (*teb()).ProcessEnvironmentBlock;
        // This buffer pointer should match the cached UNICODE_STRING in kernelbase
        let buffer = (*(*peb).ProcessParameters).CommandLine.Buffer;

        // Search this pointer in kernel32's .data section
        if let Some(kernelbase_data) = get_module_section(kernelbase_ptr, b".data") {
            let ptr = kernelbase_data.as_mut_ptr();
            let len = kernelbase_data.len() / 2;
            // Do not have two mutable references to the same memory range

            let data_as_wordsize = core::slice::from_raw_parts(ptr as *const usize, len);
            if let Some(found) = data_as_wordsize
                .iter()
                .position(|ptr| *ptr == buffer as usize)
            {
                // We originally found this while scanning usize-sized data, so we have to translate
                // this to a byte index
                let found_buffer_byte_pos = found * core::mem::size_of::<usize>();
                // Get the start of the unicode string
                let unicode_str_start =
                    found_buffer_byte_pos - core::mem::offset_of!(UNICODE_STRING, Buffer);
                let unicode_str = core::mem::transmute::<_, &mut UNICODE_STRING>(
                    ptr.offset(unicode_str_start as isize),
                );

                let args_byte_len = args.len() * core::mem::size_of::<u16>();
                unicode_str.Buffer = args.as_ptr() as *mut _;
                unicode_str.Length = args_byte_len as u16;
                unicode_str.MaximumLength = args_byte_len as u16;
            }
        }
    }
}

struct LDRP_TLS_DATA {
    TlsLinks: LIST_ENTRY,
    TlsDirectory: IMAGE_TLS_DIRECTORY64,
}

const LDRP_FIND_TLS_ENTRY_SIGNATURE_BYTES: [u8; 8] =
    [0x48, 0x3B, 0xC2, 0x75, 0xF2, 0x33, 0xC0, 0xC3];

type LdrpFindTlSEntryFn =
    unsafe extern "system" fn(entry: *const LDR_DATA_TABLE_ENTRY) -> *mut LDRP_TLS_DATA;

/// Patches the module list to change the old image name to the new image name.
///
/// This is useful to ensure that a program that depends on `GetModuleHandle*`
/// doesn't fail simply because its module is not found
pub unsafe fn patch_module_list(
    image_name: Option<&[u16]>,
    new_base_address: *mut c_void,
    module_size: usize,
    get_module_handle_fn: GetModuleHandleAFn,
    this_tls_data: *const IMAGE_TLS_DIRECTORY64,
    virtual_protect: VirtualProtectFn,
    entrypoint: *const c_void,
) -> u32 {
    let current_module = get_module_handle_fn(core::ptr::null());

    let teb = teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    let ldr_data = (*peb).Ldr;
    let module_list_head = &mut (*ldr_data).InMemoryOrderModuleList as *mut LIST_ENTRY;
    let mut next = (*module_list_head).Flink;
    while next != module_list_head {
        // -1 because this is the second field in the LDR_DATA_TABLE_ENTRY struct.
        // the first one is also a LIST_ENTRY
        let module_info = (next.offset(-1)) as *mut LDR_DATA_TABLE_ENTRY;
        if (*module_info).DllBase == current_module {
            (*module_info).DllBase = new_base_address;
            // EntryPoint
            (*module_info).Reserved3[0] = entrypoint as *mut c_void;
            // SizeOfImage
            (*module_info).Reserved3[1] = module_size as *mut c_void;

            let ntdll_addr = get_module_handle_fn("ntdll.dll\0".as_ptr() as *const _);
            if let Some(ntdll_text) = get_module_section(ntdll_addr as *mut _, b".text") {
                for window in ntdll_text.windows(LDRP_FIND_TLS_ENTRY_SIGNATURE_BYTES.len()) {
                    if window == LDRP_FIND_TLS_ENTRY_SIGNATURE_BYTES {
                        // Get this window's pointer and move backwards to find the start of the fn
                        let mut ptr = window.as_ptr();
                        loop {
                            let behind = ptr.offset(-1);
                            if *behind == 0xcc {
                                break;
                            }
                            ptr = ptr.offset(-1);
                        }

                        let LdrpFindTlsEntry: LdrpFindTlSEntryFn = core::mem::transmute(ptr);

                        let list_entry = LdrpFindTlsEntry(module_info);

                        (*list_entry).TlsDirectory = *this_tls_data;
                    }
                }
            }
            break;
        }
        next = (*next).Flink;
    }

    let dosheader = get_dos_header(current_module);
    let ntheader = get_nt_header(current_module, dosheader);

    #[cfg(target_arch = "x86_64")]
    let ntheader_ref: &mut IMAGE_NT_HEADERS64 = unsafe { core::mem::transmute(ntheader) };
    #[cfg(target_arch = "x86")]
    let ntheader_ref: &mut IMAGE_NT_HEADERS32 = unsafe { core::mem::transmute(ntheader) };

    let real_module_tls_entry =
        &mut ntheader_ref.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];

    let real_module_tls_dir = current_module.offset(real_module_tls_entry.VirtualAddress as isize)
        as *mut IMAGE_TLS_DIRECTORY64;

    let mut old_perms = 0;
    virtual_protect(
        real_module_tls_dir as *mut _ as *const _,
        core::mem::size_of::<IMAGE_TLS_DIRECTORY64>(),
        PAGE_READWRITE,
        &mut old_perms,
    );

    let idx = *((*real_module_tls_dir).AddressOfIndex as *const u32);
    *real_module_tls_dir = *this_tls_data;

    idx
}

/// Returns the Thread Environment Block (TEB)
pub fn teb() -> *mut Win32::System::Threading::TEB {
    let mut teb: *mut Win32::System::Threading::TEB;
    unsafe { core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb) }

    teb
}
