use core::mem::MaybeUninit;
// The `shellcode_utils` prelude exports an NT status `Result`.
use core::result::Result;

use alloc::boxed::Box;
use alloc::vec::Vec;
use allocators::WinGlobalAlloc;
use shellcode_utils::prelude::*;

use crate::Stage3Image;

const STAGE3_ENV_PAYLOAD_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\run.exe"#, "\0");
const STAGE3_ENV_ARGS_FILENAME: &str = concat!(r#"%LOCALAPPDATA%\..\LocalState\args.txt"#, "\0");

const STAGE2_ERROR_FILE_OPEN_FAILED: u64 = 0x20000001;
const STAGE2_ERROR_FILE_READ_FAILED: u64 = 0x20000002;
const STAGE2_ERROR_INVALID_UTF8: u64 = 0x20000003;

pub type ImageData = Box<[u8], WinGlobalAlloc>;

macro_rules! debug_print_cstr {
    ($kernelbase_ptr:expr, $cstr:expr) => {
        #[cfg(feature = "debug")]
        #[allow(unused_unsafe)]
        unsafe {
            fetch_output_debug_string($kernelbase_ptr)($cstr as _)
        }
    };
}

/// Reads the image named by `args`, or `LocalState\run.exe` and its optional
/// `LocalState\args.txt` when `args` is null.
pub fn load_image(
    args: *const ShellcodeArgs,
    kernelbase_ptr: PVOID,
    allocator: &WinGlobalAlloc,
) -> Result<Stage3Image, u64> {
    let GetFullPathNameA = fetch_get_full_path_name(kernelbase_ptr);
    let ExpandEnvironmentStringsA = fetch_expand_environment_strings(kernelbase_ptr);

    // Get the full image name without the ..\ and all other
    // unnecessary path characters.
    debug_print!(kernelbase_ptr, "Getting dynamic image name");
    let dynamic_image_name = if args.is_null() {
        debug_print!(kernelbase_ptr, "args are null -- generating image name");
        unsafe {
            let mut stage3_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
            (ExpandEnvironmentStringsA)(
                STAGE3_ENV_PAYLOAD_FILENAME.as_ptr(),
                stage3_filename.as_mut_ptr() as *mut _,
                core::mem::size_of_val(&stage3_filename) as u32,
            );

            // Get the size of the buffer needed
            let image_name_length = (GetFullPathNameA)(
                stage3_filename.as_ptr() as *const _,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );

            // Allocate some memory for the image
            let mut image_full_name = Vec::with_capacity_in(image_name_length as usize, allocator);

            // Get the full path name
            let image_full_name_len = (GetFullPathNameA)(
                stage3_filename.as_ptr() as *const _,
                image_name_length,
                image_full_name.as_mut_ptr(),
                core::ptr::null_mut(),
            ) as usize;

            image_full_name.set_len(image_full_name_len + 1);

            Some(image_full_name)
        }
    } else {
        debug_print!(
            kernelbase_ptr,
            "args are not null -- not generating a dynamic image name"
        );
        None
    };

    debug_print!(kernelbase_ptr, "Getting image ptr");
    // Borrow the generated name. `image_name_ptr` must stay valid until it is copied to UTF-16.
    let (image_name_ptr, image_name_len) = dynamic_image_name
        .as_ref()
        .map(|image_name| (image_name.as_ptr(), image_name.len()))
        .unwrap_or_else(|| unsafe {
            debug_print!(kernelbase_ptr, "Calculating str len");
            let image_name_ptr = (*args).image_name;
            let mut counter = 0;
            let image_name_len = loop {
                if *image_name_ptr.offset(counter) == 0 {
                    break counter;
                }

                counter += 1;
            };

            // +1 for null terminator
            (image_name_ptr, (image_name_len as usize) + 1)
        });

    let file_funcs = FileReaderFuncs {
        create_file: fetch_create_file(kernelbase_ptr),
        read_file: fetch_read_file(kernelbase_ptr),
        get_size: fetch_get_file_size(kernelbase_ptr),
        virtual_alloc: fetch_virtual_alloc(kernelbase_ptr),
        close_handle: fetch_close_handle(kernelbase_ptr),
    };

    // Map the returned errors to hard constants since the constants have the upper bit set
    // to signal which stage failed
    debug_print!(kernelbase_ptr, "Getting stage3 reader");
    debug_print_cstr!(kernelbase_ptr, image_name_ptr);
    let Ok(mut stage3_reader) = FileReader::open(image_name_ptr, &file_funcs, allocator.clone())
    else {
        return Err(STAGE2_ERROR_FILE_OPEN_FAILED);
    };

    debug_print!(kernelbase_ptr, "Getting PE reader");
    // Read the full stage3 PE file to memory
    let pe_data = match stage3_reader.read_all() {
        Ok(data) => data,
        Err(FileReaderError::ReadFailed) => {
            return Err(STAGE2_ERROR_FILE_READ_FAILED);
        }
        Err(FileReaderError::OpenFailed) => {
            // Should be impossible but we'll handle it anyways for completeness
            unreachable!();
        }
    };

    drop(stage3_reader);

    debug_print!(kernelbase_ptr, "Getting stage3 args");
    // Only read the args.txt file if we weren't provided any args
    let stage3_args = if args.is_null() {
        debug_print!(kernelbase_ptr, "Getting stage3 args filename");
        // Try loading stage 3's arguments. Fails gracefully if the file does not exist.
        let mut stage3_args_filename: MaybeUninit<[u8; 200]> = MaybeUninit::uninit();
        unsafe {
            (ExpandEnvironmentStringsA)(
                STAGE3_ENV_ARGS_FILENAME.as_ptr(),
                stage3_args_filename.as_mut_ptr() as *mut _,
                core::mem::size_of_val(&stage3_args_filename) as u32,
            );
        }

        FileReader::open(
            stage3_args_filename.as_ptr() as *const _,
            &file_funcs,
            allocator,
        )
        .ok()
        .and_then(|mut args_reader| {
            debug_print!(kernelbase_ptr, "Reading stage3 file");
            // Read the arguments to a buffer, create a new pointer array to hold all the args, then copy args over.
            match args_reader.read_all() {
                Ok(data) => Some(data),
                Err(FileReaderError::ReadFailed) => None,
                Err(FileReaderError::OpenFailed) => {
                    // Should be impossible but we'll handle it anyways for completeness
                    unreachable!();
                }
            }
        })
    } else {
        None
    };

    debug_print!(
        kernelbase_ptr,
        "Creating a full arg string from the input args"
    );
    // Construct the "<image name> <args>" string
    let stage3_args = stage3_args
        .as_ref()
        .map(|args| &**args)
        .or_else(|| {
            // If we weren't provided any args and we failed to read args.txt,
            // then we should have no args.
            if args.is_null() {
                None
            } else {
                unsafe {
                    let args_ptr = (*args).image_args;
                    if args_ptr.is_null() {
                        return None;
                    }

                    let mut counter = 0;
                    let args_len = loop {
                        if *args_ptr.offset(counter) == 0 {
                            break counter;
                        }

                        counter += 1;
                    };

                    // +1 for the null terminator
                    Some(core::slice::from_raw_parts(
                        (*args).image_args,
                        (args_len as usize) + 1,
                    ))
                }
            }
        })
        .and_then(|raw_args| {
            unsafe {
                let args_len = raw_args.len();
                // 3 extra characters for the quotes surrounding the image name, and space separating image name and args.
                // A null terminator character isn't necessary since it is already accounted for by `image_name.len()`
                let args_full_len = args_len + image_name_len + 3;
                let mut args_with_image_name: Vec<u8, _> =
                    Vec::with_capacity_in(args_full_len, allocator);
                let args_with_image_name_ptr = args_with_image_name.as_mut_ptr();

                let mut offset = 0;
                args_with_image_name_ptr.write(b'"');
                offset += 1;

                // do not copy the image name's null terminator
                let image_name_len = image_name_len - 1;
                core::ptr::copy_nonoverlapping(
                    image_name_ptr,
                    args_with_image_name_ptr.offset(offset),
                    image_name_len,
                );
                offset += image_name_len as isize;

                args_with_image_name_ptr.offset(offset).write(b'"');
                offset += 1;

                args_with_image_name_ptr.offset(offset).write(b' ');
                offset += 1;

                core::ptr::copy_nonoverlapping(
                    raw_args.as_ptr(),
                    args_with_image_name_ptr.offset(offset),
                    raw_args.len(),
                );

                args_with_image_name.set_len(args_full_len - 1);

                args_with_image_name.push(0);

                let utf8_args = match core::str::from_utf8(&args_with_image_name) {
                    Ok(s) => s,
                    Err(_) => return None,
                };

                Some(utf8_to_utf16(utf8_args, allocator.clone()))
            }
        });

    // SAFETY: the image_name_len comes from either a safely-allocated vec or
    // the name length calculated via null terminator, which we have to trust.
    let image_name = unsafe {
        match core::str::from_utf8(core::slice::from_raw_parts(image_name_ptr, image_name_len)) {
            Ok(name) => utf8_to_utf16(name, allocator.clone()),
            Err(_) => return Err(STAGE2_ERROR_INVALID_UTF8),
        }
    };

    let image_name: &'static [u16] = image_name.leak();

    // Default to using the image name as args
    let command_line: &'static [u16] = match stage3_args {
        Some(command_line) => command_line.leak(),
        None => image_name,
    };

    Ok(Stage3Image {
        pe_data,
        image_name,
        command_line,
    })
}
