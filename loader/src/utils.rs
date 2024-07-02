/// This function converts a mutable u8 array to a String.
/// It iterates through the array and appends each character to a new String.
/// If it encounters a null character, it returns the String.
///
/// # Arguments
///
/// * `arr` - A mutable slice of i8 representing the array to convert.
///
/// # Returns
///
/// A String representing the converted array.
#[allow(unused)]
pub fn get_string_fromu8_array(arr: &mut [u8]) -> &str {
    if let Some(null_term_offset) = arr.iter().position(|c| *c == 0) {
        return unsafe { core::str::from_utf8_unchecked(&arr[0..null_term_offset]) };
    } else {
        ""
    }
}

/// Reads a string from memory.
///
/// # Arguments
///
/// * `baseaddress` - A pointer to the base address of the string.
///
/// # Returns
///
/// A string containing the characters read from memory.
pub fn read_string_from_memory<'a>(baseaddress: *const u8) -> &'a str {
    // Find the null terminator
    let mut count = 0;
    loop {
        let byte_at_offset = unsafe { *baseaddress.offset(count) };
        if byte_at_offset == 0 {
            let bytes = unsafe { core::slice::from_raw_parts(baseaddress, count as usize) };

            // yolo
            return unsafe { core::str::from_utf8_unchecked(bytes) };
        }
        count += 1;
    }
}

/// This function checks if a given PE file contains the .NET PE flag.
/// It iterates through the file in windows of the same length as the .NET flag.
/// If it finds a window that matches the .NET flag, it returns true.
///
/// # Arguments
///
/// * `pe` - A vector of u8 representing the PE file to check.
///
/// # Returns
///
/// A boolean value indicating whether the PE file contains the .NET flag.
pub fn check_dotnet(pe: &[u8]) -> bool {
    const DOTNET_FLAG: [u8; 13] = [
        0x2E, 0x4E, 0x45, 0x54, 0x46, 0x72, 0x61, 0x6D, 0x65, 0x77, 0x6F, 0x72, 0x6B,
    ];
    pe.windows(DOTNET_FLAG.len())
        .any(|window| window.eq(&DOTNET_FLAG))
}

/// Detects the platform of a PE file.
///
/// # Arguments
///
/// * `bytes` - A slice containing the bytes of the PE file.
///
/// # Returns
///
/// An `Option` containing the platform of the PE file, or `None` if the file is not a valid PE file.
pub fn detect_platform(bytes: &[u8]) -> Option<u32> {
    // Check that the file starts with the "MZ" DOS header
    if bytes.get(0..2) != Some(&[0x4D, 0x5A]) {
        return None;
    }

    // Calculate the offset to the PE header from the DOS header
    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]);

    // Check that the PE header starts with the "PE\0\0" signature
    if bytes.get(pe_offset as usize..pe_offset as usize + 4) != Some(&[0x50, 0x45, 0x00, 0x00]) {
        return None;
    }

    // Determine the machine type from the "Machine" field in the PE header
    let machine =
        u16::from_le_bytes([bytes[pe_offset as usize + 4], bytes[pe_offset as usize + 5]]);
    match machine {
        0x014c => Some(32), // IMAGE_FILE_MACHINE_I386
        0x0200 => Some(64), // IMAGE_FILE_MACHINE_IA64
        0x8664 => Some(64), // IMAGE_FILE_MACHINE_AMD64
        _ => None,
    }
}
