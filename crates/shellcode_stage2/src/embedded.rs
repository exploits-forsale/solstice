use allocators::WinGlobalAlloc;
use shellcode_utils::prelude::*;

use crate::Stage3Image;

pub type ImageData = &'static [u8];

/// Image compiled into stage2. The loader reads the PE headers in place, so the
/// bytes need more than the 1-byte alignment `include_bytes!` guarantees.
#[repr(C, align(16))]
struct AlignedImage<T: ?Sized>(T);

// An array static instead of a `&[u8]` static: a pointer stored in `.text`
// needs a base relocation, which nothing applies to the flattened stage.
static EMBEDDED_IMAGE: AlignedImage<[u8; include_bytes!(env!("SOLSTICE_EMBEDDED_IMAGE")).len()]> =
    AlignedImage(*include_bytes!(env!("SOLSTICE_EMBEDDED_IMAGE")));

/// Returns the embedded image. It has no path of its own and takes no
/// arguments, so `args` is ignored.
pub fn load_image(
    _args: *const ShellcodeArgs,
    _kernelbase_ptr: PVOID,
    allocator: &WinGlobalAlloc,
) -> core::result::Result<Stage3Image, u64> {
    let image_name = unsafe { utf8_to_utf16("run.exe\0", allocator.clone()) }.leak();

    Ok(Stage3Image {
        pe_data: &EMBEDDED_IMAGE.0,
        image_name,
        command_line: image_name,
    })
}
