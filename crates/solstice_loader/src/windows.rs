#![allow(non_snake_case, non_camel_case_types)]



pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;
pub const DLL_PROCESS_ATTACH: u32 = 1;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGH: u16 = 1;
pub const IMAGE_REL_BASED_LOW: u16 = 2;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const IMAGE_ORDINAL_FLAG: usize = 0x80000000_00000000;

#[cfg(not(feature = "shellcode_compat"))]
pub(crate) mod ffi {
    
    
    

    
}
