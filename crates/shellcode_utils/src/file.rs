use core::alloc::Allocator;

use alloc::boxed::Box;

use crate::{
    consts::CreateFileAccess,
    functions::{CloseHandleFn, CreateFileAFn, GetFileSizeFn, ReadFileFn, VirtualAllocFn},
    PVOID,
};

pub struct FileReader<'a, A>
where
    A: Allocator,
{
    file_handle: PVOID,
    funcs: &'a FileReaderFuncs,
    allocator: A,
}

impl<'a, A> Drop for FileReader<'a, A>
where
    A: Allocator,
{
    fn drop(&mut self) {
        unsafe {
            (self.funcs.close_handle)(self.file_handle);
        }
    }
}

pub struct FileReaderFuncs {
    pub create_file: CreateFileAFn,
    pub read_file: ReadFileFn,
    pub get_size: GetFileSizeFn,
    pub virtual_alloc: VirtualAllocFn,
    pub close_handle: CloseHandleFn,
}

pub enum FileReaderError {
    OpenFailed,
    ReadFailed,
}

impl<'a, A> FileReader<'a, A>
where
    A: Allocator + Clone,
{
    /// Opens the target file and returns a `FileReader` which can be used to
    /// read the file. The input `name` must be null terminated.
    #[inline(always)]
    pub fn open(
        name: *const i8,
        funcs: &'a FileReaderFuncs,
        allocator: A,
    ) -> Result<Self, FileReaderError> {
        let handle = unsafe {
            (funcs.create_file)(
                name,                                 // Filename
                CreateFileAccess::GenericRead as u32, // Desired access
                0,                                    // ShareMode
                core::ptr::null_mut() as PVOID,       // Security attributes
                3,                                    // OPEN_EXISTING
                0x80,                                 // FILE_ATTRIBUTE_NORMAL
                core::ptr::null_mut() as PVOID,       // hTemplateFile
            )
        };

        if handle as usize == usize::MAX {
            return Err(FileReaderError::OpenFailed);
        }

        Ok(Self {
            file_handle: handle,
            funcs,
            allocator,
        })
    }

    /// Retrieves the file size, allocates memory to contain the file, and
    /// reads the file data to the allocated buffer.
    ///
    /// Upon success the returned components are the allocated buffer and its length
    #[inline(always)]
    pub fn read_all(&mut self) -> Result<Box<[u8], A>, FileReaderError> {
        let file_size = unsafe { (self.funcs.get_size)(self.file_handle, core::ptr::null_mut()) };

        // Allocate memory of sufficient size for the file
        let mut file_data = Box::new_uninit_slice_in(file_size as usize, self.allocator.clone());

        // Read the file into memory
        let mut remaining_size = file_size;
        let mut write_ptr = file_data.as_mut_ptr() as _;
        while remaining_size > 0 {
            let mut bytes_read = 0u32;

            unsafe {
                if (self.funcs.read_file)(
                    self.file_handle,
                    write_ptr,
                    remaining_size,
                    &mut bytes_read as *mut _,
                    core::ptr::null_mut(),
                ) == 0
                {
                    return Err(FileReaderError::ReadFailed);
                }
                write_ptr = write_ptr.offset(bytes_read as _);
            }
            remaining_size -= bytes_read;
        }

        unsafe { Ok(file_data.assume_init()) }
    }
}
