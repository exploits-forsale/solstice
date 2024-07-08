use crate::{
    consts::CreateFileAccess,
    functions::{CloseHandleFn, CreateFileAFn, GetFileSizeFn, ReadFileFn, VirtualAllocFn},
    PVOID,
};

pub struct FileReader<'a> {
    file_handle: PVOID,
    funcs: &'a FileReaderFuncs,
}

impl<'a> Drop for FileReader<'a> {
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

impl<'a> FileReader<'a> {
    /// Opens the target file and returns a `FileReader` which can be used to
    /// read the file. The input `name` must be null terminated.
    pub fn open(name: *const i8, funcs: &'a FileReaderFuncs) -> Result<Self, FileReaderError> {
        let handle = unsafe {
            (funcs.create_file)(
                name,                                 // Filename
                CreateFileAccess::GenericRead as u32, // Desired access
                0,                                    // ShareMode
                core::ptr::null_mut() as PVOID,       // Security attributes
                4,                                    // OPEN_ALWAYS
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
        })
    }

    /// Retrieves the file size, allocates memory to contain the file, and
    /// reads the file data to the allocated buffer.
    ///
    /// Upon success the returned components are the allocated buffer and its length
    pub fn read_all(&mut self) -> Result<(*mut u8, usize), FileReaderError> {
        let file_size = unsafe { (self.funcs.get_size)(self.file_handle, core::ptr::null_mut()) };

        // Allocate memory of sufficient size for the file
        let file_data = unsafe {
            (self.funcs.virtual_alloc)(core::ptr::null_mut(), file_size as usize, 0x3000, 4)
        };

        // Read the file into memory
        let mut remaining_size = file_size;
        let mut write_ptr = file_data;
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

        Ok((file_data as *mut _, file_size as usize))
    }
}
