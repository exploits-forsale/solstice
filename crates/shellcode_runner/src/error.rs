use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("usage: shellcode_runner <shellcode.bin> [<image path> [<image args>]]")]
    Usage,

    #[error("failed to read {path}")]
    ReadShellcode {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("shellcode file {path} is empty")]
    EmptyShellcode { path: PathBuf },

    #[error("argument contains an interior null byte")]
    InteriorNul(#[from] std::ffi::NulError),

    #[error("VirtualAlloc of {size:#X} bytes failed")]
    Allocate {
        size: usize,
        #[source]
        source: std::io::Error,
    },

    #[error("VirtualProtect of {size:#X} bytes failed")]
    Protect {
        size: usize,
        #[source]
        source: std::io::Error,
    },

    #[error("shellcode returned {code:#X}, which does not fit in a process exit code")]
    ReturnCodeOutOfRange { code: u64 },
}
