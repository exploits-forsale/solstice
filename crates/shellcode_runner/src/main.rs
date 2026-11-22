//! Maps a flattened stage into executable memory and calls its entry point the
//! same way the previous stage does. The process exit code is the value the
//! stage returns. A stage that hands off to a loaded image never returns, and
//! the image ends the process instead.

mod error;

use std::ffi::c_void;
use std::ffi::CString;
use std::path::PathBuf;

use shellcode_utils::ShellcodeArgs;
use shellcode_utils::ShellcodeEntryFn;
use windows_sys::Win32::System::Memory::VirtualAlloc;
use windows_sys::Win32::System::Memory::VirtualProtect;
use windows_sys::Win32::System::Memory::MEM_COMMIT;
use windows_sys::Win32::System::Memory::MEM_RESERVE;
use windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;

use crate::error::RunnerError;

struct Invocation {
    shellcode_path: PathBuf,
    image: Option<ImageArgs>,
}

impl Invocation {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, RunnerError> {
        let Some(shellcode_path) = args.next() else {
            return Err(RunnerError::Usage);
        };

        let image = match args.next() {
            Some(name) => Some(ImageArgs {
                name: CString::new(name)?,
                args: args.next().map(CString::new).transpose()?,
            }),
            None => None,
        };

        if args.next().is_some() {
            return Err(RunnerError::Usage);
        }

        Ok(Self {
            shellcode_path: PathBuf::from(shellcode_path),
            image,
        })
    }
}

/// Values passed to the stage through `ShellcodeArgs`.
struct ImageArgs {
    name: CString,
    args: Option<CString>,
}

fn map_shellcode(code: &[u8]) -> Result<ShellcodeEntryFn, RunnerError> {
    let size = code.len();

    // The mapping is never freed. The stage either runs until the process exits
    // or returns right before it does.
    let base = unsafe {
        VirtualAlloc(
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        return Err(RunnerError::Allocate {
            size,
            source: std::io::Error::last_os_error(),
        });
    }

    unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), base.cast::<u8>(), size) };

    // stage1 maps stage2 with the same protection.
    let mut old_protection = 0u32;
    if unsafe { VirtualProtect(base, size, PAGE_EXECUTE_READ, &mut old_protection) } == 0 {
        return Err(RunnerError::Protect {
            size,
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: `base` holds a flattened stage, whose entry point is at offset 0.
    Ok(unsafe { std::mem::transmute::<*mut c_void, ShellcodeEntryFn>(base) })
}

fn run(invocation: Invocation) -> Result<u32, RunnerError> {
    let code =
        std::fs::read(&invocation.shellcode_path).map_err(|source| RunnerError::ReadShellcode {
            path: invocation.shellcode_path.clone(),
            source,
        })?;
    if code.is_empty() {
        return Err(RunnerError::EmptyShellcode {
            path: invocation.shellcode_path,
        });
    }

    let entry = map_shellcode(&code)?;

    let shellcode_args = invocation.image.as_ref().map(|image| ShellcodeArgs {
        image_name: image.name.as_ptr().cast(),
        image_args: image
            .args
            .as_ref()
            .map_or(std::ptr::null(), |args| args.as_ptr().cast()),
    });
    let shellcode_args_ptr = shellcode_args
        .as_ref()
        .map_or(std::ptr::null(), |args| args as *const ShellcodeArgs);

    let code = unsafe { entry(shellcode_args_ptr) };

    u32::try_from(code).map_err(|_| RunnerError::ReturnCodeOutOfRange { code })
}

fn main() {
    let result = Invocation::parse(std::env::args().skip(1)).and_then(run);

    match result {
        Ok(code) => {
            eprintln!("stage returned {code:#X}");
            std::process::exit(code as i32);
        }
        Err(e) => {
            eprintln!("error: {e}");
            if let Some(source) = std::error::Error::source(&e) {
                eprintln!("caused by: {source}");
            }
            std::process::exit(1);
        }
    }
}
