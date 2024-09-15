/// Reference: https://bazizi.github.io/2022/12/29/enumerating-windows-processes-using-Rust.html

use std::error::Error;
use std::fmt::Display;
use windows::Win32::Foundation::{CloseHandle, BOOL, WIN32_ERROR};
use windows::Win32::Foundation::{GetLastError, MAX_PATH};
use windows::Win32::Foundation::{HANDLE, HMODULE};
use windows::Win32::System::ProcessStatus::EnumProcessModules;
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::ProcessStatus::GetModuleBaseNameA;
use windows::Win32::System::ProcessStatus::GetModuleFileNameExA;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};
use tracing::debug;
use tracing::error;

const DEFAULT_BUFF_SIZE: usize = 1024;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
pub struct ProcessModule {
    pub name: String,
    pub path: String,
    pub id: u32,
}

#[derive(Debug)]
pub struct CustomError {
    pub message: String,
    pub code: Option<WIN32_ERROR>,
}

impl Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CustomError {}

struct AutoProcessHandle {
    handle: HANDLE,
}

// RAI-style deallocator for the process handle
impl Drop for AutoProcessHandle {
    fn drop(&mut self) {
        if self.handle.is_invalid() {
            return;
        }

        if let Err(e) = unsafe { CloseHandle(self.handle) } {
                error!("Failed to drop process handle {:?}", self.handle);
        };
    }
}

fn get_process_ids() -> Result<Vec<u32>> {
    let mut process_ids = Vec::with_capacity(DEFAULT_BUFF_SIZE);
    process_ids.resize(DEFAULT_BUFF_SIZE, 0);
    let mut cb_needed: u32 = 0;

    match unsafe {
        EnumProcesses(
            process_ids.as_mut_ptr(),
            process_ids.len().try_into()?,
            &mut cb_needed,
        )
    } {
        Ok(_) => {
            debug!("{} bytes is needed to store all process info", cb_needed);
        }
        _ => {
            return Err(CustomError {
                message: "EnumProcesses failed".to_owned(),
                code: Some(unsafe { GetLastError() }),
            }
            .into())
        }
    }

    if cb_needed != process_ids.len().try_into()? {
        return Ok(process_ids);
    }

    // The buffer isn't large enough so we need to reallocate
    process_ids.resize(cb_needed as usize / std::mem::size_of::<u32>(), 0);

    if let Err(e) = unsafe {
        EnumProcesses(
            process_ids.as_mut_ptr(),
            (process_ids.len() * std::mem::size_of::<u32>()).try_into()?,
            &mut cb_needed,
        )
    } {
        return Err(CustomError {
            message: "EnumProcesses failed".to_owned(),
            code: Some(unsafe { GetLastError() }),
        }
        .into())
    }

    assert_ne!(cb_needed, process_ids.len().try_into()?);

    Ok(process_ids)
}

fn get_module_handle(process_handle: HANDLE) -> Result<HMODULE> {
    let mut module_handle = HMODULE::default();

    let mut cb_needed = 0;
    if let Err(e) = unsafe { EnumProcessModules(process_handle, &mut module_handle, 0, &mut cb_needed) } {
        return Err(CustomError {
            message: "EnumProcessModules failed".to_owned(),
            code: Some(unsafe { GetLastError() }),
        }
        .into())
    };

    Ok(module_handle)
}

fn get_process_module_info(
    process_handle: HANDLE,
    process_id: u32,
    module_handle: HMODULE,
) -> Result<Option<ProcessModule>> {
    let mut module_path = Vec::<u8>::with_capacity(MAX_PATH.try_into()?);
    module_path.resize(MAX_PATH.try_into()?, 0);

    match unsafe {
        GetModuleFileNameExA(
            process_handle,
            module_handle,
            &mut module_path,
        )
    } {
        0 => {
            return Ok(None);
        }
        _ => {}
    };

    let mut module_name = Vec::<u8>::with_capacity(MAX_PATH.try_into()?);
    module_name.resize(MAX_PATH.try_into()?, 0);

    match unsafe {
        GetModuleBaseNameA(
            process_handle,
            module_handle,
            &mut module_name,
        )
    } {
        0 => {
            return Ok(None);
        }
        _ => {}
    };

    Ok(Some(ProcessModule {
        name: String::from_iter(
            module_name
                .iter()
                .take_while(|&&x| x != 0)
                .map(|&x| x as char),
        ),
        path: String::from_iter(
            module_path
                .iter()
                .take_while(|&&x| x != 0)
                .map(|&x| x as char),
        ),
        id: process_id,
    }))
}

pub fn get_process_list() -> Result<Vec<ProcessModule>> {
    let mut process_module_infos = Vec::new();

    let process_ids = get_process_ids()?;
    let inherit_handle = BOOL(0);

    for i in 0..process_ids.len() {
        let process_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                inherit_handle,
                process_ids[i],
            )
        };

        match process_handle {
            Ok(process_handle) => {
                // RAII-style process handle
                let process_handle = AutoProcessHandle {
                    handle: process_handle,
                };

                let module_handle = get_module_handle(process_handle.handle)?;
                if let Some(process_module_info) =
                    get_process_module_info(process_handle.handle, process_ids[i], module_handle)?
                {
                    process_module_infos.push(process_module_info);
                }
            },
            Err(_) => continue,
        }
    }

    Ok(process_module_infos)
}
