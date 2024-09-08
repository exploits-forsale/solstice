/// Reference: https://github.com/joaovarelas/steal-token-rs/blob/main/src/main.rs
use tracing::{error, debug};
use windows::core::PSTR;
use windows::Win32::Foundation::{BOOL, FALSE, HANDLE, LUID, TRUE};
use windows::Win32::Security::{AdjustTokenPrivileges, RevertToSelf};
use windows::Win32::Security::LUID_AND_ATTRIBUTES;
use windows::Win32::Security::PRIVILEGE_SET;
use windows::Win32::Security::{
    DuplicateTokenEx, LookupPrivilegeValueW, PrivilegeCheck, SecurityImpersonation,
    TokenImpersonation, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, SetThreadToken, PROCESS_QUERY_INFORMATION,
};
use windows::Win32::System::WindowsProgramming::GetUserNameA;

mod process_list;

pub struct Impersonate {
    current_process: HANDLE,
    original_token: HANDLE,
}

impl Impersonate {
    pub fn create() -> Self {
        let own = unsafe { GetCurrentProcess() };
        let orig_token = Self::get_impersonation_token(own).unwrap();
        Self {
            current_process: own,
            original_token: orig_token,
        }
    }

    fn get_impersonation_token(process_handle: HANDLE) -> Result<HANDLE, Box<dyn std::error::Error>> {
        let mut token_handle = HANDLE::default();
        let mut new_token = HANDLE::default();

        unsafe {
            OpenProcessToken(
                process_handle,
                TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut token_handle,
            )?;

            DuplicateTokenEx(
                token_handle,
                TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
                None,
                SecurityImpersonation,
                TokenImpersonation,
                &mut new_token,
            )?;
        }
    
        Ok(new_token)
    }

    pub fn get_username() -> Result<String, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; 257];
        let lpbuffer: PSTR = PSTR(buffer.as_mut_ptr());
        let mut pcbbuffer: u32 = buffer.len() as u32;

        unsafe {
            GetUserNameA(lpbuffer, &mut pcbbuffer)?;
        }

        let username = String::from_utf8(buffer)?.trim_end_matches("\0").to_owned();
        Ok(username)
    }

    fn enable_debug_privilege(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
        let mut luid: LUID = LUID {
            LowPart: 0,
            HighPart: 0,
        };

        LookupPrivilegeValueW(None, SE_DEBUG_NAME, &mut luid)?;
        OpenProcessToken(self.current_process, TOKEN_ALL_ACCESS, &mut self.original_token)?;

        let token_priv: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(self.original_token, FALSE, Some(&token_priv), 0, None, None)?;

        let mut priv_set: PRIVILEGE_SET = PRIVILEGE_SET {
            PrivilegeCount: 1,
            Control: 1u32, // PRIVILEGE_SET_ALL_NECESSARY
            Privilege: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let mut priv_enabled: BOOL = BOOL(1);
        PrivilegeCheck(self.original_token, &mut priv_set, &mut priv_enabled)?;
        
        debug!("SeDebugPrivilege is: {:?}", priv_enabled);

        if priv_enabled.0 == 0 {
            return Err("Failed to set enable debug privilege".into());
        }
        }

        Ok(())
    }

    pub fn do_impersonate_pid(&mut self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let proc_handle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid)?;
            let new_token = Impersonate::get_impersonation_token(proc_handle)?;
            if let Err(e) = SetThreadToken(None, new_token) {
                return Err("Failed to set thread token, err: {e:?}".into());
            }
        }
        Ok(())
    }

    pub fn do_impersonate_process_name(&mut self, process_name: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.enable_debug_privilege().or_else(|e| {
            error!("Failed to enable debug privilege, err: {e:?}");
            Err(e)
        })?;

        let mut pid = 0;
        for p in process_list::get_process_list()? {
            if p.name.to_lowercase() == process_name.to_lowercase() {
                pid = p.id;
                debug!("Found PID for {process_name} -> {pid}");
            }
        }

        if pid == 0 {
            return Err(format!("Failed to get target PID for process: {process_name:?}").into());
        }


        self.do_impersonate_pid(pid)
    }

    pub fn revert_to_self() -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            RevertToSelf()?;
            Ok(())
        }
    }
}

impl Drop for Impersonate {
    fn drop(&mut self) {
        let _ = Self::revert_to_self();
    }
}
