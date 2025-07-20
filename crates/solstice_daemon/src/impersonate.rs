use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use std::mem::size_of;
use std::mem::zeroed;
use std::ptr::null;
use std::ptr::null_mut;
use tracing::debug;
use tracing::info;
use tracing::trace;
use windows::core::s;
use windows::core::w;
use windows::core::PCWSTR;
use windows::core::PWSTR;
use windows::Wdk::System::SystemServices::SE_DEBUG_PRIVILEGE;
use windows::Wdk::System::SystemServices::SE_TCB_PRIVILEGE;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::LUID;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::AdjustTokenPrivileges;
use windows::Win32::Security::Authentication::Identity::LSA_OBJECT_ATTRIBUTES;
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::DuplicateTokenEx;
use windows::Win32::Security::GetTokenInformation;
use windows::Win32::Security::ImpersonateLoggedOnUser;
use windows::Win32::Security::LookupAccountNameW;
use windows::Win32::Security::LookupPrivilegeNameW;
use windows::Win32::Security::LookupPrivilegeValueW;
use windows::Win32::Security::RevertToSelf;
use windows::Win32::Security::SecurityAnonymous;
use windows::Win32::Security::SecurityImpersonation;
use windows::Win32::Security::TokenGroups;
use windows::Win32::Security::TokenImpersonation;
use windows::Win32::Security::TokenPrimary;
use windows::Win32::Security::TokenPrivileges;
use windows::Win32::Security::LOGON32_LOGON;
use windows::Win32::Security::LOGON32_LOGON_SERVICE;
use windows::Win32::Security::LOGON32_PROVIDER;
use windows::Win32::Security::LOGON32_PROVIDER_WINNT50;
use windows::Win32::Security::LUID_AND_ATTRIBUTES;
use windows::Win32::Security::PSID;
use windows::Win32::Security::QUOTA_LIMITS;
use windows::Win32::Security::SECURITY_QUALITY_OF_SERVICE;
use windows::Win32::Security::SE_PRIVILEGE_ENABLED;
use windows::Win32::Security::SE_PRIVILEGE_ENABLED_BY_DEFAULT;
use windows::Win32::Security::SID;
use windows::Win32::Security::SID_AND_ATTRIBUTES;
use windows::Win32::Security::SID_NAME_USE;
use windows::Win32::Security::TOKEN_ACCESS_MASK;
use windows::Win32::Security::TOKEN_ALL_ACCESS;
use windows::Win32::Security::TOKEN_DEFAULT_DACL;
use windows::Win32::Security::TOKEN_DUPLICATE;
use windows::Win32::Security::TOKEN_GROUPS;
use windows::Win32::Security::TOKEN_IMPERSONATE;
use windows::Win32::Security::TOKEN_INFORMATION_CLASS;
use windows::Win32::Security::TOKEN_OWNER;
use windows::Win32::Security::TOKEN_PRIMARY_GROUP;
use windows::Win32::Security::TOKEN_PRIVILEGES;
use windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES;
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::Security::TOKEN_SOURCE;
use windows::Win32::Security::TOKEN_TYPE;
use windows::Win32::Security::TOKEN_USER;
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::Diagnostics::ToolHelp::Process32FirstW;
use windows::Win32::System::Diagnostics::ToolHelp::Process32NextW;
use windows::Win32::System::Diagnostics::ToolHelp::PROCESSENTRY32W;
use windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPPROCESS;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED_BY_DEFAULT;
use windows::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows::Win32::System::SystemServices::SE_GROUP_INTEGRITY_ENABLED;
use windows::Win32::System::SystemServices::SE_GROUP_MANDATORY;
use windows::Win32::System::SystemServices::SE_GROUP_OWNER;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::Threading::GetCurrentThread;
use windows::Win32::System::Threading::OpenProcess;
use windows::Win32::System::Threading::OpenProcessToken;
use windows::Win32::System::Threading::OpenThreadToken;
use windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

const LUID_SYSTEM: u32 = 999;

const SID_SYSTEM: &str = "S-1-5-18";
const SID_LOCALADM: &str = "S-1-5-32-544";
const SID_AUTH: &str = "S-1-5-11";
const SID_EVERYONE: &str = "S-1-1-0";
const SID_SYS: &str = "S-1-16-16384";
const SID_TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

pub fn to_u16(value: &str) -> Vec<u16> {
    value
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect::<Vec<u16>>()
}

pub type QueryUserTokenFn =
    unsafe extern "system" fn(dwSessionId: u32, handle: *mut HANDLE) -> bool;

type NtCreateTokenFn = unsafe extern "system" fn(
    TokenHandle: *mut HANDLE,
    DesiredAccess: TOKEN_ACCESS_MASK,
    ObjectAttributes: *mut LSA_OBJECT_ATTRIBUTES,
    TokenType: TOKEN_TYPE,
    AuthenticationId: *mut LUID,
    ExpirationTime: *mut i64,
    TokenUser: *mut TOKEN_USER,
    TokenGroups: *mut TOKEN_GROUPS,
    TokenPrivileges: *mut TOKEN_PRIVILEGES,
    TokenOwner: *mut TOKEN_OWNER,
    TokenPrimaryGroup: *mut TOKEN_PRIMARY_GROUP,
    TokenDefaultDacl: *mut TOKEN_DEFAULT_DACL,
    TokenSource: *mut TOKEN_SOURCE,
) -> NTSTATUS;

type RtlAdjustPrivilegeFn = unsafe extern "system" fn(
    Privilege: i32,
    Enable: bool,
    ThreadPrivilege: bool,
    Previous: *mut bool,
) -> NTSTATUS;

type NtAllocateLocallyUniqueIdFn = unsafe extern "system" fn(Luid: *mut LUID) -> NTSTATUS;

type LogonUserExExWFn = unsafe extern "system" fn(
    lpszusername: PCWSTR,
    lpszdomain: PCWSTR,
    lpszpassword: PCWSTR,
    dwlogontype: LOGON32_LOGON,
    dwlogonprovider: LOGON32_PROVIDER,
    pTokenGroups: *mut TOKEN_GROUPS,
    phtoken: *mut HANDLE,
    pplogonsid: *mut SID,
    ppprofilebuffer: *mut *mut std::ffi::c_void,
    pdwprofilelength: *mut u32,
    pquotalimits: *mut QUOTA_LIMITS,
) -> bool;

/* Inline functions, not part of windows-rs */
pub fn GetCurrentProcessToken() -> Result<HANDLE> {
    let mut handle = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle)?;
    }
    Ok(handle)
}

pub fn GetCurrentThreadToken() -> Result<HANDLE> {
    let mut handle = HANDLE::default();
    unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut handle)?;
    }
    Ok(handle)
}

pub fn fetch_query_user_token() -> Result<QueryUserTokenFn> {
    unsafe {
        let hmod = LoadLibraryW(w!("EXT-MS-WIN-SESSION-USERTOKEN-L1-1-0.DLL"))?;
        let func =
            GetProcAddress(hmod, s!("QueryUserToken")).ok_or(anyhow!("GetProcAddress failed"))?;
        let ptr: QueryUserTokenFn = std::mem::transmute(func);
        Ok(ptr)
    }
}

pub(crate) fn get_defaultaccount_token() -> Result<HANDLE> {
    #[allow(non_snake_case)]
    let QueryUserToken = fetch_query_user_token().context("Fetch QueryUserToken")?;

    let mut handle = HANDLE(std::ptr::null_mut());

    unsafe {
        if !QueryUserToken(0, &mut handle) {
            Err(anyhow!("Failed to query token"))
        } else {
            Ok(handle)
        }
    }
}

pub(crate) fn get_token_information(
    token_handle: HANDLE,
    info_class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>> {
    let mut info_len = 0;

    unsafe {
        let ret = GetTokenInformation(token_handle, info_class, None, 0, &mut info_len).err();

        if let Some(e) = ret {
            if e.code().0 != ERROR_INSUFFICIENT_BUFFER.to_hresult().0 {
                return Err(anyhow!(
                    "Unexpected error when getting required TokenInformation buffer size, err: {e}"
                ));
            }
        }

        let mut buf: Vec<u8> = Vec::with_capacity(info_len as usize);
        GetTokenInformation(
            token_handle,
            info_class,
            Some(buf.as_mut_ptr() as *mut _),
            info_len,
            &mut info_len,
        )
        .map_err(|e| anyhow!("GetTokenInformation (2), err: {e}"))?;

        Ok(buf)
    }
}

pub(crate) fn print_token_privileges(token_handle: HANDLE) -> Result<()> {
    let mut tinfo = get_token_information(token_handle, TokenPrivileges)
        .map_err(|e| anyhow!("get_token_information, err: {e}"))?;

    unsafe {
        let privs_ptr: *mut TOKEN_PRIVILEGES = tinfo.as_mut_ptr() as *mut _;
        let mut str_buf = [0u16; 0x400];
        let mut str_len: u32 = str_buf.len() as u32;
        let privs_attrs_ptr: *mut LUID_AND_ATTRIBUTES = (*privs_ptr).Privileges.as_mut_ptr();

        for i in 0..(*privs_ptr).PrivilegeCount {
            let la = privs_attrs_ptr.add(i as usize);
            trace!("LUID: {:?}, Attr: {:?}", (*la).Luid, (*la).Attributes);

            match LookupPrivilegeNameW(
                PCWSTR(null()),
                &(*la).Luid,
                PWSTR(str_buf.as_mut_ptr()),
                &mut str_len,
            ) {
                Ok(_) => {
                    let priv_name = String::from_utf16(&str_buf[..str_len as usize])
                        .map_err(|e| anyhow!("String::from_utf16, err: {e}"))?;

                    info!("name: {priv_name}");
                }
                Err(_) => {
                    debug!("Privilege {i} does not exist, LUID: {:?}", *la);
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn set_token_privilege(
    token_handle: HANDLE,
    privilege_name: &str,
    enable: bool,
) -> Result<()> {
    let mut luid = LUID::default();

    unsafe {
        let priv_name = to_u16(privilege_name);
        LookupPrivilegeValueW(
            PCWSTR(null()),
            PCWSTR::from_raw(priv_name.as_ptr()),
            &mut luid,
        )
        .map_err(|e| anyhow!("LookupPrivilegeValueW, err: {e}"))?;

        let token_privs = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: if enable {
                    SE_PRIVILEGE_ENABLED
                } else {
                    TOKEN_PRIVILEGES_ATTRIBUTES(0)
                },
            }],
        };

        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&token_privs as *const _),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
        .map_err(|e| anyhow!("AdjustTokenPrivileges, err: {e}"))?;
    }
    Ok(())
}

pub(crate) fn enable_privilege(impersonating: bool, privilege_val: i32) -> Result<()> {
    unsafe {
        let ntdll = LoadLibraryW(w!("ntdll.dll")).context("LoadLibraryW")?;
        if ntdll.0.is_null() {
            return Err(anyhow!("Failed to load ntdll.dll: {}", GetLastError().0));
        }

        let rtl_adjust_privilege = GetProcAddress(ntdll, s!("RtlAdjustPrivilege"))
            .ok_or_else(|| anyhow!("GetProcAddress(RtlAdjustPrivilege) failed"))?;

        let RtlAdjustPrivilege: RtlAdjustPrivilegeFn = std::mem::transmute(rtl_adjust_privilege);

        let mut enabled = false;
        let res = RtlAdjustPrivilege(privilege_val, true, impersonating, &mut enabled);
        if res.is_err() {
            return Err(anyhow!("RtlAdjustPrivilege failed for ID: {privilege_val}"));
        }

        Ok(())
    }
}

pub(crate) fn find_process(process: &str) -> Result<u32> {
    let mut pe32 = PROCESSENTRY32W::default();
    pe32.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| anyhow!("CreateSnapshot: {e}"))?;

        if !snap.is_invalid() {
            Process32FirstW(snap, &mut pe32).map_err(|e| anyhow!("Process32First: {e}"))?;

            loop {
                let exe_name = String::from_utf16(&pe32.szExeFile)?;
                debug!("Process name: {:?}", exe_name.trim_end_matches('\0'));
                if exe_name.trim_end_matches('\0') == process {
                    return Ok(pe32.th32ProcessID);
                }

                // This will return when no process is available anymore
                Process32NextW(snap, &mut pe32).map_err(|e| anyhow!("Process32Next: {e}"))?;
            }
        }
    }

    Err(anyhow!("Failed finding process '{process}'"))
}

pub(crate) fn get_token_by_pid(pid: u32) -> Result<HANDLE> {
    let mut hToken = HANDLE::default();
    let mut hDupToken = HANDLE::default();

    unsafe {
        let hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .map_err(|e| anyhow!("OpenProcess: {e}"))?;
        OpenProcessToken(hProcess, TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED), &mut hToken)
            .map_err(|e| anyhow!("OpenProcessToken: {e}"))?;
        DuplicateTokenEx(
            hToken,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenImpersonation,
            &mut hDupToken,
        )
        .map_err(|e| anyhow!("DuplicateToken: {e}"))?;

        Ok(hDupToken)
    }
}

pub(crate) fn get_token_by_sid(psid: PSID) -> Result<HANDLE> {
    let mut impersonating = false;
    unsafe {
        let advapi32 = LoadLibraryW(w!("advapi32.dll")).context("LoadLibraryW")?;
        if advapi32.0.is_null() {
            return Err(anyhow!("Failed to load advapi32.dll: {}", GetLastError().0));
        }

        let logon_user_ex_ex_w = GetProcAddress(advapi32, s!("LogonUserExExW"))
            .ok_or_else(|| anyhow!("GetProcAddress(LogonUserExExW) failed"))?;

        let LogonUserExExW: LogonUserExExWFn = std::mem::transmute(logon_user_ex_ex_w);

        if enable_privilege(false, SE_TCB_PRIVILEGE).is_err() {
            if enable_privilege(false, SE_DEBUG_PRIVILEGE).is_err() {
                return Err(anyhow!(
                    "Current process does not have SeTcbPrivilege or SeDebugPrivilege"
                ));
            }

            impersonating = impersonate_tcb_token().is_ok();

            if !impersonating || enable_privilege(false, SE_TCB_PRIVILEGE).is_err() {
                return Err(anyhow!("Failed to acquire SeTcbPrivilege"));
            }
        }

        let current_token = {
            if impersonating {
                GetCurrentThreadToken().context("GetCurrentThreadToken")?
            } else {
                GetCurrentProcessToken().context("GetCurrentProcessToken")?
            }
        };

        let tgroups = get_token_information(current_token, TokenGroups)?;

        let tgroups_ptr: *mut TOKEN_GROUPS = tgroups.as_ptr() as _;
        let tgroups_sid_and_attrs_ptr: *mut SID_AND_ATTRIBUTES =
            (*tgroups_ptr).Groups.as_ptr() as *mut _;
        let tgroups_count = (*tgroups_ptr).GroupCount;

        (*tgroups_sid_and_attrs_ptr.add(tgroups_count as usize - 1)).Sid = psid;
        (*tgroups_sid_and_attrs_ptr.add(tgroups_count as usize - 1)).Attributes =
            (SE_GROUP_OWNER | SE_GROUP_ENABLED) as u32;

        let mut trusted_installer_token = HANDLE::default();
        let res = LogonUserExExW(
            w!("SYSTEM"),
            w!("NT AUTHORITY"),
            PCWSTR(null()),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_WINNT50,
            tgroups_ptr,
            &mut trusted_installer_token as *mut _,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
        );

        let logon_err = GetLastError();

        if impersonating {
            RevertToSelf().context("Failed RevertToSelf")?;
        }

        if !res {
            return Err(anyhow!("LogonUserExExW failed, err: {logon_err:?}"));
        }

        Ok(trusted_installer_token)
    }
}

pub(crate) fn get_token_by_sid_str(sid_str: &str) -> Result<HANDLE> {
    let mut psid = PSID::default();
    let sid_vec16 = to_u16(sid_str);

    unsafe {
        ConvertStringSidToSidW(PCWSTR::from_raw(sid_vec16.as_ptr()), &mut psid as *mut _)
            .map_err(|e| anyhow!("ConvertStringSidToSidW {sid_str} {e}"))?;

        get_token_by_sid(psid)
    }
}

pub(crate) fn impersonate_tcb_token() -> Result<()> {
    unsafe {
        let winlogon_pid =
            find_process("winlogon.exe").context("Failed finding winlogon.exe PID")?;

        let h_process = OpenProcess(PROCESS_QUERY_INFORMATION, false, winlogon_pid)
            .map_err(|e| anyhow!("Failed OpenProcess: {e}"))?;

        let mut h_token = HANDLE::default();
        OpenProcessToken(
            h_process,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            &mut h_token,
        )
        .map_err(|e| anyhow!("Failed OpenProcessToken: {e}"))?;
        CloseHandle(h_process).context("CloseHandle hProcess")?;

        ImpersonateLoggedOnUser(h_token).context("ImpersonateLoggedOnUser")?;

        CloseHandle(h_token).context("CloseHandle hToken")?;

        Ok(())
    }
}

pub(crate) fn get_token_for_username(username: &str) -> Result<HANDLE> {
    let mut username = username.to_owned();

    if !username.ends_with("\0") {
        username += "\0";
    }

    let username_u16 = to_u16(&username);

    let mut sid_name_use = SID_NAME_USE::default();
    let mut sid_len = 0;
    let mut domain_name_len: u32 = 0;

    info!("Before lookup: sid_len: {sid_len}");

    unsafe {
        let res = LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR::from_raw(username_u16.as_ptr()),
            PSID(null_mut()),
            &mut sid_len,
            PWSTR::null(),
            &mut domain_name_len,
            &mut sid_name_use as *mut _,
        );

        if let Err(e) = res {
            info!("Insufficient buffer: {}", e.code());
            //if e.code() != 0x8007007A {
            //return Err(anyhow!("LookupAccountNameW failed unexpectedly: {e}"));
            //}
        }

        info!("sid_len: {sid_len}, domain name len: {domain_name_len}, SID_NAME_USE: {sid_name_use:?}");
        let mut sid = vec![0u8; sid_len as usize];
        let mut domain_name = vec![0u16; domain_name_len as usize];
        let psid = PSID(sid.as_mut_ptr() as *mut _);

        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR::from_raw(username_u16.as_ptr()),
            psid,
            &mut sid_len,
            PWSTR::from_raw(domain_name.as_mut_ptr()),
            &mut domain_name_len,
            &mut sid_name_use as *mut _,
        )
        .map_err(|e| anyhow!("Failed LookupAccountNameW (2): {e}"))?;

        info!(
            "Lookup success! sid: {:?}, domain: {:?}",
            &sid[..sid_len as usize],
            &domain_name[..domain_name_len as usize]
        );

        get_token_by_sid(psid)
    }
}

pub(crate) fn get_trustedinstaller_token() -> Result<HANDLE> {
    get_token_by_sid_str(SID_TRUSTED_INSTALLER)
}

/// Translated from: https://github.com/Wh04m1001/NtCreateToken/blob/main/NtCreateToken.cpp
pub(crate) fn get_trustedinstaller_token2() -> Result<HANDLE> {
    unsafe {
        let lsass_pid =
            find_process("lsass.exe").map_err(|e| anyhow!("Failed finding process: {e}"))?;

        let token_handle =
            get_token_by_pid(lsass_pid).map_err(|e| anyhow!("get_token_by_pid: {e}"))?;

        info!("Before token adjustment");
        print_token_privileges(token_handle)
            .map_err(|e| anyhow!("Failed to print token privs (1): {e}"))?;

        set_token_privilege(token_handle, "SeCreateTokenPrivilege", true)
            .map_err(|e| anyhow!("Failed to set CreateTokenPrivilege (1): {e}"))?;

        set_token_privilege(token_handle, "SeImpersonatePrivilege", true)
            .map_err(|e| anyhow!("Failed to set CreateTokenPrivilege (2): {e}"))?;

        set_token_privilege(token_handle, "SeAssignPrimaryTokenPrivilege", true)
            .map_err(|e| anyhow!("Failed to set CreateTokenPrivilege (3): {e}"))?;

        info!("After token adjustment");
        print_token_privileges(token_handle)
            .map_err(|e| anyhow!("Failed to print token privs (2): {e}"))?;

        // Step 1: Load ntdll.dll and get NtCreateToken and NtAllocateLocallyUniqueId
        let ntdll = LoadLibraryW(w!("ntdll.dll")).context("LoadLibraryW")?;
        if ntdll.0.is_null() {
            return Err(anyhow!("Failed to load ntdll.dll: {}", GetLastError().0));
        }
        let nt_create_token = GetProcAddress(ntdll, s!("NtCreateToken"))
            .ok_or_else(|| anyhow!("GetProcAddress(NtCreateToken) failed"))?;
        let nt_allocate_luid = GetProcAddress(ntdll, s!("NtAllocateLocallyUniqueId"))
            .ok_or_else(|| anyhow!("GetProcAddress(NtAllocateLocallyUniqueId) failed"))?;

        let NtCreateToken: NtCreateTokenFn = std::mem::transmute(nt_create_token);
        let NtAllocateLocallyUniqueId: NtAllocateLocallyUniqueIdFn =
            std::mem::transmute(nt_allocate_luid);

        // Step 2: Allocate LUID
        info!("Step 1: Allocate LUID");
        let mut luid: LUID = zeroed();
        let status = NtAllocateLocallyUniqueId(&mut luid);
        if status.0 != 0 {
            return Err(anyhow!("NtAllocateLocallyUniqueId failed: {:?}", status));
        }

        // Step 3: Create SIDs
        info!("Step 3: Create SIDs");
        let mut p_SYSTEMSID = PSID::default();
        let mut p_LOCALADM = PSID::default();
        let mut p_AUTH = PSID::default();
        let mut p_EVERYONE = PSID::default();
        let mut p_SYS = PSID::default();
        let mut p_TI = PSID::default();

        let SID_SYSTEM_VEC16 = to_u16(SID_SYSTEM);
        let SID_LOCALADM_VEC16 = to_u16(SID_LOCALADM);
        let SID_AUTH_VEC16 = to_u16(SID_AUTH);
        let SID_EVERYONE_VEC16 = to_u16(SID_EVERYONE);
        let SID_SYS_VEC16 = to_u16(SID_SYS);
        let SID_TRUSTED_INSTALLER_VEC16 = to_u16(SID_TRUSTED_INSTALLER);

        ConvertStringSidToSidW(
            PCWSTR::from_raw(SID_SYSTEM_VEC16.as_ptr()),
            &mut p_SYSTEMSID as *mut _,
        )
        .map_err(|e| anyhow!("ConvertStringSidToSidW SYSTEM {e}"))?;
        ConvertStringSidToSidW(
            PCWSTR::from_raw(SID_LOCALADM_VEC16.as_ptr()),
            &mut p_LOCALADM as *mut _,
        )
        .map_err(|e| anyhow!("ConvertStringSidToSidW LOCALADM {e}"))?;
        ConvertStringSidToSidW(
            PCWSTR::from_raw(SID_AUTH_VEC16.as_ptr()),
            &mut p_AUTH as *mut _,
        )
        .map_err(|e| anyhow!("ConvertStringSidToSidW AUTH {e}"))?;
        ConvertStringSidToSidW(
            PCWSTR::from_raw(SID_EVERYONE_VEC16.as_ptr()),
            &mut p_EVERYONE as *mut _,
        )
        .map_err(|e| anyhow!("ConvertStringSidToSidW EVERYONE {e}"))?;
        ConvertStringSidToSidW(
            PCWSTR::from_raw(SID_SYS_VEC16.as_ptr()),
            &mut p_SYS as *mut _,
        )
        .map_err(|e| anyhow!("ConvertStringSidToSidW SYS {e}"))?;
        ConvertStringSidToSidW(
            PCWSTR::from_raw(SID_TRUSTED_INSTALLER_VEC16.as_ptr()),
            &mut p_TI as *mut _,
        )
        .map_err(|e| anyhow!("ConvertStringSidToSidW TRUSTED_INSTALLER {e}"))?;

        // Step 4: Setup TOKEN_USER
        info!("Step 4: Setup TOKEN_USER");
        let mut token_user = TOKEN_USER {
            User: SID_AND_ATTRIBUTES {
                Sid: p_SYSTEMSID,
                Attributes: 0,
            },
        };

        // Step 5: Setup TOKEN_GROUPS
        info!("Step 5: Setup TOKEN_GROUPS");
        const GROUPCOUNT: usize = 5;
        struct TOKEN_GROUPS_CUSTOM {
            GroupCount: u32,
            Groups: [SID_AND_ATTRIBUTES; GROUPCOUNT],
        }

        let mut token_groups_arr = TOKEN_GROUPS_CUSTOM {
            GroupCount: GROUPCOUNT as u32,
            Groups: [
                SID_AND_ATTRIBUTES {
                    Sid: p_LOCALADM,
                    Attributes: (SE_GROUP_ENABLED
                        | SE_GROUP_ENABLED_BY_DEFAULT
                        | SE_GROUP_MANDATORY
                        | SE_GROUP_OWNER) as u32,
                },
                SID_AND_ATTRIBUTES {
                    Sid: p_AUTH,
                    Attributes: (SE_GROUP_ENABLED
                        | SE_GROUP_ENABLED_BY_DEFAULT
                        | SE_GROUP_MANDATORY) as u32,
                },
                SID_AND_ATTRIBUTES {
                    Sid: p_EVERYONE,
                    Attributes: (SE_GROUP_ENABLED
                        | SE_GROUP_ENABLED_BY_DEFAULT
                        | SE_GROUP_MANDATORY) as u32,
                },
                SID_AND_ATTRIBUTES {
                    Sid: p_SYS,
                    Attributes: (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED) as u32,
                },
                SID_AND_ATTRIBUTES {
                    Sid: p_TI,
                    Attributes: (SE_GROUP_ENABLED
                        | SE_GROUP_ENABLED_BY_DEFAULT
                        | SE_GROUP_MANDATORY
                        | SE_GROUP_OWNER) as u32,
                },
            ],
        };

        // Step 6: Setup TOKEN_PRIVILEGES
        info!("Step 6: Setup TOKEN_PRIVILEGES");
        let privs = [
            "SeCreateTokenPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeLockMemoryPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeMachineAccountPrivilege",
            "SeTcbPrivilege",
            "SeSecurityPrivilege",
            "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege",
            "SeSystemProfilePrivilege",
            "SeSystemtimePrivilege",
            "SeProfileSingleProcessPrivilege",
            "SeIncreaseBasePriorityPrivilege",
            "SeCreatePagefilePrivilege",
            "SeCreatePermanentPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeShutdownPrivilege",
            "SeDebugPrivilege",
            "SeAuditPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeChangeNotifyPrivilege",
            "SeRemoteShutdownPrivilege",
            "SeUndockPrivilege",
            "SeSyncAgentPrivilege",
            "SeEnableDelegationPrivilege",
            "SeManageVolumePrivilege",
            "SeImpersonatePrivilege",
            "SeCreateGlobalPrivilege",
            "SeTrustedCredManAccessPrivilege",
            "SeRelabelPrivilege",
            "SeIncreaseWorkingSetPrivilege",
            "SeTimeZonePrivilege",
            "SeCreateSymbolicLinkPrivilege",
            "SeDelegateSessionUserImpersonatePrivilege",
        ];

        const PRIVCOUNT: usize = 35;
        struct TOKEN_PRIVS_CUSTOM {
            PrivilegeCount: u32,
            Privileges: [LUID_AND_ATTRIBUTES; PRIVCOUNT],
        }

        let mut privs_arr = TOKEN_PRIVS_CUSTOM {
            PrivilegeCount: PRIVCOUNT as u32,
            Privileges: [zeroed(); PRIVCOUNT],
        };

        for (i, privname) in privs.into_iter().enumerate() {
            let mut target_luid = LUID::default();
            let privname_vec = to_u16(privname);
            let priv_wide = PCWSTR::from_raw(privname_vec.as_ptr());
            if let Err(e) = LookupPrivilegeValueW(PCWSTR(null()), priv_wide, &mut target_luid) {
                return Err(anyhow!(
                    "LookupPrivilegeValueW({privname}) failed: {e}, {:?}",
                    GetLastError()
                ));
            }
            privs_arr.Privileges[i] = LUID_AND_ATTRIBUTES {
                Luid: target_luid,
                Attributes: SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT,
            };
        }

        // Step 7: Setup TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_DEFAULT_DACL, TOKEN_SOURCE
        info!("Step 7: Setup TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_DEFAULT_DACL, TOKEN_SOURCE");
        let source_name: [i8; 8] = [
            's' as i8, 'e' as i8, 'c' as i8, 'l' as i8, 'o' as i8, 'g' as i8, 'o' as i8, 'n' as i8,
        ];
        let mut token_owner = TOKEN_OWNER { Owner: p_LOCALADM };
        let mut token_pgroup = TOKEN_PRIMARY_GROUP {
            PrimaryGroup: p_LOCALADM,
        };
        let mut token_dacl: TOKEN_DEFAULT_DACL = TOKEN_DEFAULT_DACL::default(); // Not setting DACL for now
        let mut token_source = TOKEN_SOURCE {
            SourceName: source_name,
            SourceIdentifier: luid,
        };

        // Step 8: Setup OBJECT_ATTRIBUTES and SECURITY_QUALITY_OF_SERVICE
        info!("Step 8: Setup OBJECT_ATTRIBUTES and SECURITY_QUALITY_OF_SERVICE");
        let mut sqs = SECURITY_QUALITY_OF_SERVICE {
            Length: size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32,
            ImpersonationLevel: SecurityAnonymous,
            ContextTrackingMode: 1,
            EffectiveOnly: false.into(),
        };
        let mut oa = LSA_OBJECT_ATTRIBUTES {
            Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: HANDLE::default(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: &mut sqs as *mut _ as *mut _,
        };

        // Step 9: Expiration time
        info!("Step 9: Expiration time");
        let mut exp: i64 = -1i64;
        let mut lluid = LUID {
            LowPart: LUID_SYSTEM,
            HighPart: 0,
        }; // SYSTEM_LUID

        // Step 10: Call NtCreateToken
        info!("Step 10: Call NtCreateToken");
        let mut token: HANDLE = HANDLE(std::ptr::null_mut());
        let status = NtCreateToken(
            &mut token,
            TOKEN_ALL_ACCESS,
            &mut oa,
            TokenPrimary,
            &mut lluid,
            &mut exp,
            &mut token_user,
            &mut token_groups_arr as *mut _ as *mut _,
            &mut privs_arr as *mut _ as *mut _,
            &mut token_owner,
            &mut token_pgroup,
            &mut token_dacl,
            &mut token_source,
        );
        if status.0 != 0 {
            return Err(anyhow!("NtCreateToken failed: {0:#08x} ({0})", status.0));
        }
        Ok(token)
    }
}
