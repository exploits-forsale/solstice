use anyhow::{anyhow, Context, Result};
use tracing::{debug, info, trace, warn};
use windows::core::{s, w, PWSTR};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE, LUID, NTSTATUS};
use windows::Win32::Security::Authentication::Identity::LSA_OBJECT_ATTRIBUTES;
use windows::Win32::System::LibraryLoader::{LoadLibraryW, GetProcAddress};
use windows::Win32::Security::Authorization::{ConvertStringSidToSidW};
use windows::Win32::Security::{AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeNameW, LookupPrivilegeValueW, SecurityAnonymous, TokenPrimary, TokenPrivileges, LUID_AND_ATTRIBUTES, PSID, SECURITY_QUALITY_OF_SERVICE, SECURITY_STATIC_TRACKING, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED, SID, SID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ALL_ACCESS, TOKEN_DEFAULT_DACL, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_PRIVILEGES_ATTRIBUTES, TOKEN_SOURCE, TOKEN_TYPE, TOKEN_USER};
use windows::Win32::System::SystemServices::{SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED, SE_GROUP_MANDATORY, SE_GROUP_OWNER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use std::ptr::{null_mut, null};
use std::mem::{size_of, zeroed};

const LUID_SYSTEM: u32 = 999;

const SID_SYSTEM: &str = "S-1-5-18";
const SID_LOCALADM: &str = "S-1-5-32-544";
const SID_AUTH: &str = "S-1-5-11";
const SID_EVERYONE: &str = "S-1-1-0";
const SID_SYS: &str = "S-1-16-16384";
const SID_TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

pub fn to_u16(value: &str) -> Vec<u16> {
    value.encode_utf16()
        .chain(std::iter::once(0u16))
        .collect::<Vec<u16>>()
}

pub type QueryUserTokenFn = unsafe extern "system" fn(
    dwSessionId: u32,
    handle: *mut HANDLE,
) -> bool;

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

type NtAllocateLocallyUniqueIdFn = unsafe extern "system" fn(Luid: *mut LUID) -> NTSTATUS;

pub fn fetch_query_user_token() -> Result<QueryUserTokenFn> {
    unsafe {
        let hmod = LoadLibraryW(w!("EXT-MS-WIN-SESSION-USERTOKEN-L1-1-0.DLL"))?;
        let func = GetProcAddress(hmod, s!("QueryUserToken"))
            .ok_or(anyhow!("GetProcAddress failed"))?;
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

pub(crate) fn get_token_information(token_handle: HANDLE, info_class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>> {
    let mut info_len = 0;

    unsafe {
        let ret = GetTokenInformation(token_handle, info_class, None, 0, &mut info_len).err();

        if let Some(e) = ret {            
            if e.code().0 != ERROR_INSUFFICIENT_BUFFER.to_hresult().0 {
                return Err(anyhow!("Unexpected error when getting required TokenInformation buffer size, err: {e}"));
            }
        }

        let mut buf: Vec<u8> = Vec::with_capacity(info_len as usize);
        GetTokenInformation(token_handle, info_class,Some(buf.as_mut_ptr() as *mut _), info_len, &mut info_len)
            .map_err(|e|anyhow!("GetTokenInformation (2), err: {e}"))?;

        Ok(buf)
    }
}

pub(crate) fn print_token_privileges(token_handle: HANDLE) -> Result<()> {
    let mut tinfo = get_token_information(token_handle, TokenPrivileges)
        .map_err(|e|anyhow!("get_token_information, err: {e}"))?;

    unsafe {
        let privs_ptr: *mut TOKEN_PRIVILEGES = tinfo.as_mut_ptr() as *mut _;
        let mut str_buf = [0u16; 0x400];
        let mut str_len: u32 = str_buf.len() as u32;
        let privs_attrs_ptr: *mut LUID_AND_ATTRIBUTES = (*privs_ptr).Privileges.as_mut_ptr();

        for i in 0..(*privs_ptr).PrivilegeCount {
            let la = privs_attrs_ptr.add(i as usize);
            trace!("LUID: {:?}, Attr: {:?}", (*la).Luid, (*la).Attributes);

            match LookupPrivilegeNameW(PCWSTR(null()), &(*la).Luid, PWSTR(str_buf.as_mut_ptr()), &mut str_len) {
                Ok(_) => {
                    let priv_name = String::from_utf16(&str_buf[..str_len as usize])
                        .map_err(|e|anyhow!("String::from_utf16, err: {e}"))?;
    
                    info!("name: {priv_name}");
                },
                Err(_) => {
                    debug!("Privilege {i} does not exist, LUID: {:?}", *la);
                },
            }
        }
    }

    Ok(())
}

pub(crate) fn set_token_privilege(token_handle: HANDLE, privilege_name: &str, enable: bool) -> Result<()> {
    let mut luid = LUID::default();

    unsafe {
        let priv_name = to_u16(privilege_name);
        LookupPrivilegeValueW(PCWSTR(null()), PCWSTR::from_raw(priv_name.as_ptr()), &mut luid)
            .map_err(|e|anyhow!("LookupPrivilegeValueW, err: {e}"))?;

        let token_privs = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [
                LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: if enable {SE_PRIVILEGE_ENABLED} else {TOKEN_PRIVILEGES_ATTRIBUTES(0)},
                }
            ],
        };

        AdjustTokenPrivileges(
            token_handle,
            false,
            Some(&token_privs as *const _),
            size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None
        )
            .map_err(|e|anyhow!("AdjustTokenPrivileges, err: {e}"))?;

    }
    Ok(())
}

/// Translated from: https://github.com/Wh04m1001/NtCreateToken/blob/main/NtCreateToken.cpp
pub(crate) fn get_trustedinstaller_token() -> Result<HANDLE> {
    unsafe {
        let mut token_handle = HANDLE::default();
        // Step 0: Adjust token privileges to allow token creation
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token_handle as *mut _)
            .map_err(|e|anyhow!("Failed to open process token: {e}"))?;

        info!("Before token adjustment");
        print_token_privileges(token_handle)
            .map_err(|e|anyhow!("Failed to print token privs (1): {e}"))?;

        set_token_privilege(token_handle, "SeCreateTokenPrivilege", true)
            .map_err(|e|anyhow!("Failed to set CreateTokenPrivilege (1): {e}"))?;

        set_token_privilege(token_handle, "SeImpersonatePrivilege", true)
            .map_err(|e|anyhow!("Failed to set CreateTokenPrivilege (2): {e}"))?;

        set_token_privilege(token_handle, "SeAssignPrimaryTokenPrivilege", true)
            .map_err(|e|anyhow!("Failed to set CreateTokenPrivilege (3): {e}"))?;

        info!("After token adjustment");
        print_token_privileges(token_handle)
            .map_err(|e|anyhow!("Failed to print token privs (2): {e}"))?;

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
        let NtAllocateLocallyUniqueId: NtAllocateLocallyUniqueIdFn = std::mem::transmute(nt_allocate_luid);

        // Step 2: Allocate LUID
        info!("Step 1: Allocate LUID");
        let mut luid: LUID = zeroed();
        let status = NtAllocateLocallyUniqueId(&mut luid);
        if status.0 != 0 {
            return Err(anyhow!("NtAllocateLocallyUniqueId failed: {:?}", status));
        }

        // Step 3: Create SIDs
        info!("Step 3: Create SIDs");
        let mut s_SYSTEMSID = SID::default();
        let mut s_LOCALADM = SID::default();
        let mut s_AUTH = SID::default();
        let mut s_EVERYONE = SID::default();
        let mut s_SYS = SID::default();
        let mut s_TI = SID::default();

        let SID_SYSTEM_VEC16 = to_u16(SID_SYSTEM);
        let SID_LOCALADM_VEC16 = to_u16(SID_LOCALADM);
        let SID_AUTH_VEC16 = to_u16(SID_AUTH);
        let SID_EVERYONE_VEC16 = to_u16(SID_EVERYONE);
        let SID_SYS_VEC16 = to_u16(SID_SYS);
        let SID_TRUSTED_INSTALLER_VEC16 = to_u16(SID_TRUSTED_INSTALLER);

        ConvertStringSidToSidW(PCWSTR::from_raw(SID_SYSTEM_VEC16.as_ptr()), &mut s_SYSTEMSID as *mut _ as *mut _)
            .map_err(|e|anyhow!("ConvertStringSidToSidW SYSTEM {e}"))?;
        ConvertStringSidToSidW(PCWSTR::from_raw(SID_LOCALADM_VEC16.as_ptr()), &mut s_LOCALADM as *mut _ as *mut _)
            .map_err(|e|anyhow!("ConvertStringSidToSidW LOCALADM {e}"))?;
        ConvertStringSidToSidW(PCWSTR::from_raw(SID_AUTH_VEC16.as_ptr()), &mut s_AUTH as *mut _ as *mut _)
            .map_err(|e|anyhow!("ConvertStringSidToSidW AUTH {e}"))?;
        ConvertStringSidToSidW(PCWSTR::from_raw(SID_EVERYONE_VEC16.as_ptr()), &mut s_EVERYONE as *mut _ as *mut _)
            .map_err(|e|anyhow!("ConvertStringSidToSidW EVERYONE {e}"))?;
        ConvertStringSidToSidW(PCWSTR::from_raw(SID_SYS_VEC16.as_ptr()), &mut s_SYS as *mut _ as *mut _)
            .map_err(|e|anyhow!("ConvertStringSidToSidW SYS {e}"))?;
        ConvertStringSidToSidW(PCWSTR::from_raw(SID_TRUSTED_INSTALLER_VEC16.as_ptr()),  &mut s_TI as *mut _ as *mut _)
            .map_err(|e|anyhow!("ConvertStringSidToSidW TRUSTED_INSTALLER {e}"))?;

        info!("s_SYSTEMSID: {s_SYSTEMSID:?}\n
             s_LOCALADM: {s_LOCALADM:?}\n
             s_AUTH: {s_AUTH:?}\n
             s_EVERYONE: {s_EVERYONE:?}\n
             s_SYS: {s_SYS:?}\n
             s_TI: {s_TI:?}\n
"
        );

        let p_SYSTEMSID = PSID(&mut s_SYSTEMSID as *mut _ as *mut _);
        let p_LOCALADM = PSID(&mut s_LOCALADM as *mut _ as *mut _);
        let p_AUTH = PSID(&mut s_AUTH as *mut _ as *mut _);
        let p_EVERYONE = PSID(&mut s_EVERYONE as *mut _ as *mut _);
        let p_SYS = PSID(&mut s_SYS as *mut _ as *mut _);
        let p_TI = PSID(&mut s_TI as *mut _ as *mut _);

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

        let mut token_groups_arr= TOKEN_GROUPS_CUSTOM {
            GroupCount: GROUPCOUNT as u32,
            Groups: [
                SID_AND_ATTRIBUTES { Sid: p_LOCALADM, Attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER) as u32 },
                SID_AND_ATTRIBUTES { Sid: p_AUTH, Attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32 },
                SID_AND_ATTRIBUTES { Sid: p_EVERYONE, Attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY) as u32 },
                SID_AND_ATTRIBUTES { Sid: p_SYS, Attributes: (SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED) as u32 },
                SID_AND_ATTRIBUTES { Sid: p_TI, Attributes: (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER) as u32 },
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
            "SeDelegateSessionUserImpersonatePrivilege"
        ];

        const PRIVCOUNT: usize = 35;
        struct TOKEN_PRIVS_CUSTOM {
            PrivilegeCount: u32,
            Privileges: [LUID_AND_ATTRIBUTES; PRIVCOUNT],
        }

        let mut privs_arr= TOKEN_PRIVS_CUSTOM {
            PrivilegeCount: PRIVCOUNT as u32,
            Privileges: [zeroed(); PRIVCOUNT]
        };

        for (i, privname) in privs.into_iter().enumerate() {
            let mut target_luid = LUID::default();
            let privname_vec = to_u16(privname);
            let priv_wide = PCWSTR::from_raw(privname_vec.as_ptr());
            if let Err(e) = LookupPrivilegeValueW(PCWSTR(null()), priv_wide, &mut target_luid) {
                return Err(anyhow!("LookupPrivilegeValueW({privname}) failed: {e}, {:?}", GetLastError()));
            }
            privs_arr.Privileges[i] = LUID_AND_ATTRIBUTES {
                Luid: target_luid,
                Attributes: SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT,
            };
        }

        // Step 7: Setup TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_DEFAULT_DACL, TOKEN_SOURCE
        info!("Step 7: Setup TOKEN_OWNER, TOKEN_PRIMARY_GROUP, TOKEN_DEFAULT_DACL, TOKEN_SOURCE");
        let source_name: [i8; 8] = ['s' as i8, 'e' as i8, 'c' as i8, 'l' as i8, 'o' as i8, 'g' as i8, 'o' as i8, 'n' as i8];
        let mut token_owner = TOKEN_OWNER { Owner: p_LOCALADM };
        let mut token_pgroup = TOKEN_PRIMARY_GROUP { PrimaryGroup: p_LOCALADM };
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
            ContextTrackingMode: SECURITY_STATIC_TRACKING.0,
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
        let mut lluid = LUID { LowPart: LUID_SYSTEM, HighPart: 0 }; // SYSTEM_LUID

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