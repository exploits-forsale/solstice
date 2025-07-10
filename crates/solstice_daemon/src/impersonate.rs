use anyhow::{anyhow, Context, Result};
use winapi::um::winnt::HANDLE;
use windows::core::s;
use windows::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

pub type QueryUserTokenFn = unsafe extern "system" fn(
    dwSessionId: u32,
    handle: *mut HANDLE,
) -> bool;

pub fn fetch_query_user_token() -> Result<QueryUserTokenFn> {
    unsafe {
        let hmod = LoadLibraryA(s!("EXT-MS-WIN-SESSION-USERTOKEN-L1-1-0.DLL"))?;
        let func = GetProcAddress(hmod, s!("QueryUserToken"))
            .ok_or(anyhow!("GetProcAddress failed"))?;
        let ptr: QueryUserTokenFn = std::mem::transmute(func);
        Ok(ptr)
    }
}

pub(crate) fn get_token() -> Result<HANDLE> {
    #[allow(non_snake_case)]
    let QueryUserToken = fetch_query_user_token().context("Fetch QueryUserToken")?;

    let mut handle = std::ptr::null_mut();

    unsafe {
        if !QueryUserToken(0, &mut handle) {
            Err(anyhow!("Failed to query token"))
        } else {
            Ok(handle)
        }
    }
}