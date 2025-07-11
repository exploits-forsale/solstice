use std::path::Path;
use std::path::PathBuf;
use anyhow::{Result, anyhow};
use tracing::{debug, trace};

pub fn canonizalize_unix_path_name(path: &PathBuf) -> PathBuf {
    let mut parts = vec![];
    for part in path {
        match part.to_str() {
            Some(".") => continue,
            Some("\\") => continue,
            Some("..") => _ = parts.pop(),
            Some(val) => parts.push(val),
            None => {}
        }
    }

    let res = String::from("/") + parts.join("/").as_str();
    PathBuf::from(&res)
}


pub fn unix_like_path_to_windows_path(unix_path: &str) -> Option<PathBuf> {
    let parsed_path = Path::new(&unix_path);
    debug!("unix to windows path: {unix_path}");
    // Only accept full paths
    if !parsed_path.has_root() {
        debug!("returning None");
        return None;
    } else if unix_path == "/" {
        debug!("unix->windows: returning root path: /");
        return Some(PathBuf::from("/"));
    }

    // Grab the drive letter. We assume the first dir is the drive
    let mut split = unix_path.split('/').skip(1);
    if let Some(mount) = split.next() {
        // They're statting something under a drive letter
        let mut translated_path = PathBuf::from(format!("{}:\\", mount));
        for component in split {
            translated_path.push(component);
        }

        translated_path = std::path::absolute(&translated_path).unwrap_or(translated_path);
        debug!("returning translated path: {:?}", translated_path);

        Some(translated_path)
    } else {
        Some(PathBuf::from("/"))
    }
}

pub fn get_drivelist() -> Result<Vec<String>> {
    // returns the existing drives as a bitfield
    let assigned_letters =
        unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };

    // Iterate over each bit and construct a list of drive letters
    let drives = (0..27)
        .filter(|i| assigned_letters & (1 << i) != 0)
        .map(|i| String::from_utf8(vec![b'A' + i]).unwrap())
        .collect();

    Ok(drives)
}


pub fn wildcard_path_to_filedir_list(path: &str) -> Result<String> {
    let mut path = path.strip_suffix("*")
        .ok_or( anyhow!("Expected path to end with wildcard"))?
        .to_owned();

    if path.is_empty() || path == "pwd" || path == "/" || path.len() == 2 {
        let drivelist = get_drivelist()?
            .iter()
            .map(|x| "/".to_string() + x + "/")
            .filter(|x| (path.len() == 2 && x.starts_with(&path)) || (path.len() != 2) )
            .collect::<Vec<String>>()
            .join("\n");

        return Ok(drivelist)
    }

    if !path.starts_with("/") {
        return Err(anyhow!("Path should start with /"));
    }

    // Unix paths contain backslash as escape charater, Windows does not
    // To be able to compare paths, this needs to be stripped
    path = path.replace("\\", "");

    let requests_dir = path.ends_with("/");
    let winpath = unix_like_path_to_windows_path(&path)
        .ok_or(anyhow!("Failed converting path"))?;

    let sep_index = path.rfind("/").unwrap();
    let partial = path.split_off(sep_index + 1)
        .replace("\\","");

    let listdir = if requests_dir { Some(winpath.as_path()) } else { winpath.parent() };

    let mut ret = vec![];
    if let Some(listdir) = listdir {
        // This is an incomplete / wildcard match, request all files and dir of parent and return them
        let entries: Vec<PathBuf> = listdir.read_dir()?
            .map(|b| {
                b.unwrap().path()
            })
            .collect();  

        
        for e in entries {
            let fname = e.file_name().unwrap().to_string_lossy();

            if e.is_file() {
                ret.push(path.clone() + &fname + "*");
            } else if e.is_dir() {
                ret.push(path.clone() + &fname + "/");
            } else {
                ret.push(path.clone() + &fname);
            }
        }
    }

    let filtered = ret.clone()
        .into_iter()
        .filter(|x|
            x.to_lowercase().starts_with(&(path.clone() + &partial).to_lowercase())
        )
        .collect::<Vec<String>>();

    trace!("All: {ret:?}, Path: {path:?}, Partial: {partial:?}, Filtered: {filtered:?}");

    Ok(filtered.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_path_name() {
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from(".")), PathBuf::from("/"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/")), PathBuf::from("/"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/..")), PathBuf::from("/"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/../..")), PathBuf::from("/"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C")), PathBuf::from("/C"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/")), PathBuf::from("/C"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/../..")), PathBuf::from("/"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users")), PathBuf::from("/C/users"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/")), PathBuf::from("/C/users"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/appdata/local/")), PathBuf::from("/C/users/appdata/local"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/appdata/local/../")), PathBuf::from("/C/users/appdata"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/..")), PathBuf::from("/C"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/../.")), PathBuf::from("/C"));
        assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/../C/users/.././.")), PathBuf::from("/C"));
    }

    #[test]
    fn test_unix_style_to_windows_path() {
        assert_eq!(unix_like_path_to_windows_path(""), None);
        assert_eq!(unix_like_path_to_windows_path("C/"), None);
        assert_eq!(unix_like_path_to_windows_path("C/Windows"), None);
        assert_eq!(unix_like_path_to_windows_path("/").unwrap(), PathBuf::from("/"));
        assert_eq!(unix_like_path_to_windows_path("/C").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/./.").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/././").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows").unwrap(), PathBuf::from("C:\\Windows"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/").unwrap(), PathBuf::from("C:\\Windows"));
        assert_eq!(unix_like_path_to_windows_path("/C/./././Windows/").unwrap(), PathBuf::from("C:\\Windows"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/System32").unwrap(), PathBuf::from("C:\\Windows\\System32"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/System32/").unwrap(), PathBuf::from("C:\\Windows\\System32"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/././System32/").unwrap(), PathBuf::from("C:\\Windows\\System32"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/System32/..").unwrap(), PathBuf::from("C:\\Windows"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/System32/../").unwrap(), PathBuf::from("C:\\Windows"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/././System32/../").unwrap(), PathBuf::from("C:\\Windows"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/System32/../..").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/Windows/System32/../../").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/./././Windows/System32/../../").unwrap(), PathBuf::from("C:\\"));
        assert_eq!(unix_like_path_to_windows_path("/C/Program Files").unwrap(), PathBuf::from("C:\\Program Files"));
        assert_eq!(unix_like_path_to_windows_path("/C/Program Files (x86)").unwrap(), PathBuf::from("C:\\Program Files (x86)"));
    }

    #[test]
    pub fn test_wildcard_path() {
        assert!(wildcard_path_to_filedir_list("pwd*").unwrap().contains("/C/"));
        assert!(wildcard_path_to_filedir_list("/*").unwrap().contains("/C/"));
        assert!(wildcard_path_to_filedir_list("*").unwrap().contains("/C/"));

        assert_eq!(wildcard_path_to_filedir_list("/C/abcdef*").unwrap(), "");
        assert_eq!(wildcard_path_to_filedir_list("/C/ProgramD*").unwrap(), "/C/ProgramData/");
    }
}