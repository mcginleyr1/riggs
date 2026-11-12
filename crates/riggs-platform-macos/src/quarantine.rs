//! The `com.apple.quarantine` extended attribute that browsers and other
//! quarantine-enabled apps put on what they download. The sensor only reports
//! the raw value; the detection stage decides what it means.

use std::ffi::{CStr, CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Once;

use riggs_types::events::DownloadMark;
use tracing::warn;

const ATTRIBUTE: &CStr = c"com.apple.quarantine";

static UNREADABLE: Once = Once::new();

/// The download mark on the executable, or else on its first non-flag
/// argument (relative to the process's `cwd`): the script an interpreter runs.
/// Later arguments are its data (`python3 convert.py data.csv` runs no
/// data.csv). A flag that takes a value (`python3 -W ignore x.py`) hides the
/// script; a miss there is better than an alert that is wrong.
pub(crate) fn find(
    exe: Option<&Path>,
    args: &[OsString],
    cwd: Option<&Path>,
) -> Option<DownloadMark> {
    let operand = args
        .iter()
        .skip(1)
        .find(|arg| !arg.as_bytes().starts_with(b"-"))
        .and_then(|arg| {
            let arg = Path::new(arg);
            if arg.is_absolute() {
                Some(arg.to_path_buf())
            } else {
                cwd.map(|cwd| cwd.join(arg))
            }
        });
    exe.map(Path::to_path_buf)
        .into_iter()
        .chain(operand)
        .find_map(|path| {
            let quarantine = match read(&CString::new(path.as_os_str().as_bytes()).ok()?) {
                Ok(value) => value?,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    UNREADABLE.call_once(|| {
                        warn!(
                            path = %path.display(),
                            error = %e,
                            "cannot read download marks here; the executed-download rule is blind to such files (does the daemon have Full Disk Access?)"
                        )
                    });
                    return None;
                }
                Err(_) => return None,
            };
            Some(DownloadMark {
                path: path.to_string_lossy().into_owned(),
                quarantine,
            })
        })
}

/// The attribute's value, or None when the file has none.
pub(crate) fn read(path: &CStr) -> io::Result<Option<String>> {
    let mut buf = [0u8; 1024];
    // SAFETY: both names are NUL-terminated and `buf` is writable for its
    // whole length. macOS getxattr takes a position and options (6 arguments).
    let len = unsafe {
        libc::getxattr(
            path.as_ptr(),
            ATTRIBUTE.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            0,
        )
    };
    if len < 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOATTR) => Ok(None),
            _ => Err(err),
        };
    }
    Ok(Some(
        String::from_utf8_lossy(&buf[..len as usize]).into_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_real_quarantine_mark_on_the_script_but_not_on_its_data() {
        let dir = std::env::temp_dir().join(format!("riggs-quarantine-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c_path = |name: &str| CString::new(dir.join(name).as_os_str().as_bytes()).unwrap();
        for name in ["install.sh", "convert.py", "data.csv"] {
            std::fs::write(dir.join(name), "x\n").unwrap();
        }
        // The documented `flags;hex-seconds;agent;UUID` shape.
        let value = "0083;5991b778;Safari.app;BC4DFC58-6E4C-4A4F-9C5B-6B1E2D7F0A11";
        let set: Vec<(libc::c_int, io::Error)> = ["install.sh", "data.csv"]
            .iter()
            .map(|name| {
                // SAFETY: NUL-terminated names; `value` is readable for its length.
                let ret = unsafe {
                    libc::setxattr(
                        c_path(name).as_ptr(),
                        ATTRIBUTE.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                        0,
                    )
                };
                (ret, io::Error::last_os_error())
            })
            .collect();

        let marked = read(&c_path("install.sh"));
        let unmarked = read(&c_path("convert.py"));
        let script = find(
            Some(Path::new("/bin/bash")),
            &["bash".into(), "-x".into(), "install.sh".into()],
            Some(&dir),
        );
        let data = find(
            Some(Path::new("/usr/bin/python3")),
            &["python3".into(), "convert.py".into(), "data.csv".into()],
            Some(&dir),
        );
        std::fs::remove_dir_all(&dir).unwrap();

        for (ret, error) in set {
            assert_eq!(ret, 0, "setxattr: {error}");
        }
        assert_eq!(marked.unwrap().as_deref(), Some(value));
        assert_eq!(unmarked.unwrap(), None);
        assert_eq!(
            script,
            Some(DownloadMark {
                path: dir.join("install.sh").to_string_lossy().into_owned(),
                quarantine: value.into(),
            })
        );
        assert_eq!(data, None);
    }
}
