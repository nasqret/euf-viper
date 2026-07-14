use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Fingerprint {
        device: u64,
        inode: u64,
        length: u64,
        modified_seconds: i64,
        modified_nanoseconds: i64,
        changed_seconds: i64,
        changed_nanoseconds: i64,
    }

    fn fingerprint(file: &File) -> Result<Fingerprint, String> {
        let metadata = file
            .metadata()
            .map_err(|error| format!("failed to inspect descriptor: {error}"))?;
        Ok(Fingerprint {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    fn c_name(name: &OsStr) -> Result<CString, String> {
        CString::new(name.as_bytes()).map_err(|_| "path component contains NUL".to_owned())
    }

    fn open_dir_at(parent: &File, name: &OsStr) -> io::Result<File> {
        let name = c_name(name).map_err(io::Error::other)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn root_dir(absolute: bool) -> Result<File, String> {
        let name = if absolute { c"/" } else { c"." };
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(format!(
                "failed to open traversal root: {}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn split_path(path: &Path) -> Result<(bool, Vec<&OsStr>, &OsStr), String> {
        let absolute = path.is_absolute();
        let mut names = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => names.push(name),
                Component::ParentDir => {
                    return Err(format!(
                        "parent traversal is forbidden in evidence path {}",
                        path.display()
                    ));
                }
                Component::Prefix(_) => {
                    return Err(format!("unsupported evidence path {}", path.display()));
                }
            }
        }
        let leaf = names
            .pop()
            .ok_or_else(|| format!("path has no file name: {}", path.display()))?;
        Ok((absolute, names, leaf))
    }

    fn open_parent(path: &Path, create: bool) -> Result<(File, Vec<(u64, u64)>, &OsStr), String> {
        let (absolute, parents, leaf) = split_path(path)?;
        let mut current = root_dir(absolute)?;
        let mut chain = Vec::with_capacity(parents.len() + 1);
        let root = fingerprint(&current)?;
        chain.push((root.device, root.inode));
        for name in parents {
            let next = match open_dir_at(&current, name) {
                Ok(directory) => directory,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    let name_c = c_name(name)?;
                    let result =
                        unsafe { libc::mkdirat(current.as_raw_fd(), name_c.as_ptr(), 0o755) };
                    if result < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(format!(
                            "failed to create directory component {:?}: {}",
                            name,
                            io::Error::last_os_error()
                        ));
                    }
                    open_dir_at(&current, name).map_err(|error| {
                        format!("failed to open directory component {:?}: {error}", name)
                    })?
                }
                Err(error) => {
                    return Err(format!(
                        "failed no-follow traversal of directory component {:?}: {error}",
                        name
                    ));
                }
            };
            let metadata = fingerprint(&next)?;
            chain.push((metadata.device, metadata.inode));
            current = next;
        }
        Ok((current, chain, leaf))
    }

    fn open_leaf(parent: &File, leaf: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
        let leaf = c_name(leaf).map_err(io::Error::other)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn recheck_parent(path: &Path, expected: &[(u64, u64)]) -> Result<File, String> {
        let (parent, actual, _) = open_parent(path, false)?;
        if actual != expected {
            return Err(format!(
                "path directory chain changed during access: {}",
                path.display()
            ));
        }
        Ok(parent)
    }

    pub(crate) fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
        let (parent, chain, leaf) = open_parent(path, false)?;
        let mut file = open_leaf(&parent, leaf, libc::O_RDONLY, 0).map_err(|error| {
            format!(
                "failed to open {} without following links: {error}",
                path.display()
            )
        })?;
        let before = fingerprint(&file)?;
        if !file
            .metadata()
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?
            .is_file()
        {
            return Err(format!("path is not a regular file: {}", path.display()));
        }
        let mut bytes = Vec::with_capacity(before.length as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let after = fingerprint(&file)?;
        if before != after || bytes.len() as u64 != after.length {
            return Err(format!("file changed while reading: {}", path.display()));
        }
        let current_parent = recheck_parent(path, &chain)?;
        let current = open_leaf(&current_parent, leaf, libc::O_RDONLY, 0)
            .map_err(|error| format!("path changed while reading {}: {error}", path.display()))?;
        let current_fingerprint = fingerprint(&current)?;
        if (current_fingerprint.device, current_fingerprint.inode) != (after.device, after.inode) {
            return Err(format!(
                "path was replaced while reading: {}",
                path.display()
            ));
        }
        Ok(bytes)
    }

    fn unlink_at(parent: &File, name: &OsStr) {
        if let Ok(name) = c_name(name) {
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
            }
        }
    }

    pub(crate) fn atomic_write_immutable(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let (parent, chain, leaf) = open_parent(path, true)?;
        let leaf_c = c_name(leaf)?;
        let existing = unsafe {
            libc::faccessat(
                parent.as_raw_fd(),
                leaf_c.as_ptr(),
                libc::F_OK,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if existing == 0 || io::Error::last_os_error().kind() != io::ErrorKind::NotFound {
            return Err(format!(
                "refusing to replace immutable evidence {}",
                path.display()
            ));
        }

        let temporary_name = CString::new(format!(
            ".euf-viper.tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("temporary evidence name contains no NUL");
        let temporary_os = OsStr::from_bytes(temporary_name.as_bytes());
        let mut temporary = open_leaf(
            &parent,
            temporary_os,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
        .map_err(|error| format!("failed to create evidence temporary: {error}"))?;
        let result = (|| {
            temporary
                .write_all(bytes)
                .map_err(|error| format!("failed to write evidence temporary: {error}"))?;
            temporary
                .sync_all()
                .map_err(|error| format!("failed to sync evidence temporary: {error}"))?;
            recheck_parent(path, &chain)?;
            let linked = unsafe {
                libc::linkat(
                    parent.as_raw_fd(),
                    temporary_name.as_ptr(),
                    parent.as_raw_fd(),
                    leaf_c.as_ptr(),
                    0,
                )
            };
            if linked < 0 {
                return Err(format!(
                    "failed to publish immutable evidence {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                ));
            }
            parent
                .sync_all()
                .map_err(|error| format!("failed to sync evidence directory: {error}"))?;
            recheck_parent(path, &chain)?;
            Ok(())
        })();
        unlink_at(&parent, temporary_os);
        result
    }
}

#[cfg(unix)]
pub(crate) use unix::{atomic_write_immutable, read_regular};

#[cfg(not(unix))]
pub(crate) fn read_regular(_path: &Path) -> Result<Vec<u8>, String> {
    Err("production evidence requires Unix no-follow descriptor traversal".to_owned())
}

#[cfg(not(unix))]
pub(crate) fn atomic_write_immutable(_path: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err("production evidence requires Unix no-follow descriptor traversal".to_owned())
}
