//! Keeps a second `bwac` from running with the same access connector token on one host.

use uuid::Uuid;

/// Held for the life of the process. The operating system releases it when the process exits, even
/// after a crash.
pub struct InstanceLock {
    _guard: platform::Guard,
}

/// Why [`acquire`] did not take the lock.
#[derive(Debug, thiserror::Error)]
pub enum InstanceLockError {
    /// Another process on this host holds the lock for the same token.
    #[error("another bwac process is already running with this access connector token")]
    AlreadyRunning,
    /// The check itself failed, so it is unknown whether another process is running.
    #[error("could not check for another bwac process: {0}")]
    Unavailable(std::io::Error),
}

/// Takes the host-wide lock for the token whose API key ID is `api_key_id`.
pub fn acquire(api_key_id: Uuid) -> Result<InstanceLock, InstanceLockError> {
    platform::acquire(&lock_name(api_key_id)).map(|guard| InstanceLock { _guard: guard })
}

fn lock_name(api_key_id: Uuid) -> String {
    format!("bwac-{api_key_id}")
}

/// A lock file opened for exclusive access. It is never removed, since a process could be opening
/// it at that moment.
#[cfg(any(windows, target_os = "macos"))]
mod platform {
    use std::{
        fs::{File, OpenOptions},
        io,
        path::PathBuf,
    };

    use super::InstanceLockError;

    pub(super) struct Guard {
        _file: File,
    }

    pub(super) fn acquire(name: &str) -> Result<Guard, InstanceLockError> {
        let path = path(name).map_err(InstanceLockError::Unavailable)?;
        let mut options = OpenOptions::new();
        exclusive(&mut options);

        // Another account's file can't be opened for writing, but read access is enough.
        let opened = match options.clone().write(true).create(true).open(&path) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => options.read(true).open(&path),
            result => result,
        };
        match opened {
            Ok(file) => Ok(Guard { _file: file }),
            Err(e) if held_elsewhere(&e) => Err(InstanceLockError::AlreadyRunning),
            Err(e) => Err(InstanceLockError::Unavailable(e)),
        }
    }

    /// Every account can create files in `%ProgramData%` and read other accounts' files there.
    #[cfg(windows)]
    pub(super) fn path(name: &str) -> io::Result<PathBuf> {
        let dir = std::env::var_os("ProgramData")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData is not set"))?;
        Ok(PathBuf::from(dir).join(format!("{name}.lock")))
    }

    #[cfg(windows)]
    fn exclusive(options: &mut OpenOptions) {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }

    #[cfg(windows)]
    fn held_elsewhere(e: &io::Error) -> bool {
        const ERROR_SHARING_VIOLATION: i32 = 32;
        e.raw_os_error() == Some(ERROR_SHARING_VIOLATION)
    }

    /// Every account shares `/var/tmp`, and periodic cleanup sweeps only `/tmp`.
    #[cfg(target_os = "macos")]
    pub(super) fn path(name: &str) -> io::Result<PathBuf> {
        Ok(PathBuf::from("/var/tmp").join(format!("{name}.lock")))
    }

    #[cfg(target_os = "macos")]
    fn exclusive(options: &mut OpenOptions) {
        use std::os::unix::fs::OpenOptionsExt;
        // O_EXLOCK takes an exclusive flock with the open; O_NONBLOCK fails rather than waits.
        const O_NONBLOCK: i32 = 0x4;
        const O_EXLOCK: i32 = 0x20;
        options.custom_flags(O_EXLOCK | O_NONBLOCK);
    }

    #[cfg(target_os = "macos")]
    fn held_elsewhere(e: &io::Error) -> bool {
        e.kind() == io::ErrorKind::WouldBlock
    }
}

/// An abstract socket. It has no file, so the systemd unit's PrivateTmp and ProtectSystem can't
/// hide it from a console run.
#[cfg(target_os = "linux")]
mod platform {
    use std::{
        io,
        os::{
            linux::net::SocketAddrExt,
            unix::net::{SocketAddr, UnixListener},
        },
    };

    use super::InstanceLockError;

    pub(super) struct Guard {
        _listener: UnixListener,
    }

    pub(super) fn acquire(name: &str) -> Result<Guard, InstanceLockError> {
        let addr = SocketAddr::from_abstract_name(name).map_err(InstanceLockError::Unavailable)?;
        match UnixListener::bind_addr(&addr) {
            Ok(listener) => Ok(Guard {
                _listener: listener,
            }),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                Err(InstanceLockError::AlreadyRunning)
            }
            Err(e) => Err(InstanceLockError::Unavailable(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_lock_for_the_same_token_is_refused() {
        let id = Uuid::new_v4();
        let held = acquire(id).expect("first lock");

        assert!(matches!(
            acquire(id),
            Err(InstanceLockError::AlreadyRunning)
        ));
        drop(held);
        remove_lock_file(id);
    }

    #[test]
    fn different_tokens_do_not_conflict() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let first = acquire(a).expect("first lock");
        let second = acquire(b).expect("second lock");

        drop((first, second));
        remove_lock_file(a);
        remove_lock_file(b);
    }

    #[test]
    fn dropping_the_lock_releases_it() {
        let id = Uuid::new_v4();
        drop(acquire(id).expect("first lock"));

        drop(acquire(id).expect("lock after release"));
        remove_lock_file(id);
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn remove_lock_file(id: Uuid) {
        if let Ok(path) = platform::path(&lock_name(id)) {
            let _ = std::fs::remove_file(path);
        }
    }

    #[cfg(target_os = "linux")]
    fn remove_lock_file(_: Uuid) {}
}
