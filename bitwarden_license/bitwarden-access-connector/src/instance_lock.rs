//! Keeps a second `bwac` from running with the same access connector token on one host.
//!
//! The lock lives where every account on the host can reach it, so it also catches a `bwac` started
//! from a console under another account. The cost is that any local account can take the lock for a
//! token first, since the API key ID is not secret, and keep the connector exiting with code 5. The
//! lock only saves wasted work: the server hands each job to one connector, so two processes on one
//! token can't both rotate it.

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

/// A lock file, locked with `File::try_lock`. It is never removed, since a process could be opening
/// it at that moment.
#[cfg(any(windows, target_os = "macos"))]
mod platform {
    use std::{
        fs::{File, OpenOptions, TryLockError},
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
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // `/var/tmp` is world-writable, so a planted symlink would otherwise make the connector
            // create a file wherever it points.
            const O_NOFOLLOW: i32 = 0x100;
            options.custom_flags(O_NOFOLLOW);
        }

        // Another account's file can't be opened for writing, but read access is enough to lock it.
        let opened = match options.clone().write(true).create(true).open(&path) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => options.read(true).open(&path),
            result => result,
        };
        let file = opened.map_err(InstanceLockError::Unavailable)?;
        match file.try_lock() {
            Ok(()) => Ok(Guard { _file: file }),
            Err(TryLockError::WouldBlock) => Err(InstanceLockError::AlreadyRunning),
            Err(TryLockError::Error(e)) => Err(InstanceLockError::Unavailable(e)),
        }
    }

    /// Every account can create files in `%ProgramData%` and read other accounts' files there.
    #[cfg(windows)]
    pub(super) fn path(name: &str) -> io::Result<PathBuf> {
        let dir = std::env::var_os("ProgramData")
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData is not set"))?;
        Ok(PathBuf::from(dir).join(format!("{name}.lock")))
    }

    /// Every account shares `/var/tmp`, and periodic cleanup sweeps only `/tmp`.
    #[cfg(target_os = "macos")]
    pub(super) fn path(name: &str) -> io::Result<PathBuf> {
        Ok(PathBuf::from("/var/tmp").join(format!("{name}.lock")))
    }
}

/// An abstract socket. It has no file, so the systemd unit's PrivateTmp and ProtectSystem can't
/// hide it from a console run. Abstract sockets are per network namespace, so a process in another
/// namespace (a container, for example) doesn't see the lock.
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

    #[cfg(target_os = "macos")]
    #[test]
    fn a_symlink_at_the_lock_path_is_not_followed() {
        let id = Uuid::new_v4();
        let target = std::env::temp_dir().join(format!("bwac-symlink-target-{id}"));
        let link = platform::path(&lock_name(id)).expect("lock path");
        std::os::unix::fs::symlink(&target, &link).expect("plant symlink");

        let result = acquire(id);

        let created = target.exists();
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        assert!(matches!(result, Err(InstanceLockError::Unavailable(_))));
        assert!(!created);
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
