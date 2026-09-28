//! Seams for the ambient system state the daemon reads.

use std::{ffi::OsString, path::Path, sync::Arc};

/// Read-only access to the process environment.
pub(crate) trait EnvSource: Send + Sync {
    /// The value of a single variable, or `None` if it is unset.
    fn var(&self, key: &str) -> Option<OsString>;

    /// Every variable whose name and value are valid Unicode.
    ///
    /// Mirrors `std::env::vars`, which skips non-Unicode entries rather than panicking.
    fn vars(&self) -> Vec<(String, String)>;
}

/// Reads the real process environment.
pub(crate) struct SystemEnv;

impl EnvSource for SystemEnv {
    fn var(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }

    fn vars(&self) -> Vec<(String, String)> {
        std::env::vars().collect()
    }
}

/// An in-memory environment for tests.
#[cfg(test)]
pub(crate) struct FakeEnv {
    vars: std::collections::HashMap<String, String>,
}

#[cfg(test)]
impl FakeEnv {
    /// An environment containing nothing at all.
    pub(crate) fn empty() -> Self {
        Self {
            vars: std::collections::HashMap::new(),
        }
    }

    /// Adds one variable, chainable.
    pub(crate) fn with(mut self, key: &str, value: &str) -> Self {
        self.vars.insert(key.to_string(), value.to_string());
        self
    }
}

#[cfg(test)]
impl<const N: usize> From<[(&str, &str); N]> for FakeEnv {
    fn from(pairs: [(&str, &str); N]) -> Self {
        pairs
            .into_iter()
            .fold(FakeEnv::empty(), |env, (k, v)| env.with(k, v))
    }
}

#[cfg(test)]
impl EnvSource for FakeEnv {
    fn var(&self, key: &str) -> Option<OsString> {
        self.vars.get(key).map(OsString::from)
    }

    fn vars(&self) -> Vec<(String, String)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Read-only probing of the filesystem.
pub(crate) trait FileSystem: Send + Sync {
    /// Whether `path` exists and is a file.
    fn is_file(&self, path: &Path) -> bool;

    /// Resolves `path` to an absolute form with symlinks and `..` removed.
    fn canonicalize(&self, path: &Path) -> std::io::Result<std::path::PathBuf>;
}

/// Probes the real filesystem.
pub(crate) struct SystemFs;

impl FileSystem for SystemFs {
    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn canonicalize(&self, path: &Path) -> std::io::Result<std::path::PathBuf> {
        path.canonicalize()
    }
}

/// An in-memory filesystem for tests.
#[cfg(test)]
pub(crate) struct FakeFs {
    files: std::collections::HashSet<std::path::PathBuf>,
    canonical: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
}

#[cfg(test)]
impl FakeFs {
    /// A filesystem containing nothing at all.
    pub(crate) fn empty() -> Self {
        Self {
            files: std::collections::HashSet::new(),
            canonical: std::collections::HashMap::new(),
        }
    }

    /// Adds one file, which canonicalises to itself.
    pub(crate) fn with_file(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        let path = path.into();
        self.files.insert(path.clone());
        self.canonical.insert(path.clone(), path);
        self
    }

    /// Adds a directory, which canonicalises to itself but is not a file.
    pub(crate) fn with_dir(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        let path = path.into();
        self.canonical.insert(path.clone(), path);
        self
    }

    /// Adds a symlink: `from` canonicalises to `to`.
    pub(crate) fn with_link(
        mut self,
        from: impl Into<std::path::PathBuf>,
        to: impl Into<std::path::PathBuf>,
    ) -> Self {
        let (from, to) = (from.into(), to.into());
        self.files.insert(from.clone());
        self.canonical.insert(from, to);
        self
    }
}

#[cfg(test)]
impl FileSystem for FakeFs {
    fn is_file(&self, path: &Path) -> bool {
        self.files.contains(path)
    }

    fn canonicalize(&self, path: &Path) -> std::io::Result<std::path::PathBuf> {
        self.canonical.get(path).cloned().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no such path in FakeFs")
        })
    }
}

/// The ambient system state the scripting layer depends on, grouped so it travels as one
/// argument. Each half is still its own trait, so a test can fake one and keep the other real.
#[derive(Clone)]
pub(crate) struct Platform {
    pub(crate) env: Arc<dyn EnvSource>,
    pub(crate) fs: Arc<dyn FileSystem>,
}

impl Platform {
    /// The real environment and the real filesystem.
    pub(crate) fn system() -> Self {
        Self {
            env: Arc::new(SystemEnv),
            fs: Arc::new(SystemFs),
        }
    }
}

#[cfg(test)]
impl Platform {
    pub(crate) fn fake(env: FakeEnv, fs: FakeFs) -> Self {
        Self {
            env: Arc::new(env),
            fs: Arc::new(fs),
        }
    }

    /// A platform where nothing exists: no variables, no files.
    pub(crate) fn blank() -> Self {
        Self::fake(FakeEnv::empty(), FakeFs::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_env_returns_only_what_it_was_given() {
        let env = FakeEnv::from([("A", "1"), ("B", "2")]);
        assert_eq!(env.var("A"), Some(OsString::from("1")));
        assert_eq!(env.var("MISSING"), None);

        let mut names: Vec<String> = env.vars().into_iter().map(|(k, _)| k).collect();
        names.sort();
        assert_eq!(names, vec!["A", "B"]);
    }

    #[test]
    fn fake_env_does_not_see_the_real_environment() {
        // The point of the seam: PATH is set in every real process, and must not leak in.
        assert!(SystemEnv.var("PATH").is_some());
        assert_eq!(FakeEnv::empty().var("PATH"), None);
    }
}
