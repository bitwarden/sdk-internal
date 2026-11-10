//! PowerShell launcher for the custom-script integration.

use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

use super::{CommandSpec, InvokeError};
use crate::sys::{FileSystem, Platform};

const HOST_CANDIDATES: &[&str] = &["pwsh", "pwsh.exe", "powershell.exe"];
const ENV_ALLOWLIST: &[&str] = &[
    // Windows
    "SystemRoot",
    "windir",
    "PATHEXT",
    "COMSPEC",
    "PSModulePath",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMDATA",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    // Cross-platform.
    "PATH",
    "TEMP",
    "TMP",
    "HOME",
    "TMPDIR",
    "LANG",
];

pub(crate) fn build_command(
    configured_host: Option<&Path>,
    script: &Path,
    operation: &str,
    execution_policy: &str,
    platform: &Platform,
) -> Result<CommandSpec, InvokeError> {
    let host = resolve_host(configured_host, platform).ok_or(InvokeError::HostNotFound)?;

    Ok(CommandSpec {
        program: host,
        args: vec![
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-ExecutionPolicy".into(),
            execution_policy.into(),
            "-File".into(),
            strip_verbatim_path_prefix(script).into_os_string(),
            operation.into(),
        ],
        env: allowlisted_env(platform),
    })
}

fn allowlisted_env(platform: &Platform) -> Vec<(OsString, OsString)> {
    ENV_ALLOWLIST
        .iter()
        .filter_map(|name| {
            platform
                .env
                .var(name)
                .map(|value| (OsString::from(name), value))
        })
        .collect()
}

fn resolve_host(configured: Option<&Path>, platform: &Platform) -> Option<PathBuf> {
    resolve_host_in(
        configured,
        platform.env.var("PATH").as_deref(),
        platform.fs.as_ref(),
    )
}

fn resolve_host_in(
    configured: Option<&Path>,
    path_var: Option<&OsStr>,
    fs: &dyn FileSystem,
) -> Option<PathBuf> {
    if let Some(configured) = configured {
        return Some(configured.to_path_buf());
    }

    let path_var = path_var?;
    for candidate in HOST_CANDIDATES {
        for dir in std::env::split_paths(path_var) {
            let full = dir.join(candidate);
            if fs.is_file(&full) {
                return Some(full);
            }
        }
    }
    None
}

fn strip_verbatim_path_prefix(path: &Path) -> PathBuf {
    let Some(rest) = path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) else {
        return path.to_path_buf();
    };

    // Starts with a drive letter, a colon, then a separator?
    let is_verbatim_disk = {
        let mut chars = rest.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
            && matches!(chars.next(), Some(':'))
            && matches!(chars.next(), Some('\\'))
    };

    if is_verbatim_disk {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
    };

    use super::*;
    use crate::sys::{FakeEnv, FakeFs, Platform};

    #[test]
    fn resolve_host_returns_none_when_path_is_empty_or_absent() {
        let fs = FakeFs::empty();
        assert_eq!(resolve_host_in(None, None, &fs), None);
        assert_eq!(resolve_host_in(None, Some(OsStr::new("")), &fs), None);
    }

    #[test]
    fn resolve_host_reads_path_from_the_injected_environment() {
        assert_eq!(resolve_host(None, &Platform::blank()), None);
    }

    #[test]
    fn resolve_host_prefers_pwsh_over_powershell_across_the_whole_path() {
        let fs = FakeFs::empty()
            .with_file("/first/powershell.exe")
            .with_file("/second/pwsh");
        let joined = std::env::join_paths(["/first", "/second"]).unwrap();

        assert_eq!(
            resolve_host_in(None, Some(&joined), &fs),
            Some(PathBuf::from("/second/pwsh"))
        );
    }

    #[test]
    fn resolve_host_falls_back_to_windows_powershell() {
        let fs = FakeFs::empty().with_file("/hostdir/powershell.exe");
        let joined = std::env::join_paths(["/hostdir"]).unwrap();

        assert_eq!(
            resolve_host_in(None, Some(&joined), &fs),
            Some(PathBuf::from("/hostdir/powershell.exe"))
        );
    }

    fn args_of(spec: &CommandSpec) -> Vec<String> {
        spec.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn build_command_uses_file_and_passes_the_operation() {
        let host = PathBuf::from("/usr/local/bin/pwsh");
        let spec = build_command(
            Some(&host),
            Path::new("/opt/bwrd/rotate.ps1"),
            "rotate",
            "Bypass",
            &Platform::blank(),
        )
        .unwrap();

        assert_eq!(spec.program, host);
        assert_eq!(
            args_of(&spec),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "/opt/bwrd/rotate.ps1",
                "rotate",
            ]
        );
    }

    #[test]
    fn build_command_honours_a_custom_execution_policy() {
        let host = PathBuf::from("/usr/local/bin/pwsh");
        let spec = build_command(
            Some(&host),
            Path::new("/opt/bwrd/rotate.ps1"),
            "verify",
            "AllSigned",
            &Platform::blank(),
        )
        .unwrap();
        assert!(args_of(&spec).contains(&"AllSigned".to_string()));
    }

    #[test]
    fn build_command_uses_a_configured_host_verbatim() {
        let configured = PathBuf::from("/nonexistent/pwsh");
        let spec = build_command(
            Some(&configured),
            Path::new("/opt/bwrd/rotate.ps1"),
            "rotate",
            "Bypass",
            &Platform::blank(),
        )
        .unwrap();
        assert_eq!(spec.program, configured);
    }

    #[test]
    fn build_command_without_a_host_reports_host_not_found() {
        let err = build_command(
            None,
            Path::new("/opt/bwrd/rotate.ps1"),
            "rotate",
            "Bypass",
            &Platform::blank(),
        )
        .unwrap_err();
        assert_eq!(err, InvokeError::HostNotFound);
    }

    #[test]
    fn allowlisted_env_forwards_only_listed_names() {
        let env = FakeEnv::from([
            ("PATH", "/usr/bin"),
            ("SystemRoot", r"C:\Windows"),
            ("BWRD_TOKEN", "SENTINEL_TOKEN"),
            (
                "A1B2C3D4_0000_0000_0000_000000000001_CLIENT_SECRET",
                "SENTINEL_SECRET",
            ),
            ("SOME_OTHER_VAR", "nope"),
        ]);

        let forwarded = allowlisted_env(&Platform::fake(env, FakeFs::empty()));
        let mut names: Vec<String> = forwarded
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["PATH", "SystemRoot"]);

        let flattened = format!("{forwarded:?}");
        assert!(!flattened.contains("SENTINEL_TOKEN"), "{flattened}");
        assert!(!flattened.contains("SENTINEL_SECRET"), "{flattened}");
    }

    #[test]
    fn allowlisted_env_skips_names_that_are_unset() {
        let forwarded = allowlisted_env(&Platform::fake(
            FakeEnv::from([("PATH", "/usr/bin")]),
            FakeFs::empty(),
        ));
        assert_eq!(forwarded.len(), 1, "{forwarded:?}");
    }

    #[test]
    fn strip_verbatim_prefix_unwraps_a_verbatim_disk_path() {
        assert_eq!(
            strip_verbatim_path_prefix(Path::new(r"\\?\C:\bwrd\rotate.ps1")),
            PathBuf::from(r"C:\bwrd\rotate.ps1")
        );
    }

    #[test]
    fn strip_verbatim_prefix_leaves_unc_and_plain_paths_alone() {
        for untouched in [
            r"\\?\UNC\server\share\rotate.ps1",
            r"C:\bwrd\rotate.ps1",
            "/opt/bwrd/rotate.ps1",
        ] {
            assert_eq!(
                strip_verbatim_path_prefix(Path::new(untouched)),
                PathBuf::from(untouched),
                "{untouched} must be left as-is"
            );
        }
    }

    #[test]
    fn env_allowlist_contains_no_credential_or_daemon_names() {
        for name in ENV_ALLOWLIST {
            assert!(
                !name.starts_with("BWRD"),
                "daemon variable {name} must never be forwarded"
            );
            for suffix in [
                "SCRIPT",
                "CLIENT_SECRET",
                "CLIENT_ID",
                "TENANT_ID",
                "SECRET",
            ] {
                assert!(
                    !name.contains(suffix),
                    "credential-shaped name {name} must not be in the allowlist"
                );
            }
        }
    }

    #[test]
    fn env_allowlist_includes_the_windows_host_essentials() {
        for required in ["SystemRoot", "PSModulePath", "PATH", "PATHEXT"] {
            assert!(
                ENV_ALLOWLIST.contains(&required),
                "{required} is required for a PowerShell host"
            );
        }
    }
}
