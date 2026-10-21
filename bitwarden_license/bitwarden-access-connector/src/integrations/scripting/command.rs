//! Script resolution and the process each script type runs as.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use super::{Operation, PowershellConfig, misconfigured};
use crate::{
    integrations::IntegrationError,
    resolver::ResolvedCredentials,
    sys::{FileSystem, Platform},
};

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

/// How the connector launches an operator-supplied script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ScriptType {
    /// Execute the file itself, relying on a shebang or the executable bit.
    Direct,
    /// Launch the file through a PowerShell host. The default for a `.ps1`.
    Powershell,
}

impl ScriptType {
    /// Parses an operator-supplied `SCRIPT_TYPE` value, or `None` if it names no known type.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "direct" => Some(Self::Direct),
            "powershell" => Some(Self::Powershell),
            _ => None,
        }
    }

    /// The config spelling of this variant.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Powershell => "powershell",
        }
    }

    /// The launcher for `script`: `explicit` when set, otherwise PowerShell for a `.ps1`.
    pub(crate) fn detect(script: &Path, explicit: Option<ScriptType>) -> Self {
        if let Some(explicit) = explicit {
            return explicit;
        }
        match script.extension() {
            Some(ext) if ext.eq_ignore_ascii_case("ps1") => Self::Powershell,
            _ => Self::Direct,
        }
    }
}

/// A process to run, as a plain value: no OS handles and no ambient state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandSpec {
    pub(crate) program: PathBuf,
    /// Arguments, excluding the program name.
    pub(crate) args: Vec<OsString>,
    /// The child's complete environment; nothing is inherited.
    pub(crate) env: Vec<(OsString, OsString)>,
}

/// Resolves the `SCRIPT` credential to a canonical path, confined to `script_root` when set.
pub(crate) fn resolve_script_path(
    creds: &ResolvedCredentials,
    script_root: Option<&Path>,
    fs: &dyn FileSystem,
) -> Result<PathBuf, IntegrationError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    let script_val = creds
        .get("SCRIPT")
        .ok_or_else(|| misconfigured("MissingScript"))?;

    let script_str = script_val.expose();
    let raw_path = PathBuf::from(script_str.as_ref() as &str);

    let canonical = fs
        .canonicalize(&raw_path)
        .map_err(|_| misconfigured("ScriptNotFound"))?;

    if let Some(root) = script_root {
        let canonical_root = fs
            .canonicalize(root)
            .map_err(|_| misconfigured("ScriptRootInvalid"))?;

        if !canonical.starts_with(&canonical_root) {
            return Err(misconfigured("ScriptOutsideRoot"));
        }
    }

    Ok(canonical)
}

/// The launcher for `script`: the `SCRIPT_TYPE` credential when set, otherwise by extension.
pub(crate) fn resolve_script_type(
    creds: &ResolvedCredentials,
    script: &Path,
) -> Result<ScriptType, IntegrationError> {
    use bitwarden_sensitive_value::ExposeSensitive as _;

    let explicit = match creds.get("SCRIPT_TYPE") {
        Some(value) => {
            let exposed = value.expose();
            Some(
                ScriptType::parse(exposed.as_ref() as &str)
                    .ok_or_else(|| misconfigured("UnknownScriptType"))?,
            )
        }
        None => None,
    };

    Ok(ScriptType::detect(script, explicit))
}

/// The process that runs `script` for `operation`: the script itself, or the PowerShell host
/// running it.
pub(crate) fn build_command(
    script: &Path,
    script_type: ScriptType,
    operation: Operation,
    powershell: &PowershellConfig,
    platform: &Platform,
) -> Result<CommandSpec, IntegrationError> {
    match script_type {
        ScriptType::Direct => Ok(CommandSpec {
            program: script.to_path_buf(),
            args: vec![operation.as_str().into()],
            env: Vec::new(),
        }),
        ScriptType::Powershell => {
            let host = resolve_host(powershell.host.as_deref(), platform)
                .ok_or_else(|| misconfigured("PowerShellHostNotFound"))?;

            Ok(CommandSpec {
                program: host,
                args: vec![
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-ExecutionPolicy".into(),
                    powershell.execution_policy.as_str().into(),
                    "-File".into(),
                    strip_verbatim_path_prefix(script).into_os_string(),
                    operation.as_str().into(),
                ],
                env: allowlisted_env(platform),
            })
        }
    }
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

/// The configured PowerShell host, else the first candidate found on `PATH`.
fn resolve_host(configured: Option<&Path>, platform: &Platform) -> Option<PathBuf> {
    if let Some(configured) = configured {
        return Some(configured.to_path_buf());
    }

    let path_var = platform.env.var("PATH")?;
    for candidate in HOST_CANDIDATES {
        for dir in std::env::split_paths(&path_var) {
            let full = dir.join(candidate);
            if platform.fs.is_file(&full) {
                return Some(full);
            }
        }
    }
    None
}

/// Rewrites a `\\?\C:\...` verbatim disk path to `C:\...`; other paths are returned unchanged.
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
    use bitwarden_pam::RotationFailureCode;

    use super::*;
    use crate::{
        error::Retry,
        integrations::TargetEffect,
        sys::{FakeEnv, FakeFs},
    };

    const SH_SCRIPT: &str = "/opt/bwac/rotate.sh";
    const PS_SCRIPT: &str = "/opt/bwac/rotate.ps1";
    const HOST: &str = "/usr/local/bin/pwsh";

    fn creds_with_script(path: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT".to_string(), path.to_string());
        creds
    }

    fn detail_of(err: IntegrationError) -> String {
        err.detail.as_str().to_string()
    }

    #[test]
    fn resolve_script_path_requires_the_script_credential() {
        let err =
            resolve_script_path(&ResolvedCredentials::new(), None, &FakeFs::empty()).unwrap_err();
        assert_eq!(detail_of(err), "error kind: MissingScript");
    }

    #[test]
    fn resolve_script_path_rejects_a_path_that_does_not_exist() {
        let err = resolve_script_path(
            &creds_with_script("/opt/missing.sh"),
            None,
            &FakeFs::empty(),
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptNotFound");
    }

    #[test]
    fn resolve_script_path_accepts_a_script_under_the_root() {
        let fs = FakeFs::empty()
            .with_dir("/opt/bwac")
            .with_file("/opt/bwac/rotate.sh");
        let resolved = resolve_script_path(
            &creds_with_script("/opt/bwac/rotate.sh"),
            Some(Path::new("/opt/bwac")),
            &fs,
        )
        .unwrap();
        assert_eq!(resolved, PathBuf::from("/opt/bwac/rotate.sh"));
    }

    #[test]
    fn resolve_script_path_rejects_a_script_outside_the_root() {
        let fs = FakeFs::empty()
            .with_dir("/opt/bwac")
            .with_file("/etc/passwd");
        let err = resolve_script_path(
            &creds_with_script("/etc/passwd"),
            Some(Path::new("/opt/bwac")),
            &fs,
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptOutsideRoot");
    }

    /// Containment is checked after resolution, so an in-root link pointing out is rejected. The
    /// filesystem is faked; real symlink canonicalisation is not covered by unit tests.
    #[test]
    fn resolve_script_path_rejects_a_link_escaping_the_root() {
        let fs = FakeFs::empty()
            .with_dir("/opt/bwac")
            .with_link("/opt/bwac/escape.sh", "/bin/sh");
        let err = resolve_script_path(
            &creds_with_script("/opt/bwac/escape.sh"),
            Some(Path::new("/opt/bwac")),
            &fs,
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptOutsideRoot");
    }

    #[test]
    fn resolve_script_path_rejects_an_unresolvable_root() {
        let fs = FakeFs::empty().with_file("/opt/bwac/rotate.sh");
        let err = resolve_script_path(
            &creds_with_script("/opt/bwac/rotate.sh"),
            Some(Path::new("/nonexistent")),
            &fs,
        )
        .unwrap_err();
        assert_eq!(detail_of(err), "error kind: ScriptRootInvalid");
    }

    fn creds_with_script_type(value: &str) -> ResolvedCredentials {
        let mut creds = ResolvedCredentials::new();
        creds.insert("SCRIPT_TYPE".to_string(), value.to_string());
        creds
    }

    #[test]
    fn parse_accepts_known_types_case_insensitively() {
        assert_eq!(ScriptType::parse("direct"), Some(ScriptType::Direct));
        assert_eq!(
            ScriptType::parse("powershell"),
            Some(ScriptType::Powershell)
        );
        assert_eq!(
            ScriptType::parse("PowerShell"),
            Some(ScriptType::Powershell)
        );
        assert_eq!(
            ScriptType::parse("  POWERSHELL  "),
            Some(ScriptType::Powershell)
        );
    }

    #[test]
    fn parse_rejects_unknown_type() {
        assert_eq!(ScriptType::parse("bash"), None);
        assert_eq!(ScriptType::parse("pwsh"), None);
        assert_eq!(ScriptType::parse(""), None);
    }

    #[test]
    fn as_str_round_trips_through_parse() {
        for t in [ScriptType::Direct, ScriptType::Powershell] {
            assert_eq!(ScriptType::parse(t.as_str()), Some(t));
        }
    }

    #[test]
    fn detect_selects_powershell_for_ps1() {
        let t = ScriptType::detect(Path::new("/opt/bwac/rotate.ps1"), None);
        assert_eq!(t, ScriptType::Powershell);
    }

    #[test]
    fn detect_is_case_insensitive_on_the_extension() {
        // Windows paths routinely differ in case.
        for name in ["rotate.PS1", "rotate.Ps1", "rotate.pS1"] {
            assert_eq!(
                ScriptType::detect(Path::new(name), None),
                ScriptType::Powershell,
                "{name} should select PowerShell"
            );
        }
    }

    #[test]
    fn detect_selects_direct_for_everything_else() {
        for name in ["rotate.sh", "rotate.exe", "rotate", "rotate.ps1.bak"] {
            assert_eq!(
                ScriptType::detect(Path::new(name), None),
                ScriptType::Direct,
                "{name} should execute directly"
            );
        }
    }

    #[test]
    fn explicit_type_overrides_the_extension_both_ways() {
        assert_eq!(
            ScriptType::detect(Path::new("rotate.ps1"), Some(ScriptType::Direct)),
            ScriptType::Direct
        );
        assert_eq!(
            ScriptType::detect(Path::new("rotate"), Some(ScriptType::Powershell)),
            ScriptType::Powershell
        );
    }

    #[test]
    fn resolve_script_type_falls_back_to_the_extension() {
        let creds = ResolvedCredentials::new();
        assert_eq!(
            resolve_script_type(&creds, Path::new("/opt/rotate.ps1")).unwrap(),
            ScriptType::Powershell
        );
        assert_eq!(
            resolve_script_type(&creds, Path::new("/opt/rotate.sh")).unwrap(),
            ScriptType::Direct
        );
    }

    #[test]
    fn resolve_script_type_lets_the_credential_override_the_extension() {
        assert_eq!(
            resolve_script_type(
                &creds_with_script_type("direct"),
                Path::new("/opt/rotate.ps1")
            )
            .unwrap(),
            ScriptType::Direct
        );
        assert_eq!(
            resolve_script_type(
                &creds_with_script_type("powershell"),
                Path::new("/opt/rotate")
            )
            .unwrap(),
            ScriptType::Powershell
        );
    }

    #[test]
    fn resolve_script_type_rejects_an_unknown_value() {
        let err = resolve_script_type(
            &creds_with_script_type("pwsh"),
            Path::new("/opt/rotate.ps1"),
        )
        .unwrap_err();
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: UnknownScriptType");
    }

    fn platform_with_path(dirs: &[&str], fs: FakeFs) -> Platform {
        let joined = std::env::join_paths(dirs).unwrap();
        Platform::fake(FakeEnv::from([("PATH", joined.to_str().unwrap())]), fs)
    }

    #[test]
    fn resolve_host_returns_none_when_path_is_empty_or_absent() {
        assert_eq!(resolve_host(None, &Platform::blank()), None);
        assert_eq!(
            resolve_host(None, &platform_with_path(&[], FakeFs::empty())),
            None
        );
    }

    #[test]
    fn resolve_host_prefers_pwsh_over_powershell_across_the_whole_path() {
        let fs = FakeFs::empty()
            .with_file("/first/powershell.exe")
            .with_file("/second/pwsh");
        let platform = platform_with_path(&["/first", "/second"], fs);

        assert_eq!(
            resolve_host(None, &platform),
            Some(PathBuf::from("/second/pwsh"))
        );
    }

    #[test]
    fn resolve_host_falls_back_to_windows_powershell() {
        let fs = FakeFs::empty().with_file("/hostdir/powershell.exe");
        let platform = platform_with_path(&["/hostdir"], fs);

        assert_eq!(
            resolve_host(None, &platform),
            Some(PathBuf::from("/hostdir/powershell.exe"))
        );
    }

    fn args_of(spec: &CommandSpec) -> Vec<String> {
        spec.args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn pinned_host() -> PowershellConfig {
        PowershellConfig {
            host: Some(PathBuf::from(HOST)),
            execution_policy: "Bypass".to_string(),
        }
    }

    #[test]
    fn direct_launcher_executes_the_script_itself_with_no_environment() {
        let spec = build_command(
            Path::new(SH_SCRIPT),
            ScriptType::Direct,
            Operation::Rotate,
            &pinned_host(),
            &Platform::blank(),
        )
        .unwrap();

        assert_eq!(spec.program, PathBuf::from(SH_SCRIPT));
        assert_eq!(args_of(&spec), vec!["rotate"]);
        assert!(
            spec.env.is_empty(),
            "a directly executed script inherits nothing: {:?}",
            spec.env
        );
    }

    #[test]
    fn powershell_launcher_runs_the_host_with_file() {
        let spec = build_command(
            Path::new(PS_SCRIPT),
            ScriptType::Powershell,
            Operation::Rotate,
            &pinned_host(),
            &Platform::blank(),
        )
        .unwrap();

        assert_eq!(spec.program, PathBuf::from(HOST));
        assert_eq!(
            args_of(&spec),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                PS_SCRIPT,
                "rotate",
            ]
        );
    }

    #[test]
    fn powershell_launcher_honours_a_custom_execution_policy() {
        let config = PowershellConfig {
            execution_policy: "AllSigned".to_string(),
            ..pinned_host()
        };
        let spec = build_command(
            Path::new(PS_SCRIPT),
            ScriptType::Powershell,
            Operation::Verify,
            &config,
            &Platform::blank(),
        )
        .unwrap();
        assert!(args_of(&spec).contains(&"AllSigned".to_string()));
    }

    #[test]
    fn powershell_launcher_forwards_the_allowlist_and_nothing_else() {
        // The credential and token exist in the connector's environment; only allowlisted names
        // reach the child.
        let env = FakeEnv::from([
            ("PATH", "/usr/bin"),
            ("BWAC_TOKEN", "SENTINEL_TOKEN"),
            (
                "A1B2C3D4_0000_0000_0000_000000000001_CLIENT_SECRET",
                "SENTINEL_SECRET",
            ),
        ]);
        let spec = build_command(
            Path::new(PS_SCRIPT),
            ScriptType::Powershell,
            Operation::Rotate,
            &pinned_host(),
            &Platform::fake(env, FakeFs::empty()),
        )
        .unwrap();

        let names: Vec<String> = spec
            .env
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["PATH"], "only PATH is allowlisted here");

        let flattened = format!("{:?}", spec.env);
        assert!(!flattened.contains("SENTINEL_TOKEN"), "{flattened}");
        assert!(!flattened.contains("SENTINEL_SECRET"), "{flattened}");
    }

    #[test]
    fn powershell_launcher_uses_a_configured_host_verbatim() {
        let configured = PathBuf::from("/nonexistent/pwsh");
        let config = PowershellConfig {
            host: Some(configured.clone()),
            execution_policy: "Bypass".to_string(),
        };
        let spec = build_command(
            Path::new(PS_SCRIPT),
            ScriptType::Powershell,
            Operation::Rotate,
            &config,
            &Platform::blank(),
        )
        .unwrap();
        assert_eq!(spec.program, configured);
    }

    #[test]
    fn powershell_launcher_without_any_host_is_fatal() {
        // No configured host and an environment with no PATH to search.
        let config = PowershellConfig {
            host: None,
            execution_policy: "Bypass".to_string(),
        };
        let err = build_command(
            Path::new(PS_SCRIPT),
            ScriptType::Powershell,
            Operation::Rotate,
            &config,
            &Platform::blank(),
        )
        .unwrap_err();
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.effect, TargetEffect::NotApplied);
        assert_eq!(err.code, RotationFailureCode::CredentialsUnresolved);
        assert_eq!(err.detail.as_str(), "error kind: PowerShellHostNotFound");
    }

    #[test]
    fn allowlisted_env_forwards_only_listed_names() {
        let env = FakeEnv::from([
            ("PATH", "/usr/bin"),
            ("SystemRoot", r"C:\Windows"),
            ("BWAC_TOKEN", "SENTINEL_TOKEN"),
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
            strip_verbatim_path_prefix(Path::new(r"\\?\C:\bwac\rotate.ps1")),
            PathBuf::from(r"C:\bwac\rotate.ps1")
        );
    }

    #[test]
    fn strip_verbatim_prefix_leaves_unc_and_plain_paths_alone() {
        for untouched in [
            r"\\?\UNC\server\share\rotate.ps1",
            r"C:\bwac\rotate.ps1",
            "/opt/bwac/rotate.ps1",
        ] {
            assert_eq!(
                strip_verbatim_path_prefix(Path::new(untouched)),
                PathBuf::from(untouched),
                "{untouched} must be left as-is"
            );
        }
    }

    #[test]
    fn env_allowlist_contains_no_credential_or_connector_names() {
        for name in ENV_ALLOWLIST {
            assert!(
                !name.starts_with("BWAC"),
                "connector variable {name} must never be forwarded"
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
