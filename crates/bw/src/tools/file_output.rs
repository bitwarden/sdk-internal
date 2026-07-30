//! Shared helpers for writing command output to files.
//!
//! Ports the legacy CLI's `CliUtils.saveFile` / `CliUtils.saveResultToFile`
//! (`apps/cli/src/utils.ts`) path-resolution rules, which are part of the user-facing
//! contract for every flag that takes an output location (`bw receive --obj`,
//! `bw export --output`, `bw get attachment --output`). Kept separate from the commands
//! themselves so those rules are defined — and tested — exactly once.

use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use color_eyre::eyre::{Context as _, Result, eyre};

/// Reject paths containing a `..` segment before they reach the filesystem: a script that
/// forwards an unsanitized path through to this CLI should not be able to resolve outside the
/// directory it intended, even though `bw` itself only ever reads and writes with the invoking
/// user's own permissions.
///
/// `flag` names the user-facing argument the path came from so the error points at the input the
/// caller actually typed.
pub(crate) fn reject_path_traversal(flag: &str, path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let has_parent_dir_segment = path.components().any(|c| c == Component::ParentDir);
    if has_parent_dir_segment {
        return Err(eyre!(
            "Invalid {flag} path: {} (path traversal segments are not allowed).",
            path.display()
        ));
    }
    Ok(())
}

/// Resolve where to write a command's file output, porting `CliUtils.saveFile`'s rules exactly:
///
/// | `output`                              | result                                        |
/// | ------------------------------------- | --------------------------------------------- |
/// | absent / empty                        | `<cwd>/<default_file_name>`, no directories created |
/// | no path separator (`report.json`)     | `<cwd>/report.json`, no directories created   |
/// | trailing separator (`out/`)           | `out/<default_file_name>`, `mkdir -p out`     |
/// | separator, no trailing (`out/x.json`) | `out/x.json`, `mkdir -p out`                  |
///
/// The "no separator" case deliberately does *not* create directories — there are none to
/// create — which is why it is distinct from the third row rather than folded into it.
///
/// Relative results are made absolute against the current directory (legacy's
/// `path.resolve`). The resolved path is checked for `..` segments; the resolution happens
/// first so a `..` hidden behind a relative prefix is still caught.
pub(crate) fn resolve_output_path(
    output: Option<&str>,
    default_file_name: &str,
) -> Result<PathBuf> {
    let cwd = std::env::current_dir().wrap_err("Could not determine the current directory")?;

    let (path, create_parents) = match output.filter(|o| !o.is_empty()) {
        None => (cwd.join(default_file_name), false),
        Some(output) => {
            if contains_separator(output) {
                let path = if ends_with_separator(output) {
                    // Trailing separator means "this is a directory"; append the default name.
                    Path::new(output).join(default_file_name)
                } else {
                    PathBuf::from(output)
                };
                (path, true)
            } else {
                // A bare file name is always relative to the working directory, never to
                // wherever the default name would have gone.
                (cwd.join(output), false)
            }
        }
    };

    let path = if path.is_relative() {
        cwd.join(path)
    } else {
        path
    };

    reject_path_traversal("output", &path)?;

    if create_parents
        && let Some(parent) = path.parent()
        && !parent.exists()
    {
        create_dir_all_private(parent)
            .wrap_err_with(|| format!("Could not create directory {}", parent.display()))?;
    }

    Ok(path)
}

/// Write `data` to the location [`resolve_output_path`] picks for `(output, default_file_name)`
/// and return the path written, so the caller can report it back to the user.
pub(crate) fn save_file(
    output: Option<&str>,
    default_file_name: &str,
    data: &[u8],
) -> Result<PathBuf> {
    let path = resolve_output_path(output, default_file_name)?;
    write_file_private(&path, data)
        .wrap_err_with(|| format!("Cannot save file to {}", path.display()))?;
    Ok(path)
}

/// Derive the file name to save a received Send's file under.
///
/// The name comes from the *decrypted* Send, i.e. it is chosen by whoever created the Send, so
/// it is reduced to its final component before use: without that, a Send named `../../x` or
/// `/etc/x` would decide where `bw receive` writes. Matches legacy's `path.basename(...)`, with
/// the same timestamped fallback when the Send carries no file name.
pub(crate) fn default_send_file_name(file_name: Option<&str>) -> String {
    file_name
        .map(Path::new)
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("BitwardenSendFile-{}", Utc::now().timestamp_millis()))
}

/// `true` when `output` contains a path separator. Windows accepts both `\` and `/`, and Rust's
/// `Path` treats both as separators there, so both are checked rather than just
/// [`std::path::MAIN_SEPARATOR`].
fn contains_separator(output: &str) -> bool {
    output.contains(std::path::MAIN_SEPARATOR) || (cfg!(windows) && output.contains('/'))
}

fn ends_with_separator(output: &str) -> bool {
    output.ends_with(std::path::MAIN_SEPARATOR) || (cfg!(windows) && output.ends_with('/'))
}

/// Create `dir` and its missing parents, owner-only on unix (legacy creates them `700`).
fn create_dir_all_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `data` to `path`, owner-only on unix (legacy writes `0o600`).
///
/// The mode applies at creation only, so an existing file keeps whatever permissions it already
/// has — this never widens them.
fn write_file_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `resolve_output_path` resolves relative results against the *process* working
    /// directory, which is global state; changing it in a test would race every other test in
    /// the binary. Instead the tests assert on the relationship between the result and the
    /// current directory.
    fn cwd() -> PathBuf {
        std::env::current_dir().expect("cwd is readable")
    }

    // ---- resolve_output_path: the four legacy branches ----

    #[test]
    fn no_output_uses_cwd_and_default_name() {
        let path = resolve_output_path(None, "default.bin").unwrap();
        assert_eq!(path, cwd().join("default.bin"));
    }

    #[test]
    fn empty_output_is_treated_as_absent() {
        // Legacy checks `output != null && output !== ""`; an empty `--obj ""` must not
        // produce a path ending in a bare separator.
        let path = resolve_output_path(Some(""), "default.bin").unwrap();
        assert_eq!(path, cwd().join("default.bin"));
    }

    #[test]
    fn bare_file_name_lands_in_cwd() {
        let path = resolve_output_path(Some("renamed.bin"), "default.bin").unwrap();
        assert_eq!(path, cwd().join("renamed.bin"));
    }

    #[test]
    fn directory_output_appends_the_default_name_and_creates_the_directory() {
        let temp = std::env::temp_dir().join(format!(
            "bw-file-output-dir-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let with_trailing_separator = format!("{}{}", temp.display(), std::path::MAIN_SEPARATOR);

        let path = resolve_output_path(Some(&with_trailing_separator), "default.bin").unwrap();

        assert_eq!(path, temp.join("default.bin"));
        assert!(
            temp.is_dir(),
            "the target directory should have been created"
        );
        std::fs::remove_dir_all(&temp).ok();
    }

    #[test]
    fn explicit_path_is_used_verbatim_and_its_parent_created() {
        let temp = std::env::temp_dir().join(format!(
            "bw-file-output-explicit-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let target = temp.join("nested").join("chosen.bin");

        let path = resolve_output_path(Some(&target.to_string_lossy()), "default.bin").unwrap();

        assert_eq!(path, target);
        assert!(
            target.parent().expect("has a parent").is_dir(),
            "the parent directory should have been created"
        );
        std::fs::remove_dir_all(&temp).ok();
    }

    // ---- traversal rejection ----

    #[test]
    fn resolve_output_path_rejects_parent_dir_segments() {
        let err = resolve_output_path(
            Some(&format!("..{}escaped.bin", std::path::MAIN_SEPARATOR)),
            "default.bin",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("path traversal"),
            "expected a traversal rejection, got: {err}"
        );
    }

    #[test]
    fn reject_path_traversal_accepts_plain_paths() {
        assert!(reject_path_traversal("--file", "secrets.txt").is_ok());
        assert!(reject_path_traversal("--file", "/tmp/secrets.txt").is_ok());
        assert!(reject_path_traversal("--file", "./dir/secrets.txt").is_ok());
    }

    #[test]
    fn reject_path_traversal_rejects_parent_dir_segments() {
        assert!(reject_path_traversal("--file", "../secrets.txt").is_err());
        assert!(reject_path_traversal("--file", "dir/../../secrets.txt").is_err());
        assert!(reject_path_traversal("--file", "/tmp/../etc/passwd").is_err());
    }

    #[test]
    fn reject_path_traversal_names_the_offending_flag() {
        let err = reject_path_traversal("--passwordfile", "../pw.txt").unwrap_err();
        assert!(
            err.to_string().contains("--passwordfile"),
            "error should name the flag it came from, got: {err}"
        );
    }

    // ---- default_send_file_name ----

    #[test]
    fn default_send_file_name_uses_the_final_component() {
        assert_eq!(default_send_file_name(Some("secrets.txt")), "secrets.txt");
        assert_eq!(
            default_send_file_name(Some("some/dir/secrets.txt")),
            "secrets.txt"
        );
    }

    /// The Send's file name is attacker-controlled (it comes from whoever created the Send), so
    /// a traversing or absolute name must be reduced to a bare file name rather than steering
    /// the write.
    #[test]
    fn default_send_file_name_strips_traversal_and_absolute_prefixes() {
        assert_eq!(
            default_send_file_name(Some("../../../etc/passwd")),
            "passwd"
        );
        assert_eq!(default_send_file_name(Some("/etc/passwd")), "passwd");
    }

    #[test]
    fn default_send_file_name_falls_back_when_absent_or_unusable() {
        for input in [None, Some(""), Some(".."), Some("/")] {
            let name = default_send_file_name(input);
            assert!(
                name.starts_with("BitwardenSendFile-"),
                "expected the timestamped fallback for {input:?}, got {name}"
            );
        }
    }

    // ---- save_file ----

    #[test]
    fn save_file_writes_the_data_and_returns_the_path() {
        let temp = std::env::temp_dir().join(format!(
            "bw-file-output-save-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let target = temp.join("saved.bin");

        let path = save_file(Some(&target.to_string_lossy()), "default.bin", b"contents").unwrap();

        assert_eq!(path, target);
        assert_eq!(std::fs::read(&path).unwrap(), b"contents");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "decrypted output must be owner-only");
        }

        std::fs::remove_dir_all(&temp).ok();
    }
}
