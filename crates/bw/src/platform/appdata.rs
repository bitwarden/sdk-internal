//! CLI appdata directory resolution.
//!
//! Returns the directory that holds the legacy `config.json`, the session DB,
//! and any other CLI state. The lookup order mirrors Node CLI's
//! `service-container.ts` so users keep one appdata location across CLI
//! versions:
//!
//! 1. A `bw-data` directory next to the running executable, if it exists (portable install).
//! 2. `BITWARDENCLI_APPDATA_DIR` env var (if set and non-empty).
//! 3. OS default:
//!    - macOS: `$HOME/Library/Application Support/Bitwarden CLI`
//!    - Windows: `%APPDATA%\Bitwarden CLI`
//!    - Other: `$XDG_CONFIG_HOME/Bitwarden CLI` (falling back to `$HOME/.config/Bitwarden CLI`)

use std::path::PathBuf;

use color_eyre::eyre::{ContextCompat, Result};

pub fn appdata_dir() -> Result<PathBuf> {
    if let Some(portable) = portable_data_dir() {
        return Ok(portable);
    }
    if let Some(v) = std::env::var_os("BITWARDENCLI_APPDATA_DIR")
        && !v.is_empty()
    {
        return Ok(PathBuf::from(v));
    }
    default_appdata_dir()
}

fn portable_data_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.join("bw-data");
    candidate.is_dir().then_some(candidate)
}

fn default_appdata_dir() -> Result<PathBuf> {
    let parent = if cfg!(target_os = "windows") {
        let appdata =
            std::env::var_os("APPDATA").context("APPDATA environment variable is not set")?;
        PathBuf::from(appdata)
    } else if cfg!(target_os = "macos") {
        let home = std::env::var_os("HOME").context("HOME environment variable is not set")?;
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
    } else {
        match std::env::var_os("XDG_CONFIG_HOME") {
            Some(v) if !v.is_empty() => PathBuf::from(v),
            _ => {
                let home =
                    std::env::var_os("HOME").context("HOME environment variable is not set")?;
                PathBuf::from(home).join(".config")
            }
        }
    };
    Ok(parent.join("Bitwarden CLI"))
}
