//! The 1Password client this module impersonates.
//!
//! Every value the server sees as our client identity is defined here and nowhere else, so
//! refreshing a fingerprint that has gone stale is a single-file change. None of it is load-bearing
//! for the protocol: it only has to look like a plausible 1Password desktop client.
//!
//! Taken from 1Password for Mac/Windows/Linux 8.12.10, released 7 April 2026:
//! - <https://releases.1password.com/mac/stable/#1password-for-mac-8.12.10>
//! - <https://releases.1password.com/windows/stable/#1password-for-windows-8.12.10>
//! - <https://releases.1password.com/linux/stable/#1password-for-linux-8.12.10>
//!
//! Whether per-platform impersonation is needed at all, or whether one fixed identity would do, is
//! an open question. See the development notes in this module's README.

/// The desktop app's build number, sent as the client version and inside the op user agent.
pub const VERSION: &str = "81210036";

/// The HTTP library the desktop app reports. That app is itself written in Rust, so this is *its*
/// reqwest version, not ours. Do not sync it with the workspace's reqwest pin; it is part of the
/// fingerprint, and the two are unrelated.
pub const HTTP_LIB: &str = "reqwest|0.12.24";

/// The per-platform half of the identity. The version and HTTP library above are the same
/// everywhere, so only these four fields vary.
pub struct Platform {
    /// Names the client: `1Password for Mac`.
    pub os: &'static str,
    /// Single-letter platform code, the second field of the op user agent.
    pub op_code: &'static str,
    /// `os|version|arch`, the last field of the op user agent.
    pub os_suffix: &'static str,
    /// The `osName` in the device descriptor.
    pub os_name: &'static str,
}

#[cfg(target_os = "macos")]
pub const PLATFORM: Platform = Platform {
    os: "Mac",
    op_code: "M",
    os_suffix: "MacOSX|26.3.1|aarch64",
    os_name: "macOS",
};

#[cfg(target_os = "linux")]
pub const PLATFORM: Platform = Platform {
    os: "Linux",
    op_code: "L",
    os_suffix: "Linux|Ubuntu 24.04|x86_64",
    os_name: "Linux",
};

// Every other target, wasm32 included, presents as the Windows build.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub const PLATFORM: Platform = Platform {
    os: "Windows",
    op_code: "W",
    os_suffix: "Windows|25H2 11.0.26200|x86_64",
    os_name: "Windows",
};
