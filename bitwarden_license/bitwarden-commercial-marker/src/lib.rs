//! Compile-time marker for Bitwarden commercial (licensed) crates.
//!
//! Every crate in `bitwarden_license/` (except this one) must invoke [`commercial_crate!`] once in
//! its `lib.rs`.
#![no_std]

/// Marks the calling crate as commercial (Bitwarden-licensed).
///
/// Expands to a `compile_error!` when built with `--cfg bitwarden_ensure_non_commercial`, so
/// commercial code cannot leak into a non-commercial build. Invoke once per commercial crate:
///
/// ```ignore
/// bitwarden_commercial_marker::commercial_crate!();
/// ```
#[macro_export]
macro_rules! commercial_crate {
    () => {
        #[cfg(bitwarden_ensure_non_commercial)]
        ::core::compile_error!(
            "A commercial (Bitwarden-licensed) crate was compiled with `--cfg bitwarden_ensure_non_commercial` \
             set. Look for a non-weak `bitwarden-commercial-*/<feature>` reference that should be \
             `bitwarden-commercial-*?/<feature>`, or a commercial dependency activated outside \
             `bitwarden-license`."
        );
    };
}

commercial_crate!();
