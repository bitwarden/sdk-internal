//! A set of helper macros to more consisely express parsing logic.

/// Ensures that an expression matches a given pattern. Otherwise an error is returned.
/// ```
/// use bitwarden_crypto::ensure_matches;
/// use bitwarden_crypto::CryptoError;
/// fn example(value: Option<i32>) -> Result<(), CryptoError> {
///    ensure_matches!(value, Some(v) if v > 0 => CryptoError::InvalidKey);
///    Ok(())
/// }
/// ```
#[macro_export]
macro_rules! ensure_matches {
    // Without guard
    ($expr:expr, $pat:pat => $err:expr) => {
        if !matches!($expr, $pat) {
            return Err($err);
        }
    };
    // With guard
    ($expr:expr, $pat:pat if $guard:expr => $err:expr) => {
        if !matches!($expr, $pat if $guard) {
            return Err($err);
        }
    };
}

/// Ensures that two expressions are equal. Otherwise an error is returned.
/// ```
/// use bitwarden_crypto::ensure_equal;
/// use bitwarden_crypto::CryptoError;
/// fn example(a: i32, b: i32) -> Result<(), CryptoError> {
///    ensure_equal!(a, b => CryptoError::InvalidKey);
///    Ok(())
/// }
#[macro_export]
macro_rules! ensure_equal {
    ($left:expr, $right:expr => $err:expr) => {
        if $left != $right {
            return Err($err);
        }
    };
}

/// Ensures that an expression is true. Otherwise an error is returned.
/// ```
/// use bitwarden_crypto::ensure;
/// use bitwarden_crypto::CryptoError;
/// fn example(value: bool) -> Result<(), CryptoError> {
///   ensure!(value => CryptoError::InvalidKey);
///   Ok(())
/// }
/// ```
#[macro_export]
macro_rules! ensure {
    ($cond:expr => $err:expr) => {
        if !$cond {
            return Err($err);
        }
    };
}
