//! Hazmat module
//!
//! Inside here live low level crypto implementations that are not safe to use by themselves and
//! can be easily misused. This should never be used from another crate, and handled with extreme
//! care.

pub(crate) mod symmetric_encryption;
