/// Cookie data model and security validation.
pub mod cookie;
/// Cookie error types.
pub mod cookie_error;

pub use cookie::{Cookie, SameSite};
pub use cookie_error::CookieError;
