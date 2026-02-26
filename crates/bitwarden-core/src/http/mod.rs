/// Cookie data model and security validation.
pub mod cookie;
/// Cookie error types.
pub mod cookie_error;
/// Cookie storage abstraction.
pub mod cookie_store;

pub use cookie::{Cookie, SameSite};
pub use cookie_error::CookieError;
pub use cookie_store::CookieStore;
