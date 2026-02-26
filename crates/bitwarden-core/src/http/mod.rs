/// Cookie data model and security validation.
pub mod cookie;
/// Cookie error types.
pub mod cookie_error;
/// Cookie injection middleware.
pub mod cookie_middleware;
/// Cookie storage abstraction.
pub mod cookie_store;
/// In-memory cookie storage implementation.
pub mod in_memory_cookie_store;

pub use cookie::{Cookie, SameSite};
pub use cookie_error::CookieError;
pub use cookie_middleware::CookieInjectionMiddleware;
pub use cookie_store::CookieStore;
pub use in_memory_cookie_store::InMemoryCookieStore;
