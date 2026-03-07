//! Cookie middleware for SSO session affinity.
//!
//! This module provides middleware for automatic cookie acquisition and injection
//! to support self-hosted Bitwarden deployments with SSO load balancers requiring
//! session affinity (PM-27126).

mod acquisition_middleware;
mod injection_middleware;

pub use acquisition_middleware::CookieAcquisitionMiddleware;
pub use injection_middleware::CookieInjectionMiddleware;
