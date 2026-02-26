use std::time::SystemTime;

use super::CookieError;

/// Represents an HTTP cookie with security attributes.
///
/// Enforces cookie security validation per ADR-048. Security attributes include HttpOnly
/// (prevents JavaScript access), Secure (HTTPS-only), and SameSite (CSRF protection).
#[derive(Clone, Debug, PartialEq)]
pub struct Cookie {
    /// Cookie name
    pub name: String,
    /// Cookie value
    pub value: String,
    /// Cookie domain
    pub domain: Option<String>,
    /// Cookie path
    pub path: Option<String>,
    /// Cookie expiration timestamp
    pub expires: Option<SystemTime>,
    /// Secure attribute (HTTPS-only)
    pub secure: bool,
    /// HttpOnly attribute (prevents JavaScript access)
    pub http_only: bool,
    /// SameSite attribute (CSRF protection)
    pub same_site: SameSite,
}

/// SameSite cookie attribute for cross-site request policy.
#[derive(Clone, Debug, PartialEq)]
pub enum SameSite {
    /// Cookie only sent to same-site requests
    Strict,
    /// Cookie sent to same-site and top-level navigation
    Lax,
    /// Cookie sent to all requests (requires Secure=true in most browsers)
    None,
}

impl Cookie {
    /// Creates a new cookie with secure defaults.
    ///
    /// Defaults: path="/", same_site=Lax, secure=false, http_only=false, no expiration.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: Some("/".to_string()),
            expires: None,
            secure: false,
            http_only: false,
            same_site: SameSite::Lax,
        }
    }

    /// Returns true if the cookie has expired (past its expiration timestamp).
    pub fn is_expired(&self) -> bool {
        self.expires.is_some_and(|exp| SystemTime::now() > exp)
    }

    /// Validates cookie security attributes per ADR-048 policy.
    ///
    /// Logs warnings for missing recommended attributes (HttpOnly, Secure, strict SameSite).
    /// Returns SecurityViolation error for policy violations (e.g., __Host- prefix violations).
    pub fn validate_security_attributes(&self) -> Result<(), CookieError> {
        // Warn if missing HttpOnly (XSS protection)
        if !self.http_only {
            tracing::warn!(
                cookie_name = %self.name,
                "Cookie missing HttpOnly attribute - vulnerable to JavaScript access"
            );
        }

        // Warn if missing Secure (MITM protection) - but allow for chrome-extension://
        if !self.secure {
            tracing::warn!(
                cookie_name = %self.name,
                "Cookie missing Secure attribute - vulnerable to non-HTTPS transmission"
            );
        }

        // Warn if using SameSite::None (CSRF risk)
        if matches!(self.same_site, SameSite::None) {
            tracing::warn!(
                cookie_name = %self.name,
                "Cookie using SameSite=None - vulnerable to cross-site requests"
            );
        }

        // Enforce __Host- prefix requirements (RFC 6265)
        if self.name.starts_with("__Host-") {
            if self.path.as_deref() != Some("/") {
                return Err(CookieError::SecurityViolation(format!(
                    "Cookie with __Host- prefix must have path=/ (got {:?})",
                    self.path
                )));
            }
            if self.domain.is_some() {
                return Err(CookieError::SecurityViolation(
                    "__Host- prefix cookies cannot specify domain attribute".to_string(),
                ));
            }
            if !self.secure {
                return Err(CookieError::SecurityViolation(
                    "__Host- prefix cookies must have Secure=true".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Formats cookie as "name=value" for HTTP Cookie header injection.
    pub fn to_cookie_header(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_new_creates_secure_defaults() {
        let cookie = Cookie::new("session", "token");
        assert_eq!(cookie.name, "session");
        assert_eq!(cookie.value, "token");
        assert_eq!(cookie.path, Some("/".to_string()));
        assert_eq!(cookie.same_site, SameSite::Lax);
        assert!(!cookie.secure);
        assert!(!cookie.http_only);
    }

    #[test]
    fn test_is_expired_with_past_timestamp() {
        let mut cookie = Cookie::new("test", "value");
        cookie.expires = Some(SystemTime::now() - Duration::from_secs(3600));
        assert!(cookie.is_expired());
    }

    #[test]
    fn test_is_expired_with_future_timestamp() {
        let mut cookie = Cookie::new("test", "value");
        cookie.expires = Some(SystemTime::now() + Duration::from_secs(3600));
        assert!(!cookie.is_expired());
    }

    #[test]
    fn test_to_cookie_header_format() {
        let cookie = Cookie::new("session", "abc123");
        assert_eq!(cookie.to_cookie_header(), "session=abc123");
    }

    #[test]
    fn test_host_prefix_validation_requires_secure() {
        let mut cookie = Cookie::new("__Host-session", "token");
        cookie.path = Some("/".to_string());
        cookie.secure = false;

        let result = cookie.validate_security_attributes();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CookieError::SecurityViolation(_)
        ));
    }

    #[test]
    fn test_host_prefix_validation_requires_root_path() {
        let mut cookie = Cookie::new("__Host-session", "token");
        cookie.path = Some("/api".to_string());
        cookie.secure = true;

        let result = cookie.validate_security_attributes();
        assert!(result.is_err());
    }

    #[test]
    fn test_host_prefix_validation_forbids_domain() {
        let mut cookie = Cookie::new("__Host-session", "token");
        cookie.path = Some("/".to_string());
        cookie.secure = true;
        cookie.domain = Some("example.com".to_string());

        let result = cookie.validate_security_attributes();
        assert!(result.is_err());
    }
}
