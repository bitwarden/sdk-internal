use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use super::{Cookie, CookieError, CookieStore};

/// In-memory cookie storage using HashMap with RwLock for thread-safe access.
///
/// Optimized for read-heavy workloads (multiple concurrent get_cookie() calls).
/// Suitable for development, testing, and non-persistent cookie requirements.
pub struct InMemoryCookieStore {
    cookies: Arc<RwLock<HashMap<String, Cookie>>>,
}

impl InMemoryCookieStore {
    /// Creates a new empty in-memory cookie store.
    pub fn new() -> Self {
        Self {
            cookies: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryCookieStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl CookieStore for InMemoryCookieStore {
    async fn get_cookie(&self, name: &str) -> Result<Option<Cookie>, CookieError> {
        let cookies = self.cookies.read().await;
        Ok(cookies.get(name).filter(|c| !c.is_expired()).cloned())
    }

    async fn set_cookie(&self, cookie: Cookie) -> Result<(), CookieError> {
        // Validate security attributes before storing
        cookie.validate_security_attributes()?;

        let mut cookies = self.cookies.write().await;
        cookies.insert(cookie.name.clone(), cookie);
        Ok(())
    }

    async fn remove_cookie(&self, name: &str) -> Result<(), CookieError> {
        let mut cookies = self.cookies.write().await;
        cookies.remove(name);
        Ok(())
    }

    async fn clear(&self) -> Result<(), CookieError> {
        let mut cookies = self.cookies.write().await;
        cookies.clear();
        Ok(())
    }

    async fn list_cookies(&self) -> Result<Vec<String>, CookieError> {
        let cookies = self.cookies.read().await;
        Ok(cookies
            .iter()
            .filter(|(_, c)| !c.is_expired())
            .map(|(name, _)| name.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get_cookie() {
        let store = InMemoryCookieStore::new();
        let cookie = Cookie::new("session", "token123");

        store.set_cookie(cookie.clone()).await.unwrap();
        let retrieved = store.get_cookie("session").await.unwrap();

        assert_eq!(retrieved, Some(cookie));
    }

    #[tokio::test]
    async fn test_remove_cookie() {
        let store = InMemoryCookieStore::new();
        let cookie = Cookie::new("session", "token123");

        store.set_cookie(cookie).await.unwrap();
        store.remove_cookie("session").await.unwrap();

        let retrieved = store.get_cookie("session").await.unwrap();
        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn test_clear_cookies() {
        let store = InMemoryCookieStore::new();
        store
            .set_cookie(Cookie::new("cookie1", "value1"))
            .await
            .unwrap();
        store
            .set_cookie(Cookie::new("cookie2", "value2"))
            .await
            .unwrap();

        store.clear().await.unwrap();

        let list = store.list_cookies().await.unwrap();
        assert_eq!(list.len(), 0);
    }

    #[tokio::test]
    async fn test_expired_cookie_filtered() {
        use std::time::{Duration, SystemTime};

        let store = InMemoryCookieStore::new();
        let mut cookie = Cookie::new("session", "token");
        cookie.expires = Some(SystemTime::now() - Duration::from_secs(3600));

        store.set_cookie(cookie).await.unwrap();
        let retrieved = store.get_cookie("session").await.unwrap();

        assert_eq!(retrieved, None);
    }

    #[tokio::test]
    async fn test_list_cookies_excludes_expired() {
        use std::time::{Duration, SystemTime};

        let store = InMemoryCookieStore::new();

        let mut expired = Cookie::new("expired", "old");
        expired.expires = Some(SystemTime::now() - Duration::from_secs(3600));
        store.set_cookie(expired).await.unwrap();

        store
            .set_cookie(Cookie::new("active", "new"))
            .await
            .unwrap();

        let list = store.list_cookies().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0], "active");
    }
}
