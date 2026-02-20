use async_trait::async_trait;
use http::Extensions;
use reqwest::{Request, header};
use reqwest_middleware::{Middleware, Next, Result};

/// Middleware that injects cookies from ServerCommunicationConfigClient into HTTP requests
///
/// This middleware reconstructs sharded AWS ELB cookies (AWSALBAPP-N pattern) and injects
/// them as a Cookie header before forwarding requests down the middleware chain.
pub struct CookieInjectionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository
        + Send
        + Sync
        + 'static,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi
        + Send
        + Sync
        + 'static,
{
    cookie_provider: bitwarden_server_communication_config::ServerCommunicationConfigClient<R, P>,
}

impl<R, P> CookieInjectionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository
        + Send
        + Sync
        + 'static,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi
        + Send
        + Sync
        + 'static,
{
    /// Creates a new cookie injection middleware with the given cookie provider
    pub fn new(
        cookie_provider: bitwarden_server_communication_config::ServerCommunicationConfigClient<
            R,
            P,
        >,
    ) -> Self {
        Self { cookie_provider }
    }
}

#[async_trait]
impl<R, P> Middleware for CookieInjectionMiddleware<R, P>
where
    R: bitwarden_server_communication_config::ServerCommunicationConfigRepository
        + Send
        + Sync
        + 'static,
    P: bitwarden_server_communication_config::ServerCommunicationConfigPlatformApi
        + Send
        + Sync
        + 'static,
{
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<reqwest::Response> {
        // Extract hostname from request URL
        if let Some(host) = req.url().host_str() {
            let hostname = host.to_string();

            // Retrieve cookies from provider
            let cookies = self.cookie_provider.cookies(hostname).await;

            if !cookies.is_empty() {
                // Reconstruct sharded cookies and format as Cookie header
                let cookie_header_value = reconstruct_cookie_header(&cookies);

                // Inject Cookie header
                if let Ok(header_value) = header::HeaderValue::from_str(&cookie_header_value) {
                    req.headers_mut().insert(header::COOKIE, header_value);
                }
            }
        }

        // Forward request down middleware chain
        next.run(req, extensions).await
    }
}

/// Reconstructs sharded AWS ELB cookies and formats as RFC 6265 Cookie header
///
/// Algorithm:
/// 1. Filter cookies matching "AWSALBAPP-{digit}" pattern
/// 2. Sort fragments by N in ascending order (0, 1, 2, 3)
/// 3. Concatenate fragment values into single cookie value
/// 4. Format as semicolon-separated name=value pairs
///
/// # Example
///
/// Input: `[("AWSALBAPP-2", "shard2"), ("AWSALBAPP-0", "shard0"), ("AWSALBAPP-1", "shard1")]`
/// Output: `"AWSALBAPP=shard0shard1shard2"`
fn reconstruct_cookie_header(cookies: &[(String, String)]) -> String {
    // Check if we have sharded cookies (AWSALBAPP-N pattern)
    let sharded_cookies: Vec<_> = cookies
        .iter()
        .filter_map(|(name, value)| {
            if let Some(index_str) = name.strip_prefix("AWSALBAPP-") {
                let index = index_str.parse::<usize>().ok()?;
                Some((index, value.clone()))
            } else {
                None
            }
        })
        .collect();

    if !sharded_cookies.is_empty() {
        // Reconstruct sharded cookie
        let mut sorted_fragments = sharded_cookies;
        sorted_fragments.sort_by_key(|(index, _)| *index);

        let concatenated_value: String = sorted_fragments
            .into_iter()
            .map(|(_, value)| value)
            .collect();

        format!("AWSALBAPP={}", concatenated_value)
    } else {
        // Format non-sharded cookies as semicolon-separated pairs
        cookies
            .iter()
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconstruct_sharded_cookie_sorted() {
        let cookies = vec![
            ("AWSALBAPP-2".to_string(), "shard2".to_string()),
            ("AWSALBAPP-0".to_string(), "shard0".to_string()),
            ("AWSALBAPP-1".to_string(), "shard1".to_string()),
        ];
        let result = reconstruct_cookie_header(&cookies);
        assert_eq!(result, "AWSALBAPP=shard0shard1shard2");
    }

    #[test]
    fn test_reconstruct_single_fragment() {
        let cookies = vec![("AWSALBAPP-0".to_string(), "single".to_string())];
        let result = reconstruct_cookie_header(&cookies);
        assert_eq!(result, "AWSALBAPP=single");
    }

    #[test]
    fn test_reconstruct_empty_returns_empty_string() {
        let cookies = vec![];
        let result = reconstruct_cookie_header(&cookies);
        assert_eq!(result, "");
    }

    #[test]
    fn test_reconstruct_non_sequential_indices() {
        let cookies = vec![
            ("AWSALBAPP-2".to_string(), "shard2".to_string()),
            ("AWSALBAPP-0".to_string(), "shard0".to_string()),
        ];
        let result = reconstruct_cookie_header(&cookies);
        assert_eq!(result, "AWSALBAPP=shard0shard2");
    }

    #[test]
    fn test_reconstruct_filters_non_awsalbapp() {
        let cookies = vec![
            ("AWSALBAPP-0".to_string(), "shard0".to_string()),
            ("SessionID".to_string(), "ignored".to_string()),
            ("AWSALBAPP-1".to_string(), "shard1".to_string()),
        ];
        let result = reconstruct_cookie_header(&cookies);
        // Only AWSALBAPP fragments reconstructed, others ignored
        assert_eq!(result, "AWSALBAPP=shard0shard1");
    }

    #[test]
    fn test_non_sharded_cookie_formatting() {
        let cookies = vec![
            ("SessionID".to_string(), "abc123".to_string()),
            ("Token".to_string(), "xyz789".to_string()),
        ];
        let result = reconstruct_cookie_header(&cookies);
        assert_eq!(result, "SessionID=abc123; Token=xyz789");
    }
}
