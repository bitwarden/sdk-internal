# Attack Plans for PM-27126: ServerCommunicationConfigMiddleware

## Context Summary

**Ticket**: PM-27126 - Create ServerCommunicationConfigMiddleware and attach cookies to requests  
**Prerequisites**: PM-29492 (Middleware support) ✅ DONE, PM-29145 (ServerCommunicationConfigClient) ✅ DONE  
**Goal**: Intercept redirects to acquire ALB cookies and attach them to subsequent requests

**Key Technical Details**:
- AWS ALB cookies >4KB are sharded with `-N` suffixes (e.g., `AWSELBAuthSessionCookie-0`, `AWSELBAuthSessionCookie-1`)
- ServerCommunicationConfigClient already has `acquire_cookie()` method that validates and stores cookies
- Middleware pattern established in PR #699 (Dani Garcia)
- Need to handle both cookie acquisition (on redirect) and cookie attachment (on subsequent requests)

**Known Implementation Considerations** (from PM-27126):
- CookieStore trait may not work if cookies are read before middleware runs
- Middleware injection may be the safer approach
- Must handle non-cloneable requests (streamed bodies)

---

## Plan A: Pure Middleware Approach (Recommended)

**Philosophy**: Single middleware handles both acquisition and injection using reqwest-middleware pattern from PR #699.

### Research Phase

1. **Deep dive into Dani's PR #699 middleware pattern**
   - Study the `reqwest_middleware::Middleware` trait implementation
   - Understand `Request`, `Extensions`, `Next` pattern
   - Learn retry loop pattern with `req.try_clone()`
   - Note platform-specific async_trait differences (WASM vs non-WASM)

2. **Analyze ServerCommunicationConfigClient integration points**
   - Read `client.rs:acquire_cookie()` - already validates and stores cookies
   - Understand `Repository` trait for persistence
   - Study `PlatformApi` trait for cookie acquisition from platform
   - Review cookie validation logic (exact match or sharded pattern)

3. **Study reqwest response redirect handling**
   - Determine how to detect redirect responses (3xx status codes)
   - Understand redirect location header extraction
   - Research reqwest redirect policies and how middleware intercepts them

4. **Investigate Extensions usage for request metadata**
   - How to mark requests that need cookies attached
   - How to pass hostname context through the request pipeline
   - Study existing extension patterns in codebase

### Starter TODOs

1. Create `ServerCommunicationConfigMiddleware` struct in new file `crates/bitwarden-server-communication-config/src/middleware.rs`
   - Add `client: Arc<ServerCommunicationConfigClient<R, P>>` field
   - Import reqwest_middleware traits

2. Implement `reqwest_middleware::Middleware` trait with platform-specific async_trait
   - Skeleton `handle()` method with request/response pass-through
   - Add proper WASM guards from PR #699 pattern

3. Implement redirect detection and cookie acquisition logic
   - Check if response status is 3xx
   - Extract hostname from request URL
   - Call `self.client.acquire_cookie(hostname).await`
   - Return original response after acquisition

4. Implement cookie injection logic
   - Check if request needs cookies (via Extensions or hostname)
   - Retrieve cookies via `self.client.cookies(hostname)`
   - Inject cookies into request headers as Cookie header
   - Handle cookie serialization format

5. Add integration tests
   - Test redirect triggers cookie acquisition
   - Test subsequent requests include cookies
   - Test cookie sharding (multiple cookies combined into Cookie header)
   - Test requests without hostname don't get cookies

6. Update `Client::new()` in bitwarden-core to register middleware
   - Add ServerCommunicationConfigMiddleware to ClientBuilder
   - Ensure proper ordering with other middleware

### Pros
- Single source of truth for cookie logic
- Follows established PR #699 pattern closely
- No dependency on CookieStore trait timing
- Full control over request/response flow

### Cons
- Must manually serialize cookies into Cookie header
- Middleware chain complexity may grow
- Need to handle non-cloneable requests for retries

---

## Plan B: Hybrid Middleware + CookieStore Approach

**Philosophy**: Use middleware for acquisition, leverage reqwest's native CookieStore for attachment.

### Research Phase

1. **Deep dive into Dani's PR #699 middleware pattern** (same as Plan A)

2. **Study reqwest CookieStore trait**
   - Read reqwest documentation for CookieStore trait
   - Understand when cookies() is called in request lifecycle
   - Determine if middleware runs before CookieStore
   - Research cookie jar patterns in Rust HTTP clients

3. **Analyze ServerCommunicationConfigClient as CookieStore**
   - Design wrapper struct that implements CookieStore
   - Map `cookies(url)` method to `ServerCommunicationConfigClient::cookies(hostname)`
   - Handle hostname extraction from URL

4. **Investigate cookie persistence timing**
   - Test if CookieStore is consulted after middleware runs
   - Verify middleware can populate cookies that CookieStore then reads
   - Understand thread safety requirements for shared state

### Starter TODOs

1. Create `ServerCommunicationConfigMiddleware` for redirect handling only
   - Detect 3xx responses
   - Extract hostname and call `acquire_cookie()`
   - No cookie injection logic (delegated to CookieStore)

2. Create `ServerCommunicationConfigCookieStore` wrapper
   - Wrap `Arc<ServerCommunicationConfigClient<R, P>>`
   - Implement `reqwest::cookie::CookieStore` trait
   - Map URL to hostname extraction
   - Call `self.client.cookies(hostname)` and convert to reqwest cookie format

3. Wire both components into Client builder
   - Register middleware in ClientBuilder
   - Call `.cookie_provider()` with CookieStore implementation
   - Ensure proper Arc sharing between middleware and store

4. Test cookie lifecycle
   - Verify middleware acquisition updates shared state
   - Verify CookieStore reads updated cookies
   - Test that cookies are attached automatically by reqwest

5. Handle edge cases
   - CookieStore called before middleware (Plan B blocker)
   - Multiple hosts in single client
   - Cookie expiration (if CookieStore expects it)

### Pros
- Leverages reqwest's built-in cookie handling
- Cleaner separation of concerns (acquire vs attach)
- Less manual cookie serialization

### Cons
- **High Risk**: CookieStore may be consulted before middleware runs (ticket notes this concern)
- More complex integration with two components
- Requires converting between cookie formats
- Shared state synchronization between middleware and store

---

## Plan C: Middleware with Request Extension Metadata

**Philosophy**: Middleware-only like Plan A, but with richer Extension-based request tagging for fine-grained control.

### Research Phase

1. **Deep dive into Dani's PR #699 middleware pattern** (same as Plan A)

2. **Study Extensions pattern for request metadata**
   - Read reqwest Extensions documentation
   - Review how other middleware uses extensions for flags
   - Design custom extension types for cookie requirements

3. **Research cookie requirement determination**
   - How to know which endpoints need cookies upfront
   - Analyze bitwarden-api-api endpoints for patterns
   - Design extension types: `NeedsCookie(String)` with hostname

4. **Investigate generated API code modification**
   - Study bitwarden-api-api request building
   - Determine where to inject `.extensions().insert()` calls
   - Review if openapi-generator template can add this

### Starter TODOs

1. Define extension types in bitwarden-server-communication-config
   - `struct RequiresCookie(pub String)` - hostname marker
   - Export for use by API crates

2. Create `ServerCommunicationConfigMiddleware` with extension support
   - Check for `RequiresCookie` extension
   - If present, inject cookies for that hostname
   - If absent, check URL hostname as fallback

3. Modify API generation or add wrapper to tag requests
   - Option A: Update openapi template to add extension on all requests
   - Option B: Create request builder wrapper that adds extension
   - Option C: Manual tagging of known cookie-requiring endpoints

4. Implement redirect acquisition logic (same as Plan A)

5. Implement cookie injection with extension priority
   - First check `RequiresCookie` extension
   - Fall back to URL hostname if no extension
   - Retrieve and inject cookies

6. Add comprehensive tests
   - Test extension-based cookie injection
   - Test fallback to URL hostname
   - Test mixed scenarios

### Pros
- Explicit request tagging improves debuggability
- Can handle complex per-endpoint cookie requirements
- Middleware still has full control
- Future-proof for multi-cookie scenarios

### Cons
- Requires modifying API request building (either template or wrapper)
- More complex implementation
- Extension overhead on every request
- May be over-engineered for initial use case

---

## Recommendation

**Start with Plan A** - it's the most direct implementation that follows the proven PR #699 pattern and addresses the ticket's concern about CookieStore timing. The middleware has full control over both acquisition and injection.

**Fallback to Plan C** if we discover that determining which requests need cookies is more complex than expected, or if we want better observability.

**Avoid Plan B** unless testing proves that CookieStore is consulted after middleware, which contradicts the ticket's warning.

## Next Steps

1. **Share these plans with Addison for selection**
2. **Once confirmed, create TODO memory as home base**
3. **Begin implementation in pm-27126-cookie-middleware worktree**
