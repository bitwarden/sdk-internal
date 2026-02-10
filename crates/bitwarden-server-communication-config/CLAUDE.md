# bitwarden-server-communication-config - Claude Code Configuration

Storage abstraction for server communication configuration, specifically SSO load balancer cookies
for self-hosted environments requiring session affinity.

## Overview

### What This Crate Does

- Provides data structures and repository pattern for storing per-hostname server communication
  settings
- Manages SSO cookie configuration for load balancers that require session affinity
- Coordinates platform-specific cookie acquisition through dependency injection
- Exposes WASM bindings for TypeScript integration via State Provider
- Exposes UniFFI bindings for mobile platforms (Swift/Kotlin)

### Key Concepts

- **Repository Pattern**: Storage abstraction allowing TypeScript to implement via State Provider
  while Rust provides business logic
- **Platform Integration Pattern**: Dependency injection for platform-specific operations (cookie
  acquisition UI/WebView) that SDK cannot implement cross-platform
- **Bootstrap Configuration**: Two modes - `Direct` (standard connection) or `SsoCookieVendor`
  (requires SSO cookie for load balancer)
- **Hostname-Keyed Storage**: Configuration stored per vault hostname (e.g., "vault.acme.com"), not
  full URLs
- **Thread-Safe WASM**: `ThreadBoundRunner` pins JavaScript repository calls to main thread for
  browser safety

---

## Architecture & Patterns

### System Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    Platform Clients                           │
│  TypeScript (Web/Desktop)  │  Swift (iOS)  │  Kotlin (Android)│
└───────────────────────────────────────────────────────────────┘
         ↓                            ↓                ↓
   WASM Bindings                          UniFFI Bindings
   (JsClient)                           (UniffiClient wrapper)
         ↓                            ↓                ↓
   ┌───────────────────────────────────────────────────────────┐
   │      ServerCommunicationConfigClient<R, P>                │
   │       ├─ get_config(hostname) → Config                   │
   │       ├─ needs_bootstrap(hostname) → bool                │
   │       ├─ cookies(hostname) → Vec<(K,V)>                  │
   │       └─ acquire_cookie(hostname) → Result<(), E>        │
   └───────────────────────────────────────────────────────────┘
         ↓                                    ↓
   ┌─────────────────────────┐  ┌─────────────────────────────────────┐
   │ Repository (storage)    │  │ PlatformApi (acquisition)           │
   │  ├─ get(hostname)       │  │  └─ acquire_cookies(hostname)       │
   │  └─ save(hostname, cfg) │  │       → Option<Vec<AcquiredCookie>>│
   └─────────────────────────┘  └─────────────────────────────────────┘
         ↓                                    ↓
   Platform Storage               Platform WebView/Browser API
```

### Code Organization

```
src/
├── lib.rs              # Public re-exports
├── config.rs           # Data structures (ServerCommunicationConfig, BootstrapConfig)
├── repository.rs       # Repository trait and error types
├── platform_api.rs     # Platform API trait, AcquiredCookie, and acquisition errors
├── client.rs           # Client business logic
└── wasm/               # WASM-only bindings (feature = "wasm")
    ├── mod.rs          # WASM module re-exports
    ├── client.rs       # JsServerCommunicationConfigClient wrapper
    ├── js_repository.rs    # ThreadBoundRunner-wrapped repository
    └── js_platform_api.rs  # ThreadBoundRunner-wrapped platform API

UniFFI bindings (feature = "uniffi"):
├── uniffi.toml         # UniFFI configuration
└── Integrated into bitwarden-uniffi crate:
    └── src/platform/server_communication_config.rs
        ├── UniffiServerCommunicationConfigClient wrapper
        ├── ServerCommunicationConfigRepositoryTrait (foreign trait)
        ├── UniffiRepositoryBridge adapter
        └── UniffiPlatformApiBridge adapter
```

### Key Principles

1. **Security First**: Cookie values are sensitive authentication tokens - never log, debug print,
   or expose in errors
2. **Graceful Degradation**: Methods return safe defaults (empty cookies, `Direct` mode) on errors
   rather than panicking
3. **Caller Validation**: This crate does NOT validate hostnames - caller responsibility to ensure
   safe inputs

### Core Patterns

#### Repository Pattern

**Purpose**: Abstracts storage to allow TypeScript implementation via State Provider while Rust
provides business logic

**Implementation**:

```rust
pub trait ServerCommunicationConfigRepository: Send + Sync + 'static {
    type GetError: std::fmt::Debug + Send + Sync + 'static;
    type SaveError: std::fmt::Debug + Send + Sync + 'static;

    async fn get(&self, hostname: String)
        -> Result<Option<ServerCommunicationConfig>, Self::GetError>;

    async fn save(&self, hostname: String, config: ServerCommunicationConfig)
        -> Result<(), Self::SaveError>;
}
```

**Usage**:

```rust
// In tests: Use mock repository and platform API
let repo = MockRepository::default();
let platform_api = MockPlatformApi::default();
let client = ServerCommunicationConfigClient::new(repo, platform_api);

// In WASM: TypeScript implements both traits via JS bridges
let js_repo = JsServerCommunicationConfigRepository::new(raw_js_repo);
let js_platform_api = JsServerCommunicationConfigPlatformApi::new(raw_js_platform_api);
let client = ServerCommunicationConfigClient::new(js_repo, js_platform_api);

// In UniFFI: Swift/Kotlin implements traits, SDK provides wrapper
let uniffi_client = UniffiServerCommunicationConfigClient::new(
    Arc::new(platform_repository_impl),  // Implements ServerCommunicationConfigRepositoryTrait
    Arc::new(platform_api_impl),          // Implements ServerCommunicationConfigPlatformApi
);
```

#### Platform Integration Pattern

**Purpose**: Dependency injection for platform-specific operations that SDK cannot implement
cross-platform (WebView cookie flows, browser APIs, native UI)

**Implementation**:

```rust
/// Cookie acquired from platform
///
/// Represents a single cookie name/value pair. For sharded cookies (AWS ALB pattern),
/// each shard is a separate AcquiredCookie with its own name including the -{N} suffix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AcquiredCookie {
    /// Cookie name (includes -N suffix for sharded cookies)
    pub name: String,
    /// Cookie value
    pub value: String,
}

#[cfg_attr(feature = "uniffi", uniffi::export(with_foreign))]
#[async_trait::async_trait]
pub trait ServerCommunicationConfigPlatformApi: Send + Sync {
    /// Acquires cookies for the given hostname.
    ///
    /// Platform returns all cookies as a Vec, where each entry has the full
    /// name (with -N suffix for sharded cookies) and value.
    async fn acquire_cookies(&self, hostname: String) -> Option<Vec<AcquiredCookie>>;
}
```

**Note**: `AcquiredCookie` struct is used instead of tuple `(String, String)` because UniFFI does
not support tuples in FFI signatures. The struct provides a consistent type across all platform
bindings.

**Platform-Specific Implementations**:

- **Web (WASM)**: Opens browser window/iframe, uses `document.cookie` API
- **Desktop/Mobile**: Opens WebView, intercepts cookie from navigation
- **Tests**: Returns mock cookie tuples

**Cookie Acquisition Flow**:

1. SDK calls `client.acquire_cookie(hostname)`
2. SDK retrieves expected cookie name (base name) from stored configuration
3. SDK invokes `platform_api.acquire_cookies(hostname)` to trigger UI flow
4. Platform opens IDP login URL in WebView/browser
5. User authenticates with identity provider
6. Platform extracts all relevant cookies from browser/WebView
   - For unsharded cookies: Returns `[AcquiredCookie { name: "CookieName", value: "..." }]`
   - For sharded cookies: Returns
     `[AcquiredCookie { name: "CookieName-0", value: "..." }, AcquiredCookie { name: "CookieName-1", value: "..." }, ...]`
7. SDK validates all cookie names match the expected pattern:
   - Either exact match with base name (unsharded)
   - Or match pattern `{base_name}-{N}` where N is a digit (sharded)
8. SDK saves all cookies to repository exactly as received
9. When returning cookies via `cookies()`, SDK passes them through unchanged

**Error Handling**:

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum AcquireCookieError {
    #[error("Cookie acquisition was cancelled")]
    Cancelled,

    #[error("Server configuration does not support SSO cookie acquisition (Direct bootstrap)")]
    UnsupportedConfiguration,

    #[error("Cookie name mismatch: expected {expected}, got {actual}")]
    CookieNameMismatch { expected: String, actual: String },

    #[error("Failed to get server configuration: {0}")]
    RepositoryGetError(String),

    #[error("Failed to save server configuration: {0}")]
    RepositorySaveError(String),
}
```

#### Tagged Enum Serialization

**Purpose**: Type-safe configuration variants with language-neutral JSON representation

**Implementation**:

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BootstrapConfig {
    Direct,                              // {"type": "direct"}
    SsoCookieVendor(SsoCookieVendorConfig), // {"type": "sso_cookie_vendor", ...}
}
```

**Usage**:

```rust
// Direct mode - no special handling
let config = ServerCommunicationConfig {
    bootstrap: BootstrapConfig::Direct,
};

// SSO cookie vendor mode
let config = ServerCommunicationConfig {
    bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
        idp_login_url: Some("https://idp.example.com/login".to_string()),
        cookie_name: Some("ALBAuthSessionCookie".to_string()),
        cookie_domain: Some("vault.example.com".to_string()),
        cookie_value: None, // Populated after bootstrap
    }),
};
```

#### ThreadBoundRunner for WASM Safety

**Purpose**: Ensures JavaScript repository calls execute on main thread (required in browsers)

**Implementation**:

```rust
pub struct JsServerCommunicationConfigRepository(
    ThreadBoundRunner<RawJsServerCommunicationConfigRepository>,
);

impl ServerCommunicationConfigRepository for JsServerCommunicationConfigRepository {
    async fn get(&self, hostname: String) -> Result<Option<ServerCommunicationConfig>, String> {
        self.0.run_in_thread(move |repo| async move {
            let js_value = repo.get(hostname).await.map_err(|e| format!("{e:?}"))?;

            if js_value.is_undefined() || js_value.is_null() {
                return Ok(None);
            }

            Ok(Some(serde_wasm_bindgen::from_value(js_value).map_err(|e| e.to_string())?))
        }).await.map_err(|e| e.to_string())?
    }

    // save() follows same pattern
}
```

---

## Data Models

### Core Types

```rust
/// Root configuration per hostname
pub struct ServerCommunicationConfig {
    pub bootstrap: BootstrapConfig,
}

/// Bootstrap configuration variants
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BootstrapConfig {
    /// Standard direct connection (no special handling)
    Direct,

    /// SSO cookie vendor configuration for load balancer authentication
    SsoCookieVendor(SsoCookieVendorConfig),
}

/// SSO cookie configuration from server /api/config endpoint
pub struct SsoCookieVendorConfig {
    /// IDP login URL for browser redirect
    pub idp_login_url: Option<String>,

    /// Cookie name - base name without shard suffix (e.g., "AWSELBAuthSessionCookie")
    pub cookie_name: Option<String>,

    /// Cookie domain for validation
    pub cookie_domain: Option<String>,

    /// Acquired cookies (populated after bootstrap flow)
    ///
    /// For sharded cookies, contains multiple entries with names like
    /// "AWSELBAuthSessionCookie-0", "AWSELBAuthSessionCookie-1", etc.
    /// For unsharded cookies, contains a single entry with the base name.
    pub cookie_value: Option<Vec<AcquiredCookie>>,
}
```

### Error Types

```rust
/// Repository operation errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum ServerCommunicationConfigRepositoryError {
    #[error("Failed to get configuration: {0}")]
    GetError(String),

    #[error("Failed to save configuration: {0}")]
    SaveError(String),
}

/// Cookie acquisition errors
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum AcquireCookieError {
    #[error("Cookie acquisition was cancelled")]
    Cancelled,

    #[error("Server configuration does not support SSO cookie acquisition (Direct bootstrap)")]
    UnsupportedConfiguration,

    #[error("Cookie name mismatch: expected {expected}, got {actual}")]
    CookieNameMismatch { expected: String, actual: String },

    #[error("Failed to get server configuration: {0}")]
    RepositoryGetError(String),

    #[error("Failed to save server configuration: {0}")]
    RepositorySaveError(String),
}
```

**Note on `#[bitwarden_error(flat)]`**: This macro automatically generates:

- WASM bindings (converts to string errors for JavaScript)
- TypeScript interfaces for error handling
- UniFFI error mappings for mobile bindings

---

## Security & Configuration

### Security Rules

**MANDATORY - These rules have no exceptions:**

1. **Never Log Cookie Values**: Cookie values in `SsoCookieVendorConfig.cookie_value` are sensitive
   authentication tokens. They must NEVER appear in logs, error messages, debug output, traces, or
   test failures. Use redacted strings in assertions.

2. **Use Constant-Time Equality**: When comparing sensitive data (cookies, tokens), use
   `bitwarden_crypto::constant_time_eq()` to prevent timing attacks. Never use `==` for sensitive
   comparisons.

3. **Generic Error Messages**: Repository implementations must not expose sensitive data, internal
   paths, or implementation details in error messages. Return generic descriptions only.

4. **No Hostname Validation**: This crate does NOT validate or sanitize hostnames. Callers are
   responsible for ensuring hostnames are safe before passing them to the repository.

### Authentication & Authorization

This crate stores authentication configuration but does not perform authentication itself:

- **Cookie Storage**: Stores SSO cookie configuration received from server
- **Cookie Retrieval**: Provides cookies for HTTP client middleware to attach to requests
- **Cookie Acquisition**: Coordinates platform-specific cookie acquisition through dependency
  injection
- **Bootstrap Detection**: Determines if cookie acquisition flow is needed

**Cookie Validation**: When acquiring cookies, the SDK validates that the cookie name returned by
the platform matches the expected name from the server configuration. This prevents accepting wrong
cookies that could cause authentication failures.

---

## References

### Official Documentation

- [Bitwarden SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/)

### Internal Documentation

- [Root CLAUDE.md](../../CLAUDE.md) - SDK-wide architectural patterns
- [README.md](./README.md) - Crate architecture and usage
- [bitwarden-ipc/CLAUDE.md](../bitwarden-ipc/CLAUDE.md) - Repository pattern origin
- [bitwarden-threading/CLAUDE.md](../bitwarden-threading/CLAUDE.md) - ThreadBoundRunner details
