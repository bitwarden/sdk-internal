# bitwarden-server-communication-config - Claude Code Configuration

Storage abstraction for server communication configuration, specifically SSO load balancer cookies
for self-hosted environments requiring session affinity.

## Overview

### What This Crate Does

- Provides data structures and repository pattern for storing per-hostname server communication
  settings
- Manages SSO cookie configuration for load balancers that require session affinity
- Exposes WASM bindings for TypeScript integration via State Provider

### Key Concepts

- **Repository Pattern**: Storage abstraction allowing TypeScript to implement via State Provider
  while Rust provides business logic
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
TypeScript Client (Desktop/Mobile)
         ↓
   WASM Bindings (JsServerCommunicationConfigClient)
         ↓
   ┌────────────────────────────────────────┐
   │ ServerCommunicationConfigClient<R>     │
   │  ├─ get_config(hostname) → Config      │
   │  ├─ needs_bootstrap(hostname) → bool   │
   │  └─ cookies(hostname) → Vec<(K,V)>     │
   └────────────────────────────────────────┘
         ↓
   ┌────────────────────────────────────────┐
   │ ServerCommunicationConfigRepository    │
   │  ├─ get(hostname) → Option<Config>     │
   │  └─ save(hostname, config)             │
   └────────────────────────────────────────┘
         ↓
   TypeScript State Provider (implements repo)
```

### Code Organization

```
src/
├── lib.rs              # Public re-exports
├── config.rs           # Data structures (ServerCommunicationConfig, BootstrapConfig)
├── repository.rs       # Repository trait and error types
├── client.rs           # Client business logic
└── wasm/               # WASM-only bindings (feature-gated)
    ├── mod.rs          # WASM module re-exports
    ├── client.rs       # JsServerCommunicationConfigClient wrapper
    └── js_repository.rs # ThreadBoundRunner-wrapped repository
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
// In tests: Use mock repository
let repo = Arc::new(MockRepository::default());
let client = ServerCommunicationConfigClient::new(repo);

// In WASM: TypeScript implements repository
let js_repo = JsServerCommunicationConfigRepository::new(raw_js_repo);
let client = ServerCommunicationConfigClient::new(Arc::new(js_repo));
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
        idp_login_url: "https://idp.example.com/login".to_string(),
        cookie_name: "ALBAuthSessionCookie".to_string(),
        cookie_domain: "vault.example.com".to_string(),
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
    pub idp_login_url: String,

    /// Cookie name (e.g., "ALBAuthSessionCookie")
    pub cookie_name: String,

    /// Cookie domain for validation
    pub cookie_domain: String,

    /// Cookie value (populated after bootstrap flow)
    pub cookie_value: Option<String>,
}
```

### Error Types

```rust
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[bitwarden_error(flat)]
pub enum ServerCommunicationConfigRepositoryError {
    #[error("Failed to get configuration: {0}")]
    GetError(String),

    #[error("Failed to save configuration: {0}")]
    SaveError(String),
}
```

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
- **Bootstrap Detection**: Determines if cookie acquisition flow is needed

---

## References

### Official Documentation

- [Bitwarden SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/)

### Internal Documentation

- [Root CLAUDE.md](../../CLAUDE.md) - SDK-wide architectural patterns
- [README.md](./README.md) - Crate architecture and usage
- [bitwarden-ipc/CLAUDE.md](../bitwarden-ipc/CLAUDE.md) - Repository pattern origin
- [bitwarden-threading/CLAUDE.md](../bitwarden-threading/CLAUDE.md) - ThreadBoundRunner details
