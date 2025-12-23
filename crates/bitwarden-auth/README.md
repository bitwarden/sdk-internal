# Bitwarden Auth

Contains the implementation of the auth functionality for the Bitwarden Password Manager.

## Send Access

- Manages obtaining send access tokens for accessing secured send endpoints.

## Identity / Login

**LoginClient**: Authenticates Bitwarden users to obtain access tokens.

### Available Login Methods

- **Password**: Email and master password authentication (2FA not yet supported)
  - See
    [`login_via_password`](https://docs.rs/bitwarden-auth/latest/bitwarden_auth/identity/login_via_password/index.html)
    module for details and examples
- **Future**: SSO, device-based, etc.

### Quick Example

```rust
// 1. Get user's KDF config
let prelogin = login_client.get_password_prelogin(email).await?;

// 2. Login with credentials
let response = login_client.login_via_password(PasswordLoginRequest {
    email, password, prelogin_response: prelogin, /* ... */
}).await?;

// 3. Use response.access_token for authenticated requests
```

See module documentation for complete examples and security details.
