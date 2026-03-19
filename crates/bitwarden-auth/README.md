---
category: features
---

# Bitwarden Auth

Authentication functionality including identity token management, user registration with account
cryptography initialization (SSO, master password, TDE, key-connector flows), and send access token
requests for password/email-protected sends.

## Send Access

- Manages obtaining send access tokens for accessing secured send endpoints.

## Login

**LoginClient**: Authenticates Bitwarden users to obtain access tokens.

### Available Login Methods

- **Password**: Email and master password authentication (2FA not yet supported)
  - See [crate::login::LoginClient::login_via_password]
- **Future**: SSO, device-based, etc.
