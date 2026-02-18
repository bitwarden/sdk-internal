# Bitwarden Auth

Contains the implementation of the auth functionality for the Bitwarden Password Manager.

## Send Access

- Manages obtaining send access tokens for accessing secured send endpoints.

## Login

**LoginClient**: Authenticates Bitwarden users to obtain access tokens.

### Available Login Methods

- **Password**: Email and master password authentication (2FA not yet supported)
  - See [crate::login::LoginClient::login_via_password]
- **Future**: SSO, device-based, etc.
