# Bitwarden Auth

Contains the implementation of the auth functionality for the Bitwarden Password Manager.

## Send Access

- Manages obtaining send access tokens for accessing secured send endpoints.

## Identity / Login

- **LoginClient**: Authenticates Bitwarden users to obtain access tokens
- **Login Mechanisms**:
  - Password-based authentication (`login_via_password`)
    - **Prelogin**: Retrieves user KDF configuration before authentication
    - Note: Currently 2FA is not supported
  - Future: SSO, device-based, etc.
