/// The common bucket of login fields to be re-used across all login mechanisms
/// (e.g., password, SSO, etc.). This will include handling client_id and 2FA.
pub struct LoginRequest {
    /// OAuth client identifier
    pub client_id: String,
    // TODO: add two factor support
    // Two-factor authentication
    // pub two_factor: Option<TwoFactorRequest>,
}
