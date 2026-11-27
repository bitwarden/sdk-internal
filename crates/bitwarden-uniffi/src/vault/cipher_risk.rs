use bitwarden_vault::{PasskeyCandidate, PasskeyDirectoryEntry, PasskeyOpportunity};

/// Vault health operations, such as finding passkey opportunities.
#[derive(uniffi::Object)]
pub struct CipherRiskClient(pub(crate) bitwarden_vault::CipherRiskClient);

#[uniffi::export]
impl CipherRiskClient {
    /// Find login items whose site supports passkeys, according to the passkey directory. See the
    /// Rust docs on `bitwarden_vault::CipherRiskClient::find_passkey_opportunities` for the
    /// eligibility and matching rules.
    pub fn find_passkey_opportunities(
        &self,
        candidates: Vec<PasskeyCandidate>,
        directory: Vec<PasskeyDirectoryEntry>,
    ) -> Vec<PasskeyOpportunity> {
        self.0.find_passkey_opportunities(candidates, directory)
    }
}
