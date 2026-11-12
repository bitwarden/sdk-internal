/// Internal Feature flag representation for the Bitwarden SDK client.
///
/// **Note:** The struct should be deserialized directly from the `api/config` endpoint. Take care
/// to ensure any appropriate aliases are used. By default we use `kebab-schema` but there may be
/// value in having shorter names.
///
/// **Note:** This struct while public, is intended for internal use and may change in future
/// releases.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default, rename_all = "kebab-case")]
pub struct Flags {
    /// Enable strict cipher field decryption (propagates errors instead of nulling fields).
    #[serde(alias = "pm-34500-strict-cipher-decryption")]
    pub strict_cipher_decryption: bool,

    /// Enable FedRAMP government region behavior.
    #[serde(alias = "fedrampGovRegion")]
    pub fedramp_gov_region: bool,

    /// Finish SSO JIT provisioning through the `sso-jit-provision-finish` endpoints. These
    /// endpoints let the client choose whether the organization membership stays Invited.
    #[serde(alias = "pm-34429-invite-link-auto-confirm")]
    pub invite_link_auto_confirm: bool,

    /// Upgrade V1 user keys to V2 on key rotation. While off, a V1 user key rotates to a new V1
    /// user key, so older devices that cannot read V2 data keep working.
    pub force_upgrade_v2_encryption: bool,
}

impl Flags {
    /// Create a new `Flags` instance from a map of flag names and values.
    pub fn load_from_map(map: std::collections::HashMap<String, bool>) -> Self {
        let map = map
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::Bool(v)))
            .collect();
        serde_json::from_value(serde_json::Value::Object(map)).expect("Valid map")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_empty_map() {
        let map = std::collections::HashMap::new();
        let flags = Flags::load_from_map(map);
        assert!(!flags.strict_cipher_decryption);
    }

    #[test]
    fn test_load_valid_map() {
        let mut map = std::collections::HashMap::new();
        map.insert("strict-cipher-decryption".into(), true);
        let flags = Flags::load_from_map(map);
        assert!(flags.strict_cipher_decryption);
    }

    #[test]
    fn test_load_valid_map_alias() {
        let mut map = std::collections::HashMap::new();
        map.insert("pm-34500-strict-cipher-decryption".into(), true);
        let flags = Flags::load_from_map(map);
        assert!(flags.strict_cipher_decryption);
    }

    #[test]
    fn test_load_invite_link_auto_confirm_alias() {
        let mut map = std::collections::HashMap::new();
        map.insert("pm-34429-invite-link-auto-confirm".into(), true);
        let flags = Flags::load_from_map(map);
        assert!(flags.invite_link_auto_confirm);
    }

    #[test]
    fn test_load_invalid_map() {
        let mut map = std::collections::HashMap::new();
        map.insert("thisIsNotAFlag".into(), true);
        let flags = Flags::load_from_map(map);
        assert!(!flags.strict_cipher_decryption);
    }
}
