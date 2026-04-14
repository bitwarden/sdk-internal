use std::collections::HashMap;

use crate::{Policy, PolicyType};

/// Aggregated password generator policy requirements from one or more organizations.
///
/// These constraints represent the most restrictive combination of all applicable
/// organization policies. When a user's explicit flags conflict with a policy
/// requirement, the command will fail with an explanatory message rather than
/// silently overriding either the user's intent or the organization's policy.
#[derive(Debug, Clone, Default)]
pub struct PasswordGeneratorPolicy {
    // -- Password fields --
    /// The minimum length of generated passwords.
    pub min_length: u8,
    /// When true, an uppercase character must be part of the generated password.
    pub use_uppercase: bool,
    /// When true, a lowercase character must be part of the generated password.
    pub use_lowercase: bool,
    /// When true, at least one digit must be part of the generated password.
    pub use_numbers: bool,
    /// When true, at least one special character must be part of the generated password.
    pub use_special: bool,
    /// The minimum quantity of digits to include in the generated password.
    pub number_count: u8,
    /// The minimum quantity of special characters to include in the generated password.
    pub special_count: u8,

    // -- Generation type override --
    /// When set, forces the generation type to "password" or "passphrase".
    pub override_password_type: Option<String>,

    // -- Passphrase fields --
    /// The minimum number of words in a generated passphrase.
    pub min_number_words: u8,
    /// When true, passphrase words must be capitalized.
    pub capitalize: bool,
    /// When true, the passphrase must include a number appended to a word.
    pub include_number: bool,
}

impl PasswordGeneratorPolicy {
    /// Extract a password generator policy from a generic [`Policy`]'s data.
    ///
    /// Returns `None` if the policy is not a `PasswordGenerator` type or is disabled.
    /// The data field keys match the server's policy data JSON format as consumed by
    /// the TypeScript `passwordLeastPrivilege` and `passphraseLeastPrivilege` functions.
    pub fn from_policy(policy: &Policy) -> Option<Self> {
        if !matches!(policy.policy_type(), PolicyType::PasswordGenerator) || !policy.enabled() {
            return None;
        }
        let data = policy.policy_data()?;
        Some(Self {
            min_length: get_u8(data, "minLength"),
            use_uppercase: get_bool(data, "useUpper"),
            use_lowercase: get_bool(data, "useLower"),
            use_numbers: get_bool(data, "useNumbers"),
            use_special: get_bool(data, "useSpecial"),
            number_count: get_u8(data, "minNumbers"),
            special_count: get_u8(data, "minSpecial"),
            override_password_type: data
                .get("overridePasswordType")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from),
            min_number_words: get_u8(data, "minNumberWords"),
            capitalize: get_bool(data, "capitalize"),
            include_number: get_bool(data, "includeNumber"),
        })
    }

    /// Aggregate multiple policies using "least privilege" -- the most restrictive
    /// combination across all organizations.
    ///
    /// Boolean flags use OR (any org requiring a charset forces it on).
    /// Numeric constraints use MAX (the highest minimum wins).
    /// For `override_password_type`, "password" takes priority over "passphrase"
    /// (matching the TS `availableAlgorithms` reduction).
    pub fn aggregate(policies: impl IntoIterator<Item = Self>) -> Self {
        policies.into_iter().fold(Self::default(), |acc, p| Self {
            min_length: acc.min_length.max(p.min_length),
            use_uppercase: acc.use_uppercase || p.use_uppercase,
            use_lowercase: acc.use_lowercase || p.use_lowercase,
            use_numbers: acc.use_numbers || p.use_numbers,
            use_special: acc.use_special || p.use_special,
            number_count: acc.number_count.max(p.number_count),
            special_count: acc.special_count.max(p.special_count),
            override_password_type: match (&acc.override_password_type, &p.override_password_type) {
                // "password" takes priority over any other value
                (Some(t), _) | (_, Some(t)) if t == "password" => Some("password".to_string()),
                (_, Some(t)) => Some(t.clone()),
                (t, None) => t.clone(),
            },
            min_number_words: acc.min_number_words.max(p.min_number_words),
            capitalize: acc.capitalize || p.capitalize,
            include_number: acc.include_number || p.include_number,
        })
    }

    /// Check whether explicit user charset choices conflict with this policy.
    ///
    /// A conflict occurs when the policy requires a character set that the user
    /// did not include. Returns a list of human-readable violation descriptions,
    /// or an empty vec if the choices are compatible.
    pub fn check_charset_conflicts(
        &self,
        uppercase: bool,
        lowercase: bool,
        numbers: bool,
        special: bool,
    ) -> Vec<String> {
        let mut violations = Vec::new();
        if self.use_uppercase && !uppercase {
            violations.push("uppercase characters".to_string());
        }
        if self.use_lowercase && !lowercase {
            violations.push("lowercase characters".to_string());
        }
        if self.use_numbers && !numbers {
            violations.push("numbers".to_string());
        }
        if self.use_special && !special {
            violations.push("special characters".to_string());
        }
        violations
    }

    /// Check whether explicit numeric option values conflict with policy minimums.
    ///
    /// Only `Some` values (explicitly set by the user) are checked. `None` values
    /// indicate the user did not set the option, so there is no conflict — the
    /// default will be raised to the policy floor instead.
    pub fn check_numeric_conflicts(
        &self,
        length: Option<u8>,
        min_number: Option<u8>,
        min_special: Option<u8>,
    ) -> Vec<String> {
        let mut violations = Vec::new();
        if let Some(len) = length {
            if self.min_length > 0 && len < self.min_length {
                violations.push(format!(
                    "a minimum password length of {}, but --length {} was specified",
                    self.min_length, len
                ));
            }
        }
        if let Some(mn) = min_number {
            if self.number_count > 0 && mn < self.number_count {
                violations.push(format!(
                    "at least {} numeric character(s), but --min-number {} was specified",
                    self.number_count, mn
                ));
            }
        }
        if let Some(ms) = min_special {
            if self.special_count > 0 && ms < self.special_count {
                violations.push(format!(
                    "at least {} special character(s), but --min-special {} was specified",
                    self.special_count, ms
                ));
            }
        }
        violations
    }

    /// Check whether an explicit `--words` value conflicts with the policy minimum.
    pub fn check_words_conflict(&self, words: Option<u8>) -> Option<String> {
        if let Some(w) = words {
            if self.min_number_words > 0 && w < self.min_number_words {
                return Some(format!(
                    "at least {} word(s), but --words {} was specified",
                    self.min_number_words, w
                ));
            }
        }
        None
    }
}

fn get_bool(data: &HashMap<String, serde_json::Value>, key: &str) -> bool {
    data.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn get_u8(data: &HashMap<String, serde_json::Value>, key: &str) -> u8 {
    data.get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(u8::MAX as u64) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_empty_returns_default() {
        let result = PasswordGeneratorPolicy::aggregate(std::iter::empty());
        assert_eq!(result.min_length, 0);
        assert!(!result.use_uppercase);
        assert!(!result.use_lowercase);
        assert!(!result.use_numbers);
        assert!(!result.use_special);
        assert_eq!(result.number_count, 0);
        assert_eq!(result.special_count, 0);
        assert!(result.override_password_type.is_none());
        assert_eq!(result.min_number_words, 0);
        assert!(!result.capitalize);
        assert!(!result.include_number);
    }

    #[test]
    fn test_aggregate_takes_most_restrictive() {
        let policy_a = PasswordGeneratorPolicy {
            min_length: 10,
            use_uppercase: true,
            use_numbers: false,
            min_number_words: 3,
            capitalize: true,
            ..Default::default()
        };
        let policy_b = PasswordGeneratorPolicy {
            min_length: 14,
            use_numbers: true,
            number_count: 3,
            min_number_words: 5,
            include_number: true,
            ..Default::default()
        };

        let result = PasswordGeneratorPolicy::aggregate([policy_a, policy_b]);
        assert_eq!(result.min_length, 14);
        assert!(result.use_uppercase);
        assert!(result.use_numbers);
        assert_eq!(result.number_count, 3);
        assert_eq!(result.min_number_words, 5);
        assert!(result.capitalize);
        assert!(result.include_number);
    }

    #[test]
    fn test_aggregate_password_type_override_password_wins() {
        let policy_a = PasswordGeneratorPolicy {
            override_password_type: Some("passphrase".to_string()),
            ..Default::default()
        };
        let policy_b = PasswordGeneratorPolicy {
            override_password_type: Some("password".to_string()),
            ..Default::default()
        };

        // "password" wins regardless of order
        let result = PasswordGeneratorPolicy::aggregate([policy_a.clone(), policy_b.clone()]);
        assert_eq!(result.override_password_type.as_deref(), Some("password"));

        let result = PasswordGeneratorPolicy::aggregate([policy_b, policy_a]);
        assert_eq!(result.override_password_type.as_deref(), Some("password"));
    }

    #[test]
    fn test_aggregate_password_type_override_none_preserves() {
        let policy_a = PasswordGeneratorPolicy {
            override_password_type: Some("passphrase".to_string()),
            ..Default::default()
        };
        let policy_b = PasswordGeneratorPolicy {
            override_password_type: None,
            ..Default::default()
        };

        let result = PasswordGeneratorPolicy::aggregate([policy_a, policy_b]);
        assert_eq!(result.override_password_type.as_deref(), Some("passphrase"));
    }

    #[test]
    fn test_check_charset_conflicts_all_satisfied() {
        let policy = PasswordGeneratorPolicy {
            use_uppercase: true,
            use_numbers: true,
            ..Default::default()
        };
        let violations = policy.check_charset_conflicts(true, false, true, false);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_check_charset_conflicts_missing() {
        let policy = PasswordGeneratorPolicy {
            use_uppercase: true,
            use_numbers: true,
            use_special: true,
            ..Default::default()
        };
        let violations = policy.check_charset_conflicts(true, false, false, false);
        assert_eq!(violations.len(), 2);
        assert!(violations.contains(&"numbers".to_string()));
        assert!(violations.contains(&"special characters".to_string()));
    }

    #[test]
    fn test_check_numeric_conflicts_explicit_below_policy() {
        let policy = PasswordGeneratorPolicy {
            min_length: 20,
            number_count: 3,
            special_count: 2,
            ..Default::default()
        };
        let violations = policy.check_numeric_conflicts(Some(8), Some(1), Some(0));
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn test_check_numeric_conflicts_explicit_above_policy() {
        let policy = PasswordGeneratorPolicy {
            min_length: 10,
            number_count: 2,
            ..Default::default()
        };
        let violations = policy.check_numeric_conflicts(Some(14), Some(3), None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_check_numeric_conflicts_none_never_conflicts() {
        let policy = PasswordGeneratorPolicy {
            min_length: 20,
            number_count: 5,
            special_count: 5,
            ..Default::default()
        };
        let violations = policy.check_numeric_conflicts(None, None, None);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_check_words_conflict_below_policy() {
        let policy = PasswordGeneratorPolicy {
            min_number_words: 5,
            ..Default::default()
        };
        assert!(policy.check_words_conflict(Some(3)).is_some());
    }

    #[test]
    fn test_check_words_conflict_above_policy() {
        let policy = PasswordGeneratorPolicy {
            min_number_words: 5,
            ..Default::default()
        };
        assert!(policy.check_words_conflict(Some(6)).is_none());
    }

    #[test]
    fn test_check_words_conflict_none_never_conflicts() {
        let policy = PasswordGeneratorPolicy {
            min_number_words: 10,
            ..Default::default()
        };
        assert!(policy.check_words_conflict(None).is_none());
    }

    // -- from_policy tests --

    /// Helper to construct a Policy from raw data via the API model conversion.
    fn make_policy(
        policy_type: bitwarden_api_api::models::PolicyType,
        enabled: bool,
        data: HashMap<String, serde_json::Value>,
    ) -> Policy {
        use bitwarden_api_api::models::PolicyResponseModel;
        Policy::try_from(PolicyResponseModel {
            object: Some("policy".to_string()),
            id: Some(uuid::Uuid::new_v4()),
            organization_id: Some(uuid::Uuid::new_v4()),
            r#type: Some(policy_type),
            data: Some(data),
            enabled: Some(enabled),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
        })
        .unwrap()
    }

    #[test]
    fn test_from_policy_parses_all_password_fields() {
        let mut data = HashMap::new();
        data.insert("minLength".into(), serde_json::json!(20));
        data.insert("useUpper".into(), serde_json::json!(true));
        data.insert("useLower".into(), serde_json::json!(true));
        data.insert("useNumbers".into(), serde_json::json!(true));
        data.insert("minNumbers".into(), serde_json::json!(3));
        data.insert("useSpecial".into(), serde_json::json!(true));
        data.insert("minSpecial".into(), serde_json::json!(2));

        let policy = make_policy(
            bitwarden_api_api::models::PolicyType::PasswordGenerator,
            true,
            data,
        );
        let parsed = PasswordGeneratorPolicy::from_policy(&policy).unwrap();
        assert_eq!(parsed.min_length, 20);
        assert!(parsed.use_uppercase);
        assert!(parsed.use_lowercase);
        assert!(parsed.use_numbers);
        assert_eq!(parsed.number_count, 3);
        assert!(parsed.use_special);
        assert_eq!(parsed.special_count, 2);
    }

    #[test]
    fn test_from_policy_parses_all_passphrase_fields() {
        let mut data = HashMap::new();
        data.insert("minNumberWords".into(), serde_json::json!(5));
        data.insert("capitalize".into(), serde_json::json!(true));
        data.insert("includeNumber".into(), serde_json::json!(true));

        let policy = make_policy(
            bitwarden_api_api::models::PolicyType::PasswordGenerator,
            true,
            data,
        );
        let parsed = PasswordGeneratorPolicy::from_policy(&policy).unwrap();
        assert_eq!(parsed.min_number_words, 5);
        assert!(parsed.capitalize);
        assert!(parsed.include_number);
    }

    #[test]
    fn test_from_policy_parses_override_password_type() {
        let mut data = HashMap::new();
        data.insert(
            "overridePasswordType".into(),
            serde_json::json!("passphrase"),
        );

        let policy = make_policy(
            bitwarden_api_api::models::PolicyType::PasswordGenerator,
            true,
            data,
        );
        let parsed = PasswordGeneratorPolicy::from_policy(&policy).unwrap();
        assert_eq!(parsed.override_password_type.as_deref(), Some("passphrase"));
    }

    #[test]
    fn test_from_policy_returns_none_for_wrong_type() {
        let policy = make_policy(
            bitwarden_api_api::models::PolicyType::MasterPassword,
            true,
            HashMap::new(),
        );
        assert!(PasswordGeneratorPolicy::from_policy(&policy).is_none());
    }

    #[test]
    fn test_from_policy_returns_none_when_disabled() {
        let policy = make_policy(
            bitwarden_api_api::models::PolicyType::PasswordGenerator,
            false,
            HashMap::new(),
        );
        assert!(PasswordGeneratorPolicy::from_policy(&policy).is_none());
    }

    #[test]
    fn test_from_policy_missing_keys_use_defaults() {
        let policy = make_policy(
            bitwarden_api_api::models::PolicyType::PasswordGenerator,
            true,
            HashMap::new(),
        );
        let parsed = PasswordGeneratorPolicy::from_policy(&policy).unwrap();
        assert_eq!(parsed.min_length, 0);
        assert!(!parsed.use_uppercase);
        assert!(!parsed.use_numbers);
        assert!(parsed.override_password_type.is_none());
        assert_eq!(parsed.min_number_words, 0);
        assert!(!parsed.capitalize);
    }

    // -- Helper function tests --

    #[test]
    fn test_get_u8_clamps_large_values() {
        let mut data = HashMap::new();
        data.insert("big".to_string(), serde_json::Value::from(999));
        assert_eq!(get_u8(&data, "big"), 255);
    }

    #[test]
    fn test_get_u8_missing_key_returns_zero() {
        let data = HashMap::new();
        assert_eq!(get_u8(&data, "missing"), 0);
    }

    #[test]
    fn test_get_bool_missing_key_returns_false() {
        let data = HashMap::new();
        assert!(!get_bool(&data, "missing"));
    }
}
