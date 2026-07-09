use std::str::FromStr;

use ipnet::IpNet;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{conditions::AccessCondition, models::AccessRuleAddEditRequest};

/// Maximum length of an access rule's `name` field, matching the server's constraint.
const MAX_NAME_LENGTH: usize = 256;
/// Maximum number of conditions allowed on a single access rule.
const MAX_CONDITIONS: usize = 10;

/// Errors returned when a locally-constructed [`AccessRuleAddEditRequest`] fails validation
/// before being sent to the server.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccessRuleValidationError {
    /// `name` was empty (after trimming whitespace) or exceeded 256 characters.
    #[error("Name must be between 1 and {MAX_NAME_LENGTH} characters")]
    InvalidName,
    /// `allows_extensions` was `true` but `max_extension_duration_seconds` was missing or not
    /// positive.
    #[error("A positive max extension duration is required when extensions are allowed")]
    MissingMaxExtensionDuration,
    /// More than 10 conditions were provided.
    #[error("A rule may have at most {MAX_CONDITIONS} conditions")]
    TooManyConditions,
    /// An `ip_allowlist` condition contained a CIDR range that failed to parse.
    #[error("Invalid CIDR range: {0}")]
    InvalidCidr(String),
    /// An `ip_allowlist` condition was provided without any CIDR ranges.
    #[error("An IP allowlist condition must contain at least one CIDR range")]
    EmptyCidrList,
}

/// Validates a request before it is sent to the server. Unknown condition kinds are skipped -
/// the server is the source of truth for validating condition kinds this SDK version doesn't
/// model.
pub fn validate_request(
    request: &AccessRuleAddEditRequest,
) -> Result<(), AccessRuleValidationError> {
    let trimmed_name = request.name.trim();
    if trimmed_name.is_empty() || trimmed_name.chars().count() > MAX_NAME_LENGTH {
        return Err(AccessRuleValidationError::InvalidName);
    }

    if request.allows_extensions
        && request
            .max_extension_duration_seconds
            .is_none_or(|seconds| seconds <= 0)
    {
        return Err(AccessRuleValidationError::MissingMaxExtensionDuration);
    }

    if request.conditions.len() > MAX_CONDITIONS {
        return Err(AccessRuleValidationError::TooManyConditions);
    }

    for condition in &request.conditions {
        if let AccessCondition::IpAllowlist { cidrs } = condition {
            if cidrs.is_empty() {
                return Err(AccessRuleValidationError::EmptyCidrList);
            }
            for cidr in cidrs {
                if !is_valid_cidr(cidr) {
                    return Err(AccessRuleValidationError::InvalidCidr(cidr.clone()));
                }
            }
        }
    }

    Ok(())
}

/// Returns true when `value` is a valid CIDR range, matching the server's `IPNetwork.TryParse`
/// semantics: the value must parse as a CIDR range AND have no host bits set (e.g. `10.0.0.0/8`
/// is valid, `10.0.0.1/8` is not because the low 24 bits aren't all zero).
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn is_valid_cidr(value: &str) -> bool {
    match IpNet::from_str(value) {
        Ok(net) => net.trunc() == net,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> AccessRuleAddEditRequest {
        AccessRuleAddEditRequest {
            name: "My rule".to_string(),
            description: None,
            enabled: true,
            conditions: Vec::new(),
            single_active_lease: false,
            default_lease_duration_seconds: None,
            max_lease_duration_seconds: None,
            allows_extensions: false,
            max_extension_duration_seconds: None,
            collections: Vec::new(),
        }
    }

    #[test]
    fn blank_name_is_invalid() {
        let mut request = base_request();
        request.name = "   ".to_string();
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidName)
        );
    }

    #[test]
    fn name_over_256_chars_is_invalid() {
        let mut request = base_request();
        request.name = "a".repeat(257);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidName)
        );
    }

    #[test]
    fn name_at_256_chars_is_valid() {
        let mut request = base_request();
        request.name = "a".repeat(256);
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn name_at_256_chars_with_surrounding_whitespace_is_valid() {
        let mut request = base_request();
        request.name = format!("  {}  ", "a".repeat(256));
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn allows_extensions_without_max_duration_is_invalid() {
        let mut request = base_request();
        request.allows_extensions = true;
        request.max_extension_duration_seconds = None;
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::MissingMaxExtensionDuration)
        );
    }

    #[test]
    fn allows_extensions_with_zero_max_duration_is_invalid() {
        let mut request = base_request();
        request.allows_extensions = true;
        request.max_extension_duration_seconds = Some(0);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::MissingMaxExtensionDuration)
        );
    }

    #[test]
    fn allows_extensions_with_positive_max_duration_is_valid() {
        let mut request = base_request();
        request.allows_extensions = true;
        request.max_extension_duration_seconds = Some(60);
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn more_than_ten_conditions_is_invalid() {
        let mut request = base_request();
        request.conditions = (0..11).map(|_| AccessCondition::HumanApproval).collect();
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::TooManyConditions)
        );
    }

    #[test]
    fn exactly_ten_conditions_is_valid() {
        let mut request = base_request();
        request.conditions = (0..10).map(|_| AccessCondition::HumanApproval).collect();
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn empty_cidr_list_is_invalid() {
        let mut request = base_request();
        request.conditions = vec![AccessCondition::IpAllowlist { cidrs: Vec::new() }];
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::EmptyCidrList)
        );
    }

    #[test]
    fn valid_ipv4_cidr() {
        assert!(is_valid_cidr("10.0.0.0/8"));
    }

    #[test]
    fn valid_ipv6_cidr() {
        assert!(is_valid_cidr("2001:db8::/32"));
    }

    #[test]
    fn cidr_with_host_bits_set_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.1/8"));
    }

    #[test]
    fn cidr_without_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0"));
    }

    #[test]
    fn garbage_cidr_is_invalid() {
        assert!(!is_valid_cidr("not-a-cidr"));
    }

    #[test]
    fn ip_allowlist_with_invalid_cidr_is_rejected() {
        let mut request = base_request();
        request.conditions = vec![AccessCondition::IpAllowlist {
            cidrs: vec!["10.0.0.1/8".to_string()],
        }];
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidCidr(
                "10.0.0.1/8".to_string()
            ))
        );
    }

    #[test]
    fn unknown_condition_kind_is_skipped() {
        let mut request = base_request();
        request.conditions = vec![AccessCondition::Unknown(serde_json::json!({
            "kind": "time_of_day",
        }))];
        assert_eq!(validate_request(&request), Ok(()));
    }
}
