use std::net::IpAddr;

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
    /// `default_lease_duration_seconds` or `max_lease_duration_seconds` was present but not
    /// positive.
    #[error("Lease durations must be positive")]
    InvalidLeaseDuration,
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
    if trimmed_name.is_empty() || trimmed_name.encode_utf16().count() > MAX_NAME_LENGTH {
        return Err(AccessRuleValidationError::InvalidName);
    }

    if request.allows_extensions
        && request
            .max_extension_duration_seconds
            .is_none_or(|seconds| seconds <= 0)
    {
        return Err(AccessRuleValidationError::MissingMaxExtensionDuration);
    }

    if request
        .default_lease_duration_seconds
        .is_some_and(|d| d <= 0)
        || request.max_lease_duration_seconds.is_some_and(|m| m <= 0)
    {
        return Err(AccessRuleValidationError::InvalidLeaseDuration);
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

/// Returns `true` when `value` is a CIDR range in canonical form: `address/prefix` where the
/// address parses strictly (RFC dotted-quad IPv4 / RFC 4291 IPv6, no leading-zero octets, hex
/// octets, partial addresses, or zone IDs), the prefix is a plain decimal integer in range, and
/// no host bits are set (e.g. `10.0.0.0/8` is valid, `10.0.0.1/8` is not).
///
/// This is deliberately stricter than the server, which currently stores conditions verbatim, and
/// stricter than .NET 10's `IPNetwork.TryParse`, which silently truncates host bits and interprets
/// leading-zero octets as octal. Rejecting ambiguous input here avoids a client/server
/// disagreement about which network a rule matches.
///
/// IPv4-mapped IPv6 addresses (e.g. `::ffff:10.0.0.0/104`) are also rejected as ambiguous:
/// client and server may disagree about whether such a range overlaps the equivalent native IPv4
/// CIDR. Use the native IPv4 form (e.g. `10.0.0.0/8`) instead.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn is_valid_cidr(value: &str) -> bool {
    let Some((addr, prefix)) = value.split_once('/') else {
        return false;
    };
    // `u8::from_str` accepts a leading `+`, which is not a valid CIDR prefix.
    if !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => prefix <= 32 && no_host_bits(u32::from(ip).into(), prefix, 32),
        Ok(IpAddr::V6(ip)) => {
            // Reject IPv4-mapped IPv6 addresses (::ffff:a.b.c.d). Use to_ipv4_mapped() rather
            // than to_ipv4() because to_ipv4() also matches the deprecated IPv4-compatible range
            // (::a.b.c.d), which would wrongly reject ::/0 and ::1.
            ip.to_ipv4_mapped().is_none() && prefix <= 128 && no_host_bits(ip.into(), prefix, 128)
        }
        Err(_) => false,
    }
}

/// Returns true when the low `width - prefix` host bits of `addr` are all zero.
///
/// # Preconditions
///
/// Callers **must** ensure `prefix <= width`. The `host_bits == 0` branch is not merely an
/// optimisation: it is load-bearing for panic-safety. When `prefix == width`, `host_bits` is `0`
/// and we return early, avoiding the expression `u128::MAX >> 128`, which would panic due to
/// Rust's overflow checks on shift amounts.
fn no_host_bits(addr: u128, prefix: u8, width: u8) -> bool {
    debug_assert!(prefix <= width);
    let host_bits = width - prefix;
    host_bits == 0 || addr & (u128::MAX >> (128 - u32::from(host_bits))) == 0
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

    // --- Edge cases for is_valid_cidr ---

    #[test]
    fn zero_zero_zero_zero_slash_zero_is_valid() {
        assert!(is_valid_cidr("0.0.0.0/0"));
    }

    #[test]
    fn ipv6_slash_zero_is_valid() {
        assert!(is_valid_cidr("::/0"));
    }

    #[test]
    fn ipv4_nonzero_host_with_slash_zero_is_invalid() {
        // 10.0.0.0/0 has host bits set because the entire address must be zero for /0
        assert!(!is_valid_cidr("10.0.0.0/0"));
    }

    #[test]
    fn ipv4_full_prefix_is_valid() {
        assert!(is_valid_cidr("10.0.0.1/32"));
    }

    #[test]
    fn ipv6_full_prefix_is_valid() {
        assert!(is_valid_cidr("2001:db8::1/128"));
    }

    #[test]
    fn ipv4_prefix_out_of_range_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/33"));
    }

    #[test]
    fn ipv6_prefix_out_of_range_is_invalid() {
        assert!(!is_valid_cidr("2001:db8::/129"));
    }

    #[test]
    fn empty_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/"));
    }

    #[test]
    fn empty_address_is_invalid() {
        assert!(!is_valid_cidr("/8"));
    }

    #[test]
    fn double_slash_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/8/8"));
    }

    #[test]
    fn leading_whitespace_is_invalid() {
        assert!(!is_valid_cidr(" 10.0.0.0/8"));
    }

    #[test]
    fn prefix_with_leading_whitespace_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/ 8"));
    }

    #[test]
    fn ipv6_prefix_300_is_invalid() {
        assert!(!is_valid_cidr("2001:db8::/300"));
    }

    // --- Signed/non-digit prefix characters ---

    #[test]
    fn signed_positive_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/+8"));
    }

    #[test]
    fn signed_negative_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/-8"));
    }

    // --- Leading zero in prefix (unambiguous decimal — matches .NET behaviour) ---

    #[test]
    fn prefix_with_leading_zero_is_valid() {
        assert!(is_valid_cidr("10.0.0.0/08"));
    }

    // --- Ambiguous / non-canonical address forms ---

    #[test]
    fn leading_zero_octet_is_invalid() {
        // .NET parses leading-zero octets as octal (`010` → `8`), so accepting this would let
        // client and server disagree about which network the rule matches.
        assert!(!is_valid_cidr("010.0.0.0/8"));
    }

    #[test]
    fn hex_octet_is_invalid() {
        assert!(!is_valid_cidr("0x0A.0.0.0/8"));
    }

    #[test]
    fn partial_ipv4_address_is_invalid() {
        assert!(!is_valid_cidr("1.2.3/24"));
    }

    #[test]
    fn ipv6_zone_id_is_invalid() {
        assert!(!is_valid_cidr("fe80::1%1/64"));
    }

    // --- Change 1: IPv4-mapped IPv6 CIDRs are rejected ---

    #[test]
    fn ipv4_mapped_ipv6_is_invalid() {
        // ::ffff:10.0.0.0/104 is the IPv4-mapped IPv6 form of 10.0.0.0/8; reject it as
        // ambiguous so client and server always agree on which network a rule matches.
        assert!(!is_valid_cidr("::ffff:10.0.0.0/104"));
    }

    #[test]
    fn ipv6_loopback_is_not_treated_as_mapped() {
        // ::1 has a small numeric value but is NOT an IPv4-mapped address; it must still be
        // accepted. Regression guard for the to_ipv4_mapped() vs to_ipv4() distinction.
        assert!(is_valid_cidr("::1/128"));
    }

    // --- Change 2: name length is measured in UTF-16 code units ---

    #[test]
    fn name_with_supplementary_chars_measured_in_utf16() {
        // U+1D538 MATHEMATICAL DOUBLE-STRUCK CAPITAL A encodes as a surrogate pair in UTF-16
        // (2 code units). 128 such chars = 256 UTF-16 units → valid; 129 = 258 units → invalid.
        let base_char = '𝔸';
        let mut request = base_request();

        request.name = base_char.to_string().repeat(128);
        assert_eq!(validate_request(&request), Ok(()));

        request.name = base_char.to_string().repeat(129);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidName)
        );
    }

    // --- Change 4: lease durations must be positive when provided ---

    #[test]
    fn negative_default_lease_duration_is_invalid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = Some(-1);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidLeaseDuration)
        );
    }

    #[test]
    fn zero_default_lease_duration_is_invalid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = Some(0);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidLeaseDuration)
        );
    }

    #[test]
    fn negative_max_lease_duration_is_invalid() {
        let mut request = base_request();
        request.max_lease_duration_seconds = Some(-1);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::InvalidLeaseDuration)
        );
    }

    #[test]
    fn positive_lease_durations_are_valid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = Some(300);
        request.max_lease_duration_seconds = Some(3600);
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn none_lease_durations_are_valid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = None;
        request.max_lease_duration_seconds = None;
        assert_eq!(validate_request(&request), Ok(()));
    }
}
