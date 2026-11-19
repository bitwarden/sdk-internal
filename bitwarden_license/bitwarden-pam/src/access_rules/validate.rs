use std::net::IpAddr;

use thiserror::Error;

use super::{conditions::AccessCondition, models::AccessRuleAddEditRequest};
use crate::MAX_REQUEST_ACCESS_WINDOW_SECONDS;

/// Maximum length of an access rule's `name` field, matching the server's constraint.
const MAX_NAME_LENGTH: usize = 256;
const MAX_CONDITIONS: usize = 10;

/// Errors from validating an [`AccessRuleAddEditRequest`] before it is sent to the server.
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
    /// `default_lease_duration_seconds` exceeded `max_lease_duration_seconds`.
    #[error("The default lease duration cannot exceed the maximum lease duration")]
    DefaultLeaseDurationExceedsMax,
    /// A lease duration exceeded the global ceiling.
    #[error("A lease duration cannot exceed {MAX_REQUEST_ACCESS_WINDOW_SECONDS} seconds")]
    LeaseDurationExceedsGlobalMax,
    /// More than 10 conditions were provided.
    #[error("A rule may have at most {MAX_CONDITIONS} conditions")]
    TooManyConditions,
    /// An `ip_allowlist` condition contained an invalid CIDR range.
    #[error("Invalid CIDR range: {0}")]
    InvalidCidr(String),
    /// An `ip_allowlist` condition was provided without any CIDR ranges.
    #[error("An IP allowlist condition must contain at least one CIDR range")]
    EmptyCidrList,
}

/// Validates a request before it is sent to the server. Unknown condition kinds are left to the
/// server.
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

    // An absent max is "no cap", so it never constrains the default.
    if let (Some(default), Some(max)) = (
        request.default_lease_duration_seconds,
        request.max_lease_duration_seconds,
    ) && default > max
    {
        return Err(AccessRuleValidationError::DefaultLeaseDurationExceedsMax);
    }

    // The lease paths never check an uncapped default or the extension length against the
    // ceiling. Bounds each value, not the cumulative length of a repeatedly extended lease.
    let ceiling = i64::from(MAX_REQUEST_ACCESS_WINDOW_SECONDS);
    if [
        request.default_lease_duration_seconds,
        request.max_lease_duration_seconds,
        request.max_extension_duration_seconds,
    ]
    .iter()
    .any(|seconds| seconds.is_some_and(|s| i64::from(s) > ceiling))
    {
        return Err(AccessRuleValidationError::LeaseDurationExceedsGlobalMax);
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

/// Returns `true` for a canonical CIDR range such as `10.0.0.0/8`, with no host bits set.
/// Ambiguous forms (leading-zero or hex octets, IPv4-mapped IPv6) are rejected so client and
/// server agree on which network a rule matches.
#[bitwarden_ffi::wasm_export]
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
            // Reject IPv4-mapped addresses (::ffff:a.b.c.d). `to_ipv4()` would also match the
            // IPv4-compatible range (::a.b.c.d) and wrongly reject ::/0 and ::1.
            ip.to_ipv4_mapped().is_none() && prefix <= 128 && no_host_bits(ip.into(), prefix, 128)
        }
        Err(_) => false,
    }
}

/// Returns true when the low `width - prefix` host bits of `addr` are all zero. Requires
/// `prefix <= width`; the `host_bits == 0` check also avoids `u128::MAX >> 128`, which panics.
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

    #[test]
    fn signed_positive_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/+8"));
    }

    #[test]
    fn signed_negative_prefix_is_invalid() {
        assert!(!is_valid_cidr("10.0.0.0/-8"));
    }

    #[test]
    fn prefix_with_leading_zero_is_valid() {
        // A leading zero in the prefix is unambiguous decimal, as .NET also reads it.
        assert!(is_valid_cidr("10.0.0.0/08"));
    }

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

    #[test]
    fn ipv4_mapped_ipv6_is_invalid() {
        // The IPv4-mapped form of 10.0.0.0/8.
        assert!(!is_valid_cidr("::ffff:10.0.0.0/104"));
    }

    #[test]
    fn ipv6_loopback_is_not_treated_as_mapped() {
        // `::1` is not IPv4-mapped, though `to_ipv4()` would treat it as IPv4-compatible.
        assert!(is_valid_cidr("::1/128"));
    }

    #[test]
    fn name_with_supplementary_chars_measured_in_utf16() {
        // U+1D538 takes two UTF-16 code units, so 128 of them make 256 (valid) and 129 make 258.
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
    fn lease_durations_past_the_global_ceiling_are_invalid() {
        let ceiling = i32::try_from(MAX_REQUEST_ACCESS_WINDOW_SECONDS).unwrap();
        for (default, max) in [(None, Some(ceiling + 1)), (Some(ceiling + 1), None)] {
            let mut request = base_request();
            request.default_lease_duration_seconds = default;
            request.max_lease_duration_seconds = max;

            assert_eq!(
                validate_request(&request),
                Err(AccessRuleValidationError::LeaseDurationExceedsGlobalMax),
                "default {default:?} max {max:?}"
            );
        }
    }

    #[test]
    fn a_max_extension_past_the_global_ceiling_is_invalid() {
        let mut request = base_request();
        request.allows_extensions = true;
        request.max_extension_duration_seconds =
            Some(i32::try_from(MAX_REQUEST_ACCESS_WINDOW_SECONDS).unwrap() + 1);

        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::LeaseDurationExceedsGlobalMax)
        );
    }

    #[test]
    fn lease_durations_at_the_global_ceiling_are_valid() {
        let ceiling = i32::try_from(MAX_REQUEST_ACCESS_WINDOW_SECONDS).unwrap();
        let mut request = base_request();
        request.default_lease_duration_seconds = None;
        request.max_lease_duration_seconds = Some(ceiling);
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn none_lease_durations_are_valid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = None;
        request.max_lease_duration_seconds = None;
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn default_lease_duration_above_max_is_invalid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = Some(3600);
        request.max_lease_duration_seconds = Some(900);
        assert_eq!(
            validate_request(&request),
            Err(AccessRuleValidationError::DefaultLeaseDurationExceedsMax)
        );
    }

    #[test]
    fn default_lease_duration_equal_to_max_is_valid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = Some(900);
        request.max_lease_duration_seconds = Some(900);
        assert_eq!(validate_request(&request), Ok(()));
    }

    #[test]
    fn default_lease_duration_without_a_max_is_valid() {
        let mut request = base_request();
        request.default_lease_duration_seconds = Some(7 * 86_400);
        request.max_lease_duration_seconds = None;
        assert_eq!(validate_request(&request), Ok(()));
    }
}
