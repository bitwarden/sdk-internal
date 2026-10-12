//! Converts a verified job's [`SealedPasswordPolicy`] into a [`PasswordGeneratorRequest`].
//!
//! `executor::verify` already validates the policy; re-validating here fails closed for any call
//! site that skips `verify`.

use bitwarden_generators::PasswordGeneratorRequest;
use bitwarden_pam_sealed::{
    GENERATOR_MAX_LENGTH, GENERATOR_MIN_LENGTH, PasswordPolicyError, SealedPasswordPolicy,
};

/// Convert a [`SealedPasswordPolicy`] into a [`PasswordGeneratorRequest`] of length `max_length`.
pub(crate) fn to_generator_request(
    policy: &SealedPasswordPolicy,
) -> Result<PasswordGeneratorRequest, PasswordPolicyError> {
    policy.validate()?;

    let length = policy
        .max_length
        .clamp(GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH);

    // The generator's maximum length fits in a u8.
    #[allow(clippy::cast_possible_truncation)]
    let length_u8 = length as u8;

    Ok(PasswordGeneratorRequest {
        lowercase: policy.include_lowercase,
        uppercase: policy.include_uppercase,
        numbers: policy.include_digits,
        special: policy.include_symbols,
        length: length_u8,
        avoid_ambiguous: false,
        min_lowercase: None,
        min_uppercase: None,
        min_number: None,
        min_special: None,
        custom_required_chars: None,
        custom_allowed_chars: None,
        max_consecutive: None,
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_core::Client;
    use bitwarden_generators::GeneratorClientsExt as _;

    use super::*;

    fn all_classes(min_length: u32, max_length: u32) -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length,
            max_length,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    fn password(
        req: PasswordGeneratorRequest,
    ) -> Result<String, bitwarden_generators::PasswordError> {
        Client::new(None).generator().password(req)
    }

    #[test]
    fn valid_policy_converts_length_from_max_length() {
        let req = to_generator_request(&all_classes(5, 20)).unwrap();
        assert_eq!(req.length, 20);
    }

    #[test]
    fn min_length_equal_max_length_is_valid() {
        let req = to_generator_request(&all_classes(16, 16)).unwrap();
        assert_eq!(req.length, 16);
    }

    #[test]
    fn max_length_at_generator_ceiling_is_valid() {
        let req = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH)).unwrap();
        assert_eq!(u32::from(req.length), GENERATOR_MAX_LENGTH);
    }

    #[test]
    fn min_length_at_generator_floor_is_valid() {
        let req =
            to_generator_request(&all_classes(GENERATOR_MIN_LENGTH, GENERATOR_MIN_LENGTH)).unwrap();
        assert_eq!(u32::from(req.length), GENERATOR_MIN_LENGTH);
    }

    #[test]
    fn min_greater_than_max_is_rejected() {
        let err = to_generator_request(&all_classes(30, 20)).unwrap_err();
        assert_eq!(err, PasswordPolicyError::InvalidLengthBounds);
    }

    #[test]
    fn max_length_above_generator_ceiling_is_rejected() {
        let err = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH + 1)).unwrap_err();
        assert_eq!(err, PasswordPolicyError::InvalidLengthBounds);
    }

    #[test]
    fn min_length_below_generator_floor_is_rejected() {
        let err = to_generator_request(&all_classes(GENERATOR_MIN_LENGTH - 1, 20)).unwrap_err();
        assert_eq!(err, PasswordPolicyError::InvalidLengthBounds);
    }

    #[test]
    fn no_character_classes_is_rejected() {
        let policy = SealedPasswordPolicy {
            min_length: GENERATOR_MIN_LENGTH,
            max_length: 20,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
        };
        let err = to_generator_request(&policy).unwrap_err();
        assert_eq!(err, PasswordPolicyError::NoCharacterClasses);
    }

    #[test]
    fn single_class_enabled_is_sufficient() {
        for (upper, lower, digits, symbols) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let policy = SealedPasswordPolicy {
                min_length: 30,
                max_length: 30,
                include_uppercase: upper,
                include_lowercase: lower,
                include_digits: digits,
                include_symbols: symbols,
            };
            assert!(
                to_generator_request(&policy).is_ok(),
                "expected Ok for a single enabled class at length 30: \
                 upper={upper} lower={lower} digits={digits} symbols={symbols}"
            );
        }
    }

    #[test]
    fn include_flags_map_correctly() {
        let policy = SealedPasswordPolicy {
            min_length: 30,
            max_length: 30,
            include_uppercase: true,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        let req = to_generator_request(&policy).unwrap();
        assert!(req.uppercase);
        assert!(!req.lowercase);
        assert!(req.numbers);
        assert!(!req.special);
        assert!(req.min_uppercase.is_none());
        assert!(req.min_lowercase.is_none());
        assert!(req.min_number.is_none());
        assert!(req.min_special.is_none());
        assert!(!req.avoid_ambiguous);
        assert!(req.custom_required_chars.is_none());
        assert!(req.custom_allowed_chars.is_none());
        assert!(req.max_consecutive.is_none());
    }

    #[test]
    fn generated_request_produces_valid_password() {
        let req = to_generator_request(&all_classes(14, 32)).unwrap();
        let result = password(req);
        assert!(result.is_ok(), "expected password() to succeed: {result:?}");
        let pwd = result.unwrap();
        assert!(
            pwd.len() >= 5 && pwd.len() <= 128,
            "password length {len} out of expected range",
            len = pwd.len()
        );
    }

    #[test]
    fn generated_password_uses_only_enabled_charset() {
        let policy = SealedPasswordPolicy {
            min_length: 30,
            max_length: 30,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        let req = to_generator_request(&policy).unwrap();
        assert_eq!(req.length, 30);
        let pwd = password(req).unwrap();
        assert!(
            pwd.chars().all(|c| c.is_ascii_digit()),
            "expected only digits in {pwd:?}"
        );
    }

    #[test]
    fn generated_password_at_maximum_length() {
        let req = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH)).unwrap();
        assert_eq!(u32::from(req.length), GENERATOR_MAX_LENGTH);
        let pwd = password(req).unwrap();
        assert_eq!(pwd.len() as u32, GENERATOR_MAX_LENGTH);
    }
}
