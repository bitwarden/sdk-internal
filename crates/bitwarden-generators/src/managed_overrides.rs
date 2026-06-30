//! [`ApplyManagedOverride`] implementations for the generator request types.
//!
//! Maps the dotted-key namespace onto the typed fields of
//! [`PasswordGeneratorRequest`] and [`PassphraseGeneratorRequest`], clamping to
//! the existing `MINIMUM_*` / `MAXIMUM_*` constants.
//!
//! The trait is **infallible**. A bad value in the profile is clamped to the
//! valid range or ignored. Failure to apply admin policy must never block the
//! user from generating a credential.

use bitwarden_managed_settings::{ApplyManagedOverride, ManagementProfile};

use crate::{
    PassphraseGeneratorRequest, PasswordGeneratorRequest,
    passphrase::{MAXIMUM_PASSPHRASE_NUM_WORDS, MINIMUM_PASSPHRASE_NUM_WORDS},
    password::{
        MAXIMUM_MIN_CHAR_COUNT, MAXIMUM_PASSWORD_LENGTH, MINIMUM_MIN_CHAR_COUNT,
        MINIMUM_PASSWORD_LENGTH,
    },
};

/// Read a u8 from the profile under `key`, clamped to `[min, max]`. Returns `None`
/// when the key is absent or the value fails to decode.
fn read_u8_clamped(profile: &ManagementProfile, key: &str, min: u8, max: u8) -> Option<u8> {
    profile
        .get_as::<u64>(key)
        .ok()
        .flatten()
        .map(|v| v.clamp(min as u64, max as u64) as u8)
}

fn read_bool(profile: &ManagementProfile, key: &str) -> Option<bool> {
    profile.get_as::<bool>(key).ok().flatten()
}

fn read_string_nonempty(profile: &ManagementProfile, key: &str) -> Option<String> {
    profile
        .get_as::<String>(key)
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
}

impl ApplyManagedOverride for PasswordGeneratorRequest {
    fn apply_managed_override(mut self, profile: &ManagementProfile) -> Self {
        if let Some(v) = read_bool(profile, "generator.password.lowercase") {
            self.lowercase = v;
        }
        if let Some(v) = read_bool(profile, "generator.password.uppercase") {
            self.uppercase = v;
        }
        if let Some(v) = read_bool(profile, "generator.password.numbers") {
            self.numbers = v;
        }
        if let Some(v) = read_bool(profile, "generator.password.special") {
            self.special = v;
        }
        if let Some(v) = read_bool(profile, "generator.password.avoidAmbiguous") {
            self.avoid_ambiguous = v;
        }
        if let Some(v) = read_u8_clamped(
            profile,
            "generator.password.length",
            MINIMUM_PASSWORD_LENGTH,
            MAXIMUM_PASSWORD_LENGTH,
        ) {
            self.length = v;
        }
        if let Some(v) = read_u8_clamped(
            profile,
            "generator.password.minLowercase",
            MINIMUM_MIN_CHAR_COUNT,
            MAXIMUM_MIN_CHAR_COUNT,
        ) {
            self.min_lowercase = Some(v);
        }
        if let Some(v) = read_u8_clamped(
            profile,
            "generator.password.minUppercase",
            MINIMUM_MIN_CHAR_COUNT,
            MAXIMUM_MIN_CHAR_COUNT,
        ) {
            self.min_uppercase = Some(v);
        }
        if let Some(v) = read_u8_clamped(
            profile,
            "generator.password.minNumber",
            MINIMUM_MIN_CHAR_COUNT,
            MAXIMUM_MIN_CHAR_COUNT,
        ) {
            self.min_number = Some(v);
        }
        if let Some(v) = read_u8_clamped(
            profile,
            "generator.password.minSpecial",
            MINIMUM_MIN_CHAR_COUNT,
            MAXIMUM_MIN_CHAR_COUNT,
        ) {
            self.min_special = Some(v);
        }
        self
    }
}

impl ApplyManagedOverride for PassphraseGeneratorRequest {
    fn apply_managed_override(mut self, profile: &ManagementProfile) -> Self {
        if let Some(v) = read_u8_clamped(
            profile,
            "generator.passphrase.numWords",
            MINIMUM_PASSPHRASE_NUM_WORDS,
            MAXIMUM_PASSPHRASE_NUM_WORDS,
        ) {
            self.num_words = v;
        }
        if let Some(v) = read_string_nonempty(profile, "generator.passphrase.wordSeparator") {
            self.word_separator = v;
        }
        if let Some(v) = read_bool(profile, "generator.passphrase.capitalize") {
            self.capitalize = v;
        }
        if let Some(v) = read_bool(profile, "generator.passphrase.includeNumber") {
            self.include_number = v;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_managed_settings::ManagementProfile;

    use super::*;

    fn profile_with(pairs: &[(&str, &str)]) -> ManagementProfile {
        let mut p = ManagementProfile::empty();
        for (k, v) in pairs {
            p.settings.insert((*k).to_owned(), (*v).to_owned());
        }
        p
    }

    #[test]
    fn password_no_profile_keys_leaves_request_unchanged() {
        let req = PasswordGeneratorRequest {
            length: 12,
            uppercase: false,
            ..Default::default()
        };
        let profile = ManagementProfile::empty();
        let out = PasswordGeneratorRequest {
            length: 12,
            uppercase: false,
            ..Default::default()
        }
        .apply_managed_override(&profile);

        assert_eq!(out.length, req.length);
        assert_eq!(out.uppercase, req.uppercase);
    }

    #[test]
    fn password_length_forced_to_20_overrides_12() {
        let profile = profile_with(&[("generator.password.length", "20")]);
        let req = PasswordGeneratorRequest {
            length: 12,
            ..Default::default()
        };
        let out = req.apply_managed_override(&profile);
        assert_eq!(out.length, 20);
    }

    #[test]
    fn password_length_clamped_to_maximum() {
        let profile = profile_with(&[("generator.password.length", "500")]);
        let out = PasswordGeneratorRequest::default().apply_managed_override(&profile);
        assert_eq!(out.length, MAXIMUM_PASSWORD_LENGTH);
    }

    #[test]
    fn password_length_clamped_to_minimum() {
        let profile = profile_with(&[("generator.password.length", "1")]);
        let out = PasswordGeneratorRequest::default().apply_managed_override(&profile);
        assert_eq!(out.length, MINIMUM_PASSWORD_LENGTH);
    }

    #[test]
    fn password_bool_fields_apply() {
        let profile = profile_with(&[
            ("generator.password.uppercase", "true"),
            ("generator.password.special", "true"),
            ("generator.password.avoidAmbiguous", "true"),
        ]);
        let out = PasswordGeneratorRequest {
            uppercase: false,
            special: false,
            avoid_ambiguous: false,
            ..Default::default()
        }
        .apply_managed_override(&profile);
        assert!(out.uppercase);
        assert!(out.special);
        assert!(out.avoid_ambiguous);
    }

    #[test]
    fn password_min_special_applied_and_clamped() {
        let profile = profile_with(&[("generator.password.minSpecial", "12")]);
        let out = PasswordGeneratorRequest::default().apply_managed_override(&profile);
        assert_eq!(out.min_special, Some(MAXIMUM_MIN_CHAR_COUNT));
    }

    #[test]
    fn password_bad_value_ignored() {
        let profile = profile_with(&[("generator.password.length", "\"not-a-number\"")]);
        let out = PasswordGeneratorRequest {
            length: 12,
            ..Default::default()
        }
        .apply_managed_override(&profile);
        // Bad value silently dropped, request unchanged.
        assert_eq!(out.length, 12);
    }

    #[test]
    fn passphrase_overrides_apply() {
        let profile = profile_with(&[
            ("generator.passphrase.numWords", "7"),
            ("generator.passphrase.wordSeparator", "\"-\""),
            ("generator.passphrase.capitalize", "true"),
            ("generator.passphrase.includeNumber", "true"),
        ]);
        let out = PassphraseGeneratorRequest::default().apply_managed_override(&profile);
        assert_eq!(out.num_words, 7);
        assert_eq!(out.word_separator, "-");
        assert!(out.capitalize);
        assert!(out.include_number);
    }

    #[test]
    fn passphrase_num_words_clamped() {
        let profile = profile_with(&[("generator.passphrase.numWords", "50")]);
        let out = PassphraseGeneratorRequest::default().apply_managed_override(&profile);
        assert_eq!(out.num_words, MAXIMUM_PASSPHRASE_NUM_WORDS);
    }

    #[test]
    fn passphrase_empty_separator_ignored() {
        let profile = profile_with(&[("generator.passphrase.wordSeparator", "\"\"")]);
        let out = PassphraseGeneratorRequest::default().apply_managed_override(&profile);
        // Default separator preserved.
        assert_eq!(out.word_separator, " ");
    }
}
