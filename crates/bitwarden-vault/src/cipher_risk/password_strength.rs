//! Password strength calculation using zxcvbn with cipher context.
//!
//! This module implements password strength scoring with cipher-specific
//! context (username/email) to penalize weak passwords.

/// Calculate password strength with cipher-specific context.
///
/// Uses zxcvbn to score password strength from 0 (weakest) to 4 (strongest).
/// Penalizes passwords that contain parts of the username/email.
pub(super) fn calculate_password_strength(password: &str, username: Option<&str>) -> u8 {
    let mut user_inputs = Vec::new();

    // Extract meaningful parts from username field
    if let Some(username) = username {
        user_inputs.extend(extract_user_inputs(username));
    }

    // Call zxcvbn with cipher-specific inputs only (no "bitwarden" globals)
    let inputs_refs: Vec<&str> = user_inputs.iter().map(|s| s.as_str()).collect();
    zxcvbn::zxcvbn(password, &inputs_refs).score().into()
}

/// Extract meaningful tokens from username/email for password penalization.
///
/// Handles both email addresses and plain usernames:
/// - For emails: extracts and tokenizes the local part (before @)
/// - For usernames: tokenizes the entire string
/// - Splits on non-alphanumeric characters and converts to lowercase
fn extract_user_inputs(username: &str) -> Vec<String> {
    username
        // Check if it's email-like (contains @)
        .split_once('@')
        // Email: extract local part tokens
        .map_or(username, |(local_part, _domain)| local_part)
        .trim()
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_user_inputs_from_email() {
        let inputs = extract_user_inputs("john.doe@example.com");
        assert_eq!(inputs, vec!["john", "doe"]);
    }

    #[test]
    fn test_extract_user_inputs_from_username() {
        let inputs = extract_user_inputs("john_doe123");
        assert_eq!(inputs, vec!["john", "doe123"]);
    }

    #[test]
    fn test_extract_user_inputs_lowercase() {
        let inputs = extract_user_inputs("JohnDoe@Example.COM");
        assert_eq!(inputs, vec!["johndoe"]);
    }

    #[test]
    fn test_extract_user_inputs_empty() {
        let inputs = extract_user_inputs("");
        assert!(inputs.is_empty());
    }

    #[test]
    fn test_calculate_password_strength_penalizes_username() {
        // Password containing username should be weaker
        let strength_with_username = calculate_password_strength("johndoe123!", Some("johndoe"));
        let strength_without_username = calculate_password_strength("johndoe123!", None);

        assert!(
            strength_with_username <= strength_without_username,
            "Password should be weaker when it contains username"
        );
    }
}
