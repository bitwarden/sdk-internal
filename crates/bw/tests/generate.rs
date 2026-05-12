//! Integration tests for the `bw generate` command.
//!
//! These tests run against the compiled binary without authentication,
//! so no organization policies are applied. They verify flag parsing,
//! default values, clamping behavior, and output format.

mod common;
use common::bw;

// -- Password defaults and flags --

#[test]
fn test_generate_default_password_length() {
    let output = bw().arg("generate").output().expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim().len(),
        14,
        "Default password length should be 14"
    );
}

#[test]
fn test_generate_explicit_length() {
    let output = bw()
        .args(["generate", "--length", "25"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim().len(), 25);
}

#[test]
fn test_generate_length_clamped_to_5() {
    let output = bw()
        .args(["generate", "--length", "3"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim().len(),
        5,
        "Length below 5 should be clamped to 5"
    );
}

#[test]
fn test_generate_length_clamped_to_128() {
    let output = bw()
        .args(["generate", "--length", "200"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim().len(),
        128,
        "Length above 128 should be clamped to 128"
    );
}

#[test]
fn test_generate_min_number_clamped_to_9() {
    // `min_number` above 9 would cause the SDK to fail with an InvalidLength error
    // because `min_number + min_special > length`. The CLI silently clamps to 9
    // (matching the legacy CLI / Angular clients' `fitToBounds` behavior).
    let output = bw()
        .args(["generate", "-ln", "--length", "20", "--min-number", "20"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success(), "min-number > 9 should be clamped");
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.len(), 20);
}

#[test]
fn test_generate_min_number_enables_numbers() {
    // Only lowercase is explicitly selected, but `--min-number 3` should cascade
    // into enabling numbers — matching `PasswordGeneratorOptionsEvaluator.applyPolicy`.
    let output = bw()
        .args(["generate", "-l", "--min-number", "3", "--length", "20"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        password.chars().any(|c| c.is_ascii_digit()),
        "--min-number should cascade into enabling numbers, got: {}",
        password
    );
}

#[test]
fn test_generate_min_special_enables_special() {
    let output = bw()
        .args(["generate", "-l", "--min-special", "3", "--length", "20"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let special_chars = ['!', '@', '#', '$', '%', '^', '&', '*'];
    assert!(
        password.chars().any(|c| special_chars.contains(&c)),
        "--min-special should cascade into enabling special chars, got: {}",
        password
    );
}

#[test]
fn test_generate_uppercase_only() {
    let output = bw()
        .args(["generate", "--uppercase"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.len(), 14);
    assert!(
        password.chars().all(|c| c.is_ascii_uppercase()),
        "Password should only contain uppercase characters, got: {}",
        password
    );
}

#[test]
fn test_generate_lowercase_only() {
    let output = bw()
        .args(["generate", "--lowercase"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        password.chars().all(|c| c.is_ascii_lowercase()),
        "Password should only contain lowercase characters, got: {}",
        password
    );
}

#[test]
fn test_generate_all_charsets() {
    let output = bw()
        .args(["generate", "-ulns", "--length", "50"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.len(), 50);
    // With length 50 and all charsets, statistically all should be present.
    // Use a loose check: at least some non-alpha characters.
    assert!(
        password.chars().any(|c| c.is_ascii_digit()),
        "With -n flag, password should contain digits: {}",
        password
    );
}

#[test]
fn test_generate_ambiguous_flag() {
    let output = bw()
        .args(["generate", "--ambiguous", "--length", "50", "-uln"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let ambiguous_chars = ['I', 'O', 'l', '0', '1'];
    assert!(
        !password.chars().any(|c| ambiguous_chars.contains(&c)),
        "Password should not contain ambiguous characters (I, O, l, 0, 1), got: {}",
        password
    );
}

#[test]
fn test_generate_camelcase_aliases_work() {
    let output = bw()
        .args([
            "generate",
            "-ulns",
            "--minNumber",
            "3",
            "--minSpecial",
            "2",
            "--length",
            "20",
        ])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(password.len(), 20);
}

// -- Passphrase defaults and flags --

#[test]
fn test_generate_passphrase_default_words() {
    let output = bw()
        .args(["generate", "-p"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let word_count = stdout.split('-').count();
    assert_eq!(
        word_count, 6,
        "Default passphrase should have 6 words, got: {}",
        stdout
    );
}

#[test]
fn test_generate_passphrase_explicit_words() {
    let output = bw()
        .args(["generate", "-p", "--words", "4"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let word_count = stdout.split('-').count();
    assert_eq!(word_count, 4);
}

#[test]
fn test_generate_passphrase_words_clamped_to_3() {
    let output = bw()
        .args(["generate", "-p", "--words", "1"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let word_count = stdout.split('-').count();
    assert_eq!(word_count, 3, "Words below 3 should be clamped to 3");
}

#[test]
fn test_generate_passphrase_words_clamped_to_20() {
    let output = bw()
        .args(["generate", "-p", "--words", "50"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let word_count = stdout.split('-').count();
    assert_eq!(word_count, 20, "Words above 20 should be clamped to 20");
}

#[test]
fn test_generate_passphrase_separator_space() {
    let output = bw()
        .args(["generate", "-p", "--separator", "space"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        stdout.contains(' '),
        "Passphrase should contain spaces: {}",
        stdout
    );
    assert!(
        !stdout.contains("space"),
        "Passphrase should not contain literal 'space': {}",
        stdout
    );
}

#[test]
fn test_generate_passphrase_separator_empty() {
    let output = bw()
        .args(["generate", "-p", "--separator", "empty"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !stdout.contains('-') && !stdout.contains(' '),
        "Passphrase with empty separator should have no delimiters: {}",
        stdout
    );
}

#[test]
fn test_generate_passphrase_capitalize() {
    let output = bw()
        .args(["generate", "-p", "--capitalize"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    for word in stdout.split('-') {
        assert!(
            word.starts_with(|c: char| c.is_uppercase()),
            "Each word should be capitalized, got: {}",
            word
        );
    }
}

#[test]
fn test_generate_passphrase_include_number_alias() {
    // Test that the camelCase alias --includeNumber works
    let output = bw()
        .args(["generate", "-p", "--includeNumber"])
        .output()
        .expect("Failed to execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        stdout.chars().any(|c| c.is_ascii_digit()),
        "Passphrase with --includeNumber should contain a digit: {}",
        stdout
    );
}

// -- No-flag default charset behavior --

#[test]
fn test_generate_no_flags_uses_uppercase_lowercase_numbers() {
    // Run multiple times to increase confidence (default is -uln)
    for _ in 0..3 {
        let output = bw().arg("generate").output().expect("Failed to execute");
        assert!(output.status.success());
        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let has_special = password.chars().any(|c| "!@#$%^&*".contains(c));
        assert!(
            !has_special,
            "Default password should not contain special characters (default is -uln), got: {}",
            password
        );
    }
}
