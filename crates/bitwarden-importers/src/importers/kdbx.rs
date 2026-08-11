//! KeePass KDBX (`.kdbx`) parser.
//!
//! Parses an encrypted KeePass database (3.1 and 4) via the `keepass` crate and maps its group tree
//! into a [`ParsedImport`] (ciphers + folder paths + relationships) for the generic submit
//! pipeline.

use std::io::Cursor;

use bitwarden_exporters::{CipherType, Field, ImportingCipher, Login, LoginUri};
use chrono::Utc;
use keepass::{
    Database, DatabaseKey,
    db::{
        DatabaseOpenError,
        fields::{NOTES, OTP, PASSWORD, TITLE, URL, USERNAME},
    },
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{ImportError, pipeline::ParsedImport};

/// Maximum group nesting that will be traversed
const MAX_GROUP_DEPTH: usize = 256;

/// KeePass 2.x native TOTP fields and KeePassXC's `otp`
const TOTP_FIELD_KEYS: &[&str] = &[
    OTP,
    "TimeOtp-Secret",
    "TimeOtp-Secret-Hex",
    "TimeOtp-Secret-Base32",
    "TimeOtp-Secret-Base64",
    "TimeOtp-Period",
    "TimeOtp-Length",
    "TimeOtp-Algorithm",
];

/// The first four bytes of every KDBX file: signature `0x9AA2D903`, little-endian.
const KDBX_SIGNATURE: [u8; 4] = [0x03, 0xd9, 0xa2, 0x9a];

/// Ceiling on the input file size
const MAX_KDBX_SIZE: usize = 10 * 1024 * 1024;

fn check_kdbx_size(len: usize) -> Result<(), ImportError> {
    if len > MAX_KDBX_SIZE {
        return Err(ImportError::KdbxFileTooLarge);
    }
    Ok(())
}

/// Parses a KeePass KDBX database, zeroizing the secret inputs (file bytes, password, key file).
pub(crate) fn parse(
    file: Vec<u8>,
    password: Option<String>,
    key_file: Option<Vec<u8>>,
) -> Result<ParsedImport, ImportError> {
    let file = Zeroizing::new(file);
    let password = password.map(Zeroizing::new);
    let key_file = key_file.map(Zeroizing::new);

    parse_kdbx(
        &file,
        password.as_ref().map(|p| p.as_str()),
        key_file.as_ref().map(|k| k.as_slice()),
    )
}

fn parse_kdbx(
    data: &[u8],
    password: Option<&str>,
    key_file: Option<&[u8]>,
) -> Result<ParsedImport, ImportError> {
    check_kdbx_size(data.len())?;

    if data.len() < KDBX_SIGNATURE.len() || data[..KDBX_SIGNATURE.len()] != KDBX_SIGNATURE {
        return Err(ImportError::KdbxInvalidFormat);
    }

    let mut key = DatabaseKey::new();
    if let Some(password) = password {
        key = key.with_password(password);
    }
    if let Some(key_file) = key_file {
        key = key
            .with_keyfile(&mut Cursor::new(key_file))
            .map_err(|_| ImportError::KdbxCorruptOrUnsupported)?;
    }

    let db = Database::open(&mut Cursor::new(data), key).map_err(map_open_error)?;

    // Only treat the UUID as the recycle bin when the feature is enabled; KeePass retains the last
    // recycle-bin UUID after the feature is turned off, and it may still point at a real group.
    let recycle_bin = if db.meta.recyclebin_enabled == Some(true) {
        db.meta.recyclebin_uuid
    } else {
        None
    };
    let mut result = ParsedImport {
        ciphers: Vec::new(),
        folders: Vec::new(),
        folder_relationships: Vec::new(),
    };
    traverse(&db.root(), true, "", recycle_bin, 0, &mut result)?;
    Ok(result)
}

/// Maps `keepass` open errors to the credential-vs-corrupt distinction the UI surfaces.
///
/// A wrong password/key file surfaces as a key or decryption error (KDBX 3.1 has no key HMAC, so it
/// fails as bad padding). keepass's `CryptographyError` isn't public, so we can't separate that
/// from genuine corruption — bias both to wrong-credentials; everything else is
/// corrupt/unsupported.
fn map_open_error(error: DatabaseOpenError) -> ImportError {
    match error {
        DatabaseOpenError::Key(_) | DatabaseOpenError::Cryptography(_) => {
            ImportError::KdbxWrongCredentials
        }
        _ => ImportError::KdbxCorruptOrUnsupported,
    }
}

fn traverse(
    group: &keepass::db::GroupRef<'_>,
    is_root: bool,
    prefix: &str,
    recycle_bin: Option<Uuid>,
    depth: usize,
    result: &mut ParsedImport,
) -> Result<(), ImportError> {
    if depth > MAX_GROUP_DEPTH {
        return Err(ImportError::KdbxCorruptOrUnsupported);
    }

    if let Some(recycle_bin) = recycle_bin
        && group.id().uuid() == recycle_bin
    {
        return Ok(());
    }

    let folder_index = result.folders.len();
    let mut group_name = prefix.to_string();
    if !is_root {
        if !group_name.is_empty() {
            group_name.push('/');
        }
        group_name.push_str(if group.name.trim().is_empty() {
            "-"
        } else {
            &group.name
        });
        result.folders.push(group_name.clone());
    }

    for entry in group.entries() {
        let cipher_index = result.ciphers.len();
        result.ciphers.push(map_entry(&entry));
        if !is_root {
            result
                .folder_relationships
                .push((cipher_index, folder_index));
        }
    }

    for subgroup in group.groups() {
        traverse(
            &subgroup,
            false,
            &group_name,
            recycle_bin,
            depth + 1,
            result,
        )?;
    }

    Ok(())
}

fn map_entry(entry: &keepass::db::EntryRef<'_>) -> ImportingCipher {
    let totp = build_totp(entry);

    let uris = match entry.get_url().filter(|u| !u.trim().is_empty()) {
        Some(url) => vec![LoginUri {
            uri: Some(url.to_string()),
            r#match: None,
        }],
        None => vec![],
    };

    let mut login = Login {
        username: non_empty(entry.get_username()),
        password: non_empty(entry.get_password()),
        login_uris: uris,
        totp,
        fido2_credentials: None,
    };

    login.sanitize_uris();

    let notes = entry
        .get(NOTES)
        .filter(|n| !n.trim().is_empty())
        .map(str::to_string);

    let mut fields = Vec::new();
    for (key, value) in &entry.fields {
        if TOTP_FIELD_KEYS.contains(&key.as_str())
            || [TITLE, USERNAME, PASSWORD, URL, NOTES].contains(&key.as_str())
        {
            continue;
        }
        let text = value.get();
        if text.trim().is_empty() {
            continue;
        }
        // Protected strings import as hidden fields (type 1); plain ones as text (type 0).
        fields.push(Field {
            name: Some(key.clone()),
            value: Some(text.clone()),
            r#type: if value.is_protected() { 1 } else { 0 },
            linked_id: None,
        });
    }

    let now = Utc::now();
    ImportingCipher {
        folder_id: None,
        name: entry
            .get_title()
            .filter(|t| !t.trim().is_empty())
            .unwrap_or("--")
            .to_string(),
        notes,
        r#type: CipherType::Login(Box::new(login)),
        favorite: false,
        reprompt: 0,
        fields,
        revision_date: now,
        creation_date: now,
        deleted_date: None,
    }
}

/// Builds the login TOTP value from either KeePassXC's `otp` field or KeePass 2.x's `TimeOtp-*`
/// fields, returning a Base32 secret for default settings or an otpauth URI otherwise.
fn build_totp(entry: &keepass::db::EntryRef<'_>) -> Option<String> {
    if let Some(otp) = entry.get(OTP).filter(|o| !o.trim().is_empty()) {
        // KeePassXC stores either an `otpauth://` URI or a leading `key=<base32>`. Strip only a
        // leading `key=` so a `key=` occurring elsewhere in a URI isn't mangled.
        return Some(otp.strip_prefix("key=").unwrap_or(otp).to_string());
    }

    let secret = time_otp_secret_as_base32(entry)?;

    let period = non_default(entry.get("TimeOtp-Period"), "30");
    let digits = non_default(entry.get("TimeOtp-Length"), "6");
    let algorithm = totp_algorithm(entry.get("TimeOtp-Algorithm"));

    if period.is_none() && digits.is_none() && algorithm.is_none() {
        return Some(secret);
    }

    let mut query = format!("secret={secret}");
    if let Some(algorithm) = algorithm {
        query.push_str(&format!("&algorithm={algorithm}"));
    }
    if let Some(digits) = digits {
        query.push_str(&format!("&digits={digits}"));
    }
    if let Some(period) = period {
        query.push_str(&format!("&period={period}"));
    }
    Some(format!("otpauth://totp/Imported?{query}"))
}

/// Resolves the KeePass 2.x TOTP secret (in any supported encoding) to a Base32 secret.
fn time_otp_secret_as_base32(entry: &keepass::db::EntryRef<'_>) -> Option<String> {
    if let Some(base32) = entry
        .get("TimeOtp-Secret-Base32")
        .filter(|s| !s.trim().is_empty())
    {
        // Validate by decoding and re-encoding canonically, so malformed input becomes `None`
        // rather than a string that merely looks like a secret (matches the other branches).
        let normalized: String = base32
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '=')
            .collect::<String>()
            .to_uppercase();
        let bytes = data_encoding::BASE32_NOPAD
            .decode(normalized.as_bytes())
            .ok()?;
        return Some(data_encoding::BASE32_NOPAD.encode(&bytes));
    }
    if let Some(base64) = entry
        .get("TimeOtp-Secret-Base64")
        .filter(|s| !s.trim().is_empty())
    {
        let bytes = data_encoding::BASE64
            .decode(base64.trim().as_bytes())
            .ok()?;
        return Some(data_encoding::BASE32_NOPAD.encode(&bytes));
    }
    if let Some(hex) = entry
        .get("TimeOtp-Secret-Hex")
        .filter(|s| !s.trim().is_empty())
    {
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .ok()?;
        return Some(data_encoding::BASE32_NOPAD.encode(&bytes));
    }
    if let Some(utf8) = entry.get("TimeOtp-Secret").filter(|s| !s.trim().is_empty()) {
        return Some(data_encoding::BASE32_NOPAD.encode(utf8.as_bytes()));
    }
    None
}

fn totp_algorithm(value: Option<&str>) -> Option<String> {
    match value.map(|v| v.trim().to_uppercase()).as_deref() {
        Some("HMAC-SHA-256") => Some("SHA256".to_string()),
        Some("HMAC-SHA-512") => Some("SHA512".to_string()),
        _ => None,
    }
}

fn non_default(value: Option<&str>, default: &str) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() || trimmed == default {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty()).map(str::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use keepass::db::{GroupMut, fields};

    use super::*;

    const PASSWORD: &str = "test-password";

    /// Encrypts a database to KDBX4 bytes via the `save_kdbx4` test feature.
    fn save(db: &Database) -> Vec<u8> {
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password(PASSWORD))
            .unwrap();
        bytes
    }

    /// Builds a KDBX4 database and returns its encrypted bytes.
    fn build_db(build: impl FnOnce(&mut GroupMut<'_>)) -> Vec<u8> {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            build(&mut root);
        }
        save(&db)
    }

    fn parse_bytes(bytes: &[u8]) -> ParsedImport {
        parse_kdbx(bytes, Some(PASSWORD), None).unwrap()
    }

    fn login(cipher: &ImportingCipher) -> &Login {
        match &cipher.r#type {
            CipherType::Login(login) => login,
            _ => panic!("expected login"),
        }
    }

    #[test]
    fn maps_standard_fields_and_group_to_folder() {
        let bytes = build_db(|root| {
            let mut group = root.add_group();
            group.name = "Social".into();
            let mut entry = group.add_entry();
            entry.set_unprotected(fields::TITLE, "GitHub");
            entry.set_unprotected(fields::USERNAME, "octocat");
            entry.set_protected(fields::PASSWORD, "hunter2");
            entry.set_unprotected(fields::URL, "https://github.com");
            entry.set_unprotected(fields::NOTES, "my note");
            entry.set_unprotected(fields::OTP, "JBSWY3DPEHPK3PXP");
        });

        let result = parse_bytes(&bytes);

        assert_eq!(result.ciphers.len(), 1);
        let cipher = &result.ciphers[0];
        assert_eq!(cipher.name, "GitHub");
        assert_eq!(cipher.notes.as_deref(), Some("my note"));
        let login = login(cipher);
        assert_eq!(login.username.as_deref(), Some("octocat"));
        assert_eq!(login.password.as_deref(), Some("hunter2"));
        assert_eq!(
            login.login_uris[0].uri.as_deref(),
            Some("https://github.com")
        );
        assert_eq!(login.totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));

        assert_eq!(result.folders, vec!["Social".to_string()]);
        assert_eq!(result.folder_relationships, vec![(0, 0)]);
    }

    #[test]
    fn nested_groups_become_folder_paths() {
        let bytes = build_db(|root| {
            let mut parent = root.add_group();
            parent.name = "Parent".into();
            let mut child = parent.add_group();
            child.name = "Child".into();
            child.add_entry().set_unprotected(fields::TITLE, "Nested");
        });

        let result = parse_bytes(&bytes);

        assert!(result.folders.contains(&"Parent".to_string()));
        assert!(result.folders.contains(&"Parent/Child".to_string()));
        let child_index = result
            .folders
            .iter()
            .position(|f| f == "Parent/Child")
            .unwrap();
        assert_eq!(result.folder_relationships, vec![(0, child_index)]);
    }

    #[test]
    fn protected_strings_are_hidden_fields_plain_are_text() {
        let bytes = build_db(|root| {
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Custom");
            entry.set_unprotected("PlainField", "plain value");
            entry.set_protected("SecretField", "secret value");
        });

        let cipher = &parse_bytes(&bytes).ciphers[0];
        let plain = cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("PlainField"))
            .unwrap();
        let secret = cipher
            .fields
            .iter()
            .find(|f| f.name.as_deref() == Some("SecretField"))
            .unwrap();
        assert_eq!(plain.r#type, 0);
        assert_eq!(plain.value.as_deref(), Some("plain value"));
        assert_eq!(secret.r#type, 1);
        assert_eq!(secret.value.as_deref(), Some("secret value"));
    }

    #[test]
    fn time_otp_base32_maps_totp() {
        let bytes = build_db(|root| {
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Entry with OTP");
            entry.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
        });

        let cipher = &parse_bytes(&bytes).ciphers[0];
        assert_eq!(login(cipher).totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(
            !cipher
                .fields
                .iter()
                .any(|f| f.name.as_deref() == Some("TimeOtp-Secret-Base32"))
        );
    }

    #[test]
    fn time_otp_non_default_settings_build_otpauth_uri() {
        let bytes = build_db(|root| {
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Custom OTP");
            entry.set_protected("TimeOtp-Secret-Base32", "JBSWY3DPEHPK3PXP");
            entry.set_unprotected("TimeOtp-Period", "60");
            entry.set_unprotected("TimeOtp-Length", "8");
            entry.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
        });

        let cipher = &parse_bytes(&bytes).ciphers[0];
        let totp = login(cipher).totp.as_deref().unwrap();
        assert!(totp.starts_with("otpauth://totp/"));
        assert!(totp.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(totp.contains("period=60"));
        assert!(totp.contains("digits=8"));
        assert!(totp.contains("algorithm=SHA256"));
    }

    #[test]
    fn time_otp_secret_encodings_convert_to_base32() {
        // "Hello" encodes to the Base32 secret "JBSWY3DP".
        for (field, value) in [
            ("TimeOtp-Secret-Base64", "SGVsbG8="),
            ("TimeOtp-Secret-Hex", "48656c6c6f"),
            ("TimeOtp-Secret", "Hello"),
        ] {
            let bytes = build_db(|root| {
                let mut entry = root.add_entry();
                entry.set_unprotected(fields::TITLE, "Encoded OTP");
                entry.set_protected(field, value);
            });
            let cipher = &parse_bytes(&bytes).ciphers[0];
            assert_eq!(
                login(cipher).totp.as_deref(),
                Some("JBSWY3DP"),
                "field {field}"
            );
        }
    }

    #[test]
    fn wrong_password_is_wrong_credentials() {
        let bytes = build_db(|root| {
            root.add_entry().set_unprotected(fields::TITLE, "Secret");
        });

        assert!(matches!(
            parse_kdbx(&bytes, Some("incorrect"), None),
            Err(ImportError::KdbxWrongCredentials)
        ));
    }

    #[test]
    fn non_kdbx_input_is_invalid_format() {
        assert!(matches!(
            parse_kdbx(b"not a kdbx file", Some(PASSWORD), None),
            Err(ImportError::KdbxInvalidFormat)
        ));
    }

    #[test]
    fn input_over_size_limit_is_rejected() {
        // Boundary-checked on length so the test doesn't allocate a multi-hundred-MB buffer.
        assert!(check_kdbx_size(MAX_KDBX_SIZE).is_ok());
        assert!(matches!(
            check_kdbx_size(MAX_KDBX_SIZE + 1),
            Err(ImportError::KdbxFileTooLarge)
        ));
    }

    /// Builds a db whose only group is referenced by `recyclebin_uuid`, with the feature toggled.
    fn db_with_recycle_bin(enabled: bool) -> Vec<u8> {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut group = root.add_group();
            group.name = "Trash".into();
            group.add_entry().set_unprotected(fields::TITLE, "in trash");
        }
        let group_id = db.root().groups().next().unwrap().id().uuid();
        db.meta.recyclebin_enabled = Some(enabled);
        db.meta.recyclebin_uuid = Some(group_id);
        save(&db)
    }

    #[test]
    fn recycle_bin_group_is_skipped_when_enabled() {
        let result = parse_bytes(&db_with_recycle_bin(true));
        assert!(result.ciphers.is_empty());
        assert!(result.folders.is_empty());
    }

    #[test]
    fn recycle_bin_uuid_is_ignored_when_disabled() {
        // The feature is off, so the still-present UUID must not cause the group to be dropped.
        let result = parse_bytes(&db_with_recycle_bin(false));
        assert_eq!(result.folders, vec!["Trash".to_string()]);
        assert_eq!(result.ciphers.len(), 1);
        assert_eq!(result.ciphers[0].name, "in trash");
    }
}
