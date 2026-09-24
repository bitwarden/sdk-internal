//! Converter tests, driven over the captured 1Password account.
//!
//! The vaults come out of the production download path replayed over recorded server responses,
//! so these tests see exactly what an import would. Synthetic details cover the shapes the capture
//! has no example of.

use bitwarden_exporters::{CipherType, ImportingCipher, Login};

use super::{
    category::{first_totp, login},
    claimed::Claimed,
    convert,
    field::{HIDDEN_FIELD, fields_from_details},
};
use crate::{
    importers::onepassword::access::{
        model::ItemCategory,
        replay::download_captured_account,
        wire::{VaultItemDetails, VaultItemOverview},
    },
    pipeline::ParsedImport,
};

/// Converts the captured account. The vaults come out of the production download path, driven
/// over the recorded server responses, so these tests see exactly what an import would.
async fn converted() -> ParsedImport {
    convert(download_captured_account().await)
}

fn cipher<'a>(parsed: &'a ParsedImport, name: &str) -> &'a ImportingCipher {
    parsed
        .ciphers
        .iter()
        .find(|cipher| cipher.name == name)
        .unwrap_or_else(|| panic!("no cipher named {name}"))
}

fn login_of(cipher: &ImportingCipher) -> &Login {
    match &cipher.r#type {
        CipherType::Login(login) => login,
        other => panic!("{} is a {other}, expected a login", cipher.name),
    }
}

fn uris(login: &Login) -> Vec<&str> {
    login
        .login_uris
        .iter()
        .map(|uri| uri.uri.as_deref().expect("a uri"))
        .collect()
}

/// The cipher's custom fields as `(type, name, value)`, in order.
fn fields_of(cipher: &ImportingCipher) -> Vec<(u8, &str, &str)> {
    cipher
        .fields
        .iter()
        .map(|field| {
            (
                field.r#type,
                field.name.as_deref().expect("a name"),
                field.value.as_deref().expect("a value"),
            )
        })
        .collect()
}

/// Builds a value the way 1Password sends it, for the shapes the captured account has no
/// example of.
fn fields_from_json(details: serde_json::Value) -> Vec<(u8, String, String)> {
    rendered(&details_from_json(details), &Claimed::default())
}

/// The custom fields left over after `claimed`, as `(type, name, value)`.
fn rendered(details: &VaultItemDetails, claimed: &Claimed) -> Vec<(u8, String, String)> {
    fields_from_details(details, claimed)
        .into_iter()
        .map(|field| {
            (
                field.r#type,
                field.name.expect("a name"),
                field.value.expect("a value"),
            )
        })
        .collect()
}

fn details_from_json(details: serde_json::Value) -> VaultItemDetails {
    serde_json::from_value(details).expect("valid details")
}

/// An overview with nothing in it, for the mappings that only read the details.
fn overview() -> VaultItemOverview {
    serde_json::from_value(serde_json::json!({})).expect("valid overview")
}

fn section_field(kind: &str, value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "sections": [{"name": "s", "title": "Section", "fields": [
            {"n": "id", "t": "the field", "k": kind, "v": value}
        ]}]
    })
}

#[tokio::test]
async fn every_vault_becomes_a_folder_holding_its_items() {
    let parsed = converted().await;

    assert_eq!(parsed.folders, vec!["Personal", "Importer"]);
    assert_eq!(parsed.ciphers.len(), 28);
    // Nothing is dropped and nothing is left folderless.
    assert_eq!(parsed.folder_relationships.len(), parsed.ciphers.len());

    let personal = parsed
        .folder_relationships
        .iter()
        .filter(|(_, folder)| *folder == 0)
        .count();
    assert_eq!(personal, 1);
}

#[tokio::test]
async fn a_login_takes_its_credentials_from_the_designation_fields() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Login: username, password and one URL");
    let login = login_of(cipher);

    assert_eq!(login.username.as_deref(), Some("plain@example.com"));
    assert_eq!(login.password.as_deref(), Some("plain-pass"));
    assert_eq!(
        cipher.notes.as_deref(),
        Some("A login with nothing but the basics.")
    );
    // Both credential fields were claimed, so neither is repeated as a custom field.
    assert_eq!(fields_of(cipher), []);
}

/// 1Password lets both credential fields stay empty; the item is still a login.
#[tokio::test]
async fn a_login_without_credentials_keeps_its_type() {
    let parsed = converted().await;
    let login = login_of(cipher(
        &parsed,
        "Login: sections only, no username or password",
    ));

    assert_eq!(login.username, None);
    assert_eq!(login.password, None);
}

/// The overview carries the primary address twice, in `url` and again in `URLs`.
#[tokio::test]
async fn a_repeated_website_address_becomes_one_uri() {
    let parsed = converted().await;
    let login = login_of(cipher(&parsed, "Login: username, password and one URL"));

    assert_eq!(uris(login), ["https://plain.example.com"]);
}

#[tokio::test]
async fn every_website_address_arrives_in_order() {
    let parsed = converted().await;
    let login = login_of(cipher(&parsed, "Login: three website URLs"));

    assert_eq!(
        uris(login),
        [
            "https://primary.example.com",
            "https://admin.example.com",
            "https://unlabelled.example.com",
        ]
    );
}

#[tokio::test]
async fn a_secure_note_keeps_its_multiline_note() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Note: multiline text only");

    assert!(matches!(cipher.r#type, CipherType::SecureNote(_)));
    assert_eq!(
        cipher.notes.as_deref(),
        Some("A secret note.\nWith a second line.")
    );
}

#[tokio::test]
async fn a_login_takes_its_one_time_password() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Login: TOTP field");

    assert_eq!(
        login_of(cipher).totp.as_deref(),
        Some(
            "otpauth://totp/totp.example.com:totp@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        )
    );
    // The field it came from was claimed, so it is not repeated as a custom field.
    assert_eq!(fields_of(cipher), []);
}

/// A cipher has room for one one-time password, so the others stay custom fields rather than
/// being dropped.
#[tokio::test]
async fn a_second_one_time_password_stays_a_custom_field() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Login: two TOTP fields");

    assert_eq!(
        login_of(cipher).totp.as_deref(),
        Some("otpauth://totp/first?secret=JBSWY3DPEHPK3PXP&issuer=First")
    );
    assert_eq!(
        fields_of(cipher),
        [(
            1,
            "second code",
            "otpauth://totp/second?secret=KRSXG5CTMVRXEZLU&issuer=Second"
        )]
    );
}

/// A `TOTP_` field with no secret would otherwise be taken as the one-time password, leaving
/// the real one behind in a custom field.
#[test]
fn an_empty_one_time_password_field_is_passed_over() {
    let details = details_from_json(serde_json::json!({
        "sections": [{"fields": [
            {"n": "TOTP_blank", "t": "one-time password", "k": "concealed", "v": ""},
            {"n": "TOTP_live", "t": "one-time password", "k": "concealed", "v": "otpauth://totp/real"},
        ]}]
    }));

    assert_eq!(
        first_totp(&details),
        Some((1, "otpauth://totp/real".to_string()))
    );
}

/// A claim names the exact field the mapping read. 1Password does not repeat a field id, but
/// claiming by id would spend the claim on the wrong occurrence: the secret would arrive twice
/// when the field ahead of it is blank, and a value the mapping skipped would be dropped.
#[test]
fn a_claim_is_spent_on_the_field_the_mapping_read() {
    let two_totps = |first: serde_json::Value| {
        details_from_json(serde_json::json!({
            "sections": [{"fields": [
                {"n": "TOTP_x", "t": "one-time password", "k": "concealed", "v": first},
                {"n": "TOTP_x", "t": "one-time password", "k": "concealed", "v": "otpauth://totp/real"},
            ]}]
        }))
    };
    let mapped = |first: serde_json::Value| {
        let details = two_totps(first);
        let (login, claimed) = login(&overview(), &details);
        (login.totp, rendered(&details, &claimed))
    };
    let leftover_totp = |value: &str| {
        [(
            HIDDEN_FIELD,
            "one-time password".to_string(),
            value.to_string(),
        )]
    };

    // The mapping reads the first field, so the second one stays behind.
    let (totp, leftover) = mapped(serde_json::json!("otpauth://totp/first"));
    assert_eq!(totp.as_deref(), Some("otpauth://totp/first"));
    assert_eq!(leftover, leftover_totp("otpauth://totp/real"));

    // A blank field ahead of the secret is passed over and leaves nothing behind.
    let (totp, leftover) = mapped(serde_json::json!(""));
    assert_eq!(totp.as_deref(), Some("otpauth://totp/real"));
    assert_eq!(leftover, []);

    // A value the mapping cannot read as a secret survives as a custom field.
    let (totp, leftover) = mapped(serde_json::json!(12345));
    assert_eq!(totp.as_deref(), Some("otpauth://totp/real"));
    assert_eq!(leftover, leftover_totp("12345"));
}

/// 1Password ships the whole category template, so a `file` field can arrive with no
/// attachment behind it. It must not become a placeholder for a file that does not exist.
#[test]
fn a_file_field_without_an_attachment_is_dropped() {
    for empty in [
        serde_json::json!(null),
        serde_json::json!(""),
        serde_json::json!("   "),
    ] {
        assert_eq!(fields_from_json(section_field("file", empty)), []);
    }
}

/// Tags are multi-valued and Bitwarden has nowhere to put them, so they ride along in a field
/// of their own rather than being dropped.
#[tokio::test]
async fn tags_arrive_as_a_field_of_their_own() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Login: tags and favorite");

    assert_eq!(fields_of(cipher), [(0, "tags", "work, archive, two words")]);
}

/// An import moves vault data, not files, so a document says in its note that its file stayed
/// behind rather than arriving as an empty item.
#[tokio::test]
async fn a_document_says_its_file_did_not_come_along() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Document: uploaded text file");

    assert!(matches!(cipher.r#type, CipherType::SecureNote(_)));
    assert_eq!(
        cipher.notes.as_deref(),
        Some("This was a 1Password document. The attached file was not imported.")
    );
}

#[tokio::test]
async fn a_concealed_field_imports_as_hidden() {
    let parsed = converted().await;

    assert_eq!(
        fields_of(cipher(&parsed, "Note: text plus custom fields")),
        [
            (0, "visible", "note text field"),
            (1, "secret", "note hidden field"),
        ]
    );
}

/// A section 1Password stores without labels names each field by its stable id instead.
#[tokio::test]
async fn a_field_without_a_label_is_named_by_its_id() {
    let parsed = converted().await;

    assert_eq!(
        fields_of(cipher(&parsed, "Login: section and fields with no label")),
        [
            (
                0,
                "6d6s6bmocbmogfgrvx6czy5hha",
                "a field whose label is empty"
            ),
            (
                0,
                "gjxykv6pufvfme5y2unkccugzq",
                "https://nolabel.example.com"
            ),
        ]
    );
}

/// The same label in two sections lands twice: Bitwarden custom fields are a flat list.
#[tokio::test]
async fn two_sections_may_repeat_a_field_label() {
    let parsed = converted().await;

    assert_eq!(
        fields_of(cipher(&parsed, "Login: same field label in two sections")),
        [
            (1, "api key", "prod-key-111"),
            (0, "host", "prod.example.com"),
            (1, "api key", "staging-key-222"),
            (0, "host", "staging.example.com"),
        ]
    );
}

#[tokio::test]
async fn text_survives_whatever_it_is_made_of() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Login: unicode, emoji and multiline values");
    let login = login_of(cipher);

    assert_eq!(login.username.as_deref(), Some("ünïcödé@example.com"));
    assert_eq!(login.password.as_deref(), Some("пароль-密码-🔑"));

    let fields = fields_of(cipher);
    assert!(fields.contains(&(0, "cjk", "日本語のテキストと中文文本")));
    assert!(fields.contains(&(
        0,
        "multiline",
        "first line\nsecond line\n\nfourth line after a blank one"
    )));
}

#[tokio::test]
async fn a_date_renders_as_a_calendar_day() {
    let parsed = converted().await;
    let fields = fields_of(cipher(&parsed, "Passport: three date fields and text"));

    assert!(fields.contains(&(0, "date of birth", "1990-03-15")));
    assert!(fields.contains(&(0, "issued on", "2020-07-01")));
    assert!(fields.contains(&(0, "expiry date", "2030-06-30")));
}

/// 1Password writes midnight in the writer's own zone: the first stamp is midnight in Berlin,
/// the second midnight in New York, and both mean the fourth of March.
#[test]
fn a_date_lands_on_the_same_day_from_either_side_of_utc() {
    for seconds in [1772578800, 1772600400] {
        assert_eq!(
            fields_from_json(section_field("date", serde_json::json!(seconds))),
            [(0, "the field".to_string(), "2026-03-04".to_string())],
            "{seconds} landed on the wrong day"
        );
    }
}

/// 1Password stores a month/year as `202811`, which no reader would guess at.
#[tokio::test]
async fn a_month_year_renders_as_year_and_month() {
    let parsed = converted().await;
    let fields = fields_of(cipher(&parsed, "Card: monthYear expiry, CVV and PIN"));

    assert!(fields.contains(&(0, "expiry date", "2028-11")));
    assert!(fields.contains(&(0, "valid from", "2024-01")));
}

/// A month outside 1..=12 is not a month/year at all, so the raw value survives instead.
#[test]
fn a_malformed_month_year_keeps_its_digits() {
    assert_eq!(
        fields_from_json(section_field("monthYear", serde_json::json!(209913))),
        [(0, "the field".to_string(), "209913".to_string())]
    );
}

/// The parts keep the order 1Password sent them in.
#[test]
fn an_address_becomes_one_field_per_part_it_fills_in() {
    let address = serde_json::json!({
        "street": "221B Baker Street",
        "city": "London",
        "state": "",
        "zip": "NW1 6XE",
    });

    assert_eq!(
        fields_from_json(section_field("address", address)),
        [
            (0, "street".to_string(), "221B Baker Street".to_string()),
            (0, "city".to_string(), "London".to_string()),
            (0, "zip".to_string(), "NW1 6XE".to_string()),
        ]
    );
}

/// An attachment's value carries the keys that unwrap the stored file, so only its name is
/// kept: the file itself cannot be imported.
#[tokio::test]
async fn an_attachment_keeps_only_its_name() {
    let parsed = converted().await;

    assert_eq!(
        fields_of(cipher(&parsed, "Login: file attachment")),
        [(0, "attached", "<attachment: attached>")]
    );
}

/// Only Login has a mapping so far. Everything else arrives as a note whose fields carry the
/// whole item, rather than failing the import or vanishing.
#[tokio::test]
async fn every_other_category_becomes_a_secure_note() {
    let vaults = download_captured_account().await;
    let others: Vec<String> = vaults
        .iter()
        .flat_map(|vault| &vault.items)
        .filter(|item| item.category != ItemCategory::Login)
        .map(|item| item.overview.title.clone().expect("a title"))
        .collect();
    assert_eq!(others.len(), 15);

    let parsed = convert(vaults);
    for title in others {
        assert!(
            matches!(cipher(&parsed, &title).r#type, CipherType::SecureNote(_)),
            "{title} has a mapping now, give it a test of its own"
        );
    }
}
