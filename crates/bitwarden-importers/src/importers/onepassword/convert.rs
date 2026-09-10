//! Maps downloaded 1Password vaults onto the importer's [`ParsedImport`].
//!
//! Vaults become folders, every item keeps its title and note, and a Login item picks up its
//! username, password, website addresses and one-time password. Everything a category mapping does
//! not claim survives as a custom field, with dates, month/year values and addresses rendered as
//! text. Typed mappings for the remaining categories follow in a later step.

use bitwarden_exporters::{
    CipherType, Field, ImportingCipher, Login, LoginUri, SecureNote, SecureNoteType,
};
use chrono::{DateTime, TimeDelta, Utc};
use itertools::Itertools;

use super::access::{
    model::{Item, ItemCategory, Vault},
    wire::{VaultItemDetails, VaultItemOverview, VaultItemSectionField},
};
use crate::pipeline::ParsedImport;

/// Stands in for a title 1Password left empty, matching the KDBX importer.
const UNTITLED_ITEM: &str = "--";

/// Stands in for a vault name 1Password left empty, matching the KDBX importer's group naming.
const UNNAMED_VAULT: &str = "-";

/// Bitwarden's custom field types.
const TEXT_FIELD: u8 = 0;
const HIDDEN_FIELD: u8 = 1;

/// 1Password stores a one-time password in a section field whose stable id carries this prefix.
const TOTP_PREFIX: &str = "TOTP_";

/// Names the custom field that keeps an item's tags. Bitwarden has nothing else to put them in.
const TAGS_FIELD: &str = "tags";

/// Added to a Document item's note. The item is the file, and an import moves vault data rather
/// than files, so the note is all that is left to say so.
const DOCUMENT_NOTE: &str = "This was a 1Password document. The attached file was not imported.";

/// What a category mapping already read, so the leftover pass does not repeat it.
#[derive(Default)]
struct Claimed {
    /// Designations of consumed top-level fields.
    designations: &'static [&'static str],
    /// Positions of consumed section fields, as [`section_fields`] numbers them. An id would not
    /// do: a mapping picks one field, and only its position says which.
    fields: Vec<usize>,
}

/// Converts every downloaded vault into ciphers, one folder per vault.
pub fn convert(vaults: Vec<Vault>) -> ParsedImport {
    let mut parsed = ParsedImport {
        ciphers: Vec::new(),
        folders: Vec::new(),
        folder_relationships: Vec::new(),
    };

    for (folder_index, vault) in vaults.into_iter().enumerate() {
        parsed
            .folders
            .push(non_blank(&vault.name).unwrap_or(UNNAMED_VAULT).to_string());

        for item in vault.items {
            let cipher_index = parsed.ciphers.len();
            parsed.ciphers.push(convert_item(item));
            parsed
                .folder_relationships
                .push((cipher_index, folder_index));
        }
    }

    parsed
}

fn convert_item(item: Item) -> ImportingCipher {
    // The import endpoint sets its own dates, so the ones 1Password sends are not worth carrying.
    let now = Utc::now();
    let (r#type, claimed) = cipher_type(&item);
    let mut fields = fields_from_details(&item.details, &claimed);
    fields.extend(tags_field(&item.overview));

    ImportingCipher {
        folder_id: None,
        name: item
            .overview
            .title
            .as_deref()
            .and_then(non_blank)
            .unwrap_or(UNTITLED_ITEM)
            .to_string(),
        notes: notes(&item),
        r#type,
        favorite: false,
        reprompt: 0,
        fields,
        revision_date: now,
        creation_date: now,
        deleted_date: None,
    }
}

/// The item's note, with a line added when the item was a document whose file could not come
/// along.
fn notes(item: &Item) -> Option<String> {
    let note = item.details.note.as_deref().and_then(non_blank);

    match (item.category == ItemCategory::Document, note) {
        (true, Some(note)) => Some(format!("{note}\n\n{DOCUMENT_NOTE}")),
        (true, None) => Some(DOCUMENT_NOTE.to_string()),
        (false, note) => note.map(str::to_string),
    }
}

/// Keeps an item's tags in a custom field. They are multi-valued and Bitwarden has no equivalent,
/// so they arrive as one comma-separated field rather than being dropped.
fn tags_field(overview: &VaultItemOverview) -> Option<Field> {
    let tags: Vec<&str> = overview
        .tags
        .iter()
        .flatten()
        .filter_map(|tag| non_blank(tag))
        .collect();

    (!tags.is_empty()).then(|| Field {
        name: Some(TAGS_FIELD.to_string()),
        value: Some(tags.join(", ")),
        r#type: TEXT_FIELD,
        linked_id: None,
    })
}

/// Picks the Bitwarden cipher type for an item's 1Password category, and reports which of the
/// item's fields it read. A category without a mapping yet becomes a secure note, which loses
/// nothing because every field then becomes a custom field.
fn cipher_type(item: &Item) -> (CipherType, Claimed) {
    match item.category {
        ItemCategory::Login => {
            let (login, claimed) = login(&item.overview, &item.details);
            (CipherType::Login(Box::new(login)), claimed)
        }
        _ => secure_note(),
    }
}

fn secure_note() -> (CipherType, Claimed) {
    (
        CipherType::SecureNote(Box::new(SecureNote {
            r#type: SecureNoteType::Generic,
        })),
        Claimed::default(),
    )
}

fn login(overview: &VaultItemOverview, details: &VaultItemDetails) -> (Login, Claimed) {
    let totp = first_totp(details);

    let mut login = Login {
        username: designation(details, "username"),
        password: designation(details, "password"),
        login_uris: login_uris(overview),
        totp: totp.as_ref().map(|(_, secret)| secret.clone()),
        fido2_credentials: None,
    };
    login.sanitize_uris();

    let claimed = Claimed {
        designations: &["username", "password"],
        fields: totp.map(|(position, _)| position).into_iter().collect(),
    };

    (login, claimed)
}

/// Every section field of an item, flattened in the order 1Password sent them. A mapping and the
/// leftover pass walk this same sequence, so a position names one field for both.
fn section_fields(details: &VaultItemDetails) -> impl Iterator<Item = &VaultItemSectionField> {
    details
        .sections
        .iter()
        .flatten()
        .flat_map(|section| section.fields.iter().flatten())
}

/// Reads the item's first one-time password, with the position of the field it came from. A
/// `TOTP_` field can arrive without a secret, so the first one carrying a value wins; any further
/// one stays a custom field, since a cipher has room for only one.
fn first_totp(details: &VaultItemDetails) -> Option<(usize, String)> {
    section_fields(details)
        .enumerate()
        .find_map(|(position, field)| {
            if !field
                .id
                .as_deref()
                .is_some_and(|id| id.starts_with(TOTP_PREFIX))
            {
                return None;
            }

            let secret = field.value.as_ref()?.as_str().and_then(non_blank)?;
            Some((position, secret.to_string()))
        })
}

/// Reads one of the login fields 1Password tags with a `designation`. The designation is stable,
/// unlike the field's localized `name`.
fn designation(details: &VaultItemDetails, designation: &str) -> Option<String> {
    details
        .fields
        .iter()
        .flatten()
        .find(|field| field.designation.as_deref() == Some(designation))
        .and_then(|field| field.value.as_deref())
        .and_then(non_blank)
        .map(str::to_string)
}

/// Collects the item's website addresses. 1Password keeps the primary one in `url` and repeats it
/// in `URLs`, so identical addresses collapse into a single URI.
fn login_uris(overview: &VaultItemOverview) -> Vec<LoginUri> {
    let all = overview.url.iter().chain(
        overview
            .urls
            .iter()
            .flatten()
            .filter_map(|url| url.url.as_ref()),
    );

    all.filter_map(|url| non_blank(url))
        .unique()
        .map(|uri| LoginUri {
            uri: Some(uri.to_string()),
            r#match: None,
        })
        .collect()
}

/// Collects every field a category mapping did not claim, so no part of an item is lost.
///
/// Fields without a value are skipped: 1Password stores its whole category template on every item,
/// so most of them are empty.
fn fields_from_details(details: &VaultItemDetails, claimed: &Claimed) -> Vec<Field> {
    let mut fields = Vec::new();
    // A mapping reads the first field carrying a designation, so the claim is spent on that one
    // occurrence; should an item repeat a designation, the repeat still becomes a custom field.
    let mut designations = claimed.designations.to_vec();

    for field in details.fields.iter().flatten() {
        let designation = field.designation.as_deref().unwrap_or_default();
        if let Some(claim) = designations.iter().position(|taken| *taken == designation) {
            designations.remove(claim);
            continue;
        }

        push_field(
            &mut fields,
            field
                .name
                .as_deref()
                .and_then(non_blank)
                .or(non_blank(designation)),
            field
                .value
                .as_deref()
                .and_then(non_blank)
                .map(str::to_string),
            field.kind.as_deref() == Some("P"),
        );
    }

    for (position, field) in section_fields(details).enumerate() {
        if claimed.fields.contains(&position) {
            continue;
        }

        let name = field
            .name
            .as_deref()
            .and_then(non_blank)
            .or(field.id.as_deref().and_then(non_blank));
        let hidden = field.kind.as_deref() == Some("concealed");
        let Some(value) = field.value.as_ref() else {
            continue;
        };

        match (field.kind.as_deref(), value) {
            // An attachment's value is the envelope that unwraps the stored file, encryption keys
            // included. The file cannot come along, so only its name does. A `file` field holding
            // anything but an envelope carries no attachment and falls through.
            (Some("file"), serde_json::Value::Object(_)) => push_field(
                &mut fields,
                name,
                Some(format!("<attachment: {}>", attachment_name(value, name))),
                false,
            ),
            // An address has no single text form, so each part it fills in becomes its own field.
            (Some("address"), serde_json::Value::Object(parts)) => {
                for (part, value) in parts {
                    push_field(&mut fields, Some(part), render_value(None, value), hidden);
                }
            }
            _ => push_field(
                &mut fields,
                name,
                render_value(field.kind.as_deref(), value),
                hidden,
            ),
        }
    }

    fields
}

fn attachment_name<'a>(value: &'a serde_json::Value, fallback: Option<&'a str>) -> &'a str {
    value
        .get("fileName")
        .and_then(serde_json::Value::as_str)
        .and_then(non_blank)
        .or(fallback)
        .unwrap_or("unnamed")
}

/// A field is hidden when 1Password treats its value as a secret. The `guarded` attribute is not
/// that signal: the Identity template sets it on plain fields such as the first name.
fn push_field(fields: &mut Vec<Field>, name: Option<&str>, value: Option<String>, hidden: bool) {
    let Some(value) = value else {
        return;
    };

    fields.push(Field {
        name: name.map(str::to_string),
        value: Some(value),
        r#type: if hidden { HIDDEN_FIELD } else { TEXT_FIELD },
        linked_id: None,
    });
}

/// Renders a field value as the text of one custom field. 1Password stores dates as unix seconds
/// and month/year as an integer such as `202112`; anything else it sends stays in its JSON form.
fn render_value(kind: Option<&str>, value: &serde_json::Value) -> Option<String> {
    match (kind, value) {
        (_, serde_json::Value::Null) => None,
        (_, serde_json::Value::String(text)) => non_blank(text).map(str::to_string),
        (Some("date"), serde_json::Value::Number(seconds)) => seconds
            .as_i64()
            .map(render_date)
            .or(Some(value.to_string())),
        (Some("monthYear"), serde_json::Value::Number(number)) => Some(
            number
                .as_i64()
                .and_then(render_month_year)
                .unwrap_or_else(|| value.to_string()),
        ),
        (_, other) => Some(other.to_string()),
    }
}

/// 1Password writes a date as midnight in the writer's own time zone, which it does not record.
/// Adding 12 hours before formatting in UTC recovers the intended day for every zone from UTC-11
/// to UTC+12; further east it lands a day early. No single shift covers the full 26 hours of real
/// offsets.
fn render_date(seconds: i64) -> String {
    DateTime::from_timestamp(seconds, 0)
        .and_then(|date| date.checked_add_signed(TimeDelta::hours(12)))
        .map(|date| date.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| seconds.to_string())
}

/// `202112` is December 2021.
fn render_month_year(value: i64) -> Option<String> {
    let (year, month) = (value / 100, value % 100);
    (1..=12)
        .contains(&month)
        .then(|| format!("{year:04}-{month:02}"))
}

fn non_blank(value: &str) -> Option<&str> {
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::{super::access::replay::download_captured_account, *};

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
}
