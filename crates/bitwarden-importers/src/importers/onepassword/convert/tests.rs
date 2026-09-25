//! Converter tests, driven over the captured 1Password account.
//!
//! The vaults come out of the production download path replayed over recorded server responses,
//! so these tests see exactly what an import would. Synthetic details cover the shapes the capture
//! has no example of.

use bitwarden_exporters::{Card, CipherType, Identity, ImportingCipher, Login, SshKey};

use super::{
    card::{card, card_brand},
    claimed::Claimed,
    convert,
    credential::password,
    field::{HIDDEN_FIELD, fields_from_details},
    identity::identity,
    login::{first_totp, login},
    ssh_key::ssh_key,
};
use crate::{
    importers::onepassword::access::{
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

fn card_of(cipher: &ImportingCipher) -> &Card {
    match &cipher.r#type {
        CipherType::Card(card) => card,
        other => panic!("{} is a {other}, expected a card", cipher.name),
    }
}

fn identity_of(cipher: &ImportingCipher) -> &Identity {
    match &cipher.r#type {
        CipherType::Identity(identity) => identity,
        other => panic!("{} is a {other}, expected an identity", cipher.name),
    }
}

fn ssh_key_of(cipher: &ImportingCipher) -> &SshKey {
    match &cipher.r#type {
        CipherType::SshKey(key) => key,
        other => panic!("{} is a {other}, expected an ssh key", cipher.name),
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

/// An ed25519 key in the form 1Password stores it and one in the form OpenSSH writes it.
const PKCS8_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
    MFECAQEwBQYDK2VwBCIEIDY6/OAdDr3PbDss9NsLXK4CxiKUvz5/R9uvjtIzj4Sz\n\
    gSEAxsxm1xpZ/4lKIRYm0JrJ5gRZUh7H24/YT/0qGVGzPa0=\n\
    -----END PRIVATE KEY-----\n";
const OPENSSH_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
    QyNTUxOQAAACAyQo22TXXNqvF+L8jUSSNeu8UqrsDjvf9pwIwDC9ML6gAAAJDSHpL60h6S\n\
    +gAAAAtzc2gtZWQyNTUxOQAAACAyQo22TXXNqvF+L8jUSSNeu8UqrsDjvf9pwIwDC9ML6g\n\
    AAAECLdlFLIJbEiFo/f0ROdXMNZAPHGPNhvbbftaPsUZEjaDJCjbZNdc2q8X4vyNRJI167\n\
    xSquwOO9/2nAjAML0wvqAAAAB3Rlc3RrZXkBAgMEBQY=\n\
    -----END OPENSSH PRIVATE KEY-----\n";

/// A key backed by a security key, which the vault has no way to use.
const SK_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAABpzay1zc2\n\
    gtZWQyNTUxOUBvcGVuc3NoLmNvbQAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
    AAAAAAAAAARzc2g6AAAAiHneT6B53k+gAAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY2\n\
    9tAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABHNzaDoAAAAAEAAA\n\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAE3NrLXRlc3RAZXhhbXBsZS5jb20BAgMEBQY=\n\
    -----END OPENSSH PRIVATE KEY-----\n";

/// An SSH key field the way 1Password sends it: the value repeats the private key, and the public
/// key and fingerprint are only in the attributes.
fn ssh_field(id: &str, private_key: &str) -> serde_json::Value {
    serde_json::json!({
        "n": id, "t": "private key", "k": "sshKey", "v": private_key,
        "a": {"sshKeyAttributes": {
            "privateKey": private_key,
            "publicKey": "ssh-ed25519 AAAA stored",
            "fingerprint": "SHA256:stored",
        }},
    })
}

fn ssh_details(private_key: &str) -> VaultItemDetails {
    details_from_json(serde_json::json!({
        "sections": [{"fields": [ssh_field("private_key", private_key)]}]
    }))
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

/// 1Password stores a month/year as `202401`, which no reader would guess at.
#[tokio::test]
async fn a_month_year_renders_as_year_and_month() {
    let parsed = converted().await;
    let fields = fields_of(cipher(&parsed, "Card: monthYear expiry, CVV and PIN"));

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

/// Every category built around a credential lands on the same three login slots, each reading
/// the ids its own template uses.
#[tokio::test]
async fn a_credential_category_becomes_a_login() {
    let parsed = converted().await;

    let server = login_of(cipher(
        &parsed,
        "Server: credentials plus two extra sections",
    ));
    assert_eq!(server.username.as_deref(), Some("root"));
    assert_eq!(server.password.as_deref(), Some("serverpass"));
    assert_eq!(uris(server), ["https://server.example.com"]);

    let email = login_of(cipher(&parsed, "Email account: POP and SMTP credentials"));
    assert_eq!(email.username.as_deref(), Some("mail@example.com"));
    assert_eq!(email.password.as_deref(), Some("pop-secret"));
    assert_eq!(uris(email), ["https://mail.example.com"]);
}

/// A database is reachable by its host, which is not a URL until the shared sanitizer makes it
/// one. A router's address is an IP, which becomes plain http.
#[tokio::test]
async fn a_host_or_an_ip_becomes_the_login_address() {
    let parsed = converted().await;

    let database = login_of(cipher(&parsed, "Database: host, port and credentials"));
    assert_eq!(database.username.as_deref(), Some("dbuser"));
    assert_eq!(uris(database), ["https://db.example.com"]);

    let router = login_of(cipher(
        &parsed,
        "Wireless router: base station and network passwords",
    ));
    assert_eq!(uris(router), ["http://192.168.1.1"]);
}

/// A router has no account name, and its own password is the base station's. The wireless key
/// is a field of its own and stays with the item.
#[tokio::test]
async fn a_wireless_router_keeps_its_second_password() {
    let parsed = converted().await;
    let cipher = cipher(
        &parsed,
        "Wireless router: base station and network passwords",
    );

    assert_eq!(login_of(cipher).username, None);
    assert_eq!(login_of(cipher).password.as_deref(), Some("admin-secret"));

    let fields = fields_of(cipher);
    assert!(fields.contains(&(1, "wireless network password", "wifi-secret")));
    assert!(fields.contains(&(1, "attached storage password", "disk-secret")));
    assert!(fields.contains(&(0, "network name", "TestNet")));
}

/// 1Password stores its whole category template on every item, so most fields arrive empty.
/// The API credential has seven: three fill login slots, three were filled in by hand, and the
/// empty one is gone.
#[tokio::test]
async fn an_item_keeps_only_the_fields_it_filled_in() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "API credential: concealed value and two dates");
    let login = login_of(cipher);

    assert_eq!(login.username.as_deref(), Some("svc-account"));
    assert_eq!(login.password.as_deref(), Some("sk-test-abc123xyz"));
    assert_eq!(uris(login), ["https://api.example.com"]);
    assert_eq!(
        fields_of(cipher),
        [
            (0, "filename", "service-account.json"),
            (0, "valid from", "2026-01-05"),
            (0, "expires", "2027-06-30"),
        ]
    );
}

/// A Password item has no fields at all: its secret is in the details.
#[tokio::test]
async fn a_password_item_takes_its_secret_from_the_details() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Password: secret in details plus a custom section");
    let login = login_of(cipher);

    assert_eq!(login.username, None);
    assert_eq!(login.password.as_deref(), Some("Sup3rS3cret!"));
    assert_eq!(
        fields_of(cipher),
        [
            (0, "plain note", "a text field on a password item"),
            (1, "hidden value", "s3cret-on-a-password-item"),
        ]
    );
}

/// A Password item can carry website addresses like a login, and the login it becomes needs them
/// to autofill. The captured one has none.
#[test]
fn a_password_item_keeps_its_website_addresses() {
    let overview: VaultItemOverview = serde_json::from_value(serde_json::json!({
        "url": "https://vault.example.com",
        "URLs": [
            {"u": "https://vault.example.com"},
            {"l": "admin", "u": "admin.example.com"},
        ],
    }))
    .expect("valid overview");

    let (login, _) = password(&overview, &details_from_json(serde_json::json!({})));

    assert_eq!(
        uris(&login),
        ["https://vault.example.com", "https://admin.example.com"]
    );
}

#[tokio::test]
async fn an_identity_fills_the_slots_bitwarden_has() {
    let parsed = converted().await;
    let cipher = cipher(
        &parsed,
        "Identity: name, phones, birth date and internet details",
    );
    let identity = identity_of(cipher);

    assert_eq!(identity.first_name.as_deref(), Some("Jane"));
    assert_eq!(identity.middle_name.as_deref(), Some("Q"));
    assert_eq!(identity.last_name.as_deref(), Some("Tester"));
    assert_eq!(identity.company.as_deref(), Some("Test Corp"));
    assert_eq!(identity.email.as_deref(), Some("jane.tester@example.com"));
    assert_eq!(identity.phone.as_deref(), Some("+1 555 0100"));
    assert_eq!(identity.username.as_deref(), Some("jane.tester"));

    // 1Password's template is far wider than Bitwarden's, so the rest rides along.
    let fields = fields_of(cipher);
    assert!(fields.contains(&(0, "birth date", "1990-03-15")));
    assert!(fields.contains(&(0, "job title", "Senior Tester")));
    assert!(fields.contains(&(0, "cell", "+1 555 0102")));
    assert!(fields.contains(&(0, "skype", "jane.tester")));
    // The claimed ones are not repeated.
    assert!(!fields.iter().any(|(_, name, _)| *name == "first name"));
    assert!(!fields.iter().any(|(_, name, _)| *name == "email"));
}

/// 1Password keeps the whole address in one field. Its five parts each have a slot, so none of
/// them is left to become a custom field. The captured account has no filled address: the
/// 1Password CLI cannot write one.
#[test]
fn an_identity_address_fills_the_address_slots() {
    let details = details_from_json(serde_json::json!({
        "sections": [{"name": "address", "title": "Address", "fields": [
            {"n": "address", "t": "address", "k": "address", "v": {
                "street": "221B Baker Street",
                "city": "London",
                "state": "Greater London",
                "zip": "NW1 6XE",
                "country": "gb",
            }}
        ]}]
    }));

    let (identity, claimed) = identity(&details);

    assert_eq!(identity.address1.as_deref(), Some("221B Baker Street"));
    assert_eq!(identity.city.as_deref(), Some("London"));
    assert_eq!(identity.state.as_deref(), Some("Greater London"));
    assert_eq!(identity.postal_code.as_deref(), Some("NW1 6XE"));
    assert_eq!(identity.country.as_deref(), Some("gb"));
    assert_eq!(rendered(&details, &claimed), []);
}

/// A part with no slot would be lost with the claim, so such an address stays whole in the
/// custom fields. A part that is not text still fills its slot.
#[test]
fn an_identity_address_is_claimed_only_when_every_part_has_a_slot() {
    let address = |parts: serde_json::Value| {
        details_from_json(serde_json::json!({
            "sections": [{"fields": [{"n": "address", "t": "address", "k": "address", "v": parts}]}]
        }))
    };

    let numeric_zip = address(serde_json::json!({"street": "Main St", "zip": 12345}));
    let (mapped, claimed) = identity(&numeric_zip);
    assert_eq!(mapped.postal_code.as_deref(), Some("12345"));
    assert_eq!(rendered(&numeric_zip, &claimed), []);

    let unknown_part = address(serde_json::json!({"street": "Main St", "region": "North"}));
    let (mapped, claimed) = identity(&unknown_part);
    assert_eq!(mapped.address1, None);
    assert_eq!(
        rendered(&unknown_part, &claimed),
        [
            (0, "street".to_string(), "Main St".to_string()),
            (0, "region".to_string(), "North".to_string()),
        ]
    );
}

#[tokio::test]
async fn a_card_fills_its_typed_slots() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "Card: monthYear expiry, CVV and PIN");
    let card = card_of(cipher);

    assert_eq!(card.cardholder_name.as_deref(), Some("Jane Q. Tester"));
    assert_eq!(card.number.as_deref(), Some("4111111111111111"));
    assert_eq!(card.code.as_deref(), Some("123"));
    // 1Password sends `202811`, which Bitwarden keeps as two values.
    assert_eq!(card.exp_month.as_deref(), Some("11"));
    assert_eq!(card.exp_year.as_deref(), Some("2028"));
    // The item leaves its card type empty, so there is no brand to map.
    assert_eq!(card.brand, None);

    // Everything the card type has no room for stays with the item.
    let fields = fields_of(cipher);
    assert!(fields.contains(&(0, "valid from", "2024-01")));
    assert!(fields.contains(&(1, "PIN", "1357")));
    assert!(fields.contains(&(0, "interest rate", "19.9%")));
    assert!(!fields.iter().any(|(_, name, _)| *name == "number"));
    assert!(!fields.iter().any(|(_, name, _)| *name == "expiry date"));
}

/// 1Password writes its own card type ids, so `mc` has to become `Mastercard` rather than
/// reaching the vault as it stands. An id with no Bitwarden brand keeps its own field.
#[test]
fn a_card_type_maps_onto_a_bitwarden_brand() {
    assert_eq!(card_brand("visa").as_deref(), Some("Visa"));
    assert_eq!(card_brand("mc").as_deref(), Some("Mastercard"));
    assert_eq!(card_brand("americanexpress").as_deref(), Some("Amex"));
    assert_eq!(card_brand("diners").as_deref(), Some("Diners Club"));
    assert_eq!(card_brand("jcb").as_deref(), Some("JCB"));

    let details = details_from_json(serde_json::json!({
        "sections": [{"fields": [
            {"n": "type", "t": "type", "k": "cctype", "v": "mercadolivre"}
        ]}]
    }));
    let (card, claimed) = card(&details);

    assert_eq!(card.brand, None);
    assert_eq!(
        rendered(&details, &claimed),
        [(0, "type".to_string(), "mercadolivre".to_string())]
    );
}

/// The public key and the fingerprint are only ever in the field's attributes, so a mapping that
/// read the value alone would lose both. The captured key is PKCS#8 and arrives as OpenSSH, with
/// the fingerprint 1Password showed.
#[tokio::test]
async fn an_ssh_key_takes_its_material_from_the_field_attributes() {
    let parsed = converted().await;
    let cipher = cipher(&parsed, "SSH key: ed25519 with a custom section");
    let key = ssh_key_of(cipher);

    assert!(
        key.private_key
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
    );
    assert!(key.public_key.starts_with("ssh-ed25519 "));
    assert_eq!(
        key.fingerprint,
        "SHA256:FlyEkMObqGorzjukxrU4+K89uD9ODaeeQUVMvQDGnk8"
    );
    // The key field was claimed; the item's own section survives beside it.
    assert_eq!(
        fields_of(cipher),
        [(0, "purpose", "deploy key for the test host")]
    );
}

#[tokio::test]
async fn an_rsa_key_maps_the_same_way() {
    let parsed = converted().await;
    let key = ssh_key_of(cipher(&parsed, "SSH key: RSA 4096"));

    assert!(key.public_key.starts_with("ssh-rsa "));
    assert_eq!(
        key.fingerprint,
        "SHA256:iykJ4i2Txk1Owsd9HT6cf5+n546m+q1Ikr4LtapwFBY"
    );
}

/// 1Password stores a private key as PKCS#8, which neither the SSH agent nor Credential Exchange
/// reads, so a key arrives in OpenSSH form whichever way it was stored.
#[test]
fn a_key_in_either_form_becomes_a_usable_openssh_key() {
    for private_key in [PKCS8_KEY, OPENSSH_KEY] {
        let details = ssh_details(private_key);
        let (key, claimed) = ssh_key(&details).expect("an ssh key");

        assert!(
            key.private_key
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        assert!(bitwarden_ssh::export_pkcs8_der_key(&key.private_key).is_ok());
        assert!(key.public_key.starts_with("ssh-ed25519 "));
        assert!(key.fingerprint.starts_with("SHA256:"));
        // The key field is spoken for, so none of its material is repeated.
        assert_eq!(rendered(&details, &claimed), []);
    }
}

/// A key in a form the vault cannot use stays a note, with its material in the fields rather than
/// lost. The value repeats the private key and is not kept twice.
#[test]
fn a_key_the_vault_cannot_use_keeps_its_material_in_the_note() {
    for private_key in ["not a key", SK_KEY] {
        let details = ssh_details(private_key);

        assert!(ssh_key(&details).is_none());
        assert_eq!(
            rendered(&details, &Claimed::default()),
            [
                (1, "private key".to_string(), private_key.to_string()),
                (
                    0,
                    "public key".to_string(),
                    "ssh-ed25519 AAAA stored".to_string()
                ),
                (0, "fingerprint".to_string(), "SHA256:stored".to_string()),
            ]
        );
    }
}

/// The template's own key field arrives empty when the key sits in a section of its own, and a
/// key the vault cannot use must not hide one it can.
#[test]
fn the_first_usable_key_is_taken_and_the_rest_stay_in_the_fields() {
    let details = details_from_json(serde_json::json!({
        "sections": [{"fields": [
            {"n": "private_key", "k": "sshKey", "a": {"sshKeyAttributes": {}}},
            ssh_field("old_key", "not a key"),
            ssh_field("new_key", PKCS8_KEY),
        ]}]
    }));

    let (_, claimed) = ssh_key(&details).expect("an ssh key");

    assert_eq!(
        rendered(&details, &claimed),
        [
            (1, "private key".to_string(), "not a key".to_string()),
            (
                0,
                "public key".to_string(),
                "ssh-ed25519 AAAA stored".to_string()
            ),
            (0, "fingerprint".to_string(), "SHA256:stored".to_string()),
        ]
    );
}

/// 1Password repeats the private key in the field's value. A value that is anything else holds
/// more than the attributes do, so it is neither claimed with the key nor skipped as a repeat.
#[test]
fn an_ssh_value_that_is_not_the_key_is_kept() {
    let usable_key_beside_something_else = details_from_json(serde_json::json!({
        "sections": [{"fields": [{
            "n": "private_key", "t": "private key", "k": "sshKey", "v": "something else",
            "a": {"sshKeyAttributes": {"privateKey": PKCS8_KEY}},
        }]}]
    }));
    assert!(ssh_key(&usable_key_beside_something_else).is_none());
    assert_eq!(
        rendered(&usable_key_beside_something_else, &Claimed::default()),
        [
            (1, "private key".to_string(), PKCS8_KEY.to_string()),
            (1, "private key".to_string(), "something else".to_string()),
        ]
    );

    let no_key_in_the_attributes = details_from_json(serde_json::json!({
        "sections": [{"fields": [{
            "n": "private_key", "t": "private key", "k": "sshKey", "v": 12345,
            "a": {"sshKeyAttributes": {}},
        }]}]
    }));
    assert_eq!(
        rendered(&no_key_in_the_attributes, &Claimed::default()),
        [(1, "private key".to_string(), "12345".to_string())]
    );
}

/// A category without a mapping arrives as a note whose fields carry the whole item.
#[tokio::test]
async fn an_unmapped_category_stays_a_secure_note() {
    let parsed = converted().await;

    for name in [
        "Bank account: concealed PIN and branch section",
        "Passport: three date fields and text",
        "Document: uploaded text file",
    ] {
        assert!(
            matches!(cipher(&parsed, name).r#type, CipherType::SecureNote(_)),
            "{name} is not a secure note"
        );
    }
}
