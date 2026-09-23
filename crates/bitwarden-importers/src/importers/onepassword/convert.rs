//! Maps downloaded 1Password vaults onto the importer's [`ParsedImport`].
//!
//! First step: vaults become folders, every item keeps its title and note, and a Login item
//! picks up its username, password and website addresses. Every other category becomes a secure
//! note for now. Typed mappings for those categories, and custom fields for whatever a mapping
//! does not claim, follow in later steps.

use bitwarden_exporters::{
    CipherType, ImportingCipher, Login, LoginUri, SecureNote, SecureNoteType,
};
use chrono::Utc;
use itertools::Itertools;

use super::access::{
    model::{Item, ItemCategory, Vault},
    wire::{VaultItemDetails, VaultItemOverview},
};
use crate::pipeline::ParsedImport;

/// Stands in for a title 1Password left empty, matching the KDBX importer.
const UNTITLED_ITEM: &str = "--";

/// Stands in for a vault name 1Password left empty, matching the KDBX importer's group naming.
const UNNAMED_VAULT: &str = "-";

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

    ImportingCipher {
        folder_id: None,
        name: item
            .overview
            .title
            .as_deref()
            .and_then(non_blank)
            .unwrap_or(UNTITLED_ITEM)
            .to_string(),
        notes: item
            .details
            .note
            .as_deref()
            .and_then(non_blank)
            .map(str::to_string),
        r#type: cipher_type(&item),
        favorite: false,
        reprompt: 0,
        fields: Vec::new(),
        revision_date: now,
        creation_date: now,
        deleted_date: None,
    }
}

/// Picks the Bitwarden cipher type for an item's 1Password category. A category without a mapping
/// yet becomes a secure note, so the item still arrives with its title and note.
fn cipher_type(item: &Item) -> CipherType {
    match item.category {
        ItemCategory::Login => CipherType::Login(Box::new(login(&item.overview, &item.details))),
        _ => CipherType::SecureNote(Box::new(SecureNote {
            r#type: SecureNoteType::Generic,
        })),
    }
}

fn login(overview: &VaultItemOverview, details: &VaultItemDetails) -> Login {
    let mut login = Login {
        username: designation(details, "username"),
        password: designation(details, "password"),
        login_uris: login_uris(overview),
        totp: None,
        fido2_credentials: None,
    };
    login.sanitize_uris();
    login
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

    /// Only Login has a mapping so far. Everything else arrives as a note with its title rather
    /// than failing the import or vanishing.
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
