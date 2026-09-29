//! Maps downloaded 1Password vaults onto the importer's [`ParsedImport`].
//!
//! Vaults become folders and every item keeps its title and note. Login and the categories built
//! around a credential land on a login; Credit Card, Identity and SSH Key on their own types.
//! Everything else becomes a secure note. Whatever a mapping does not claim survives as a custom
//! field, with dates, month/year values and addresses rendered as text.
//!
//! This module drives the walk and picks each item's mapping; `login`, `credential`, `card`,
//! `identity` and `ssh_key` hold the mappings, `field` the leftover pass that keeps whatever they
//! did not claim, and `claimed` the bookkeeping that joins the two.

mod card;
mod claimed;
mod credential;
mod field;
mod identity;
mod login;
mod ssh_key;
#[cfg(test)]
mod tests;
mod value;

use bitwarden_exporters::{CipherType, Field, ImportingCipher, SecureNote, SecureNoteType};
use chrono::Utc;

use self::{
    card::card,
    claimed::Claimed,
    credential::{
        API_CREDENTIAL_FIELDS, CredentialFields, DATABASE_FIELDS, EMAIL_ACCOUNT_FIELDS,
        SERVER_FIELDS, WIRELESS_ROUTER_FIELDS, credential_login, password,
    },
    field::{TEXT_FIELD, fields_from_details},
    identity::identity,
    login::login,
    ssh_key::ssh_key,
    value::non_blank,
};
use crate::{
    importers::onepassword::access::{
        model::{Item, ItemCategory, Vault},
        wire::VaultItemOverview,
    },
    pipeline::ParsedImport,
};

/// Stands in for a title 1Password left empty, matching the KDBX importer.
const UNTITLED_ITEM: &str = "--";

/// Stands in for a vault name 1Password left empty, matching the KDBX importer's group naming.
const UNNAMED_VAULT: &str = "-";

/// Names the custom field that keeps an item's tags. Bitwarden has nothing else to put them in.
const TAGS_FIELD: &str = "tags";

/// Added to a Document item's note. The item is the file, and an import moves vault data rather
/// than files, so the note is all that is left to say so.
const DOCUMENT_NOTE: &str = "This was a 1Password document. The attached file was not imported.";

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
/// item's fields it read. A category without a mapping becomes a secure note, which loses nothing
/// because every field then becomes a custom field.
fn cipher_type(item: &Item) -> (CipherType, Claimed) {
    let (overview, details) = (&item.overview, &item.details);
    let credential = |fields: &CredentialFields| {
        typed(
            credential_login(overview, details, fields),
            CipherType::Login,
        )
    };

    match item.category {
        ItemCategory::Login => typed(login(overview, details), CipherType::Login),
        ItemCategory::Password => typed(password(overview, details), CipherType::Login),
        ItemCategory::Server => credential(&SERVER_FIELDS),
        ItemCategory::Database => credential(&DATABASE_FIELDS),
        ItemCategory::ApiCredential => credential(&API_CREDENTIAL_FIELDS),
        ItemCategory::EmailAccount => credential(&EMAIL_ACCOUNT_FIELDS),
        ItemCategory::WirelessRouter => credential(&WIRELESS_ROUTER_FIELDS),
        ItemCategory::CreditCard => typed(card(details), CipherType::Card),
        ItemCategory::Identity => typed(identity(details), CipherType::Identity),
        // A key the vault cannot use stays a note, with its material kept in the fields.
        ItemCategory::SshKey => {
            ssh_key(details).map_or_else(secure_note, |key| typed(key, CipherType::SshKey))
        }
        _ => secure_note(),
    }
}

/// Wraps what a mapping read in the cipher type it belongs to.
fn typed<T>(
    (mapped, claimed): (T, Claimed),
    cipher_type: fn(Box<T>) -> CipherType,
) -> (CipherType, Claimed) {
    (cipher_type(Box::new(mapped)), claimed)
}

fn secure_note() -> (CipherType, Claimed) {
    (
        CipherType::SecureNote(Box::new(SecureNote {
            r#type: SecureNoteType::Generic,
        })),
        Claimed::default(),
    )
}
