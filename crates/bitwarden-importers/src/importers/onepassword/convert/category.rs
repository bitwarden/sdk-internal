//! Maps a 1Password category onto a typed Bitwarden cipher, reporting what it read.
//!
//! Only Login has a mapping so far. The remaining categories fall back to a secure note, which
//! loses nothing: [`super::field`] keeps every field they carry.

use bitwarden_exporters::{CipherType, Login, LoginUri, SecureNote, SecureNoteType};
use itertools::Itertools;

use super::{
    claimed::{Claimed, designation, section_fields},
    value::non_blank,
};
use crate::importers::onepassword::access::wire::{VaultItemDetails, VaultItemOverview};

/// 1Password stores a one-time password in a section field whose stable id carries this prefix.
const TOTP_PREFIX: &str = "TOTP_";

pub(super) fn login(overview: &VaultItemOverview, details: &VaultItemDetails) -> (Login, Claimed) {
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

pub(super) fn secure_note() -> (CipherType, Claimed) {
    (
        CipherType::SecureNote(Box::new(SecureNote {
            r#type: SecureNoteType::Generic,
        })),
        Claimed::default(),
    )
}

/// Reads the item's first one-time password, with the position of the field it came from. A
/// `TOTP_` field can arrive without a secret, so the first one carrying a value wins; any further
/// one stays a custom field, since a cipher has room for only one.
pub(super) fn first_totp(details: &VaultItemDetails) -> Option<(usize, String)> {
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
