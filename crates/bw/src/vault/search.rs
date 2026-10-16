//! Text matching shared by `list items --search` and the single-object `get` resolvers.
//!
//! Mirrors the TypeScript CLI's basic search: case-insensitive substring match on the name,
//! subtitle and login URIs, plus an id prefix match for terms of at least [`MIN_ID_PREFIX_LEN`]
//! characters. Notes and custom fields are intentionally not searched.

use bitwarden_vault::{CipherListView, CipherListViewType, FolderView};

/// Minimum term length for which the term is also matched as a cipher id prefix.
const MIN_ID_PREFIX_LEN: usize = 8;

/// Returns true if the cipher matches the search term.
pub(super) fn cipher_matches(cipher: &CipherListView, term: &str) -> bool {
    let term = term.trim().to_lowercase();
    if term.is_empty() {
        return false;
    }
    let contains = |s: &str| s.to_lowercase().contains(&term);

    if contains(&cipher.name) || contains(&cipher.subtitle) {
        return true;
    }

    if term.len() >= MIN_ID_PREFIX_LEN
        && cipher
            .id
            .is_some_and(|id| id.to_string().to_lowercase().starts_with(&term))
    {
        return true;
    }

    match &cipher.r#type {
        CipherListViewType::Login(login) => login
            .uris
            .iter()
            .flatten()
            .filter_map(|u| u.uri.as_deref())
            .any(contains),
        _ => false,
    }
}

/// Returns true if the folder name matches the search term.
pub(super) fn folder_matches(folder: &FolderView, term: &str) -> bool {
    let term = term.trim().to_lowercase();
    !term.is_empty() && folder.name.to_lowercase().contains(&term)
}

#[cfg(test)]
pub(super) mod test_support {
    use bitwarden_vault::{CipherListView, FolderView};
    use serde_json::json;

    /// Build a login `CipherListView` via JSON so wasm-only fields don't need to be spelled out.
    pub fn cipher_with_id(
        id: &str,
        name: &str,
        subtitle: &str,
        uris: &[&str],
        trashed: bool,
    ) -> CipherListView {
        let login = json!({
            "hasFido2": false,
            "uris": uris.iter().map(|u| json!({ "uri": u })).collect::<Vec<_>>(),
        });
        serde_json::from_value(json!({
            "id": id,
            "collectionIds": [],
            "name": name,
            "subtitle": subtitle,
            "type": { "login": login },
            "favorite": false,
            "reprompt": 0,
            "organizationUseTotp": false,
            "edit": true,
            "viewPassword": true,
            "attachments": 0,
            "hasOldAttachments": false,
            "creationDate": "2025-01-01T00:00:00Z",
            "deletedDate": trashed.then_some("2025-02-01T00:00:00Z"),
            "revisionDate": "2025-01-01T00:00:00Z",
            "copyableFields": [],
        }))
        .unwrap()
    }

    pub fn folder(id: &str, name: &str) -> FolderView {
        FolderView {
            id: Some(id.parse().unwrap()),
            name: name.into(),
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::cipher_with_id, *};

    const ID: &str = "25afb11c-9c95-4db5-8bac-c21cb204a3f1";

    fn cipher(name: &str, subtitle: &str, uris: &[&str]) -> CipherListView {
        cipher_with_id(ID, name, subtitle, uris, false)
    }

    #[test]
    fn matches_name_case_insensitively() {
        assert!(cipher_matches(&cipher("GitHub", "", &[]), "github"));
        assert!(cipher_matches(&cipher("GitHub", "", &[]), "HUB"));
        assert!(!cipher_matches(&cipher("GitHub", "", &[]), "gitlab"));
    }

    #[test]
    fn matches_subtitle_and_uris() {
        let c = cipher(
            "Work",
            "jane@example.com",
            &["https://git.example.org/login"],
        );
        assert!(cipher_matches(&c, "jane@"));
        assert!(cipher_matches(&c, "git.example.org"));
    }

    #[test]
    fn id_prefix_requires_min_length() {
        let c = cipher("Work", "", &[]);
        assert!(cipher_matches(&c, "25afb11c"));
        assert!(cipher_matches(&c, "25AFB11C-9C95"));
        assert!(!cipher_matches(&c, "25afb11"));
        assert!(!cipher_matches(&c, "9c95-4db5"));
    }

    #[test]
    fn empty_term_matches_nothing() {
        assert!(!cipher_matches(&cipher("Work", "", &[]), "  "));
    }

    #[test]
    fn folder_name_match() {
        let f = FolderView {
            id: None,
            name: "Personal Stuff".into(),
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
        };
        assert!(folder_matches(&f, "personal"));
        assert!(!folder_matches(&f, "work"));
    }
}
