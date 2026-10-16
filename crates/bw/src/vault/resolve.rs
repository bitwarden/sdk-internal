//! Resolution of a user-supplied `id_or_term` argument to a single vault object.
//!
//! Shared by the single-object commands (`get item`, `get folder`, and later `get username` etc.).
//! An argument that parses as an id is fetched directly; anything else is treated as a search term
//! and must match exactly one object.

use bitwarden_pm::PasswordManagerClient;
use bitwarden_vault::{
    CipherId, CipherListView, CipherView, FolderId, FolderView, GetCipherError, GetFolderError,
};

use super::search::{cipher_matches, folder_matches};

/// Failure to resolve an argument to exactly one object.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("Not found.")]
    NotFound,
    #[error(
        "More than one result was found. Try getting a specific object by `id` instead. The following objects were found: {}",
        .0.join(", ")
    )]
    MultipleResults(Vec<String>),
}

/// Extra filter applied to search matches (not to direct id lookups).
pub type CipherPredicate<'a> = &'a dyn Fn(&CipherListView) -> bool;

/// Resolve `id_or_term` to a single decrypted cipher.
///
/// If the argument parses as a cipher id the cipher is fetched directly. Otherwise non-trashed
/// ciphers matching the search term (and `predicate`, if given) are considered, and exactly one
/// must match.
pub async fn resolve_cipher(
    client: &PasswordManagerClient,
    id_or_term: &str,
    predicate: Option<CipherPredicate<'_>>,
) -> Result<CipherView, ResolveError> {
    let ciphers = client.vault().ciphers();

    if id_or_term.parse::<CipherId>().is_ok() {
        return ciphers.get(id_or_term).await.map_err(|e| match e {
            GetCipherError::ItemNotFound(_) => ResolveError::NotFound,
            // Not-found is the only expected failure; anything else is unexpected, but the
            // resolver's contract is a ResolveError, so fall back to the same TS-parity result.
            e => {
                tracing::warn!("Failed to get cipher: {e}");
                ResolveError::NotFound
            }
        });
    }

    let listed = ciphers.list().await.map_err(|e| {
        tracing::warn!("Failed to list ciphers: {e}");
        ResolveError::NotFound
    })?;
    if !listed.failures.is_empty() {
        tracing::warn!(
            "{} cipher(s) failed to decrypt and were not searched",
            listed.failures.len()
        );
    }

    let id = find_cipher_id(listed.successes, id_or_term, predicate)?;

    ciphers
        .get(&id.to_string())
        .await
        .map_err(|_| ResolveError::NotFound)
}

/// Resolve `id_or_term` to a single decrypted folder, by id or by name search.
pub async fn resolve_folder(
    client: &PasswordManagerClient,
    id_or_term: &str,
) -> Result<FolderView, ResolveError> {
    let folders = client.vault().folders();

    if let Ok(id) = id_or_term.parse::<FolderId>() {
        return folders.get(id).await.map_err(|e| match e {
            GetFolderError::ItemNotFound(_) => ResolveError::NotFound,
            e => {
                tracing::warn!("Failed to get folder: {e}");
                ResolveError::NotFound
            }
        });
    }

    let listed = folders.list().await.map_err(|e| {
        tracing::warn!("Failed to list folders: {e}");
        ResolveError::NotFound
    })?;

    find_folder(listed, id_or_term)
}

/// Pick the single non-trashed cipher matching the term and predicate, returning its id.
fn find_cipher_id(
    ciphers: Vec<CipherListView>,
    term: &str,
    predicate: Option<CipherPredicate<'_>>,
) -> Result<CipherId, ResolveError> {
    let matches = ciphers
        .into_iter()
        .filter(|c| c.deleted_date.is_none())
        .filter(|c| cipher_matches(c, term))
        .filter(|c| predicate.is_none_or(|p| p(c)))
        .collect();

    select_single(matches, |c| c.id.map(|id| id.to_string()))?
        .id
        .ok_or(ResolveError::NotFound)
}

/// Pick the single folder whose name matches the term.
fn find_folder(folders: Vec<FolderView>, term: &str) -> Result<FolderView, ResolveError> {
    let matches = folders
        .into_iter()
        .filter(|f| folder_matches(f, term))
        .collect();

    select_single(matches, |f| f.id.map(|id| id.to_string()))
}

/// Return the only element of `matches`, or the appropriate [`ResolveError`].
fn select_single<T>(
    mut matches: Vec<T>,
    id_of: impl Fn(&T) -> Option<String>,
) -> Result<T, ResolveError> {
    match matches.len() {
        0 => Err(ResolveError::NotFound),
        1 => Ok(matches.remove(0)),
        _ => Err(ResolveError::MultipleResults(
            matches.iter().filter_map(id_of).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::search::test_support::{cipher_with_id, folder};

    fn id_of(s: &&str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn select_single_not_found() {
        assert!(matches!(
            select_single(Vec::<&str>::new(), id_of),
            Err(ResolveError::NotFound)
        ));
    }

    #[test]
    fn select_single_one_match() {
        assert_eq!(select_single(vec!["a"], id_of).unwrap(), "a");
    }

    #[test]
    fn select_single_multiple_lists_every_id() {
        let Err(ResolveError::MultipleResults(ids)) = select_single(vec!["a", "b"], id_of) else {
            panic!("expected MultipleResults");
        };
        assert_eq!(ids, ["a", "b"]);
    }

    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn single_search_match_returns_its_id() {
        let ciphers = vec![
            cipher_with_id(A, "GitHub", "", &[], false),
            cipher_with_id(B, "Bank", "", &[], false),
        ];
        let id = find_cipher_id(ciphers, "github", None).unwrap();
        assert_eq!(id.to_string(), A);
    }

    #[test]
    fn multiple_search_matches_list_both_ids() {
        let ciphers = vec![
            cipher_with_id(A, "Work email", "", &[], false),
            cipher_with_id(B, "Work vpn", "", &[], false),
        ];
        let Err(ResolveError::MultipleResults(ids)) = find_cipher_id(ciphers, "work", None) else {
            panic!("expected MultipleResults");
        };
        assert_eq!(ids, [A, B]);
    }

    #[test]
    fn no_search_match_is_not_found() {
        let ciphers = vec![cipher_with_id(A, "GitHub", "", &[], false)];
        assert!(matches!(
            find_cipher_id(ciphers, "nonexistent", None),
            Err(ResolveError::NotFound)
        ));
    }

    #[test]
    fn trashed_ciphers_are_not_searched() {
        let ciphers = vec![
            cipher_with_id(A, "Work", "", &[], true),
            cipher_with_id(B, "Work", "", &[], false),
        ];
        let id = find_cipher_id(ciphers, "work", None).unwrap();
        assert_eq!(id.to_string(), B);
    }

    #[test]
    fn predicate_narrows_search_matches() {
        let ciphers = vec![
            cipher_with_id(A, "Work", "", &[], false),
            cipher_with_id(B, "Work", "", &[], false),
        ];
        let only_b = |c: &CipherListView| c.id.is_some_and(|id| id.to_string() == B);
        let id = find_cipher_id(ciphers, "work", Some(&only_b)).unwrap();
        assert_eq!(id.to_string(), B);
    }

    #[test]
    fn folder_search_resolves_one_or_errors() {
        let folders = || vec![folder(A, "Personal"), folder(B, "Personal Projects")];
        assert_eq!(
            find_folder(folders(), "projects").unwrap().name,
            "Personal Projects"
        );
        assert!(matches!(
            find_folder(folders(), "personal"),
            Err(ResolveError::MultipleResults(_))
        ));
        assert!(matches!(
            find_folder(folders(), "zzz"),
            Err(ResolveError::NotFound)
        ));
    }
}
