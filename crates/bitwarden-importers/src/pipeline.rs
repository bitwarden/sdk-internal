//! Generic submit pipeline shared by all SDK importers.
//!
//! A format-specific parser (see `crate::importers`) produces a [`ParsedImport`]; this module
//! encrypts it for the destination, builds the API request, submits it, and reports the counts.
//! Nothing here is format-specific.

use bitwarden_api_api::models::{
    CipherRequestModel, CollectionWithIdRequestModel, FolderWithIdRequestModel,
    ImportCiphersRequestModel, ImportOrganizationCiphersRequestModel, Int32Int32KeyValuePair,
};
use bitwarden_collections::collection::{Collection, CollectionId, CollectionType, CollectionView};
use bitwarden_core::{Client, NotAuthenticatedError, OrganizationId};
use bitwarden_crypto::{CompositeEncryptable, IdentifyKey};
use bitwarden_exporters::{CipherType, ImportingCipher, encrypt_import};
use bitwarden_vault::{Folder, FolderView};
use chrono::Utc;

use crate::{CipherTypeCount, ImportError, ImportOptions, ImportSummary, ImportTargetCollection};

/// Format-agnostic parse result: the ciphers, the folder paths, and which cipher belongs to which
/// folder (by index). Every importer parser produces this for the pipeline to submit.
// `pub` only so the `test-utils` re-export can reach it for the out-of-tree CLI.
// TODO: Back to `pub(crate)` once the re-export goes.
pub struct ParsedImport {
    /// The ciphers to submit, index-aligned with [`Self::folder_relationships`].
    pub ciphers: Vec<ImportingCipher>,
    /// Folder paths (e.g. `"Parent/Child"`), index-aligned with [`Self::folder_relationships`].
    pub folders: Vec<String>,
    /// `(cipher_index, folder_index)` pairs.
    pub folder_relationships: Vec<(usize, usize)>,
}

/// The encrypted request model and counts for an import, ready to submit.
enum ImportPayload {
    Individual(ImportCiphersRequestModel),
    Organization(String, ImportOrganizationCiphersRequestModel),
}

/// Encrypts a parsed import for the destination (personal vault or organization), submits it to the
/// import endpoint, and returns the per-type counts.
pub(crate) async fn submit_import(
    client: &Client,
    parsed: ParsedImport,
    options: ImportOptions,
) -> Result<ImportSummary, ImportError> {
    let user_id = client.internal.get_user_id().ok_or(NotAuthenticatedError)?;

    // Encrypt everything in one scope so the KeyStoreContext is dropped before the await.
    let (payload, summary) = {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();

        let (ciphers, folder_relationships) = filter_restricted(
            parsed.ciphers,
            parsed.folder_relationships,
            &options.restricted_types,
        );
        let cipher_count = ciphers.len();
        let cipher_type_counts = count_by_type(&ciphers);

        let cipher_models = ciphers
            .into_iter()
            .map(|c| {
                let encrypted = encrypt_import(&mut ctx, c, options.organization_id, user_id)?;
                Ok::<_, ImportError>(CipherRequestModel::from(encrypted))
            })
            .collect::<Result<Vec<_>, _>>()?;

        match options.organization_id {
            // Personal vault: groups become folders, optionally nested under the target folder.
            None => {
                let target_folder = options
                    .target_folder
                    .as_ref()
                    .map(|t| (t.id, t.name.as_str()));
                let (folder_views, folder_count) =
                    build_personal_folders(parsed.folders, target_folder);
                let folder_models = folder_views
                    .into_iter()
                    .map(|v| -> Result<FolderWithIdRequestModel, ImportError> {
                        let folder: Folder = v.encrypt_composite(&mut ctx, v.key_identifier())?;
                        Ok((&folder).into())
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let relationships = if target_folder.is_some() {
                    nest_relationships_under_target(folder_relationships, cipher_count)
                } else {
                    folder_relationships
                };

                let model = ImportCiphersRequestModel {
                    folders: Some(folder_models),
                    ciphers: Some(cipher_models),
                    folder_relationships: Some(to_kvp(&relationships)),
                };
                (
                    ImportPayload::Individual(model),
                    ImportSummary {
                        ciphers: cipher_type_counts,
                        folders: folder_count as u32,
                        collections: 0,
                    },
                )
            }
            // Organization vault: groups become collections if "My Items" not enabled
            Some(organization_id) => {
                let is_my_items = targets_my_items(options.target_collection.as_ref());

                let (
                    folder_views,
                    folder_count,
                    final_folder_relationships,
                    collection_views,
                    source_collection_count,
                    final_collection_relationships,
                ) = if is_my_items {
                    let (folder_views, folder_count) = build_personal_folders(parsed.folders, None);
                    let target = options
                        .target_collection
                        .as_ref()
                        .expect("is_my_items implies target_collection is Some");
                    let my_items = CollectionView {
                        id: Some(target.id),
                        organization_id,
                        name: target.name.clone(),
                        external_id: None,
                        hide_passwords: false,
                        read_only: false,
                        manage: true,
                        r#type: CollectionType::DefaultUserCollection,
                    };
                    let collection_relationships =
                        (0..cipher_count).map(|c| (c, 0)).collect::<Vec<_>>();
                    (
                        folder_views,
                        folder_count,
                        folder_relationships,
                        vec![my_items],
                        0,
                        collection_relationships,
                    )
                } else {
                    let target = options
                        .target_collection
                        .as_ref()
                        .map(|t| (t.id, t.name.as_str()));
                    let (collection_views, source_collection_count) =
                        build_org_collections(parsed.folders, organization_id, target);
                    let collection_relationships = if target.is_some() {
                        nest_relationships_under_target(folder_relationships, cipher_count)
                    } else {
                        // No target: brand-new top-level collections,
                        folder_relationships
                    };
                    (
                        Vec::new(),
                        0,
                        Vec::new(),
                        collection_views,
                        source_collection_count,
                        collection_relationships,
                    )
                };

                let folder_models = folder_views
                    .into_iter()
                    .map(|v| -> Result<FolderWithIdRequestModel, ImportError> {
                        let folder: Folder = v.encrypt_composite(&mut ctx, v.key_identifier())?;
                        Ok((&folder).into())
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let collection_models = collection_views
                    .into_iter()
                    .map(|v| -> Result<CollectionWithIdRequestModel, ImportError> {
                        let collection: Collection =
                            v.encrypt_composite(&mut ctx, v.key_identifier())?;
                        Ok(CollectionWithIdRequestModel {
                            name: collection.name.to_string(),
                            external_id: collection.external_id.clone(),
                            groups: None,
                            users: None,
                            id: collection.id.map(Into::into),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let model = ImportOrganizationCiphersRequestModel {
                    collections: Some(collection_models),
                    ciphers: Some(cipher_models),
                    collection_relationships: Some(to_kvp(&final_collection_relationships)),
                    folders: Some(folder_models),
                    folder_relationships: Some(to_kvp(&final_folder_relationships)),
                };
                (
                    ImportPayload::Organization(organization_id.to_string(), model),
                    ImportSummary {
                        ciphers: cipher_type_counts,
                        folders: folder_count as u32,
                        collections: source_collection_count as u32,
                    },
                )
            }
        }
    };

    let api_client = &client.internal.get_api_configurations().api_client;
    match payload {
        ImportPayload::Individual(model) => {
            api_client
                .import_ciphers_api()
                .post_import(Some(model))
                .await?;
        }
        ImportPayload::Organization(organization_id, model) => {
            api_client
                .import_ciphers_api()
                .post_import_organization(Some(&organization_id), Some(model))
                .await?;
        }
    }

    Ok(summary)
}

/// Maps an exporter [`CipherType`] to the vault [`bitwarden_vault::CipherType`] discriminant.
fn vault_cipher_type(t: &CipherType) -> bitwarden_vault::CipherType {
    use bitwarden_vault::CipherType as V;
    match t {
        CipherType::Login(_) => V::Login,
        CipherType::SecureNote(_) => V::SecureNote,
        CipherType::Card(_) => V::Card,
        CipherType::Identity(_) => V::Identity,
        CipherType::SshKey(_) => V::SshKey,
        CipherType::BankAccount => V::BankAccount,
        CipherType::Passport => V::Passport,
        CipherType::DriversLicense => V::DriversLicense,
    }
}

/// Counts ciphers by vault type, in a stable display order, omitting types with no entries.
fn count_by_type(ciphers: &[ImportingCipher]) -> Vec<CipherTypeCount> {
    use bitwarden_vault::CipherType as V;
    const ORDER: [V; 8] = [
        V::Login,
        V::Card,
        V::Identity,
        V::SecureNote,
        V::SshKey,
        V::BankAccount,
        V::Passport,
        V::DriversLicense,
    ];
    ORDER
        .into_iter()
        .filter_map(|t| {
            let count = ciphers
                .iter()
                .filter(|c| vault_cipher_type(&c.r#type) == t)
                .count() as u32;
            (count > 0).then_some(CipherTypeCount { r#type: t, count })
        })
        .collect()
}

/// Drops ciphers whose type is restricted and re-indexes the folder relationships.
fn filter_restricted(
    ciphers: Vec<ImportingCipher>,
    folder_relationships: Vec<(usize, usize)>,
    restricted: &[bitwarden_vault::CipherType],
) -> (Vec<ImportingCipher>, Vec<(usize, usize)>) {
    if restricted.is_empty() {
        return (ciphers, folder_relationships);
    }

    let mut old_to_new = vec![None; ciphers.len()];
    let mut kept = Vec::with_capacity(ciphers.len());
    for (old_index, cipher) in ciphers.into_iter().enumerate() {
        if restricted.contains(&vault_cipher_type(&cipher.r#type)) {
            continue;
        }
        old_to_new[old_index] = Some(kept.len());
        kept.push(cipher);
    }

    let relationships = folder_relationships
        .into_iter()
        .filter_map(|(cipher, folder)| old_to_new[cipher].map(|new| (new, folder)))
        .collect();

    (kept, relationships)
}

/// Builds the folder views to import, plus the count of folders actually parsed from the source
/// (excluding the injected target). When a target folder is given it becomes folder 0 and the
/// imported groups are nested beneath it as `"{target}/{group}"` — the returned count is always
/// `names.len()`, regardless of whether a target was given, so callers can't accidentally report
/// the merged list's length (which includes the pre-existing target) as an import count.
fn build_personal_folders(
    names: Vec<String>,
    target: Option<(bitwarden_vault::FolderId, &str)>,
) -> (Vec<FolderView>, usize) {
    let count = names.len();
    let revision_date = Utc::now();
    let folders = match target {
        Some((id, target)) => {
            let mut folders = Vec::with_capacity(names.len() + 1);
            folders.push(FolderView {
                id: Some(id),
                name: target.to_string(),
                revision_date,
            });
            folders.extend(names.into_iter().map(|name| FolderView {
                id: None,
                name: format!("{target}/{name}"),
                revision_date,
            }));
            folders
        }
        None => names
            .into_iter()
            .map(|name| FolderView {
                id: None,
                name,
                revision_date,
            })
            .collect(),
    };
    (folders, count)
}

/// True when the org-import target is the user's own "My items" collection
fn targets_my_items(target_collection: Option<&ImportTargetCollection>) -> bool {
    matches!(
        target_collection.map(|t| &t.r#type),
        Some(CollectionType::DefaultUserCollection)
    )
}

/// Builds the collection views for an org import, plus the count of collections actually parsed
/// from the source (excluding the injected target) — mirrors `build_personal_folders`, but for
/// collections. When a target is given it becomes collection 0 and parsed groups are nested
/// beneath it as `"{target}/{group}"`; with no target, every group becomes a brand-new
/// top-level collection (submitted with no id, same as `build_personal_folders` submits new
/// folders with no id — the server creates on an unmatched/empty id).
fn build_org_collections(
    names: Vec<String>,
    organization_id: OrganizationId,
    target: Option<(CollectionId, &str)>,
) -> (Vec<CollectionView>, usize) {
    let count = names.len();
    let new_view = |id: Option<CollectionId>, name: String| CollectionView {
        id,
        organization_id,
        name,
        external_id: None,
        hide_passwords: false,
        read_only: false,
        manage: true,
        r#type: CollectionType::SharedCollection,
    };
    let collections = match target {
        Some((id, target_name)) => {
            let mut collections = Vec::with_capacity(names.len() + 1);
            collections.push(new_view(Some(id), target_name.to_string()));
            collections.extend(
                names
                    .into_iter()
                    .map(|name| new_view(None, format!("{target_name}/{name}"))),
            );
            collections
        }
        None => names.into_iter().map(|name| new_view(None, name)).collect(),
    };
    (collections, count)
}

/// Shifts existing relationships to account for the target folder at index 0 and assigns any
/// folder-less cipher to it.
fn nest_relationships_under_target(
    relationships: Vec<(usize, usize)>,
    cipher_count: usize,
) -> Vec<(usize, usize)> {
    let assigned: std::collections::HashSet<usize> =
        relationships.iter().map(|(cipher, _)| *cipher).collect();
    let mut out: Vec<(usize, usize)> = relationships
        .iter()
        .map(|(cipher, folder)| (*cipher, folder + 1))
        .collect();
    for cipher in 0..cipher_count {
        if !assigned.contains(&cipher) {
            out.push((cipher, 0));
        }
    }
    out
}

fn to_kvp(relationships: &[(usize, usize)]) -> Vec<Int32Int32KeyValuePair> {
    relationships
        .iter()
        .map(|(cipher, folder)| Int32Int32KeyValuePair {
            key: Some(*cipher as i32),
            value: Some(*folder as i32),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use bitwarden_exporters::{CipherType, ImportingCipher, Login};
    use bitwarden_vault::{CipherType as VaultCipherType, FolderId};
    use chrono::{DateTime, Utc};

    use super::*;

    fn importing(name: &str, r#type: CipherType) -> ImportingCipher {
        let date: DateTime<Utc> = "2024-01-01T00:00:00Z".parse().unwrap();
        ImportingCipher {
            folder_id: None,
            name: name.to_string(),
            notes: None,
            r#type,
            favorite: false,
            reprompt: 0,
            fields: vec![],
            revision_date: date,
            creation_date: date,
            deleted_date: None,
        }
    }

    #[test]
    fn filter_restricted_drops_matching_and_reindexes_relationships() {
        let ciphers = vec![
            importing("a", CipherType::Passport),
            importing("b", CipherType::BankAccount),
            importing("c", CipherType::Passport),
        ];
        // a->folder0, b->folder1, c->folder0
        let relationships = vec![(0, 0), (1, 1), (2, 0)];

        let (kept, relationships) =
            filter_restricted(ciphers, relationships, &[VaultCipherType::BankAccount]);

        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].name, "a");
        assert_eq!(kept[1].name, "c");
        // b's relationship is dropped; c is reindexed from cipher 2 to cipher 1.
        assert_eq!(relationships, vec![(0, 0), (1, 0)]);
    }

    #[test]
    fn filter_restricted_empty_list_is_noop() {
        let ciphers = vec![importing("a", CipherType::Passport)];
        let relationships = vec![(0, 0)];
        let (kept, out) = filter_restricted(ciphers, relationships.clone(), &[]);
        assert_eq!(kept.len(), 1);
        assert_eq!(out, relationships);
    }

    #[test]
    fn build_personal_folders_without_target_preserves_names() {
        let (folders, count) = build_personal_folders(vec!["A".into(), "A/B".into()], None);
        assert_eq!(count, 2);
        assert_eq!(folders.len(), 2);
        assert!(folders.iter().all(|f| f.id.is_none()));
        assert_eq!(folders[0].name, "A");
        assert_eq!(folders[1].name, "A/B");
    }

    #[test]
    fn build_personal_folders_with_target_nests_under_it() {
        let target = FolderId::new(uuid::Uuid::new_v4());
        let (folders, count) = build_personal_folders(vec!["A".into()], Some((target, "Target")));
        assert_eq!(count, 1);
        assert_eq!(folders.len(), 2);
        assert_eq!(folders[0].id, Some(target));
        assert_eq!(folders[0].name, "Target");
        assert_eq!(folders[1].id, None);
        assert_eq!(folders[1].name, "Target/A");
    }

    /// Guards the `submit_import` fix directly: this is the exact call `submit_import` makes to
    /// get `ImportSummary.folders`, so this pins the real count, not a proxy for it. Reverting the
    /// fix — reporting `folders.len()` instead of the returned count — would fail this test, since
    /// the merged list still has the target at index 0 even when nothing was parsed.
    #[test]
    fn build_personal_folders_count_excludes_injected_target_when_nothing_was_parsed() {
        let target = FolderId::new(uuid::Uuid::new_v4());
        let (folders, count) = build_personal_folders(Vec::new(), Some((target, "Target")));

        assert_eq!(folders.len(), 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn targets_my_items_true_only_for_default_user_collection() {
        assert!(!targets_my_items(None));

        let shared = ImportTargetCollection {
            id: CollectionId::new(uuid::Uuid::new_v4()),
            name: "Engineering".into(),
            r#type: CollectionType::SharedCollection,
        };
        assert!(!targets_my_items(Some(&shared)));

        let my_items = ImportTargetCollection {
            id: CollectionId::new(uuid::Uuid::new_v4()),
            name: "My items".into(),
            r#type: CollectionType::DefaultUserCollection,
        };
        assert!(targets_my_items(Some(&my_items)));
    }

    #[test]
    fn build_org_collections_without_target_creates_new_top_level_collections() {
        let org_id = OrganizationId::new(uuid::Uuid::new_v4());
        let (collections, count) =
            build_org_collections(vec!["A".into(), "A/B".into()], org_id, None);

        assert_eq!(count, 2);
        assert_eq!(collections.len(), 2);
        assert!(collections.iter().all(|c| c.id.is_none()));
        assert!(collections.iter().all(|c| c.organization_id == org_id));
        assert_eq!(collections[0].name, "A");
        assert_eq!(collections[1].name, "A/B");
    }

    #[test]
    fn build_org_collections_with_target_nests_under_it() {
        let org_id = OrganizationId::new(uuid::Uuid::new_v4());
        let target = CollectionId::new(uuid::Uuid::new_v4());
        let (collections, count) =
            build_org_collections(vec!["A".into()], org_id, Some((target, "Target")));

        assert_eq!(count, 1);
        assert_eq!(collections.len(), 2);
        assert_eq!(collections[0].id, Some(target));
        assert_eq!(collections[0].name, "Target");
        assert_eq!(collections[1].id, None);
        assert_eq!(collections[1].name, "Target/A");
    }

    #[test]
    fn build_org_collections_count_excludes_injected_target_when_nothing_was_parsed() {
        let org_id = OrganizationId::new(uuid::Uuid::new_v4());
        let target = CollectionId::new(uuid::Uuid::new_v4());
        let (collections, count) =
            build_org_collections(Vec::new(), org_id, Some((target, "Target")));

        assert_eq!(collections.len(), 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn nest_relationships_shifts_existing_and_assigns_folderless() {
        // cipher 0 is in a group; cipher 1 has no folder.
        let out = nest_relationships_under_target(vec![(0, 0)], 2);
        assert!(out.contains(&(0, 1)));
        assert!(out.contains(&(1, 0)));
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn count_by_type_groups_in_stable_order_and_omits_zero() {
        let login = CipherType::Login(Box::new(Login {
            username: None,
            password: None,
            login_uris: vec![],
            totp: None,
            fido2_credentials: None,
        }));
        let ciphers = vec![
            importing("a", CipherType::Passport),
            importing("b", login),
            importing("c", CipherType::Passport),
        ];
        let counts = count_by_type(&ciphers);
        // Login is ordered before Passport; Card/etc. with zero entries are omitted.
        assert_eq!(counts.len(), 2);
        assert_eq!(counts[0].r#type, VaultCipherType::Login);
        assert_eq!(counts[0].count, 1);
        assert_eq!(counts[1].r#type, VaultCipherType::Passport);
        assert_eq!(counts[1].count, 2);
    }

    #[test]
    fn to_kvp_maps_indices() {
        let kvp = to_kvp(&[(0, 2), (3, 1)]);
        assert_eq!(kvp[0].key, Some(0));
        assert_eq!(kvp[0].value, Some(2));
        assert_eq!(kvp[1].key, Some(3));
        assert_eq!(kvp[1].value, Some(1));
    }

    /// Covers the encrypt boundary: a parsed cipher's name comes out encrypted (not the plaintext
    /// title) when run through a real key store.
    #[tokio::test]
    async fn encrypt_import_encrypts_the_cipher_name() {
        use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account};
        use bitwarden_exporters::encrypt_import;

        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();

        let login = CipherType::Login(Box::new(Login {
            username: None,
            password: None,
            login_uris: vec![],
            totp: None,
            fido2_credentials: None,
        }));
        let user_id = client.internal.get_user_id().unwrap();
        let encrypted =
            encrypt_import(&mut ctx, importing("GitHub", login), None, user_id).unwrap();

        assert_eq!(encrypted.encrypted_for, user_id);
        assert_ne!(encrypted.cipher.name.unwrap().to_string(), "GitHub");
    }
}
