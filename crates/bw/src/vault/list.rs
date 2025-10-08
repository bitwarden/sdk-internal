use bitwarden_core::Client;
use bitwarden_vault::{CipherListView, SyncRequest, VaultClientExt};
use color_eyre::eyre::{Result, bail};

use crate::render::CommandOutput;

#[derive(Debug)]
pub struct ListOptions {
    pub object: String,
    pub search: Option<String>,
    pub folderid: Option<String>,
    pub collectionid: Option<String>,
    pub organizationid: Option<String>,
    pub trash: bool,
}

pub async fn list(client: &Client, options: ListOptions) -> Result<CommandOutput> {
    match options.object.as_str() {
        "items" => list_items(client, options).await,
        "folders" => {
            bail!("Listing folders is not yet implemented")
        }
        "collections" => {
            bail!("Listing collections is not yet implemented")
        }
        "organizations" => {
            bail!("Listing organizations is not yet implemented")
        }
        "org-collections" => {
            bail!("Listing org-collections is not yet implemented")
        }
        "org-members" => {
            bail!("Listing org-members is not yet implemented")
        }
        _ => {
            bail!(
                "Invalid object type '{}'. Valid objects are: items, folders, collections, \
                 organizations, org-collections, org-members",
                options.object
            )
        }
    }
}

async fn list_items(client: &Client, options: ListOptions) -> Result<CommandOutput> {
    // Sync to get the latest vault data
    let sync_response = client
        .vault()
        .sync(&SyncRequest {
            exclude_subdomains: Some(true),
        })
        .await?;

    // Decrypt the ciphers
    let mut cipher_views: Vec<CipherListView> = client
        .vault()
        .ciphers()
        .decrypt_list(sync_response.ciphers)?;

    // Apply filters (retaining matching items)
    cipher_views.retain(|item| {
        // Filter by trash status
        if options.trash {
            if item.deleted_date.is_none() {
                return false;
            }
        } else if item.deleted_date.is_some() {
            return false;
        }

        // Filter by folder
        if let Some(ref folder_id) = options.folderid {
            if item.folder_id.as_ref().map(|id| id.to_string()) != Some(folder_id.clone()) {
                return false;
            }
        }

        // Filter by collection
        if let Some(ref collection_id) = options.collectionid {
            if !item
                .collection_ids
                .iter()
                .any(|id| id.to_string() == *collection_id)
            {
                return false;
            }
        }

        // Filter by organization
        if let Some(ref org_id) = options.organizationid {
            if item.organization_id.as_ref().map(|id| id.to_string()) != Some(org_id.clone()) {
                return false;
            }
        }

        // Search filter (case-insensitive search in name)
        if let Some(ref search_term) = options.search {
            let search_lower = search_term.to_lowercase();
            if !item.name.to_lowercase().contains(&search_lower) {
                return false;
            }
        }

        true
    });

    // Sort by name for consistent output
    cipher_views.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(CommandOutput::Object(Box::new(cipher_views)))
}
