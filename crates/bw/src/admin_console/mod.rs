use bw_macro::bw_command;
use clap::{Args, Subcommand};

#[derive(Subcommand, Clone)]
pub enum ConfirmCommand {
    OrgMember {
        /// Object's globally unique ID
        id: String,

        #[arg(
            long,
            alias = "organizationid",
            help = "Organization id for an organization object."
        )]
        organization_id: String,
    },
}

#[derive(Args, Clone)]
#[bw_command(
    path = "confirm",
    todo,
    about = "Confirm an object to the organization."
)]
pub struct ConfirmArgs {
    #[command(subcommand)]
    pub command: ConfirmCommand,
}

#[derive(clap::Args, Clone)]
#[bw_command(path = "move", todo, about = "Move an item to an organization.")]
pub struct MoveArgs {
    /// Item ID
    pub itemid: String,
    /// Organization ID
    #[arg(alias = "organizationid")]
    pub organization_id: String,
    /// Base64-encoded JSON with collection IDs (optional)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "list collections",
    todo,
    about = "List collections from the vault."
)]
pub struct ListCollectionsArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(path = "list organizations", todo, about = "List organizations.")]
pub struct ListOrganizationsArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "list org-collections",
    todo,
    about = "List organization collections."
)]
pub struct ListOrgCollectionsArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(path = "list org-members", todo, about = "List organization members.")]
pub struct ListOrgMembersArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "delete org-collection",
    todo,
    about = "Delete an organization collection."
)]
pub struct DeleteOrgCollectionArgs {
    pub id: String,
    #[arg(long, alias = "organizationid", help = "Organization ID")]
    pub organization_id: String,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "edit org-collection",
    todo,
    about = "Edit an organization collection."
)]
pub struct EditOrgCollectionArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,

    #[arg(
        long,
        alias = "organizationid",
        help = "Organization ID for an organization object"
    )]
    pub organization_id: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "get collection",
    todo,
    about = "Get a collection from the vault."
)]
pub struct GetCollectionArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get organization", todo, about = "Get an organization.")]
pub struct GetOrganizationArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "get org-collection",
    todo,
    about = "Get an organization collection."
)]
pub struct GetOrgCollectionArgs {
    pub id: String,
}

#[derive(clap::Args, Clone)]
#[bw_command(
    path = "create org-collection",
    todo,
    about = "Create an organization collection."
)]
pub struct CreateCollectionArgs {
    #[arg(help = "Base64-encoded JSON collection object")]
    encoded_json: String,

    #[arg(long, alias = "organizationid", help = "Organization ID")]
    organization_id: Option<String>,
}
