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

#[derive(clap::Args, Clone)]
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
pub struct ListCollectionsArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
pub struct ListOrganizationsArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
pub struct ListOrgCollectionsArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
pub struct ListOrgMembersArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
pub struct DeleteOrgCollectionArgs {
    pub id: String,
    #[arg(long, alias = "organizationid", help = "Organization ID")]
    pub organization_id: String,
}

#[derive(Args, Clone)]
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
pub struct GetCollectionArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetOrganizationArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetOrgCollectionArgs {
    pub id: String,
}

#[derive(clap::Args, Clone)]
pub struct CreateCollectionArgs {
    #[arg(help = "Base64-encoded JSON collection object")]
    encoded_json: String,

    #[arg(long, alias = "organizationid", help = "Organization ID")]
    organization_id: Option<String>,
}
