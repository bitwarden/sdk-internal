use clap::Subcommand;

#[derive(Subcommand, Clone)]
pub enum ConfirmCommand {
    OrgMember {
        /// Object's globally unique ID
        id: String,

        #[arg(long, help = "Organization id for an organization object.")]
        organizationid: String,
    },
}

#[derive(clap::Args, Clone)]
pub struct MoveArgs {
    /// Item ID
    pub itemid: String,
    /// Organization ID
    pub organizationid: String,
    /// Base64-encoded JSON with collection IDs (optional)
    pub encoded_json: Option<String>,
}
