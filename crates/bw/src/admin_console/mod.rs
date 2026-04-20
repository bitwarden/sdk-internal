use clap::Subcommand;

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
