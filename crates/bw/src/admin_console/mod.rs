use clap::Subcommand;

#[derive(Subcommand, Clone)]
pub enum ConfirmCommand {
    OrgMember {
        #[arg(long, help = "Organization id for an organization object.")]
        organizationid: String,
    },
}
