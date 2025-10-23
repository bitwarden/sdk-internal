use clap::Subcommand;

use crate::render::CommandResult;

#[derive(Subcommand, Clone)]
pub enum ConfigCommand {
    Server {
        base_url: Option<String>,

        #[arg(
            long,
            help = "Provides a custom web vault URL that differs from the base URL."
        )]
        web_vault: Option<String>,

        #[arg(
            long,
            help = "Provides a custom API URL that differs from the base URL."
        )]
        api: Option<String>,
        #[arg(
            long,
            help = "Provides a custom identity URL that differs from the base URL."
        )]
        identity: Option<String>,
        #[arg(
            long,
            help = "Provides a custom icons service URL that differs from the base URL."
        )]
        icons: Option<String>,
        #[arg(
            long,
            help = "Provides a custom notifications URL that differs from the base URL."
        )]
        notifications: Option<String>,
        #[arg(
            long,
            help = "Provides a custom events URL that differs from the base URL."
        )]
        events: Option<String>,

        #[arg(long, help = "Provides the URL for your Key Connector server.")]
        key_connector: Option<String>,
    },
}

impl ConfigCommand {
    #[allow(clippy::unused_async)]
    pub async fn run(self) -> CommandResult {
        todo!()
    }
}
