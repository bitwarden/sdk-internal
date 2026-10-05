use clap::{Args, CommandFactory};
use clap_complete::Shell;

use crate::{
    client_state::{AnyState, BwCommand},
    command::Cli,
    render::CommandResult,
};

#[derive(Args, Clone)]
pub struct CompletionArgs {
    #[arg(long, help = "The shell to generate completions for.")]
    pub shell: Option<Shell>,
}

impl BwCommand for CompletionArgs {
    type Client = AnyState;

    async fn run(self, _: AnyState) -> CommandResult {
        let Some(shell) = self.shell.or_else(Shell::from_env) else {
            return Ok(
                "Couldn't autodetect a valid shell. Run `bw completion --help` for more info."
                    .into(),
            );
        };

        clap_complete::generate(
            shell,
            &mut Cli::command(),
            env!("CARGO_BIN_NAME"),
            &mut std::io::stdout(),
        );
        Ok(().into())
    }
}
