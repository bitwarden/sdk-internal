use clap::Args;

#[derive(Args, Clone)]
pub(crate) struct UnlockArgs {
    pub(crate) password: Option<String>,

    #[arg(long, help = "Environment variable storing your password.")]
    pub(crate) passwordenv: Option<String>,

    #[arg(
        long,
        help = "Path to a file containing your password as its first line."
    )]
    pub(crate) passwordfile: Option<String>,

    #[arg(long, help = "Check lock status.")]
    pub(crate) check: bool,

    #[arg(long, help = "Only return the session key.")]
    pub(crate) raw: bool,
}
