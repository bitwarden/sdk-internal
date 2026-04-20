#[derive(clap::Args, Clone)]
pub struct ServeArgs {
    #[arg(long, help = "Port number to listen on.", default_value = "8087")]
    pub port: u16,

    #[arg(long, help = "Hostname to bind to.", default_value = "localhost")]
    pub hostname: String,

    #[arg(
        long,
        help = "Disable origin protection (not recommended for production use)."
    )]
    pub disable_origin_protection: bool,
}
