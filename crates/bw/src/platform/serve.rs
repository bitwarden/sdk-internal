use bw_macro::bw_command;

#[derive(clap::Args, Clone)]
#[bw_command(path = "serve", todo, about = "Start a RESTful API webserver.")]
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
