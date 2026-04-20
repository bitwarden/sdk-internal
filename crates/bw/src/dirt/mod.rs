use bw_macro::bw_command;
use clap::Args;

#[derive(Args, Clone)]
#[bw_command(
    path = "get exposed",
    todo,
    about = "Check if an item password has been exposed in a data breach."
)]
pub struct GetExposedArgs {
    pub id: String,
}
