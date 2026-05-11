use base64::{Engine, engine::general_purpose::STANDARD};
use clap::Args;

use crate::{
    client_state::{AnyState, BwCommand},
    render::CommandResult,
};

#[derive(Args, Clone)]
pub struct EncodeArgs;

impl BwCommand for EncodeArgs {
    type Client = AnyState;

    async fn run(self, _: AnyState) -> CommandResult {
        let input = std::io::read_to_string(std::io::stdin())?;
        let encoded = STANDARD.encode(input);
        Ok(encoded.into())
    }
}
