use bitwarden_core::Client;
use bitwarden_generators::{
    GeneratorClientsExt, PassphraseGeneratorRequest, PasswordGeneratorRequest,
};
use clap::{Args, Subcommand};

use crate::render::CommandResult;

// TODO(CLI): This is incompatible with the current node CLI
#[derive(Subcommand, Clone)]
pub enum GeneratorCommands {
    Password(PasswordGeneratorArgs),
    Passphrase(PassphraseGeneratorArgs),
}

impl GeneratorCommands {
    pub fn run(&self, client: &Client) -> CommandResult {
        match self {
            GeneratorCommands::Password(args) => {
                let password = client.generator().password(PasswordGeneratorRequest {
                    lowercase: args.lowercase,
                    uppercase: args.uppercase,
                    numbers: args.numbers,
                    special: args.special,
                    length: args.length,
                    ..Default::default()
                })?;

                Ok(password.into())
            }
            GeneratorCommands::Passphrase(args) => {
                let passphrase = client.generator().passphrase(PassphraseGeneratorRequest {
                    num_words: args.words,
                    word_separator: args.separator.to_string(),
                    capitalize: args.capitalize,
                    include_number: args.include_number,
                })?;

                Ok(passphrase.into())
            }
        }
    }
}

#[derive(Args, Clone)]
pub struct PasswordGeneratorArgs {
    #[arg(short = 'l', long, action, help = "Include lowercase characters (a-z)")]
    pub lowercase: bool,

    #[arg(short = 'u', long, action, help = "Include uppercase characters (A-Z)")]
    pub uppercase: bool,

    #[arg(short = 'n', long, action, help = "Include numbers (0-9)")]
    pub numbers: bool,

    #[arg(
        short = 's',
        long,
        action,
        help = "Include special characters (!@#$%^&*)"
    )]
    pub special: bool,

    #[arg(long, default_value = "16", help = "Length of generated password")]
    pub length: u8,
}

#[derive(Args, Clone)]
pub struct PassphraseGeneratorArgs {
    #[arg(long, default_value = "3", help = "Number of words in the passphrase")]
    pub words: u8,

    #[arg(long, default_value = " ", help = "Separator between words")]
    pub separator: char,

    #[arg(long, action, help = "Capitalize the first letter of each word")]
    pub capitalize: bool,

    #[arg(long, action, help = "Include a number in one of the words")]
    pub include_number: bool,
}
