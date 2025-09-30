use bitwarden_generators::{PassphraseGeneratorRequest, PasswordGeneratorRequest};
use bitwarden_pm::PasswordManagerClient;
use clap::Args;

use crate::render::CommandResult;

#[derive(Args, Clone)]
pub struct GenerateArgs {
    // Password arguments
    #[arg(short = 'u', long, action, help = "Include uppercase characters (A-Z)")]
    pub uppercase: bool,

    #[arg(short = 'l', long, action, help = "Include lowercase characters (a-z)")]
    pub lowercase: bool,

    #[arg(short = 'n', long, action, help = "Include numbers (0-9)")]
    pub number: bool,

    #[arg(
        short = 's',
        long,
        action,
        help = "Include special characters (!@#$%^&*)"
    )]
    pub special: bool,

    #[arg(long, default_value = "16", help = "Length of generated password")]
    pub length: u8,

    #[arg(long, help = "Minimum number of numeric characters")]
    pub min_numbers: Option<u8>,

    #[arg(long, help = "Minimum number of special characters")]
    pub min_special: Option<u8>,

    #[arg(long, action, help = "Avoid ambiguous characters")]
    pub ambiguous: bool,

    // Passphrase arguments
    #[arg(short = 'p', long, action, help = "Generate a passphrase")]
    pub passphrase: bool,

    #[arg(long, default_value = "5", help = "Number of words in the passphrase")]
    pub words: u8,

    #[arg(long, default_value = "-", help = "Separator between words")]
    pub separator: char,

    #[arg(long, action, help = "Capitalize the first letter of each word")]
    pub capitalize: bool,

    #[arg(long, action, help = "Include a number in one of the words")]
    pub include_number: bool,
}

impl GenerateArgs {
    pub fn run(mut self, client: &PasswordManagerClient) -> CommandResult {
        let result = if self.passphrase {
            client.generator().passphrase(PassphraseGeneratorRequest {
                num_words: self.words,
                word_separator: self.separator.to_string(),
                capitalize: self.capitalize,
                include_number: self.include_number,
            })?
        } else {
            // Default options if none are specified
            if !self.lowercase && !self.uppercase && !self.number && !self.special {
                self.lowercase = true;
                self.uppercase = true;
                self.number = true;
            }

            client.generator().password(PasswordGeneratorRequest {
                lowercase: self.lowercase,
                uppercase: self.uppercase,
                numbers: self.number,
                special: self.special,
                length: self.length,
                min_number: self.min_numbers,
                min_special: self.min_special,
                avoid_ambiguous: self.ambiguous,
                ..Default::default()
            })?
        };

        Ok(result.into())
    }
}
