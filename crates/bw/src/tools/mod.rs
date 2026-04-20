use bitwarden_generators::{PassphraseGeneratorRequest, PasswordGeneratorRequest};
use bw_macro::bw_command;
use clap::{Args, Subcommand};

use crate::{
    client_state::{BwCommand, LoggedIn},
    render::CommandResult,
};

#[derive(Args, Clone)]
#[bw_command(
    path = "generate",
    about = "Generate a password/passphrase.",
    after_help = "Notes:\n    Default options are `-uln --length 14`.\n    Minimum `length` is 5.\n    Minimum `words` is 3.\n\nExamples:\n    bw generate\n    bw generate -u -l --length 18\n    bw generate -ulns --length 25\n    bw generate -ul\n    bw generate -p --separator _\n    bw generate -p --words 5 --separator space\n    bw generate -p --words 5 --separator empty"
)]
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

impl BwCommand for GenerateArgs {
    type Client = LoggedIn;

    async fn run(mut self, LoggedIn { client, .. }: LoggedIn) -> CommandResult {
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

#[derive(Subcommand, Clone, Debug)]
pub enum SendCommands {
    #[command(about = "List all the Sends owned by you.")]
    List,

    #[command(about = "Get json templates for send objects.")]
    Template { object: String },

    #[command(about = "Get Sends owned by you.")]
    Get {
        id: String,

        #[arg(long, help = "Specify a file path to save a File-type Send to.")]
        output: Option<String>,

        #[arg(long, help = "Only return the access url.")]
        text: bool,
    },

    #[command(about = "Access a Bitwarden Send from a url.")]
    Receive {
        url: String,

        #[arg(long, help = "Optional password for the Send.")]
        password: Option<String>,

        #[arg(long, help = "Specify a file path to save a File-type Send to.")]
        obj: Option<String>,
    },

    #[command(about = "Create a Send.")]
    Create {
        encoded_json: Option<String>,

        #[arg(short = 'f', long, help = "Path to the file to Send.")]
        file: Option<String>,

        #[arg(long, help = "Text to Send.")]
        text: Option<String>,

        #[arg(
            short = 'd',
            long = "deleteInDays",
            help = "The number of days in the future to set deletion date.",
            default_value = "7"
        )]
        delete_in_days: String,

        #[arg(
            long = "maxAccessCount",
            help = "The maximum number of times this Send can be accessed."
        )]
        max_access_count: Option<u32>,

        #[arg(long, help = "Hide text.")]
        hidden: bool,

        #[arg(short = 'n', long, help = "The name of the Send.")]
        name: Option<String>,

        #[arg(long, help = "Notes to add to the Send.")]
        notes: Option<String>,

        #[arg(long, help = "Optional password to access this Send.")]
        password: Option<String>,

        #[arg(
            long = "fullObject",
            help = "Return full Send object instead of access url."
        )]
        full_object: bool,
    },

    #[command(about = "Edit a Send.")]
    Edit {
        encoded_json: Option<String>,

        #[arg(long, help = "Overrides the itemId provided in encodedJson.")]
        itemid: Option<String>,

        #[arg(
            short = 'd',
            long = "deleteInDays",
            help = "The number of days in the future to set deletion date."
        )]
        delete_in_days: Option<String>,

        #[arg(
            long = "maxAccessCount",
            help = "The maximum number of times this Send can be accessed."
        )]
        max_access_count: Option<u32>,

        #[arg(long, help = "Hide text.")]
        hidden: bool,
    },

    #[command(about = "Removes the saved password from a Send.")]
    RemovePassword { id: String },

    #[command(about = "Delete a Send.")]
    Delete { id: String },
}
