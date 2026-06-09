use bitwarden_generators::{
    MAXIMUM_MIN_CHAR_COUNT, MAXIMUM_PASSPHRASE_NUM_WORDS, MAXIMUM_PASSWORD_LENGTH,
    MINIMUM_MIN_CHAR_COUNT, MINIMUM_PASSPHRASE_NUM_WORDS, MINIMUM_PASSWORD_LENGTH,
    PassphraseGeneratorRequest, PasswordGeneratorRequest,
};
use bitwarden_pm::PasswordManagerClient;
use bitwarden_send::SendId;
use clap::{Args, Subcommand};

use crate::render::CommandResult;

mod send;

#[derive(Args, Clone)]
#[command(
    about = "Generate a password/passphrase.",
    after_help = r#"Notes:
    Default options are `-uln --length 14`.
    Minimum `length` is 5.
    Minimum `words` is 3.

Examples:
    bw generate
    bw generate -u -l --length 18
    bw generate -ulns --length 25
    bw generate -ul
    bw generate -p --separator _
    bw generate -p --words 5 --separator space
    bw generate -p --words 5 --separator empty
    "#
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

    #[arg(long, default_value = "14", help = "Length of generated password")]
    pub length: u8,

    // Default is 0 so the cascade below (`min_number > 0 → enable numbers`) only triggers when
    // the user explicitly passed the flag. When `-n` is enabled but `--min-number` is omitted,
    // the SDK's `get_minimum` still enforces at least one digit.
    #[arg(
        long,
        alias = "minNumber",
        default_value = "0",
        help = "Minimum number of numeric characters"
    )]
    pub min_number: u8,

    #[arg(
        long,
        alias = "minSpecial",
        default_value = "0",
        help = "Minimum number of special characters"
    )]
    pub min_special: u8,

    #[arg(long, action, help = "Avoid ambiguous characters")]
    pub ambiguous: bool,

    // Passphrase arguments
    #[arg(short = 'p', long, action, help = "Generate a passphrase")]
    pub passphrase: bool,

    #[arg(long, default_value = "6", help = "Number of words in the passphrase")]
    pub words: u8,

    #[arg(long, default_value = "-", help = "Separator between words")]
    pub separator: String,

    #[arg(long, action, help = "Title case passphrase.")]
    pub capitalize: bool,

    #[arg(
        long,
        alias = "includeNumber",
        action,
        help = "Include a number in one of the words"
    )]
    pub include_number: bool,
}

impl GenerateArgs {
    pub fn run(self, client: &PasswordManagerClient) -> CommandResult {
        let result = if self.passphrase {
            client.generator().passphrase(PassphraseGeneratorRequest {
                // Silently clamp to the SDK's supported range, matching the Angular clients'
                // `fitToBounds` in `passphrase-policy-constraints.ts`.
                num_words: self
                    .words
                    .clamp(MINIMUM_PASSPHRASE_NUM_WORDS, MAXIMUM_PASSPHRASE_NUM_WORDS),
                word_separator: normalize_separator(self.separator),
                capitalize: self.capitalize,
                include_number: self.include_number,
            })?
        } else {
            // When the user selects no charset, default to lowercase + uppercase + number,
            // matching the legacy CLI.
            let any_explicit = self.lowercase || self.uppercase || self.number || self.special;
            let lowercase = if any_explicit { self.lowercase } else { true };
            let uppercase = if any_explicit { self.uppercase } else { true };
            // Cascade `--min-number` / `--min-special` > 0 into enabling the charset, matching
            // `PasswordGeneratorOptionsEvaluator.applyPolicy` in the Angular clients.
            let number = if any_explicit {
                self.number || self.min_number > 0
            } else {
                true
            };
            let special = self.special || self.min_special > 0;

            client.generator().password(PasswordGeneratorRequest {
                lowercase,
                uppercase,
                numbers: number,
                special,
                length: self
                    .length
                    .clamp(MINIMUM_PASSWORD_LENGTH, MAXIMUM_PASSWORD_LENGTH),
                min_number: Some(
                    self.min_number
                        .clamp(MINIMUM_MIN_CHAR_COUNT, MAXIMUM_MIN_CHAR_COUNT),
                ),
                min_special: Some(
                    self.min_special
                        .clamp(MINIMUM_MIN_CHAR_COUNT, MAXIMUM_MIN_CHAR_COUNT),
                ),
                avoid_ambiguous: self.ambiguous,
                ..Default::default()
            })?
        };

        Ok(result.into())
    }
}

/// Map CLI-level separator input ("space", "empty", or a string) to the single character the
/// generator expects.
fn normalize_separator(separator: String) -> String {
    match separator.as_str() {
        "space" => " ".to_string(),
        "empty" => String::new(),
        s if s.len() > 1 => s.chars().next().map(|c| c.to_string()).unwrap_or_default(),
        _ => separator,
    }
}

#[derive(Args, Clone)]
pub struct GetSendArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct ImportArgs {
    /// Format to import from
    pub format: Option<String>,
    /// Filepath to data to import
    pub input: Option<String>,

    #[arg(long, help = "List formats")]
    pub formats: bool,

    #[arg(
        long,
        alias = "organizationid",
        help = "ID of the organization to import to."
    )]
    pub organization_id: Option<String>,
}

#[derive(Args, Clone)]
pub struct ExportArgs {
    #[arg(long, help = "Output directory or filename.")]
    pub output: Option<String>,

    #[arg(long, help = "Export file format.")]
    pub format: Option<String>,

    #[arg(
        long,
        help = "Use password to encrypt instead of your Bitwarden account encryption key."
    )]
    pub password: Option<String>,

    #[arg(
        long,
        alias = "organizationid",
        help = "Organization id for an organization."
    )]
    pub organization_id: Option<String>,
}

#[derive(Args, Clone)]
pub struct SendArgs {
    /// The data to Send
    pub data: Option<String>,

    #[arg(short = 'f', long, help = "Specifies that <data> is a filepath.")]
    pub file: bool,

    #[arg(
        short = 'd',
        long = "deleteInDays",
        help = "The number of days in the future to set deletion date.",
        default_value_t = 7
    )]
    pub delete_in_days: u64,

    #[arg(long, help = "Optional password to access this Send.")]
    pub password: Option<String>,

    #[arg(
        long,
        help = "Email addresses for OTP authentication (single, JSON array, comma- or space-separated)."
    )]
    pub emails: Option<String>,

    #[arg(
        short = 'a',
        long = "maxAccessCount",
        help = "The amount of max possible accesses."
    )]
    pub max_access_count: Option<u32>,

    #[arg(long, help = "Hide <data> in web by default.")]
    pub hidden: bool,

    #[arg(short = 'n', long, help = "The name of the Send.")]
    pub name: Option<String>,

    #[arg(long, help = "Notes to add to the Send.")]
    pub notes: Option<String>,

    #[arg(
        long = "fullObject",
        help = "Specifies that the full Send object should be returned."
    )]
    pub full_object: bool,

    #[command(subcommand)]
    pub command: Option<SendCommands>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum SendCommands {
    #[command(about = "List all the Sends owned by you.")]
    List(SendListArgs),

    #[command(about = "Get json templates for send objects.")]
    Template(SendTemplateArgs),

    #[command(about = "Get Sends owned by you.")]
    Get(SendGetArgs),

    #[command(about = "Access a Bitwarden Send from a url.")]
    Receive(SendReceiveArgs),

    #[command(about = "Create a Send.")]
    Create(SendCreateArgs),

    #[command(about = "Edit a Send.")]
    Edit(SendEditArgs),

    #[command(about = "Removes the saved password from a Send.")]
    RemovePassword(SendRemovePasswordArgs),

    #[command(about = "Delete a Send.")]
    Delete(SendDeleteArgs),
}

#[derive(Args, Clone, Debug)]
pub struct SendListArgs;

#[derive(Args, Clone, Debug)]
pub struct SendTemplateArgs {
    pub object: String,
}

#[derive(Args, Clone, Debug)]
pub struct SendGetArgs {
    pub id: SendId,

    // The legacy CLI uses `--output <path>` here, but the top-level `bw` already defines
    // a global `-o, --output` flag for the rendered output format (JSON, etc.). Naming
    // this `--output-file` avoids a clap runtime panic when both args resolve to the
    // same long flag with different types. Legacy parity is tracked in PM-34719 follow-ups.
    #[arg(
        long = "output-file",
        help = "File path to save a file-type Send's decrypted contents to."
    )]
    pub output_file: Option<String>,

    #[arg(long, help = "Only return the access url.")]
    pub text: bool,
}

#[derive(Args, Clone, Debug)]
pub struct SendReceiveArgs {
    pub url: String,

    #[arg(long, help = "Optional password for the Send.")]
    pub password: Option<String>,

    #[arg(long, help = "Specify a file path to save a File-type Send to.")]
    pub obj: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct SendCreateArgs {
    pub encoded_json: Option<String>,

    #[arg(short = 'f', long, help = "Path to the file to Send.")]
    pub file: Option<String>,

    #[arg(long, help = "Text to Send.")]
    pub text: Option<String>,

    #[arg(
        short = 'd',
        long = "deleteInDays",
        help = "The number of days in the future to set deletion date.",
        default_value_t = 7
    )]
    pub delete_in_days: u64,

    #[arg(
        long = "maxAccessCount",
        help = "The maximum number of times this Send can be accessed."
    )]
    pub max_access_count: Option<u32>,

    #[arg(long, help = "Hide text.")]
    pub hidden: bool,

    #[arg(short = 'n', long, help = "The name of the Send.")]
    pub name: Option<String>,

    #[arg(long, help = "Notes to add to the Send.")]
    pub notes: Option<String>,

    #[arg(long, help = "Optional password to access this Send.")]
    pub password: Option<String>,

    // TODO(PM-34719): The legacy CLI enforces `--password` and `--emails` as mutually
    // exclusive at parse time. clap-level enforcement is deferred; for now the builder
    // (`build_auth` in `tools/send.rs`) returns an error when both are supplied.
    #[arg(
        long,
        help = "Email addresses for OTP authentication (single, JSON array, comma- or space-separated)."
    )]
    pub emails: Option<String>,

    #[arg(
        long = "fullObject",
        help = "Return full Send object instead of access url."
    )]
    pub full_object: bool,
}

#[derive(Args, Clone, Debug)]
pub struct SendEditArgs {
    pub encoded_json: Option<String>,

    #[arg(long, help = "Overrides the itemId provided in encodedJson.")]
    pub itemid: Option<SendId>,

    #[arg(
        short = 'd',
        long = "deleteInDays",
        help = "The number of days in the future to set deletion date."
    )]
    pub delete_in_days: Option<u64>,

    #[arg(
        long = "maxAccessCount",
        help = "The maximum number of times this Send can be accessed."
    )]
    pub max_access_count: Option<u32>,

    #[arg(long, help = "Hide text.")]
    pub hidden: bool,

    #[arg(long, help = "Optional password to access this Send.")]
    pub password: Option<String>,

    // TODO(PM-34719): The legacy CLI enforces `--password` and `--emails` as mutually
    // exclusive at parse time. clap-level enforcement is deferred; for now the builder
    // (`build_auth_for_edit` in `tools/send.rs`) returns an error when both are supplied.
    #[arg(
        long,
        help = "Email addresses for OTP authentication (single, JSON array, comma- or space-separated)."
    )]
    pub emails: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct SendRemovePasswordArgs {
    pub id: SendId,
}

#[derive(Args, Clone, Debug)]
pub struct SendDeleteArgs {
    pub id: SendId,
}

#[derive(Args, Clone)]
pub struct ReceiveArgs {
    /// URL to access Send from
    pub url: String,

    #[arg(long, help = "Optional password for the Send.")]
    pub password: Option<String>,

    #[arg(long, help = "Specify a file path to save a File-type Send to.")]
    pub obj: Option<String>,
}
