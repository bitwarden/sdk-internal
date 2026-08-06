use bitwarden_generators::{
    MAXIMUM_MIN_CHAR_COUNT, MAXIMUM_PASSPHRASE_NUM_WORDS, MAXIMUM_PASSWORD_LENGTH,
    MINIMUM_MIN_CHAR_COUNT, MINIMUM_PASSPHRASE_NUM_WORDS, MINIMUM_PASSWORD_LENGTH,
    PassphraseGeneratorRequest, PasswordGeneratorRequest,
};
use bitwarden_pm::PasswordManagerClient;
use clap::Args;

use crate::{
    client_state::{AnyState, BwCommand},
    render::CommandResult,
};

mod file_output;
mod receive;
mod send;
pub use send::SendArgs;

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

/// `bw receive <url>`. Also used directly as the payload of `SendCommands::Receive` (`bw send
/// receive`) — the two are the same command reachable under two names, sharing this single arg
/// struct (rather than a hand-synced copy) so the flag sets can't drift apart. Both delegate to
/// [`receive::run_receive`].
#[derive(Args, Clone, Debug)]
#[command(after_help = "Notes:
    If a password is required, the provided password is used or the user is prompted.")]
pub struct ReceiveArgs {
    /// URL to access Send from
    pub url: String,

    #[arg(long, help = "Optional password for the Send.")]
    pub password: Option<String>,

    #[arg(long, help = "Environment variable storing the Send's password.")]
    pub passwordenv: Option<String>,

    #[arg(
        long,
        help = "Path to a file containing the Send's password as its first line."
    )]
    pub passwordfile: Option<String>,

    // The internal field is `output_path` (not `output`) to avoid clashing with the top-level
    // `Cli::output` (the `-o` rendered-output-format arg) — same convention as
    // `SendGetArgs::output_path`. User-facing long flag stays `--output` to match both that
    // sibling command and the legacy CLI.
    #[arg(
        long = "output",
        help = "Specify a file path to save a File-type Send to."
    )]
    pub output_path: Option<String>,

    #[arg(
        long = "fullObject",
        alias = "full-object",
        help = "Return the Send's json object rather than its content."
    )]
    pub full_object: bool,
}

impl BwCommand for ReceiveArgs {
    // `receive` is the one Send flow that needs no session at all: the key comes from the url
    // fragment and the token from the anonymous send-access grant.
    type Client = AnyState;

    async fn run(self, _: AnyState) -> CommandResult {
        receive::run_receive(receive::ReceiveInputs {
            url: self.url,
            password: self.password,
            passwordenv: self.passwordenv,
            passwordfile: self.passwordfile,
            output_path: self.output_path,
            full_object: self.full_object,
        })
        .await
    }
}
