use bitwarden_generators::{PassphraseGeneratorRequest, PasswordGeneratorRequest};
use bitwarden_pm::PasswordManagerClient;
use bitwarden_policies::{PasswordGeneratorPolicy, Policy};
use clap::{Args, Subcommand};

use crate::render::CommandResult;

const DEFAULT_PASSWORD_LENGTH: u8 = 14;
const DEFAULT_MIN_NUMBER: u8 = 1;
const DEFAULT_MIN_SPECIAL: u8 = 0;
const DEFAULT_PASSPHRASE_WORDS: u8 = 6;

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

    #[arg(long, help = "Length of generated password [default: 14]")]
    pub length: Option<u8>,

    #[arg(
        long,
        alias = "minNumber",
        help = "Minimum number of numeric characters [default: 1]"
    )]
    pub min_number: Option<u8>,

    #[arg(
        long,
        alias = "minSpecial",
        help = "Minimum number of special characters [default: 0]"
    )]
    pub min_special: Option<u8>,

    #[arg(long, action, help = "Avoid ambiguous characters")]
    pub ambiguous: bool,

    // Passphrase arguments
    #[arg(short = 'p', long, action, help = "Generate a passphrase")]
    pub passphrase: bool,

    #[arg(long, help = "Number of words in the passphrase [default: 6]")]
    pub words: Option<u8>,

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
    pub async fn run(mut self, client: &PasswordManagerClient) -> CommandResult {
        let policy = self.get_aggregated_policy(client).await;

        // Check generation type override (Gap D)
        if let Some(ref policy) = policy {
            if let Some(ref required_type) = policy.override_password_type {
                match required_type.as_str() {
                    "password" if self.passphrase => {
                        return Err(color_eyre::eyre::eyre!(
                            "Your organization requires password generation. Remove the -p flag."
                        ));
                    }
                    "passphrase" if !self.passphrase => {
                        return Err(color_eyre::eyre::eyre!(
                            "Your organization requires passphrase generation. Use the -p flag."
                        ));
                    }
                    _ => {}
                }
            }
        }

        let result = if self.passphrase {
            self.run_passphrase(client, policy.as_ref())?
        } else {
            self.run_password(client, policy.as_ref())?
        };

        Ok(result.into())
    }

    fn run_password(
        &mut self,
        client: &PasswordManagerClient,
        policy: Option<&PasswordGeneratorPolicy>,
    ) -> color_eyre::eyre::Result<String> {
        // Determine whether the user explicitly chose any charset flags.
        let user_chose_charsets = self.uppercase || self.lowercase || self.number || self.special;

        if let Some(policy) = policy {
            // Check charset conflicts: error if user's explicit choices omit a required charset.
            if user_chose_charsets {
                let violations = policy.check_charset_conflicts(
                    self.uppercase,
                    self.lowercase,
                    self.number,
                    self.special,
                );
                if !violations.is_empty() {
                    return Err(color_eyre::eyre::eyre!(
                        "Your organization requires that generated passwords include {}. \
                         Add the corresponding flag(s) or omit charset flags to use \
                         policy defaults.",
                        violations.join(", ")
                    ));
                }
            } else {
                // No explicit charset choice — apply policy charset requirements.
                self.uppercase |= policy.use_uppercase;
                self.lowercase |= policy.use_lowercase;
                self.number |= policy.use_numbers;
                self.special |= policy.use_special;
            }

            // Check numeric conflicts: error if user explicitly set a value below policy floor.
            let violations =
                policy.check_numeric_conflicts(self.length, self.min_number, self.min_special);
            if !violations.is_empty() {
                return Err(color_eyre::eyre::eyre!(
                    "Your organization requires {}.",
                    violations.join("; and ")
                ));
            }
        }

        // Resolve defaults, applying policy floors for non-explicit values.
        let policy_min_length = policy.map_or(0, |p| p.min_length);
        let policy_number_count = policy.map_or(0, |p| p.number_count);
        let policy_special_count = policy.map_or(0, |p| p.special_count);

        let length = self
            .length
            .unwrap_or(DEFAULT_PASSWORD_LENGTH.max(policy_min_length));
        let min_number = self
            .min_number
            .unwrap_or(DEFAULT_MIN_NUMBER.max(policy_number_count));
        let min_special = self
            .min_special
            .unwrap_or(DEFAULT_MIN_SPECIAL.max(policy_special_count));

        // Default charsets if still none are specified (after policy application)
        if !self.lowercase && !self.uppercase && !self.number && !self.special {
            self.lowercase = true;
            self.uppercase = true;
            self.number = true;
        }

        // Enforce an absolute minimum length for entropy
        let length = length.max(5);

        Ok(client.generator().password(PasswordGeneratorRequest {
            lowercase: self.lowercase,
            uppercase: self.uppercase,
            numbers: self.number,
            special: self.special,
            length,
            min_number: Some(min_number),
            min_special: Some(min_special),
            avoid_ambiguous: self.ambiguous,
            ..Default::default()
        })?)
    }

    fn run_passphrase(
        &mut self,
        client: &PasswordManagerClient,
        policy: Option<&PasswordGeneratorPolicy>,
    ) -> color_eyre::eyre::Result<String> {
        if let Some(policy) = policy {
            // Check words conflict: error if user explicitly set --words below policy minimum.
            if let Some(violation) = policy.check_words_conflict(self.words) {
                return Err(color_eyre::eyre::eyre!(
                    "Your organization requires {}.",
                    violation
                ));
            }

            // Silently enable capitalize/include_number if policy requires them.
            // These are additive — there is no --no-capitalize flag, so the user
            // cannot explicitly opt out.
            self.capitalize |= policy.capitalize;
            self.include_number |= policy.include_number;
        }

        // Resolve defaults, applying policy floors for non-explicit values.
        let policy_min_words = policy.map_or(0, |p| p.min_number_words);
        let words = self
            .words
            .unwrap_or(DEFAULT_PASSPHRASE_WORDS.max(policy_min_words));

        // Enforce an absolute minimum of 3 words for entropy
        let words = words.max(3);

        // Map words ("space" or "empty") entered in the terminal to actual output
        let separator = match self.separator.as_str() {
            "space" => " ".to_string(),
            "empty" => String::new(),
            s if s.len() > 1 => s.chars().next().map(|c| c.to_string()).unwrap_or_default(),
            _ => self.separator.clone(),
        };

        Ok(client.generator().passphrase(PassphraseGeneratorRequest {
            num_words: words,
            word_separator: separator,
            capitalize: self.capitalize,
            include_number: self.include_number,
        })?)
    }

    /// Retrieve and aggregate password generator policies from state.
    /// Returns `None` if not logged in, not synced, or no policies exist.
    async fn get_aggregated_policy(
        &self,
        client: &PasswordManagerClient,
    ) -> Option<PasswordGeneratorPolicy> {
        let state = client.platform().state();
        let repo = state.get::<Policy>().ok()?;

        let policies = repo.list().await.ok()?;

        let pw_policies: Vec<_> = policies
            .into_iter()
            .filter_map(|p| PasswordGeneratorPolicy::from_policy(&p))
            .collect();

        if pw_policies.is_empty() {
            None
        } else {
            Some(PasswordGeneratorPolicy::aggregate(pw_policies))
        }
    }
}

#[derive(Args, Clone)]
pub struct ImportArgs {
    /// Format to import from
    pub format: Option<String>,
    /// Filepath to data to import
    pub input: Option<String>,

    #[arg(long, help = "List formats")]
    pub formats: bool,

    #[arg(long, help = "ID of the organization to import to.")]
    pub organizationid: Option<String>,
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

    #[arg(long, help = "Organization id for an organization.")]
    pub organizationid: Option<String>,
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
        default_value = "7"
    )]
    pub delete_in_days: String,

    #[arg(long, help = "Optional password to access this Send.")]
    pub password: Option<String>,

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
    #[command(long_about = "List all the Sends owned by you.")]
    List,

    #[command(long_about = "Get json templates for send objects.")]
    Template { object: String },

    #[command(long_about = "Get Sends owned by you.")]
    Get {
        id: String,

        #[arg(long, help = "Specify a file path to save a File-type Send to.")]
        output: Option<String>,

        #[arg(long, help = "Only return the access url.")]
        text: bool,
    },

    #[command(long_about = "Access a Bitwarden Send from a url.")]
    Receive {
        url: String,

        #[arg(long, help = "Optional password for the Send.")]
        password: Option<String>,

        #[arg(long, help = "Specify a file path to save a File-type Send to.")]
        obj: Option<String>,
    },

    #[command(long_about = "Create a Send.")]
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

    #[command(long_about = "Edit a Send.")]
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

    #[command(long_about = "Removes the saved password from a Send.")]
    RemovePassword { id: String },

    #[command(long_about = "Delete a Send.")]
    Delete { id: String },
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
