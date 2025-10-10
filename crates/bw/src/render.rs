use bitwarden_cli::Color;
use clap::ValueEnum;

use crate::command::Cli;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum Output {
    JSON,
    YAML,
    Table,
    TSV,
    None,
}

pub enum CommandOutput {
    Plain(String),
    Object(Box<dyn erased_serde::Serialize>),
}
pub type CommandResult = color_eyre::eyre::Result<CommandOutput>;

impl From<&str> for CommandOutput {
    fn from(text: &str) -> Self {
        CommandOutput::Plain(text.to_owned())
    }
}
impl From<String> for CommandOutput {
    fn from(text: String) -> Self {
        CommandOutput::Plain(text)
    }
}
impl From<()> for CommandOutput {
    fn from(_: ()) -> Self {
        CommandOutput::Plain(String::new())
    }
}

pub struct RenderConfig {
    pub output: Output,
    pub color: Color,
    pub cleanexit: bool,
    pub quiet: bool,
}

impl RenderConfig {
    pub fn new(cli: &Cli) -> Self {
        Self {
            output: cli.output,
            color: cli.color,
            cleanexit: cli.cleanexit,
            quiet: cli.quiet,
        }
    }

    pub fn render_result(&self, result: CommandResult) -> color_eyre::eyre::Result<()> {
        if self.quiet || self.output == Output::None {
            return Ok(());
        }

        fn pretty_print(language: &str, data: &str, color: Color) {
            if color.is_enabled() {
                bat::PrettyPrinter::new()
                    .input_from_bytes(data.as_bytes())
                    .language(language)
                    .print()
                    .expect("Input is valid");
            } else {
                print!("{}", data);
            }
        }

        match result {
            // Errors will be passed through to the caller, and rendered by the main function
            Err(e) => Err(e),

            // With cleanexit, we don't print anything on success
            Ok(_) if self.cleanexit => Ok(()),

            // Plain text is just output as is
            Ok(CommandOutput::Plain(text)) => {
                println!("{}", text);
                Ok(())
            }

            // For objects, we serialize them based on the output format,
            Ok(CommandOutput::Object(obj)) => {
                match self.output {
                    Output::JSON => {
                        let mut json = serde_json::to_string_pretty(&*obj)?;
                        // Yaml/table/tsv serializations add a newline at the end, so we do the same
                        // here for consistency
                        json.push('\n');
                        pretty_print("json", &json, self.color);
                    }
                    Output::YAML => {
                        let yaml = serde_yaml::to_string(&*obj)?;
                        pretty_print("yaml", &yaml, self.color);
                    }
                    Output::Table => {
                        todo!()
                    }
                    Output::TSV => {
                        todo!()
                    }
                    Output::None => unreachable!(),
                }
                Ok(())
            }
        }
    }
}
