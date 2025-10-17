#![doc = include_str!("../README.md")]

mod color;

pub use color::{Color, install_color_eyre};
use inquire::{Text, error::InquireResult};

/// Prompt the user for input if the value is None
///
/// Typically used when the user can provide a value via CLI or prompt
pub fn text_prompt_when_none(prompt: &str, val: Option<String>) -> InquireResult<String> {
    Ok(if let Some(val) = val {
        val
    } else {
        Text::new(prompt).prompt()?
    })
}

/// Try to get a value from CLI arg, then from environment variables, then prompt
///
/// Checks multiple environment variable names in order (e.g., BW_CLIENTID, BW_CLIENT_ID)
pub fn resolve_user_input_value(
    prompt: &str,
    cli_val: Option<String>,
    env_var_names: &[&str],
) -> InquireResult<String> {
    // First check if provided via CLI
    if let Some(val) = cli_val {
        return Ok(val);
    }

    // Then check environment variables
    for env_var in env_var_names {
        if let Ok(val) = std::env::var(env_var) {
            if !val.is_empty() {
                return Ok(val);
            }
        }
    }

    // Finally, prompt the user
    Text::new(prompt).prompt()
}
