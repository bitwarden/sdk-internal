use std::process::Command;

/// Create a new bw CLI command
pub fn bw() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bw"))
}

/// Get the server base URL
///
/// Uses `BITWARDEN_SERVER_URL` environment variable if set,
/// otherwise defaults to "https://localhost:8080"
pub fn server_base() -> String {
    std::env::var("BITWARDEN_SERVER_URL").unwrap_or_else(|_| "https://localhost:8080".to_string())
}
