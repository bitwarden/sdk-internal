//! `bw send` command implementation.
//!
//! Dispatches the subcommands declared on [`SendArgs`] / [`SendCommands`] in
//! [`super`] to the underlying [`bitwarden_send::SendClient`] methods. The arg
//! parsing surface is intentionally defined in `super` so the legacy-CLI shape
//! (which is part of the user contract) stays close to the rest of the
//! `tools` family.

use std::path::PathBuf;

use bitwarden_pm::PasswordManagerClient;
use bitwarden_send::{
    SendAddRequest, SendAuthType, SendEditRequest, SendFileView, SendId, SendTextView, SendViewType,
};
use chrono::{Duration, Utc};
use color_eyre::eyre::{Context as _, eyre};
use serde::Serialize;

use super::{SendArgs, SendCommands};
use crate::render::{CommandOutput, CommandResult};

impl SendArgs {
    pub async fn run(self, client: Option<PasswordManagerClient>) -> CommandResult {
        // If no subcommand is supplied, the legacy CLI treats `bw send <data>` as a Create
        // shortcut. Route that through the same builder path as `bw send create` so the two
        // entry points share their happy path.
        match self.command.clone() {
            None => {
                let client = require_login(client)?;
                create_shortcut(&client, self).await
            }
            Some(cmd) => dispatch_subcommand(client, cmd).await,
        }
    }
}

fn require_login(
    client: Option<PasswordManagerClient>,
) -> color_eyre::eyre::Result<PasswordManagerClient> {
    client.ok_or_else(|| eyre!("You are not logged in. Run `bw login` first."))
}

async fn dispatch_subcommand(
    client: Option<PasswordManagerClient>,
    cmd: SendCommands,
) -> CommandResult {
    match cmd {
        // `template` doesn't talk to the server; route it before the auth gate so users can
        // generate JSON scaffolding without a session.
        SendCommands::Template { object } => render_template(&object),
        SendCommands::List => {
            let client = require_login(client)?;
            list_sends(&client).await
        }
        SendCommands::Get { id, output, text } => {
            let client = require_login(client)?;
            get_send(&client, &id, output, text).await
        }
        // The `bw receive` command handles incoming sends; `bw send receive` is the legacy
        // alias and is out of scope for this ticket. See `Commands::Receive` in main.rs.
        SendCommands::Receive { .. } => Err(eyre!(
            "`bw send receive` is not implemented; use `bw receive <url>` instead."
        )),
        SendCommands::Create {
            encoded_json,
            file,
            text,
            delete_in_days,
            max_access_count,
            hidden,
            name,
            notes,
            password,
            emails,
            full_object,
        } => {
            // TODO(PM-34719): Fall back to reading `encoded_json` from stdin when omitted,
            // matching the legacy CLI's behavior.
            let _ = encoded_json;

            let request = build_create_request(CreateInputs {
                file,
                text,
                delete_in_days,
                max_access_count,
                hidden,
                name,
                notes,
                password,
                emails,
            })?;

            let client = require_login(client)?;
            run_create(&client, request, full_object).await
        }
        SendCommands::Edit {
            encoded_json,
            itemid,
            delete_in_days,
            max_access_count,
            hidden,
            password,
            emails,
        } => {
            // TODO(PM-34719): Fall back to reading `encoded_json` from stdin when omitted,
            // matching the legacy CLI's behavior.
            let _ = encoded_json;

            let id = itemid.as_deref().ok_or_else(|| {
                eyre!("--itemid is required (or provide it via encoded JSON, TODO PM-34719).")
            })?;
            let send_id: SendId = id
                .parse()
                .wrap_err_with(|| format!("Invalid Send id: {id}"))?;

            let client = require_login(client)?;

            // TODO(PM-34719): The CLI builds the edit request from the existing decrypted view
            // plus CLI overrides. The legacy CLI lets the user supply the full object via
            // encodedJson; we should support that path too. TODO(PM-34719): Enforce type
            // immutability on edit.
            let existing = client.sends().get(send_id).await?;

            let request = build_edit_request(
                existing,
                EditOverrides {
                    delete_in_days,
                    max_access_count,
                    hidden,
                    password,
                    emails,
                },
            )?;

            let view = client.sends().edit(send_id, request).await?;
            Ok(CommandOutput::Object(Box::new(view)))
        }
        SendCommands::RemovePassword { id } => {
            let send_id: SendId = id
                .parse()
                .wrap_err_with(|| format!("Invalid Send id: {id}"))?;
            let client = require_login(client)?;
            let view = client.sends().remove_password(send_id).await?;
            Ok(CommandOutput::Object(Box::new(view)))
        }
        SendCommands::Delete { id } => {
            let send_id: SendId = id
                .parse()
                .wrap_err_with(|| format!("Invalid Send id: {id}"))?;
            let client = require_login(client)?;
            client.sends().delete(send_id).await?;
            Ok("Send deleted.".into())
        }
    }
}

async fn list_sends(client: &PasswordManagerClient) -> CommandResult {
    let views = client.sends().list().await?;
    Ok(CommandOutput::Object(Box::new(views)))
}

async fn get_send(
    client: &PasswordManagerClient,
    id: &str,
    output: Option<String>,
    text: bool,
) -> CommandResult {
    let send_id: SendId = id
        .parse()
        .wrap_err_with(|| format!("Invalid Send id: {id}"))?;
    let view = client.sends().get(send_id).await?;

    if text {
        // TODO(PM-34719): Building a shareable access URL requires the server's web vault URL
        // and the access_id + key fragment. Emit only the access_id for now.
        return Ok(view
            .access_id
            .unwrap_or_else(|| "(no access id)".to_string())
            .into());
    }

    // TODO(PM-34719): When `output` is provided for a file send, decrypt + write the file to
    // disk via `SendClient::decrypt_file`. For now we just emit the view.
    let _ = output;

    Ok(CommandOutput::Object(Box::new(view)))
}

fn render_template(object: &str) -> CommandResult {
    // The legacy CLI distinguishes `send.text` and `send.file` (the latter has a `file.fileName`
    // field). Keep the shapes minimal but distinct so round-trips via `bw send create` are
    // unambiguous.
    match object {
        "send.text" => Ok(CommandOutput::Object(Box::new(SendTextTemplate::default()))),
        "send.file" => Ok(CommandOutput::Object(Box::new(SendFileTemplate::default()))),
        other => Err(eyre!("Unknown template object: {other}")),
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SendTextTemplate {
    name: String,
    notes: String,
    #[serde(rename = "type")]
    send_type: u8, // 0 = text
    text: SendTextTemplateBody,
    deletion_date: String,
}

#[derive(Serialize, Default)]
struct SendTextTemplateBody {
    text: String,
    hidden: bool,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SendFileTemplate {
    name: String,
    notes: String,
    #[serde(rename = "type")]
    send_type: u8, // 1 = file
    file: SendFileTemplateBody,
    deletion_date: String,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct SendFileTemplateBody {
    file_name: String,
}

struct CreateInputs {
    file: Option<String>,
    text: Option<String>,
    delete_in_days: String,
    max_access_count: Option<u32>,
    hidden: bool,
    name: Option<String>,
    notes: Option<String>,
    password: Option<String>,
    emails: Option<String>,
}

fn build_create_request(inputs: CreateInputs) -> color_eyre::eyre::Result<SendAddRequest> {
    let CreateInputs {
        file,
        text,
        delete_in_days,
        max_access_count,
        hidden,
        name,
        notes,
        password,
        emails,
    } = inputs;

    // TODO(PM-34719): Validate `delete_in_days` against the legacy CLI's allowed set (1, 2, 3,
    // 7, 14, 30) instead of accepting any positive integer.
    let deletion_date = compute_deletion_date(&delete_in_days)?;

    let view_type = match (file.as_deref(), text.as_deref()) {
        (Some(path), None) => {
            // TODO(PM-34719): File sends require a premium account; enforce that check before
            // building the request.
            let path = PathBuf::from(path);
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| eyre!("Could not derive a file name from --file path"))?
                .to_string();
            SendViewType::File(SendFileView {
                id: None,
                file_name,
                size: None,
                size_name: None,
            })
        }
        (None, Some(t)) => SendViewType::Text(SendTextView {
            text: Some(t.to_string()),
            hidden,
        }),
        (Some(_), Some(_)) => {
            return Err(eyre!("--file and --text are mutually exclusive."));
        }
        (None, None) => {
            return Err(eyre!(
                "Either --text <data> or --file <path> is required when creating a Send."
            ));
        }
    };

    // Derive a default name: file sends pick up the file name; text sends require an explicit
    // name to match the legacy CLI's UX.
    let resolved_name = match (name, &view_type) {
        (Some(n), _) => n,
        (None, SendViewType::File(f)) => f.file_name.clone(),
        (None, SendViewType::Text(_)) => {
            return Err(eyre!("--name is required for text Sends."));
        }
    };

    let auth = build_auth(password, emails.as_deref())?;

    Ok(SendAddRequest {
        name: resolved_name,
        notes,
        view_type,
        max_access_count,
        disabled: false,
        hide_email: false,
        deletion_date,
        expiration_date: None,
        auth,
    })
}

struct EditOverrides {
    delete_in_days: Option<String>,
    max_access_count: Option<u32>,
    hidden: bool,
    password: Option<String>,
    emails: Option<String>,
}

fn build_edit_request(
    existing: bitwarden_send::SendView,
    overrides: EditOverrides,
) -> color_eyre::eyre::Result<SendEditRequest> {
    let EditOverrides {
        delete_in_days,
        max_access_count,
        hidden,
        password,
        emails,
    } = overrides;

    let deletion_date = match delete_in_days {
        Some(d) => compute_deletion_date(&d)?,
        None => existing.deletion_date,
    };

    let view_type = match (existing.text, existing.file) {
        (Some(t), None) => SendViewType::Text(SendTextView {
            text: t.text,
            hidden: if hidden { true } else { t.hidden },
        }),
        (None, Some(f)) => SendViewType::File(f),
        // TODO(PM-34719): Sends should always carry exactly one of text/file; the API can in
        // theory return both. The legacy CLI prefers text in that case.
        (Some(t), Some(_)) => SendViewType::Text(SendTextView {
            text: t.text,
            hidden: if hidden { true } else { t.hidden },
        }),
        (None, None) => {
            return Err(eyre!(
                "Cannot edit Send {:?}: server returned neither text nor file content.",
                existing.id
            ));
        }
    };

    // If neither --password nor --emails was provided, preserve the existing auth type. The
    // SDK doesn't expose the plaintext password back to us, so we cannot rebuild a Password
    // auth from a previously-set send — that's a known limitation noted in the parity audit.
    let auth = match (password, emails.as_deref()) {
        (None, None) => SendAuthType::None,
        (Some(p), None) => SendAuthType::Password { password: p },
        (None, Some(e)) => SendAuthType::Emails {
            emails: parse_emails(e)?,
        },
        (Some(_), Some(_)) => {
            // TODO(PM-34719): The legacy CLI rejects this combination up front. clap-level
            // mutual exclusivity is deferred; for now we surface the error here.
            return Err(eyre!("--password and --emails are mutually exclusive."));
        }
    };

    Ok(SendEditRequest {
        name: existing.name,
        notes: existing.notes,
        view_type,
        max_access_count: max_access_count.or(existing.max_access_count),
        disabled: existing.disabled,
        hide_email: existing.hide_email,
        deletion_date,
        expiration_date: existing.expiration_date,
        auth,
    })
}

async fn create_shortcut(client: &PasswordManagerClient, args: SendArgs) -> CommandResult {
    let data = args
        .data
        .clone()
        .ok_or_else(|| eyre!("Missing <data> argument. Run `bw send --help` for usage."))?;

    let inputs = if args.file {
        CreateInputs {
            file: Some(data),
            text: None,
            delete_in_days: args.delete_in_days,
            max_access_count: args.max_access_count,
            hidden: args.hidden,
            name: args.name,
            notes: args.notes,
            password: args.password,
            emails: args.emails,
        }
    } else {
        CreateInputs {
            file: None,
            text: Some(data),
            delete_in_days: args.delete_in_days,
            max_access_count: args.max_access_count,
            hidden: args.hidden,
            // Text shortcut: default name to "Send" when not provided, matching the legacy CLI's
            // permissive behavior when callers pipe data in.
            name: args.name.or_else(|| Some("Send".to_string())),
            notes: args.notes,
            password: args.password,
            emails: args.emails,
        }
    };

    let request = build_create_request(inputs)?;
    run_create(client, request, args.full_object).await
}

async fn run_create(
    client: &PasswordManagerClient,
    request: SendAddRequest,
    full_object: bool,
) -> CommandResult {
    let is_file = matches!(request.view_type, SendViewType::File(_));

    // TODO(PM-34719): For file sends, the create flow has to follow up with `upload_send_file`
    // using the encrypted file bytes. The CLI doesn't have the encrypted bytes yet — the
    // file-encryption step is its own follow-up. For now we surface the gap explicitly.
    if is_file {
        return Err(eyre!(
            "Creating file Sends from the Rust CLI is not yet implemented (PM-34719: file encryption pipeline pending)."
        ));
    }

    let view = client.sends().create(request).await?;

    if full_object {
        return Ok(CommandOutput::Object(Box::new(view)));
    }

    // TODO(PM-34719): The default output is the access URL. We don't have the web vault URL
    // wired here yet, so emit the access id (which is the path component of the URL).
    Ok(view
        .access_id
        .unwrap_or_else(|| "(no access id)".to_string())
        .into())
}

fn compute_deletion_date(days_str: &str) -> color_eyre::eyre::Result<chrono::DateTime<Utc>> {
    let days: i64 = days_str
        .parse()
        .wrap_err_with(|| format!("Invalid --deleteInDays value: {days_str}"))?;
    if days <= 0 {
        return Err(eyre!("--deleteInDays must be a positive integer"));
    }
    Ok(Utc::now() + Duration::days(days))
}

fn build_auth(
    password: Option<String>,
    emails: Option<&str>,
) -> color_eyre::eyre::Result<SendAuthType> {
    match (password, emails) {
        (None, None) => Ok(SendAuthType::None),
        (Some(p), None) => Ok(SendAuthType::Password { password: p }),
        (None, Some(e)) => Ok(SendAuthType::Emails {
            emails: parse_emails(e)?,
        }),
        (Some(_), Some(_)) => Err(eyre!("--password and --emails are mutually exclusive.")),
    }
}

/// Parse the `--emails` argument into a list of email addresses.
///
/// The legacy CLI accepts four shapes, in order of precedence:
///   1. A JSON array: `["a@b.com", "c@d.com"]`
///   2. A comma-separated list: `a@b.com,c@d.com`
///   3. A space-separated list: `a@b.com c@d.com`
///   4. A single address: `a@b.com`
///
/// Returns an error if the parsed list is empty or any entry fails a basic shape check.
pub(crate) fn parse_emails(raw: &str) -> color_eyre::eyre::Result<Vec<String>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(eyre!("--emails cannot be empty"));
    }

    // 1. JSON array
    if trimmed.starts_with('[') {
        let arr: Vec<String> = serde_json::from_str(trimmed)
            .wrap_err("--emails looked like a JSON array but failed to parse")?;
        return finalize_emails(arr);
    }

    // 2./3. Delimiter-separated. Comma takes precedence; if no comma is present we fall back
    // to whitespace splitting so a quoted-and-shell-escaped `--emails "a@b.com c@d.com"` works.
    let parts: Vec<String> = if trimmed.contains(',') {
        trimmed.split(',').map(|s| s.trim().to_string()).collect()
    } else if trimmed.contains(char::is_whitespace) {
        trimmed.split_whitespace().map(|s| s.to_string()).collect()
    } else {
        // 4. Single email
        vec![trimmed.to_string()]
    };

    finalize_emails(parts)
}

fn finalize_emails(emails: Vec<String>) -> color_eyre::eyre::Result<Vec<String>> {
    let cleaned: Vec<String> = emails
        .into_iter()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err(eyre!("--emails must contain at least one address"));
    }
    for e in &cleaned {
        // Minimal sanity check; the server is the source of truth for validity.
        if !e.contains('@') {
            return Err(eyre!("Invalid email address: {e}"));
        }
    }
    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_emails ----

    #[test]
    fn parse_emails_single() {
        let v = parse_emails("a@b.com").unwrap();
        assert_eq!(v, vec!["a@b.com".to_string()]);
    }

    #[test]
    fn parse_emails_json_array() {
        let v = parse_emails(r#"["a@b.com","c@d.com"]"#).unwrap();
        assert_eq!(v, vec!["a@b.com".to_string(), "c@d.com".to_string()]);
    }

    #[test]
    fn parse_emails_comma_separated() {
        let v = parse_emails("a@b.com,c@d.com , e@f.com").unwrap();
        assert_eq!(
            v,
            vec![
                "a@b.com".to_string(),
                "c@d.com".to_string(),
                "e@f.com".to_string(),
            ]
        );
    }

    #[test]
    fn parse_emails_space_separated() {
        let v = parse_emails("a@b.com c@d.com  e@f.com").unwrap();
        assert_eq!(
            v,
            vec![
                "a@b.com".to_string(),
                "c@d.com".to_string(),
                "e@f.com".to_string(),
            ]
        );
    }

    #[test]
    fn parse_emails_rejects_empty() {
        assert!(parse_emails("").is_err());
        assert!(parse_emails("   ").is_err());
        assert!(parse_emails("[]").is_err());
    }

    #[test]
    fn parse_emails_rejects_no_at_sign() {
        assert!(parse_emails("not-an-email").is_err());
    }

    #[test]
    fn parse_emails_rejects_malformed_json_array() {
        // Looks like JSON but isn't a valid string array.
        assert!(parse_emails("[not, valid]").is_err());
    }

    // ---- compute_deletion_date ----

    #[test]
    fn compute_deletion_date_positive() {
        let d = compute_deletion_date("7").unwrap();
        let now = Utc::now();
        let diff = d - now;
        assert!(diff.num_days() >= 6 && diff.num_days() <= 7);
    }

    #[test]
    fn compute_deletion_date_rejects_zero_and_negative() {
        assert!(compute_deletion_date("0").is_err());
        assert!(compute_deletion_date("-3").is_err());
    }

    #[test]
    fn compute_deletion_date_rejects_garbage() {
        assert!(compute_deletion_date("not-a-number").is_err());
    }

    // ---- build_auth ----

    #[test]
    fn build_auth_none_when_neither_flag_given() {
        assert!(matches!(
            build_auth(None, None).unwrap(),
            SendAuthType::None
        ));
    }

    #[test]
    fn build_auth_password_only() {
        let auth = build_auth(Some("secret".to_string()), None).unwrap();
        assert!(matches!(auth, SendAuthType::Password { password } if password == "secret"));
    }

    #[test]
    fn build_auth_emails_only() {
        let auth = build_auth(None, Some("a@b.com")).unwrap();
        match auth {
            SendAuthType::Emails { emails } => assert_eq!(emails, vec!["a@b.com".to_string()]),
            other => panic!("expected Emails, got {other:?}"),
        }
    }

    #[test]
    fn build_auth_rejects_both() {
        assert!(build_auth(Some("p".into()), Some("a@b.com")).is_err());
    }

    // ---- build_create_request ----

    #[test]
    fn build_create_request_text_send() {
        let req = build_create_request(CreateInputs {
            file: None,
            text: Some("hello".into()),
            delete_in_days: "7".into(),
            max_access_count: Some(5),
            hidden: true,
            name: Some("My Send".into()),
            notes: Some("notes".into()),
            password: None,
            emails: None,
        })
        .unwrap();

        assert_eq!(req.name, "My Send");
        assert_eq!(req.notes.as_deref(), Some("notes"));
        assert_eq!(req.max_access_count, Some(5));
        match req.view_type {
            SendViewType::Text(t) => {
                assert_eq!(t.text.as_deref(), Some("hello"));
                assert!(t.hidden);
            }
            other => panic!("expected Text, got {other:?}"),
        }
        assert!(matches!(req.auth, SendAuthType::None));
    }

    #[test]
    fn build_create_request_text_requires_name() {
        let err = build_create_request(CreateInputs {
            file: None,
            text: Some("hello".into()),
            delete_in_days: "7".into(),
            max_access_count: None,
            hidden: false,
            name: None,
            notes: None,
            password: None,
            emails: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("--name is required"));
    }

    #[test]
    fn build_create_request_file_derives_name() {
        let req = build_create_request(CreateInputs {
            file: Some("/tmp/secrets.txt".into()),
            text: None,
            delete_in_days: "7".into(),
            max_access_count: None,
            hidden: false,
            name: None,
            notes: None,
            password: None,
            emails: None,
        })
        .unwrap();

        assert_eq!(req.name, "secrets.txt");
        match req.view_type {
            SendViewType::File(f) => assert_eq!(f.file_name, "secrets.txt"),
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn build_create_request_rejects_text_and_file_together() {
        let err = build_create_request(CreateInputs {
            file: Some("/tmp/x".into()),
            text: Some("hello".into()),
            delete_in_days: "7".into(),
            max_access_count: None,
            hidden: false,
            name: Some("name".into()),
            notes: None,
            password: None,
            emails: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn build_create_request_rejects_neither() {
        let err = build_create_request(CreateInputs {
            file: None,
            text: None,
            delete_in_days: "7".into(),
            max_access_count: None,
            hidden: false,
            name: Some("name".into()),
            notes: None,
            password: None,
            emails: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("--text") || err.to_string().contains("--file"));
    }

    #[test]
    fn build_create_request_password_auth() {
        let req = build_create_request(CreateInputs {
            file: None,
            text: Some("hello".into()),
            delete_in_days: "7".into(),
            max_access_count: None,
            hidden: false,
            name: Some("name".into()),
            notes: None,
            password: Some("hunter2".into()),
            emails: None,
        })
        .unwrap();
        assert!(matches!(req.auth, SendAuthType::Password { .. }));
    }

    #[test]
    fn build_create_request_email_auth() {
        let req = build_create_request(CreateInputs {
            file: None,
            text: Some("hello".into()),
            delete_in_days: "7".into(),
            max_access_count: None,
            hidden: false,
            name: Some("name".into()),
            notes: None,
            password: None,
            emails: Some("a@b.com,c@d.com".into()),
        })
        .unwrap();
        match req.auth {
            SendAuthType::Emails { emails } => assert_eq!(emails.len(), 2),
            other => panic!("expected Emails, got {other:?}"),
        }
    }
}
