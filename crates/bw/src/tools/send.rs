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
    AuthEdit, SendAddRequest, SendAuthType, SendEditRequest, SendFileView, SendId, SendTextView,
    SendViewType,
};
use chrono::{Duration, Utc};
use color_eyre::eyre::{Context as _, eyre};
use serde::Serialize;

use super::{
    SendArgs, SendCommands, SendCreateArgs, SendDeleteArgs, SendEditArgs, SendGetArgs,
    SendListArgs, SendReceiveArgs, SendRemovePasswordArgs, SendTemplateArgs,
};
use crate::{
    client_state::{AnyState, BwCommand, BwCommandExt as _, ClientContext, LoggedIn},
    render::{CommandOutput, CommandResult},
};

impl BwCommand for SendArgs {
    // `AnyState` because `bw send template` and `bw send receive` run without a session; the
    // auth-required arms route to per-variant `BwCommand` impls below whose `type Client` is
    // `LoggedIn`, so the auth check happens via the typestate extractor in each branch.
    type Client = AnyState;

    async fn run(self, state: AnyState) -> CommandResult {
        // If no subcommand is supplied, the legacy CLI treats `bw send <data>` as a Create
        // shortcut. Route that through the same builder path as `bw send create` so the two
        // entry points share their happy path.
        let ctx = ClientContext {
            global: state.global,
            user: state.user,
        };
        match self.command.clone() {
            None => {
                let LoggedIn { user, .. } = LoggedIn::try_from(ctx)?;
                create_shortcut(&user, self).await
            }
            // `encoded_json` is intentionally pre-empted *before* `dispatch` extracts
            // `LoggedIn`. The integration tests in `tests/send.rs` assert that supplying
            // `encoded_json` to `create`/`edit` returns the "not yet implemented" error
            // even when the caller is logged out — that signals the input is unsupported
            // rather than burying it behind a confusing auth error.
            Some(SendCommands::Create(args)) if args.encoded_json.is_some() => Err(eyre!(
                "`encoded_json` input on `bw send create` is not yet implemented (PM-34719)."
            )),
            Some(SendCommands::Edit(args)) if args.encoded_json.is_some() => Err(eyre!(
                "`encoded_json` input on `bw send edit` is not yet implemented (PM-34719)."
            )),
            // `--output-file` on `get` similarly fails before the auth check: silently
            // emitting JSON to stdout while the requested file path goes uncreated would
            // be a worse UX than an explicit "not implemented" error.
            Some(SendCommands::Get(args)) if args.output_file.is_some() => Err(eyre!(
                "`--output-file` on `bw send get` is not yet implemented (PM-34719: file-decrypt pipeline pending)."
            )),
            Some(SendCommands::List(args)) => args.dispatch(ctx).await,
            Some(SendCommands::Template(args)) => args.dispatch(ctx).await,
            Some(SendCommands::Get(args)) => args.dispatch(ctx).await,
            Some(SendCommands::Receive(args)) => args.dispatch(ctx).await,
            Some(SendCommands::Create(args)) => args.dispatch(ctx).await,
            Some(SendCommands::Edit(args)) => args.dispatch(ctx).await,
            Some(SendCommands::RemovePassword(args)) => args.dispatch(ctx).await,
            Some(SendCommands::Delete(args)) => args.dispatch(ctx).await,
        }
    }
}

impl BwCommand for SendListArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        list_sends(&user).await
    }
}

impl BwCommand for SendTemplateArgs {
    // `template` doesn't talk to the server; route it through `AnyState` so users can
    // generate JSON scaffolding without a session.
    type Client = AnyState;

    async fn run(self, _: AnyState) -> CommandResult {
        render_template(&self.object)
    }
}

impl BwCommand for SendGetArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        // The `--output-file` early-error gate lives in [`SendArgs::run`] above so it can
        // fire *before* the `LoggedIn` typestate extractor — a logged-out caller passing
        // `--output-file` should see the precise "not yet implemented" error rather than
        // a generic auth message. See PM-34719 for the file-decrypt pipeline follow-up.
        get_send(&user, self.id, self.text).await
    }
}

impl BwCommand for SendReceiveArgs {
    // The `bw receive` command handles incoming sends; `bw send receive` is the legacy
    // alias and is out of scope for this ticket. See `Commands::Receive` in main.rs.
    // No login is required to reach that error path.
    type Client = AnyState;

    async fn run(self, _: AnyState) -> CommandResult {
        Err(eyre!(
            "`bw send receive` is not implemented; use `bw receive <url>` instead."
        ))
    }
}

impl BwCommand for SendCreateArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        // The `encoded_json` early-error gate lives in [`SendArgs::run`] above so it can
        // fire *before* the `LoggedIn` typestate extractor — see PM-34719 for the
        // encoded-JSON input follow-up.
        let SendCreateArgs {
            encoded_json: _,
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
        } = self;

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

        run_create(&user, request, full_object).await
    }
}

impl BwCommand for SendEditArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        // The `encoded_json` early-error gate lives in [`SendArgs::run`] above so it can
        // fire *before* the `LoggedIn` typestate extractor — see PM-34719 for the
        // encoded-JSON input follow-up.
        let SendEditArgs {
            encoded_json: _,
            itemid,
            delete_in_days,
            max_access_count,
            hidden,
            password,
            emails,
        } = self;

        let send_id = itemid.ok_or_else(|| {
            eyre!("--itemid is required (or provide it via encoded JSON, TODO PM-34719).")
        })?;

        // TODO(PM-34719): The CLI builds the edit request from the existing decrypted view
        // plus CLI overrides. The legacy CLI lets the user supply the full object via
        // encodedJson; we should support that path too. TODO(PM-34719): Enforce type
        // immutability on edit.
        let existing = user.sends().get(send_id).await?;

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

        let view = user.sends().edit(send_id, request).await?;
        Ok(CommandOutput::Object(Box::new(view)))
    }
}

impl BwCommand for SendRemovePasswordArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        let view = user.sends().remove_password(self.id).await?;
        Ok(CommandOutput::Object(Box::new(view)))
    }
}

impl BwCommand for SendDeleteArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        user.sends().delete(self.id).await?;
        Ok("Send deleted.".into())
    }
}

async fn list_sends(client: &PasswordManagerClient) -> CommandResult {
    let views = client.sends().list().await?;
    Ok(CommandOutput::Object(Box::new(views)))
}

async fn get_send(client: &PasswordManagerClient, id: SendId, text: bool) -> CommandResult {
    let view = client.sends().get(id).await?;

    if text {
        // TODO(PM-34719): Building a shareable access URL requires the server's web vault URL
        // and the access_id + key fragment. Emit only the access_id for now.
        return Ok(view
            .access_id
            .unwrap_or_else(|| "(no access id)".to_string())
            .into());
    }

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
    delete_in_days: u64,
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
    let deletion_date = compute_deletion_date(delete_in_days)?;

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
    delete_in_days: Option<u64>,
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
        Some(d) => compute_deletion_date(d)?,
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

    let auth = build_auth_for_edit(password, emails.as_deref())?;

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

fn compute_deletion_date(days: u64) -> color_eyre::eyre::Result<chrono::DateTime<Utc>> {
    if days == 0 {
        return Err(eyre!("--deleteInDays must be a positive integer"));
    }
    let signed =
        i64::try_from(days).wrap_err_with(|| format!("--deleteInDays out of range: {days}"))?;
    Ok(Utc::now() + Duration::days(signed))
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

/// Build the `auth` field for a [`SendEditRequest`].
///
/// Edit semantics differ from create:
///   - `(None, None)` returns `AuthEdit::Preserve`, telling the SDK to keep the existing auth. The
///     SDK reads the wire-format `password` hash and `emails` string off the repository row and
///     forwards them verbatim, so a partial edit (e.g. just changing `--deleteInDays`) never
///     silently strips a previously configured password or email-OTP gate. This is the fix for the
///     auth-strip bug — the previous code emitted `SendAuthType::None` here, which the server
///     treats as an overwrite.
///   - `(Some(p), None)` / `(None, Some(e))` return `AuthEdit::Set(...)` to overwrite to Password /
///     Email auth.
///   - `(Some(_), Some(_))` is rejected (mutually exclusive).
///
/// Note: passing `--password ""` is not how callers strip auth on edit. To remove a
/// previously configured password, use `bw send remove-password` (the legacy CLI's
/// dedicated subcommand), or pass `AuthEdit::Set(SendAuthType::None)` at the SDK
/// boundary.
fn build_auth_for_edit(
    password: Option<String>,
    emails: Option<&str>,
) -> color_eyre::eyre::Result<AuthEdit> {
    match (password, emails) {
        (None, None) => Ok(AuthEdit::Preserve),
        (Some(p), None) => Ok(AuthEdit::Set(SendAuthType::Password { password: p })),
        (None, Some(e)) => Ok(AuthEdit::Set(SendAuthType::Emails {
            emails: parse_emails(e)?,
        })),
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
        let d = compute_deletion_date(7).unwrap();
        let now = Utc::now();
        let diff = d - now;
        assert!(diff.num_days() >= 6 && diff.num_days() <= 7);
    }

    #[test]
    fn compute_deletion_date_rejects_zero() {
        assert!(compute_deletion_date(0).is_err());
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
            delete_in_days: 7,
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
            delete_in_days: 7,
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
            delete_in_days: 7,
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
            delete_in_days: 7,
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
            delete_in_days: 7,
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
            delete_in_days: 7,
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
            delete_in_days: 7,
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

    // ---- build_auth_for_edit ----

    /// On edit, the `(None, None)` case must return `AuthEdit::Preserve`, not
    /// `AuthEdit::Set(SendAuthType::None)` (overwrite to no-auth). This is the
    /// auth-strip regression boundary at the CLI helper level.
    #[test]
    fn build_auth_for_edit_no_flags_preserves() {
        let auth = build_auth_for_edit(None, None).unwrap();
        assert!(
            matches!(auth, AuthEdit::Preserve),
            "no flags must produce `AuthEdit::Preserve`, got {auth:?}"
        );
    }

    #[test]
    fn build_auth_for_edit_password_overwrites() {
        let auth = build_auth_for_edit(Some("hunter2".into()), None).unwrap();
        assert!(matches!(
            auth,
            AuthEdit::Set(SendAuthType::Password { ref password }) if password == "hunter2"
        ));
    }

    #[test]
    fn build_auth_for_edit_emails_overwrites() {
        let auth = build_auth_for_edit(None, Some("a@b.com,c@d.com")).unwrap();
        match auth {
            AuthEdit::Set(SendAuthType::Emails { emails }) => assert_eq!(emails.len(), 2),
            other => panic!("expected AuthEdit::Set(Emails), got {other:?}"),
        }
    }

    #[test]
    fn build_auth_for_edit_rejects_both_flags() {
        assert!(build_auth_for_edit(Some("p".into()), Some("a@b.com")).is_err());
    }

    // ---- build_edit_request ----

    use bitwarden_send::{AuthType, SendType, SendView};

    /// Helper producing a baseline `SendView` for edit fixtures. The relevant fields for
    /// these tests are `auth_type`, `has_password`, `emails`, and the text content.
    fn make_existing(auth_type: AuthType, has_password: bool, emails: Vec<String>) -> SendView {
        SendView {
            id: "25afb11c-9c95-4db5-8bac-c21cb204a3f1".parse().ok(),
            access_id: Some("access-id".to_string()),
            name: "existing".to_string(),
            notes: Some("notes".to_string()),
            key: Some("Pgui0FK85cNhBGWHAlBHBw".to_string()),
            new_password: None,
            has_password,
            r#type: SendType::Text,
            file: None,
            text: Some(SendTextView {
                text: Some("existing text".to_string()),
                hidden: false,
            }),
            max_access_count: Some(42),
            access_count: 0,
            disabled: false,
            hide_email: false,
            revision_date: "2025-01-01T00:00:00Z".parse().unwrap(),
            deletion_date: "2030-01-01T00:00:00Z".parse().unwrap(),
            expiration_date: None,
            emails,
            auth_type,
        }
    }

    fn no_override_edit() -> EditOverrides {
        EditOverrides {
            delete_in_days: None,
            max_access_count: None,
            hidden: false,
            password: None,
            emails: None,
        }
    }

    /// This is the regression test for the auth-strip bug. Before the fix,
    /// `build_edit_request` for a Send with an existing Password gate (no auth flags
    /// provided) produced `auth: SendAuthType::None`, which the server treats as an
    /// overwrite that clears the password. After the fix, the request carries
    /// `auth: AuthEdit::Preserve` (the partial-update marker), and the SDK's
    /// `edit_send` consumes that to forward the existing password hash to the server
    /// verbatim.
    #[test]
    fn build_edit_request_preserves_existing_password_when_no_auth_flags() {
        let existing = make_existing(AuthType::Password, true, Vec::new());
        let req = build_edit_request(existing, no_override_edit()).unwrap();
        assert!(
            matches!(req.auth, AuthEdit::Preserve),
            "expected `AuthEdit::Preserve`, got {:?} — the previous behavior was \
             `AuthEdit::Set(SendAuthType::None)`, which silently strips the existing password",
            req.auth
        );
    }

    #[test]
    fn build_edit_request_preserves_existing_emails_when_no_auth_flags() {
        let existing = make_existing(
            AuthType::Email,
            false,
            vec!["a@b.com".to_string(), "c@d.com".to_string()],
        );
        let req = build_edit_request(existing, no_override_edit()).unwrap();
        assert!(matches!(req.auth, AuthEdit::Preserve));
    }

    /// Existing `AuthType::None` × no new auth flags → still preserve (i.e.
    /// `AuthEdit::Preserve`). The SDK will look at the existing repository row and
    /// emit `AuthType::None` on the wire; this CLI layer doesn't need to know that
    /// detail.
    #[test]
    fn build_edit_request_preserves_existing_none_auth_when_no_auth_flags() {
        let existing = make_existing(AuthType::None, false, Vec::new());
        let req = build_edit_request(existing, no_override_edit()).unwrap();
        assert!(matches!(req.auth, AuthEdit::Preserve));
    }

    /// 4x4 matrix: existing { None, Password, Email } × override { None, Password,
    /// Emails }. The "preserve" cases all live above; the "overwrite" cases must
    /// produce a concrete `AuthEdit::Set(...)` regardless of the existing state.
    #[test]
    fn build_edit_request_password_flag_overwrites_regardless_of_existing() {
        for existing_auth in [AuthType::None, AuthType::Password, AuthType::Email] {
            let existing =
                make_existing(existing_auth, existing_auth == AuthType::Password, vec![]);
            let req = build_edit_request(
                existing,
                EditOverrides {
                    delete_in_days: None,
                    max_access_count: None,
                    hidden: false,
                    password: Some("hunter2".into()),
                    emails: None,
                },
            )
            .unwrap();
            assert!(
                matches!(
                    req.auth,
                    AuthEdit::Set(SendAuthType::Password { ref password }) if password == "hunter2"
                ),
                "existing={existing_auth:?}, got auth={:?}",
                req.auth
            );
        }
    }

    #[test]
    fn build_edit_request_emails_flag_overwrites_regardless_of_existing() {
        for existing_auth in [AuthType::None, AuthType::Password, AuthType::Email] {
            let existing =
                make_existing(existing_auth, existing_auth == AuthType::Password, vec![]);
            let req = build_edit_request(
                existing,
                EditOverrides {
                    delete_in_days: None,
                    max_access_count: None,
                    hidden: false,
                    password: None,
                    emails: Some("a@b.com".into()),
                },
            )
            .unwrap();
            match req.auth {
                AuthEdit::Set(SendAuthType::Emails { ref emails }) => assert_eq!(emails.len(), 1),
                ref other => panic!(
                    "existing={existing_auth:?}, expected AuthEdit::Set(Emails), got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn build_edit_request_rejects_both_auth_flags() {
        let existing = make_existing(AuthType::None, false, vec![]);
        let err = build_edit_request(
            existing,
            EditOverrides {
                delete_in_days: None,
                max_access_count: None,
                hidden: false,
                password: Some("p".into()),
                emails: Some("a@b.com".into()),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }
}
