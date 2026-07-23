//! `bw send` command implementation.
//!
//! Dispatches the subcommands declared on [`SendArgs`] / [`SendCommands`] in
//! [`super`] to the underlying [`bitwarden_send::SendClient`] methods. The arg
//! parsing surface is intentionally defined in `super` so the legacy-CLI shape
//! (which is part of the user contract) stays close to the rest of the
//! `tools` family.

use std::path::PathBuf;

use bitwarden_core::{auth::JwtToken, client::persisted_state::AUTHENTICATION_TOKENS};
use bitwarden_pm::PasswordManagerClient;
use bitwarden_send::{
    AuthEdit, SendAddRequest, SendAuthType, SendEditRequest, SendFileView, SendId, SendTextView,
    SendViewType,
};
use chrono::{Duration, Utc};
use clap::{
    Args, Subcommand,
    builder::{PossibleValuesParser, TypedValueParser as _},
};
use color_eyre::eyre::{Context as _, eyre};
use serde::Serialize;

use crate::{
    client_state::{AnyState, BwCommand, BwCommandExt as _, ClientContext, LoggedIn},
    platform::read_config_json,
    render::{CommandOutput, CommandResult},
};

/// Allowed values for `--deleteInDays`, matching the legacy CLI's enumerated set.
/// Kept as strings so `PossibleValuesParser` can surface them in `--help` output.
const DELETE_IN_DAYS_ALLOWED: &[&str] = &["1", "2", "3", "7", "14", "30"];

/// Clap value parser for `--deleteInDays`. Restricts input to the legacy-CLI allowed
/// set (also surfaced in `--help`) and maps it back to the `u64` field type.
fn delete_in_days_parser() -> impl clap::builder::TypedValueParser<Value = u64> {
    PossibleValuesParser::new(DELETE_IN_DAYS_ALLOWED)
        .map(|s| s.parse::<u64>().expect("allowed values are valid u64"))
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
        default_value_t = 7,
        value_parser = delete_in_days_parser(),
    )]
    pub delete_in_days: u64,

    #[arg(
        long,
        conflicts_with = "emails",
        help = "Optional password to access this Send."
    )]
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

    // The internal field is `output_path` (not `output`) to avoid clashing with the
    // top-level `Cli::output` (the `-o` rendered-output-format arg). User-facing long
    // flag stays `--output` to match the legacy CLI.
    #[arg(
        long = "output",
        help = "File path to save a file-type Send's decrypted contents to."
    )]
    pub output_path: Option<String>,

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
        default_value_t = 7,
        value_parser = delete_in_days_parser(),
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

    #[arg(
        long,
        conflicts_with = "emails",
        help = "Optional password to access this Send."
    )]
    pub password: Option<String>,

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
        help = "The number of days in the future to set deletion date.",
        value_parser = delete_in_days_parser(),
    )]
    pub delete_in_days: Option<u64>,

    #[arg(
        long = "maxAccessCount",
        help = "The maximum number of times this Send can be accessed."
    )]
    pub max_access_count: Option<u32>,

    #[arg(long, help = "Hide text.")]
    pub hidden: bool,

    #[arg(
        long,
        conflicts_with = "emails",
        help = "Optional password to access this Send."
    )]
    pub password: Option<String>,

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
                "`encoded_json` input on `bw send create` is not yet implemented (tracked under PM-39240)."
            )),
            Some(SendCommands::Edit(args)) if args.encoded_json.is_some() => Err(eyre!(
                "`encoded_json` input on `bw send edit` is not yet implemented (tracked under PM-39240)."
            )),
            // `--output` on `get` similarly fails before the auth check: silently
            // emitting JSON to stdout while the requested file path goes uncreated would
            // be a worse UX than an explicit "not implemented" error.
            Some(SendCommands::Get(args)) if args.output_path.is_some() => Err(eyre!(
                "`--output` on `bw send get` is not yet implemented (tracked under PM-34718)."
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
        // The `--output` early-error gate lives in [`SendArgs::run`] above so it can
        // fire *before* the `LoggedIn` typestate extractor — a logged-out caller passing
        // `--output` should see the precise "not yet implemented" error rather than
        // a generic auth message. The file-decrypt/download pipeline follow-up is PM-34718.
        get_send(&user, self.id, self.text).await
    }
}

impl BwCommand for SendReceiveArgs {
    // `bw send receive` is the legacy alias for the top-level `bw receive` command.
    // Both are tracked under PM-34718 ("[SDK CLI] Receive Command"), a sibling to this
    // ticket. Routed through `AnyState` so the not-yet-implemented error fires without
    // an auth check.
    type Client = AnyState;

    async fn run(self, _: AnyState) -> CommandResult {
        Err(eyre!(
            "`bw send receive` is not yet implemented (tracked under PM-34718)."
        ))
    }
}

impl BwCommand for SendCreateArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        // The `encoded_json` early-error gate lives in [`SendArgs::run`] above so it can
        // fire *before* the `LoggedIn` typestate extractor. Encoded-JSON support is PM-39240.
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
            file: file.clone(),
            text,
            delete_in_days,
            max_access_count,
            hidden,
            name,
            notes,
            password,
            emails,
        })?;

        run_create(&user, request, file, full_object).await
    }
}

impl BwCommand for SendEditArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        // The `encoded_json` early-error gate lives in [`SendArgs::run`] above so it can
        // fire *before* the `LoggedIn` typestate extractor. Encoded-JSON support is PM-39240.
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
            eyre!("--itemid is required (or provide it via encoded JSON; see PM-39240).")
        })?;

        // PM-39240: support full-object JSON input and reject text↔file type changes on edit.
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
        // `--text` emits the shareable access URL (see the flag help). Recipients paste this
        // into a browser or `bw receive` to fetch and decrypt the Send content client-side.
        let url = build_access_url(client, &view)?;
        return Ok(url.into());
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

    let deletion_date = compute_deletion_date(delete_in_days)?;

    let view_type = match (file.as_deref(), text.as_deref()) {
        (Some(path), None) => {
            // File sends require a premium account; the precondition is checked in `run_create`
            // (against the access-token JWT) before the send is created on the server.
            let path = PathBuf::from(path);
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| eyre!("Could not derive a file name from --file path"))?
                .to_string();
            // `size` is intentionally left `None` on create: the legacy client does not set
            // `file.size` on the create request (a plaintext byte count would not match the
            // uploaded ciphertext blob). The server derives the size from the uploaded blob; the
            // ciphertext length is instead sent as `file_length` inside `create_file_send`.
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
        // Sends should always carry exactly one of text/file; the API can in theory return
        // both. The legacy CLI prefers text in that case, which is what we do here.
        //
        // PM-39238 disambiguation finding (item #4): there is NO deviation from legacy to fix
        // here. `get` returns the full [`SendView`] (both `text` and `file` fields preserved), so
        // a caller reading a mixed-shape response loses nothing. `create` is built from the typed
        // [`SendViewType`] enum and so is unambiguous by construction. The only place a "prefer
        // text" choice is forced is `edit`, where a single variant must be reconstructed from the
        // existing row — and that choice matches the legacy CLI (`SendView.text ?? SendView.file`).
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

    let file_path = if args.file { Some(data.clone()) } else { None };

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
    run_create(client, request, file_path, args.full_object).await
}

async fn run_create(
    client: &PasswordManagerClient,
    request: SendAddRequest,
    file_path: Option<String>,
    full_object: bool,
) -> CommandResult {
    let is_file = matches!(request.view_type, SendViewType::File(_));

    let view = if is_file {
        // File sends require a premium membership. Match the legacy CLI's pre-check so the user
        // gets a clear error before any file is read or any request is sent to the server, rather
        // than a generic server-side rejection mid-upload.
        require_premium(client).await?;

        let path = file_path.ok_or_else(|| {
            eyre!("Internal error: file Send created without a source file path.")
        })?;
        run_create_file(client, request, &path).await?
    } else {
        client.sends().create(request).await?
    };

    if full_object {
        return Ok(CommandOutput::Object(Box::new(view)));
    }

    // The default output is the shareable access URL — the primary artifact a caller wants to
    // hand to a recipient. `--fullObject` opts back into the full JSON view.
    let url = build_access_url(client, &view)?;
    Ok(url.into())
}

/// Full file-send create pipeline:
/// 1. Read the plaintext file bytes.
/// 2. `create_file_send` encrypts them under the send key it derives, sends the ciphertext length
///    as `file_length`, registers the send, and returns the encrypted bytes plus upload metadata
///    (URL + backend).
/// 3. The ciphertext is uploaded via `upload_send_file`, which dispatches to the Direct or Azure
///    backend based on the `file_upload_type` from step 2.
async fn run_create_file(
    client: &PasswordManagerClient,
    request: SendAddRequest,
    path: &str,
) -> color_eyre::eyre::Result<bitwarden_send::SendView> {
    // Read the plaintext before creating the send so a read failure aborts before we register a
    // send that would then have no content.
    let bytes = std::fs::read(path).wrap_err_with(|| format!("Could not read file {path}"))?;

    // `create_file_send` performs the encryption internally (so `file_length` on the create request
    // reflects the true ciphertext length) and hands back the encrypted bytes for the upload.
    let resp = client.sends().create_file_send(request, bytes).await?;

    let send_id = resp
        .send
        .id
        .ok_or_else(|| eyre!("Server did not return an id for the created file Send."))?;

    client
        .sends()
        .upload_send_file(
            send_id,
            resp.file_id,
            resp.encrypted_file_name,
            resp.file_upload_type,
            resp.url,
            resp.encrypted_file_buffer,
        )
        .await?;

    Ok(resp.send)
}

/// Enforce the premium-membership precondition for file Sends by inspecting the `premium` claim on
/// the current user's access-token JWT (option a from PM-39238). Reads the persisted
/// [`AUTHENTICATION_TOKENS`] state — the same source the auth middleware attaches to requests — so
/// no additional token accessor is needed on the client.
async fn require_premium(client: &PasswordManagerClient) -> color_eyre::eyre::Result<()> {
    let tokens = client
        .platform()
        .state()
        .setting(AUTHENTICATION_TOKENS)?
        .get()
        .await?
        .ok_or_else(|| eyre!("You must be logged in to create a file Send."))?;

    let claims: JwtToken = tokens
        .access_token
        .parse()
        .wrap_err("Could not parse the current access token.")?;

    if claims.premium == Some(true) {
        Ok(())
    } else {
        Err(eyre!(
            "A premium membership is required to create file Sends."
        ))
    }
}

/// Build the shareable Send access URL from a decrypted [`bitwarden_send::SendView`].
///
/// Format: `<web-vault>/#/send/<access_id>/<url_b64_key>`, where `<web-vault>` is resolved by
/// [`web_vault_url`].
///
/// This matches the legacy CLI (`SendResponse` in `apps/cli`, which appends
/// `accessId + "/" + urlB64Key` to `env.getSendUrl()`, whose self-hosted form is
/// `<web-vault>/#/send/`) and round-trips through the legacy `bw receive` parser, which reads the
/// two trailing `#`-fragment segments (`url.hash.slice(1).split("/").slice(-2)`) and
/// URL-safe-base64-decodes the key.
///
/// Note: we always emit the `<web-vault>/#/send/` form. The US-production vanity host
/// (`https://send.bitwarden.com/#...`) is intentionally not reproduced — hitting the web-vault
/// link directly works in every environment, and the CLI has no authoritative source for the
/// vanity host (see [`web_vault_url`]).
fn build_access_url(
    client: &PasswordManagerClient,
    view: &bitwarden_send::SendView,
) -> color_eyre::eyre::Result<String> {
    let access_id = view
        .access_id
        .as_deref()
        .ok_or_else(|| eyre!("Send is missing an access id; cannot build a shareable URL."))?;
    let key = view
        .key
        .as_deref()
        .ok_or_else(|| eyre!("Send is missing a key; cannot build a shareable URL."))?;

    let web_vault = web_vault_url(client);
    let url_key = to_url_b64(key);

    Ok(format!("{web_vault}/#/send/{access_id}/{url_key}"))
}

/// Resolve the web-vault base URL that `/#/send/<access_id>/<url_b64_key>` is appended to.
///
/// Precedence, mirroring the legacy CLI's per-service-then-base resolution:
/// 1. `config.web_vault` — an explicit web-vault URL (`bw config server --web-vault <url>`).
/// 2. `config.server` — the base server URL (`bw config server <url>`).
/// 3. derive from the active client's `api_url` (see [`web_vault_from_api_url`]).
///
/// TODO: this derivation is interim. The CLI has no authoritative source for the web-vault/send
/// host (confirmed with platform in the PM-39239 review), so we infer it. Replace this with a
/// proper environment/config service in this repo (parity with the clients'
/// `DefaultEnvironmentService`) once one exists, at which point this becomes a single lookup.
fn web_vault_url(client: &PasswordManagerClient) -> String {
    if let Ok(Some(config)) = read_config_json() {
        if let Some(web_vault) = config.web_vault.as_deref() {
            return web_vault.trim_end_matches('/').to_string();
        }
        if let Some(server) = config.server.as_deref() {
            return server.trim_end_matches('/').to_string();
        }
    }

    let api_url = client
        .0
        .internal
        .get_api_configurations()
        .api_config
        .base_path
        .clone();

    web_vault_from_api_url(&api_url)
}

/// Derive the web-vault base from an API URL when no web-vault/server URL is configured (the
/// `bw login --server` and cloud paths). Pure so it can be unit-tested without a live client.
///
/// - Single-domain deployment: the API lives at `<web-vault>/api` (the suffix `bw login --server`
///   appends), so a trailing `/api` is stripped to recover the web vault.
/// - Split-domain deployment (all Bitwarden cloud regions, and the standard self-host convention):
///   the API is served from an `api.` host that does not serve the web-vault SPA, so the leading
///   `api.` host label is rewritten to `vault.` (`https://api.bitwarden.com` ->
///   `https://vault.bitwarden.com`, `https://api.bitwarden.eu` -> `https://vault.bitwarden.eu`).
/// - Any other shape is treated as its own web vault.
///
/// This is a heuristic (see the `web_vault_url` TODO): a deployment whose API host neither ends in
/// `/api` nor begins with `api.` cannot be mapped and will fall through to being used as-is. Such
/// deployments should set `bw config server --web-vault <url>` for correct links.
fn web_vault_from_api_url(api_url: &str) -> String {
    let trimmed = api_url.trim_end_matches('/');

    if let Some(base) = trimmed.strip_suffix("/api") {
        return base.trim_end_matches('/').to_string();
    }

    if let Some(vault) = rewrite_api_host_to_vault(trimmed) {
        return vault;
    }

    trimmed.to_string()
}

/// Rewrite a leading `api.` host label to `vault.` in a `scheme://host[/path]` URL, e.g.
/// `https://api.bitwarden.com` -> `https://vault.bitwarden.com`. Returns `None` when the URL has no
/// scheme or the host does not start with the `api.` label (so `apiary.example.com` is not
/// rewritten).
fn rewrite_api_host_to_vault(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let after_api = rest.strip_prefix("api.")?;
    Some(format!("{scheme}://vault.{after_api}"))
}

/// Convert standard base64 to URL-safe base64 without padding.
///
/// Reproduces the legacy client's `Utils.fromB64toUrlB64`: `+` → `-`, `/` → `_`, and `=` padding
/// stripped. The `SendView.key` is standard base64; the URL fragment must carry the URL-safe form
/// so the `bw receive` parser (`Utils.fromUrlB64ToArray`) decodes it correctly.
fn to_url_b64(b64: &str) -> String {
    b64.replace('+', "-").replace('/', "_").replace('=', "")
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
///   - `(Some(p), None)` / `(None, Some(e))` return `AuthEdit::Set { auth: _ }` to overwrite to
///     Password / Email auth.
///   - `(Some(_), Some(_))` is rejected (mutually exclusive).
///
/// Note: passing `--password ""` is not how callers strip auth on edit. To remove a
/// previously configured password, use `bw send remove-password` (the legacy CLI's
/// dedicated subcommand), or pass `AuthEdit::Set { auth: SendAuthType::None }` at the
/// SDK boundary.
fn build_auth_for_edit(
    password: Option<String>,
    emails: Option<&str>,
) -> color_eyre::eyre::Result<AuthEdit> {
    match (password, emails) {
        (None, None) => Ok(AuthEdit::Preserve),
        (Some(p), None) => Ok(AuthEdit::Set {
            auth: SendAuthType::Password { password: p },
        }),
        (None, Some(e)) => Ok(AuthEdit::Set {
            auth: SendAuthType::Emails {
                emails: parse_emails(e)?,
            },
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

    // ---- access URL construction ----

    #[test]
    fn to_url_b64_maps_standard_b64_to_url_safe() {
        // `+` -> `-`, `/` -> `_`, padding stripped.
        assert_eq!(to_url_b64("ab+/cd=="), "ab-_cd");
        assert_eq!(
            to_url_b64("Pgui0FK85cNhBGWHAlBHBw=="),
            "Pgui0FK85cNhBGWHAlBHBw"
        );
        // No special chars: unchanged.
        assert_eq!(to_url_b64("abcDEF123"), "abcDEF123");
    }

    #[test]
    fn web_vault_from_api_url_strips_single_domain_api_suffix() {
        // `bw login --server <base>` sets api_url to `<base>/api`; stripping it recovers the vault.
        assert_eq!(
            web_vault_from_api_url("https://vault.example.com/api"),
            "https://vault.example.com"
        );
        // Trailing slash after /api.
        assert_eq!(
            web_vault_from_api_url("https://vault.example.com/api/"),
            "https://vault.example.com"
        );
    }

    #[test]
    fn web_vault_from_api_url_rewrites_cloud_api_host_to_vault() {
        // Cloud (all regions) serves the API from an `api.` host that does not serve the web-vault
        // SPA, so it must be rewritten to the `vault.` host — not used as-is.
        assert_eq!(
            web_vault_from_api_url("https://api.bitwarden.com"),
            "https://vault.bitwarden.com"
        );
        assert_eq!(
            web_vault_from_api_url("https://api.bitwarden.eu"),
            "https://vault.bitwarden.eu"
        );
        // Trailing slash is trimmed before the rewrite.
        assert_eq!(
            web_vault_from_api_url("https://api.bitwarden.com/"),
            "https://vault.bitwarden.com"
        );
    }

    #[test]
    fn web_vault_from_api_url_rewrites_split_domain_self_host() {
        // Standard self-host convention: `api.<domain>` -> `vault.<domain>`.
        assert_eq!(
            web_vault_from_api_url("https://api.example.com"),
            "https://vault.example.com"
        );
    }

    #[test]
    fn web_vault_from_api_url_leaves_unmappable_host_as_is() {
        // Neither `/api` suffix nor `api.` prefix: used as-is (documented limitation — such
        // deployments should configure the web vault explicitly). `apiary.` must NOT be rewritten.
        assert_eq!(
            web_vault_from_api_url("https://apiary.example.com"),
            "https://apiary.example.com"
        );
    }

    /// The assembled URL must match the legacy `SendResponse` shape
    /// (`<web-vault>/#/send/<accessId>/<urlB64Key>`) so it round-trips through the `bw receive`
    /// fragment parser. Pins the exact string for the cloud (`api.`-rewrite) case.
    #[test]
    fn access_url_format_matches_legacy_and_round_trips() {
        let web_vault = web_vault_from_api_url("https://api.bitwarden.com");
        let access_id = "abcaccessid";
        // Standard-b64 key with chars that must be URL-encoded.
        let url_key = to_url_b64("Pgui0FK8+cNh/GWHAlBHBw==");
        let url = format!("{web_vault}/#/send/{access_id}/{url_key}");

        assert_eq!(
            url,
            "https://vault.bitwarden.com/#/send/abcaccessid/Pgui0FK8-cNh_GWHAlBHBw"
        );

        // Round-trip check: the legacy `bw receive` parser reads the last two `#`-fragment
        // segments. Reproduce that split and confirm we recover the access id + url-safe key.
        let (_, fragment) = url.split_once('#').expect("URL has a fragment");
        let segments: Vec<&str> = fragment.trim_start_matches('/').split('/').collect();
        let last_two = &segments[segments.len() - 2..];
        assert_eq!(last_two, ["abcaccessid", "Pgui0FK8-cNh_GWHAlBHBw"]);
    }

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

    /// File create derives the name from the path and leaves `SendFileView.size` unset (`None`):
    /// the legacy client does not set `file.size` on create (the server derives it from the
    /// uploaded blob), and a plaintext byte count would not match the uploaded ciphertext. The
    /// encrypted-buffer length is sent separately as `file_length` inside `create_file_send`.
    ///
    /// `build_create_request` does not touch the filesystem, so a placeholder path is fine here;
    /// the actual file read happens later in `run_create_file`.
    #[test]
    fn build_create_request_file_derives_name_and_leaves_size_unset() {
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
            SendViewType::File(f) => {
                assert_eq!(f.file_name, "secrets.txt");
                assert_eq!(f.size, None, "file.size must be unset on create");
            }
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
    /// `AuthEdit::Set { auth: SendAuthType::None }` (overwrite to no-auth). This is the
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
            AuthEdit::Set { auth: SendAuthType::Password { ref password } } if password == "hunter2"
        ));
    }

    #[test]
    fn build_auth_for_edit_emails_overwrites() {
        let auth = build_auth_for_edit(None, Some("a@b.com,c@d.com")).unwrap();
        match auth {
            AuthEdit::Set {
                auth: SendAuthType::Emails { emails },
            } => assert_eq!(emails.len(), 2),
            other => panic!("expected AuthEdit::Set {{ auth: Emails }}, got {other:?}"),
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
             `AuthEdit::Set {{ auth: SendAuthType::None }}`, which silently strips the existing password",
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
    /// produce a concrete `AuthEdit::Set { auth: _ }` regardless of the existing state.
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
                    AuthEdit::Set { auth: SendAuthType::Password { ref password } } if password == "hunter2"
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
                AuthEdit::Set {
                    auth: SendAuthType::Emails { ref emails },
                } => {
                    assert_eq!(emails.len(), 1);
                }
                ref other => panic!(
                    "existing={existing_auth:?}, expected AuthEdit::Set {{ auth: Emails }}, got {other:?}"
                ),
            }
        }
    }

    /// PM-39238 item #4 (disambiguation): when the server returns a Send carrying *both* `text`
    /// and `file` content, `edit` must reconstruct a single [`SendViewType`] and — matching the
    /// legacy CLI — prefer text. This pins that behavior so a future refactor can't silently flip
    /// it to file (which would drop the text body on a partial edit).
    #[test]
    fn build_edit_request_prefers_text_when_both_present() {
        let mut existing = make_existing(AuthType::None, false, vec![]);
        existing.text = Some(SendTextView {
            text: Some("the text body".to_string()),
            hidden: false,
        });
        existing.file = Some(SendFileView {
            id: Some("file-id".to_string()),
            file_name: "attachment.bin".to_string(),
            size: Some("10".to_string()),
            size_name: Some("10 B".to_string()),
        });

        let req = build_edit_request(existing, no_override_edit()).unwrap();
        match req.view_type {
            SendViewType::Text(t) => assert_eq!(t.text.as_deref(), Some("the text body")),
            other => panic!("expected Text (legacy prefers text on mixed-shape), got {other:?}"),
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
