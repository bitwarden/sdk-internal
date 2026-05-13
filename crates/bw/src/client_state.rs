//! Compile-time client-state machine for CLI commands.
//!
//! Each [`Commands`](crate::command::Commands) arm dispatches to a [`BwCommand`] implementation
//! whose [`BwCommand::Client`] declares the auth/lock state required to run. The dispatcher in
//! [`main`](crate::main) constructs a [`ClientContext`] once per invocation and routes the command
//! through the corresponding [`TryFrom`] extractor; commands therefore never check auth/lock state
//! manually.
#![allow(
    dead_code,
    reason = "While unused now, these states will be consumed as commands move to the CLI."
)]

use bitwarden_core::GlobalClient;
use bitwarden_pm::PasswordManagerClient;
use color_eyre::eyre::{Result, eyre};

use crate::render::CommandResult;

/// Trait implemented by commands that participate in the typestate dispatch.
///
/// Commands that don't depend on auth/lock state (e.g. shell-completion generation, base64
/// encoding) use [`AnyState`] as their [`Client`](Self::Client).
///
/// Call sites invoke commands via [`BwCommandExt::dispatch`] rather than calling [`run`](Self::run)
/// directly; the extension trait performs the typestate extraction in one place.
///
/// # Example
///
/// ```ignore
/// use crate::client_state::{BwCommand, LoggedIn};
/// use crate::render::CommandResult;
///
/// pub struct SyncArgs;
///
/// impl BwCommand for SyncArgs {
///     type Client = LoggedIn;
///
///     async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
///         user.sync().sync(Default::default()).await?;
///         Ok("Synced.".into())
///     }
/// }
/// ```
pub trait BwCommand {
    type Client: ClientState;
    async fn run(self, client: Self::Client) -> CommandResult;
}

/// Extension trait that wires [`BwCommand`] up to the [`ClientContext`] dispatcher.
///
/// Implemented for every [`BwCommand`] via a blanket impl, so commands only need to define
/// [`run`](BwCommand::run); `dispatch` is provided automatically and cannot be overridden.
///
/// # Example
///
/// ```ignore
/// // In `process_commands`:
/// Commands::Sync(args) => args.dispatch(ctx).await,
/// ```
pub trait BwCommandExt: BwCommand {
    async fn dispatch(self, ctx: ClientContext) -> CommandResult;
}

impl<C: BwCommand> BwCommandExt for C {
    async fn dispatch(self, ctx: ClientContext) -> CommandResult {
        self.run(C::Client::try_from(ctx)?).await
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Marker trait implemented by the five client-state types in this module.
///
/// Sealed: the auth/lock matrix is a closed enumeration; new states should be added here, not
/// in downstream code.
pub trait ClientState:
    sealed::Sealed + TryFrom<ClientContext, Error = color_eyre::eyre::Error>
{
}

/// Per-invocation context built once in `process_commands` and consumed by a single extractor.
pub struct ClientContext {
    pub global: GlobalClient,
    pub user: Option<PasswordManagerClient>,
}

/// Unauthenticated state. The extractor rejects when a user is already logged in.
pub struct LoggedOut {
    pub global: GlobalClient,
}

impl sealed::Sealed for LoggedOut {}
impl ClientState for LoggedOut {}

impl TryFrom<ClientContext> for LoggedOut {
    type Error = color_eyre::eyre::Error;

    fn try_from(ctx: ClientContext) -> Result<Self> {
        if ctx.user.is_some() {
            return Err(eyre!(
                "You are already logged in. Log out first with `bw logout`."
            ));
        }
        Ok(LoggedOut { global: ctx.global })
    }
}

/// Authenticated state, lock-status-agnostic. The extractor requires a user.
pub struct LoggedIn {
    pub global: GlobalClient,
    pub user: PasswordManagerClient,
}

impl sealed::Sealed for LoggedIn {}
impl ClientState for LoggedIn {}

impl TryFrom<ClientContext> for LoggedIn {
    type Error = color_eyre::eyre::Error;

    fn try_from(ctx: ClientContext) -> Result<Self> {
        let user = ctx
            .user
            .ok_or_else(|| eyre!("You are not logged in. Run `bw login` first."))?;
        Ok(LoggedIn {
            global: ctx.global,
            user,
        })
    }
}

/// Authenticated and locked. The extractor rejects an unlocked vault.
pub struct Locked {
    pub global: GlobalClient,
    pub user: PasswordManagerClient,
}

impl sealed::Sealed for Locked {}
impl ClientState for Locked {}

impl TryFrom<ClientContext> for Locked {
    type Error = color_eyre::eyre::Error;

    fn try_from(ctx: ClientContext) -> Result<Self> {
        let user = ctx
            .user
            .ok_or_else(|| eyre!("You are not logged in. Run `bw login` first."))?;
        if user.is_unlocked() {
            return Err(eyre!(
                "Your vault is already unlocked. Lock it with `bw lock` first."
            ));
        }
        Ok(Locked {
            global: ctx.global,
            user,
        })
    }
}

/// Authenticated and unlocked. The extractor requires the user's symmetric key to be loaded.
pub struct Unlocked {
    pub global: GlobalClient,
    pub user: PasswordManagerClient,
}

impl sealed::Sealed for Unlocked {}
impl ClientState for Unlocked {}

impl TryFrom<ClientContext> for Unlocked {
    type Error = color_eyre::eyre::Error;

    fn try_from(ctx: ClientContext) -> Result<Self> {
        let user = ctx
            .user
            .ok_or_else(|| eyre!("You are not logged in. Run `bw login` first."))?;
        if !user.is_unlocked() {
            return Err(eyre!(
                "Your vault is locked. Unlock it by setting the session key with `--session` or `BW_SESSION`."
            ));
        }
        Ok(Unlocked {
            global: ctx.global,
            user,
        })
    }
}

/// Catch-all. The extractor is infallible.
pub struct AnyState {
    pub global: GlobalClient,
    pub user: Option<PasswordManagerClient>,
}

impl sealed::Sealed for AnyState {}
impl ClientState for AnyState {}

impl TryFrom<ClientContext> for AnyState {
    type Error = color_eyre::eyre::Error;

    fn try_from(ctx: ClientContext) -> Result<Self> {
        Ok(AnyState {
            global: ctx.global,
            user: ctx.user,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use bitwarden_core::{DeviceType, HostPlatformInfo, init_host_platform_info};

    use super::*;

    // Multiple test binaries in this crate may concurrently call `init_host_platform_info`;
    // a single guarded init keeps cross-test ordering deterministic.
    static INIT: Once = Once::new();

    fn ensure_platform_info() {
        INIT.call_once(|| {
            init_host_platform_info(HostPlatformInfo {
                user_agent: "bw-tests".to_string(),
                device_type: DeviceType::SDK,
                device_identifier: None,
                bitwarden_client_version: None,
                bitwarden_package_type: None,
            });
        });
    }

    fn ctx(user: Option<PasswordManagerClient>) -> ClientContext {
        ensure_platform_info();
        ClientContext {
            global: GlobalClient::new(),
            user,
        }
    }

    #[test]
    fn logged_out_accepts_when_no_user() {
        assert!(LoggedOut::try_from(ctx(None)).is_ok());
    }

    #[test]
    fn logged_out_rejects_when_user_present() {
        let user = PasswordManagerClient::new(None);
        assert!(LoggedOut::try_from(ctx(Some(user))).is_err());
    }

    #[test]
    fn logged_in_accepts_when_user_present() {
        let user = PasswordManagerClient::new(None);
        assert!(LoggedIn::try_from(ctx(Some(user))).is_ok());
    }

    #[test]
    fn logged_in_rejects_when_no_user() {
        assert!(LoggedIn::try_from(ctx(None)).is_err());
    }

    #[test]
    fn locked_accepts_when_user_locked() {
        // A freshly-built `PasswordManagerClient` has no user key loaded.
        let user = PasswordManagerClient::new(None);
        assert!(Locked::try_from(ctx(Some(user))).is_ok());
    }

    #[test]
    fn locked_rejects_when_no_user() {
        assert!(Locked::try_from(ctx(None)).is_err());
    }

    #[test]
    fn unlocked_rejects_when_user_locked() {
        let user = PasswordManagerClient::new(None);
        assert!(Unlocked::try_from(ctx(Some(user))).is_err());
    }

    #[test]
    fn unlocked_rejects_when_no_user() {
        assert!(Unlocked::try_from(ctx(None)).is_err());
    }

    #[test]
    fn any_state_infallible() {
        assert!(AnyState::try_from(ctx(None)).is_ok());
        let user = PasswordManagerClient::new(None);
        assert!(AnyState::try_from(ctx(Some(user))).is_ok());
    }
}
