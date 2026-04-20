use bitwarden_core::global::GlobalClient;
use bitwarden_pm::PasswordManagerClient;
use color_eyre::eyre::{Error, eyre};

use crate::render::CommandResult;

/// Holds all available clients for the current session. Passed to [`ClientState`] extractors.
pub struct ClientContext {
    pub global: GlobalClient,
    pub user: Option<PasswordManagerClient>,
}

/// Marker trait for types that represent a required client state for a command.
/// All implementors must also implement [`TryFrom<ClientContext>`].
pub trait ClientState: TryFrom<ClientContext, Error = Error> + Sized {}

/// A command that can be executed given a specific client state.
pub trait BwCommand {
    type Client: ClientState;
    async fn run(self, client: Self::Client) -> CommandResult;
}

/// Client state for commands that require no active user session.
/// Fails at dispatch if a user session already exists.
/// For commands that should work regardless of login state, use [`AnyState`] instead.
pub struct LoggedOut {
    pub global: GlobalClient,
}

/// Client state for commands that require a logged-in user.
/// Contains the global client and the user's password manager client.
pub struct LoggedIn {
    pub global: GlobalClient,
    pub client: PasswordManagerClient,
}

/// Client state for commands that require an unlocked vault.
/// Contains the global client and the user's password manager client with an unlocked vault.
pub struct Unlocked {
    pub global: GlobalClient,
    pub client: PasswordManagerClient,
}

impl TryFrom<ClientContext> for LoggedOut {
    type Error = Error;

    fn try_from(ctx: ClientContext) -> Result<Self, Error> {
        if ctx.user.is_some() {
            return Err(eyre!(
                "You are already logged in. Log out first with `bw logout`."
            ));
        }
        Ok(LoggedOut { global: ctx.global })
    }
}

impl TryFrom<ClientContext> for LoggedIn {
    type Error = Error;

    fn try_from(ctx: ClientContext) -> Result<Self, Error> {
        Ok(LoggedIn {
            global: ctx.global,
            client: ctx
                .user
                .ok_or_else(|| eyre!("No active session found. Please log in using `bw login`."))?,
        })
    }
}

impl TryFrom<ClientContext> for Unlocked {
    type Error = Error;

    fn try_from(ctx: ClientContext) -> Result<Self, Error> {
        // TODO: add vault unlock check once unlock state is tracked
        Ok(Unlocked {
            global: ctx.global,
            client: ctx
                .user
                .filter(|client| client.is_unlocked())
                .ok_or_else(|| eyre!("No active session found. Please log in using `bw login`."))?,
        })
    }
}

/// Client state for commands that can run regardless of authentication or unlock state.
/// Used for complex scenarios where the command itself handles different states internally (e.g.
/// `bw sync`, `bw status`, ...).
pub struct AnyState {
    pub global: GlobalClient,
    pub client: Option<PasswordManagerClient>,
}

impl TryFrom<ClientContext> for AnyState {
    type Error = Error;

    fn try_from(ctx: ClientContext) -> Result<Self, Error> {
        Ok(AnyState {
            global: ctx.global,
            client: ctx.user,
        })
    }
}

impl ClientState for LoggedOut {}
impl ClientState for LoggedIn {}
impl ClientState for Unlocked {}
impl ClientState for AnyState {}
