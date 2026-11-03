//! Lets feature crates react to an unlock without `bitwarden-core` depending on them.

use std::sync::{Arc, RwLock};

use crate::{Client, key_management::crypto::InitUserCryptoMethod};

/// Runs after the client is unlocked, by `initialize_user_crypto` or `reinit_user_crypto`.
pub trait UnlockHandler: Send + Sync {
    /// Called after the user key is in the key store. The unlock does not complete until this
    /// method returns.
    ///
    /// `method` is the method that `initialize_user_crypto` unlocked with, and `None` for
    /// `reinit_user_crypto`.
    fn on_unlock(&self, client: &Client, method: Option<&InitUserCryptoMethod>);
}

/// The unlock handlers registered on a client, called in registration order.
#[derive(Default)]
pub(crate) struct UnlockHandlers {
    handlers: RwLock<Vec<Arc<dyn UnlockHandler>>>,
}

impl UnlockHandlers {
    fn register(&self, handler: Arc<dyn UnlockHandler>) {
        self.handlers
            .write()
            .expect("RwLock is not poisoned")
            .push(handler);
    }

    pub(crate) fn run_handlers(&self, client: &Client, method: Option<&InitUserCryptoMethod>) {
        // Cloned, so a handler that registers another handler does not deadlock.
        let handlers = self
            .handlers
            .read()
            .expect("RwLock is not poisoned")
            .clone();
        for handler in handlers {
            handler.on_unlock(client, method);
        }
    }
}

impl Client {
    /// Registers a handler that runs after each unlock of this client.
    pub fn register_unlock_handler(&self, handler: Arc<dyn UnlockHandler>) {
        self.internal.unlock_handlers.register(handler);
    }
}
