use std::sync::Arc;

mod lock_management;
mod protocol;
mod wasm;

use bitwarden_core::UserId;
use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::{client::PasswordManagerClientRepository, shared_unlock::wasm::WasmUserLockManagement};
