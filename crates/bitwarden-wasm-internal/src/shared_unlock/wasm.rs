use bitwarden_core::UserId;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

#[wasm_bindgen]
extern "C" {
    pub type WasmUserLockManagement;

    #[wasm_bindgen(method, catch)]
    async fn lock_user(this: &WasmUserLockManagement, user_id: UserId) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn unlock_user(this: &WasmUserLockManagement, user_id: UserId) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn list_users(this: &WasmUserLockManagement) -> Result<js_sys::Array, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn get_user_lock_state(
        this: &WasmUserLockManagement,
        user_id: UserId,
    ) -> Result<JsValue, JsValue>;
}
