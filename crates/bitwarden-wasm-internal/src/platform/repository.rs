use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const REPOSITORY_CUSTOM_TS_TYPE: &'static str = r#"
export interface Repository<T> {
    get(id: string): Promise<T | null>;
    list(): Promise<T[]>;
    set(id: string, value: T): Promise<void>;
    remove(id: string): Promise<void>;
}
"#;

macro_rules! create_wasm_repository {
    ($name:ident, $ty:ty, $typescript_ty:literal) => {
        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(js_name = $name, typescript_type = $typescript_ty)]
            pub type $name;

            #[wasm_bindgen(method, catch)]
            async fn get(
                this: &$name,
                id: String,
            ) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue>;
            #[wasm_bindgen(method, catch)]
            async fn list(this: &$name)
                -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue>;
            #[wasm_bindgen(method, catch)]
            async fn set(
                this: &$name,
                id: String,
                value: $ty,
            ) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue>;
            #[wasm_bindgen(method, catch)]
            async fn remove(
                this: &$name,
                id: String,
            ) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue>;
        }

        impl $name {
            pub fn into_channel_impl(
                self,
            ) -> ::std::sync::Arc<impl bitwarden_state::repository::Repository<$ty>> {
                use ::bitwarden_state::repository::*;
                use $crate::platform::repository::__macro_internal::*;

                struct Store(::bitwarden_threading::ThreadBoundRunner<$name>);
                let store = Store(::bitwarden_threading::ThreadBoundRunner::new(self));

                #[async_trait::async_trait]
                impl Repository<$ty> for Store {
                    async fn get(&self, id: String) -> Result<Option<$ty>, RepositoryError> {
                        run_convert(&self.0, |s| async move { s.get(id).await }).await
                    }
                    async fn list(&self) -> Result<Vec<$ty>, RepositoryError> {
                        run_convert(&self.0, |s| async move { s.list().await }).await
                    }
                    async fn set(&self, id: String, value: $ty) -> Result<(), RepositoryError> {
                        run_convert(&self.0, |s| async move { s.set(id, value).await.and(UNIT) })
                            .await
                    }
                    async fn remove(&self, id: String) -> Result<(), RepositoryError> {
                        run_convert(&self.0, |s| async move { s.remove(id).await.and(UNIT) }).await
                    }
                }

                ::std::sync::Arc::new(store)
            }
        }
    };
}
pub(super) use create_wasm_repository;

/// Some utilities to handle the conversion of JsValue to Rust types.
/// They exist outside the macro to try to reduce code bloat in the generated code.
#[doc(hidden)]
pub mod __macro_internal {
    use std::{future::Future, rc::Rc};

    use bitwarden_state::repository::RepositoryError;
    use wasm_bindgen::JsValue;

    pub const UNIT: Result<JsValue, JsValue> = Ok(JsValue::UNDEFINED);

    pub async fn run_convert<T: 'static, Func, Fut, Ret>(
        runner: &::bitwarden_threading::ThreadBoundRunner<T>,
        f: Func,
    ) -> Result<Ret, RepositoryError>
    where
        Func: FnOnce(Rc<T>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<JsValue, JsValue>>,
        Ret: serde::de::DeserializeOwned + Send + Sync + 'static,
    {
        runner
            .run_in_thread(|state| async move { convert_result(f(state).await) })
            .await
            .expect("Task should not panic")
    }

    fn convert_result<T: serde::de::DeserializeOwned>(
        result: Result<JsValue, JsValue>,
    ) -> Result<T, RepositoryError> {
        result
            .map_err(|e| RepositoryError::Internal(format!("{e:?}")))
            .and_then(|value| {
                ::tsify_next::serde_wasm_bindgen::from_value(value)
                    .map_err(|e| RepositoryError::Internal(e.to_string()))
            })
    }
}
