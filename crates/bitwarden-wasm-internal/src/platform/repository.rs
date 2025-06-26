/*!
 * To support clients implementing the [Repository] trait in a [::wasm_bindgen] environment,
 * we need to deal with an `extern "C"` interface, as that is what [::wasm_bindgen] supports:
 *
 * This looks something like this:
 *
 * ```rust,ignore
 * #[wasm_bindgen]
 * extern "C" {
 *     pub type CipherRepository;
 *
 *     #[wasm_bindgen(method, catch)]
 *     async fn get(this: &CipherRepository, id: String) -> Result<JsValue, JsValue>;
 * }
 * ```
 *
 * As you can see, this has a few limitations:
 * - The type must be known at compile time, so we cannot use generics directly, which means we
 *   can't use the existing [Repository] trait directly.
 * - The return type must be [JsValue], so we need to convert our types to and from [JsValue].
 *
 * To facilitate this, we provide some utilities:
 * - [WasmRepository] trait, which defines the methods as we expect them to come from
 *   [::wasm_bindgen], using [JsValue]. This is generic and should be implemented for each
 *   concrete repository we define, but the implementation should be very straightforward.
 * - [WasmRepositoryChannel] struct, which wraps a [WasmRepository] in a [ThreadBoundRunner] and
 *   implements the [Repository] trait. This has a few special considerations:
 *   - It uses [tsify_next::serde_wasm_bindgen] to convert between [JsValue] and our types, so
 *     we can use the existing [Repository] trait.
 *   - It runs the calls in a thread-bound manner, so we can safely call the [WasmRepository]
 *     methods from any thread.
 * - The [create_wasm_repository] macro, defines the [::wasm_bindgen] interface and implements
 *   the [WasmRepository] trait for you.
 */

use std::{future::Future, marker::PhantomData, rc::Rc};

use bitwarden_state::repository::{Repository, RepositoryError, RepositoryItem};
use bitwarden_threading::ThreadBoundRunner;
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

/// This trait defines the methods that a [::wasm_bindgen] repository must implement.
/// The trait itself exists to provide a generic way of handling the [::wasm_bindgen] interface,
/// which is !Send + !Sync, and only deals with [JsValue].
pub(crate) trait WasmRepository<T> {
    async fn get(&self, id: String) -> Result<JsValue, JsValue>;
    async fn list(&self) -> Result<JsValue, JsValue>;
    async fn set(&self, id: String, value: T) -> Result<JsValue, JsValue>;
    async fn remove(&self, id: String) -> Result<JsValue, JsValue>;
}

/// This struct wraps a [WasmRepository] in a [ThreadBoundRunner] to allow it to be used as a
/// [Repository] in a thread-safe manner. It implements the [Repository] trait directly, by
/// converting the values as needed with [tsify_next::serde_wasm_bindgen].
pub(crate) struct WasmRepositoryChannel<T, R: WasmRepository<T> + 'static>(
    ThreadBoundRunner<R>,
    PhantomData<T>,
);

impl<T, R: WasmRepository<T> + 'static> WasmRepositoryChannel<T, R> {
    pub(crate) fn new(repository: R) -> Self {
        Self(ThreadBoundRunner::new(repository), PhantomData)
    }
}

#[async_trait::async_trait]
impl<T: RepositoryItem + Serialize + DeserializeOwned, R: WasmRepository<T> + 'static> Repository<T>
    for WasmRepositoryChannel<T, R>
{
    async fn get(&self, id: String) -> Result<Option<T>, RepositoryError> {
        run_convert(&self.0, |s| async move { s.get(id).await }).await
    }
    async fn list(&self) -> Result<Vec<T>, RepositoryError> {
        run_convert(&self.0, |s| async move { s.list().await }).await
    }
    async fn set(&self, id: String, value: T) -> Result<(), RepositoryError> {
        run_convert(&self.0, |s| async move { s.set(id, value).await.and(UNIT) }).await
    }
    async fn remove(&self, id: String) -> Result<(), RepositoryError> {
        run_convert(&self.0, |s| async move { s.remove(id).await.and(UNIT) }).await
    }
}

#[wasm_bindgen(typescript_custom_section)]
const REPOSITORY_CUSTOM_TS_TYPE: &'static str = r#"
export interface Repository<T> {
    get(id: string): Promise<T | null>;
    list(): Promise<T[]>;
    set(id: string, value: T): Promise<void>;
    remove(id: string): Promise<void>;
}
"#;

/// This macro generates a [::wasm_bindgen] interface for a repository type, and provides the
/// implementation of [WasmRepository] and a way to convert it into something that implements
/// the [Repository] trait.
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

        impl $crate::platform::repository::WasmRepository<$ty> for $name {
            async fn get(
                &self,
                id: String,
            ) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue> {
                self.get(id).await
            }
            async fn list(&self) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue> {
                self.list().await
            }
            async fn set(
                &self,
                id: String,
                value: $ty,
            ) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue> {
                self.set(id, value).await
            }
            async fn remove(
                &self,
                id: String,
            ) -> Result<::wasm_bindgen::JsValue, ::wasm_bindgen::JsValue> {
                self.remove(id).await
            }
        }

        impl $name {
            pub fn into_channel_impl(
                self,
            ) -> ::std::sync::Arc<impl bitwarden_state::repository::Repository<$ty>> {
                use $crate::platform::repository::WasmRepositoryChannel;
                ::std::sync::Arc::new(WasmRepositoryChannel::new(self))
            }
        }
    };
}
pub(crate) use create_wasm_repository;

const UNIT: Result<JsValue, JsValue> = Ok(JsValue::UNDEFINED);

/// Utility function that runs a closure in a thread-bound manner, and converts the Result from
/// [Result<JsValue, JsValue>] to a typed [Result<T, RepositoryError>].
async fn run_convert<T: 'static, Func, Fut, Ret>(
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

/// Converts a [Result<JsValue, JsValue>] to a typed [Result<T, RepositoryError>] using
/// [tsify_next::serde_wasm_bindgen]
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
