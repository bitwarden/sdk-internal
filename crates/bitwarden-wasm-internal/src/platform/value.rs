/*!
 * Client-managed persisted values in a [::wasm_bindgen] environment.
 *
 * Every value shares one [::wasm_bindgen] interface, [JsPersistedValue], because values cross
 * the boundary as [JsValue] converted with [tsify::serde_wasm_bindgen] in both directions. That
 * keeps value types free of wasm ABI requirements; the TypeScript type named for a value in the
 * list must still exist in the generated declarations.
 * - [WasmPersistedValueChannel] wraps a [JsPersistedValue] in a [ThreadBoundRunner] and
 *   implements [PersistedValueTrait] for one key.
 * - The [create_wasm_persisted_values] macro defines the container type clients pass in, and
 *   its TypeScript declaration.
 */

use std::{future::Future, marker::PhantomData, rc::Rc};

use bitwarden_state::{PersistedValueError, PersistedValueKey, PersistedValueTrait};
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen]
extern "C" {
    /// A client's implementation of the `PersistedValue<T>` TypeScript interface.
    pub type JsPersistedValue;

    #[wasm_bindgen(method, catch)]
    async fn get(this: &JsPersistedValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn set(this: &JsPersistedValue, value: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn remove(this: &JsPersistedValue) -> Result<JsValue, JsValue>;
}

#[wasm_bindgen(typescript_custom_section)]
const PERSISTED_VALUE_CUSTOM_TS_TYPE: &'static str = r#"
export interface PersistedValue<T> {
    get(): Promise<T | null>;
    set(value: T): Promise<void>;
    remove(): Promise<void>;
}
"#;

/// Wraps a [JsPersistedValue] in a [ThreadBoundRunner] so it can be used as the
/// [PersistedValueTrait] backend of `K` from any thread.
pub(crate) struct WasmPersistedValueChannel<K> {
    runner: ThreadBoundRunner<JsPersistedValue>,
    _marker: PhantomData<fn() -> K>,
}

impl<K: PersistedValueKey> WasmPersistedValueChannel<K> {
    pub(crate) fn new(value: JsPersistedValue) -> Self {
        Self {
            runner: ThreadBoundRunner::new(value),
            _marker: PhantomData,
        }
    }

    async fn call<R, F, Fut>(&self, f: F) -> Result<R, PersistedValueError>
    where
        F: FnOnce(Rc<JsPersistedValue>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<R, PersistedValueError>>,
        R: Send + Sync + 'static,
    {
        self.runner
            .run_in_thread(f)
            .await
            .expect("Task should not panic")
    }
}

// The serde messages can quote the value, so they are not propagated.
#[async_trait::async_trait]
impl<K: PersistedValueKey> PersistedValueTrait<K::Value> for WasmPersistedValueChannel<K> {
    async fn get(&self) -> Result<Option<K::Value>, PersistedValueError> {
        self.call(move |v| async move {
            let value = v.get().await.map_err(js_error)?;
            ::tsify::serde_wasm_bindgen::from_value(value).map_err(|_| {
                PersistedValueError::Internal(format!("Failed to deserialize '{}'", K::NAME))
            })
        })
        .await
    }

    async fn set(&self, value: K::Value) -> Result<(), PersistedValueError> {
        self.call(move |v| async move {
            let value = ::tsify::serde_wasm_bindgen::to_value(&value).map_err(|_| {
                PersistedValueError::Internal(format!("Failed to serialize '{}'", K::NAME))
            })?;
            v.set(value).await.map(drop).map_err(js_error)
        })
        .await
    }

    async fn remove(&self) -> Result<(), PersistedValueError> {
        self.call(|v| async move { v.remove().await.map(drop).map_err(js_error) })
            .await
    }
}

fn js_error(e: JsValue) -> PersistedValueError {
    PersistedValueError::Internal(format!("{e:?}"))
}

/// This macro generates the container type clients use to pass their persisted values, and a
/// `register_all` that registers the ones they provided.
macro_rules! create_wasm_persisted_values {
    ( $container_name:ident ; $( $key:path, $ts_type:literal, $field_name:ident, $value_name:ident );+ $(;)? ) => {

        const _: () = {
            #[wasm_bindgen(typescript_custom_section)]
            const PERSISTED_VALUES_CUSTOM_TS_TYPE: &'static str = concat!(
                "export interface ",
                stringify!($container_name),
                " {\n",
                $( "    ", stringify!($field_name), ": PersistedValue<", $ts_type, "> | null;\n", )+
                "}\n"
            );
        };

        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(typescript_type = $container_name)]
            pub type $container_name;

            $(
                #[wasm_bindgen(method, getter)]
                pub fn $field_name(
                    this: &$container_name,
                ) -> Option<$crate::platform::value::JsPersistedValue>;
            )+
        }

        impl $container_name {
            pub fn register_all(self, client: &bitwarden_core::platform::StateClient) {
                $(
                    if let Some(value) = self.$field_name() {
                        let channel = $crate::platform::value::WasmPersistedValueChannel::<$key>::new(value);
                        client.register_client_managed_value::<$key>(::std::sync::Arc::new(channel));
                    }
                )+
            }
        }
    };
}
pub(crate) use create_wasm_persisted_values;

#[cfg(test)]
mod tests {
    use wasm_bindgen::prelude::wasm_bindgen;
    use wasm_bindgen_test::wasm_bindgen_test;

    bitwarden_state::register_persisted_value!(THEME: String = "wasm_test_theme");

    create_wasm_persisted_values!(TestPersistedValues; THEME, "string", theme, TestThemeValue);

    #[wasm_bindgen(inline_js = "
        export function make_values() {
            const theme = {
                value: null,
                get: async () => theme.value,
                set: async (value) => { theme.value = value; },
                remove: async () => { throw new Error('storage unavailable'); },
            };
            return { theme };
        }
        export function stored_theme(values) { return values.theme.value; }
    ")]
    extern "C" {
        fn make_values() -> TestPersistedValues;
        fn stored_theme(values: &TestPersistedValues) -> Option<String>;
    }

    #[wasm_bindgen_test]
    async fn test_registered_value_reads_and_writes_the_js_implementation() {
        let client = bitwarden_core::Client::new(None);
        let values = make_values();
        // `register_all` consumes `values`; keep a handle to read back what the JS side stored.
        let js_values: TestPersistedValues = wasm_bindgen::JsCast::unchecked_into(values.clone());
        values.register_all(&client.platform().state());

        let theme = client.platform().state().value::<THEME>();
        theme.set("dark".to_string()).await.unwrap();

        assert_eq!(stored_theme(&js_values).as_deref(), Some("dark"));
        assert_eq!(theme.get().await.unwrap(), "dark");
        assert!(matches!(
            theme.remove().await,
            Err(bitwarden_state::PersistedValueError::Internal(msg)) if msg.contains("storage unavailable")
        ));
    }
}
