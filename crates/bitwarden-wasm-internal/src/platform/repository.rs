use ::tokio::sync::oneshot::Sender;
use bitwarden_core::client::repository::RepositoryError;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

pub enum RepositoryMessage<T> {
    Get(String, Sender<Result<Option<T>, RepositoryError>>),
    List(Sender<Result<Vec<T>, RepositoryError>>),
    Set(String, T, Sender<Result<(), RepositoryError>>),
    Remove(String, Sender<Result<(), RepositoryError>>),
}

#[derive(Debug, Clone)]
pub struct ChannelRepository<T> {
    pub sender: ::tokio::sync::mpsc::Sender<RepositoryMessage<T>>,
}

impl<T> ChannelRepository<T> {
    async fn send<Res>(&self, func: impl FnOnce(Sender<Res>) -> RepositoryMessage<T>) -> Res {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.sender
            .send(func(tx))
            .await
            .expect("must always send a message");
        rx.await.expect("must always receive a response")
    }
}

#[async_trait::async_trait]
impl<T: Send> bitwarden_core::client::repository::Repository<T> for ChannelRepository<T> {
    async fn get(&self, id: String) -> Result<Option<T>, RepositoryError> {
        self.send(|tx| RepositoryMessage::Get(id, tx)).await
    }
    async fn list(&self) -> Result<Vec<T>, RepositoryError> {
        self.send(|tx| RepositoryMessage::List(tx)).await
    }
    async fn set(&self, id: String, value: T) -> Result<(), RepositoryError> {
        self.send(|tx| RepositoryMessage::Set(id, value, tx)).await
    }
    async fn remove(&self, id: String) -> Result<(), RepositoryError> {
        self.send(|tx| RepositoryMessage::Remove(id, tx)).await
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
pub fn convert_result<T: serde::de::DeserializeOwned>(
    result: Result<JsValue, JsValue>,
) -> Result<T, RepositoryError> {
    result
        .map_err(|e| RepositoryError::Internal(format!("{e:?}")))
        .and_then(|value| {
            ::tsify_next::serde_wasm_bindgen::from_value(value)
                .map_err(|e| RepositoryError::Internal(e.to_string()))
        })
}

macro_rules! create_wasm_repository {
    ($name:ident, $ty:ty) => {
        #[wasm_bindgen]
        extern "C" {
            #[wasm_bindgen(js_name = $name, typescript_type = "Repository<Cipher>")]
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
            ) -> ::std::sync::Arc<$crate::platform::repository::ChannelRepository<$ty>> {
                let (tx, mut rx) = tokio::sync::mpsc::channel(16);

                use $crate::platform::repository::RepositoryMessage;

                wasm_bindgen_futures::spawn_local(async move {
                    while let Some(cmd) = rx.recv().await {
                        match cmd {
                            RepositoryMessage::Get(id, sender) => {
                                let result = self.get(id).await;
                                let _ = sender
                                    .send($crate::platform::repository::convert_result(result));
                            }
                            RepositoryMessage::List(sender) => {
                                let result = self.list().await;
                                let _ = sender
                                    .send($crate::platform::repository::convert_result(result));
                            }
                            RepositoryMessage::Set(id, value, sender) => {
                                let result = self.set(id, value).await;
                                let _ = sender.send($crate::platform::repository::convert_result(
                                    result.and(Ok(::wasm_bindgen::JsValue::UNDEFINED)),
                                ));
                            }
                            RepositoryMessage::Remove(id, sender) => {
                                let result = self.remove(id).await;
                                let _ = sender.send($crate::platform::repository::convert_result(
                                    result.and(Ok(::wasm_bindgen::JsValue::UNDEFINED)),
                                ));
                            }
                        }
                    }
                });
                ::std::sync::Arc::new($crate::platform::repository::ChannelRepository {
                    sender: tx,
                })
            }
        }
    };
}
pub(super) use create_wasm_repository;
