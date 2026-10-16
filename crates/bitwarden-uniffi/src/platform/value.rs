use bitwarden_state::PersistedValueError;

use crate::platform::repository::RepositoryError;

impl From<RepositoryError> for PersistedValueError {
    fn from(e: RepositoryError) -> Self {
        match e {
            RepositoryError::Internal(msg) => Self::Internal(msg),
        }
    }
}

/// This macro creates a Uniffi trait for each client-managed persisted value, and its
/// implementation of the [bitwarden_state::PersistedValueTrait] trait on the shared
/// [UniffiRepositoryBridge](crate::platform::repository::UniffiRepositoryBridge).
macro_rules! create_uniffi_persisted_values {
    ( $container_name:ident ; $( $key:path, $ts_type:literal, $field_name:ident, $value_name:ident );+ $(;)? ) => {

        #[derive(::uniffi::Record)]
        pub struct $container_name {
            $(
                pub $field_name: Option<::std::sync::Arc<dyn $value_name>>,
            )+
        }

        impl $container_name {
            pub fn register_all(self, client: &bitwarden_core::platform::StateClient) {
                $(
                    if let Some(value) = self.$field_name {
                        let bridge = $crate::platform::repository::UniffiRepositoryBridge::new(value);
                        client.register_client_managed_value::<$key>(bridge);
                    }
                )+
            }
        }

        $(
            #[::uniffi::export(with_foreign)]
            #[::async_trait::async_trait]
            pub trait $value_name: Send + Sync {
                async fn get(
                    &self,
                ) -> Result<
                    Option<<$key as ::bitwarden_state::PersistedValueKey>::Value>,
                    $crate::platform::repository::RepositoryError,
                >;
                async fn set(
                    &self,
                    value: <$key as ::bitwarden_state::PersistedValueKey>::Value,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
                async fn remove(&self) -> Result<(), $crate::platform::repository::RepositoryError>;
            }

            #[::async_trait::async_trait]
            impl ::bitwarden_state::PersistedValueTrait<<$key as ::bitwarden_state::PersistedValueKey>::Value>
                for $crate::platform::repository::UniffiRepositoryBridge<::std::sync::Arc<dyn $value_name>>
            {
                async fn get(
                    &self,
                ) -> Result<
                    Option<<$key as ::bitwarden_state::PersistedValueKey>::Value>,
                    ::bitwarden_state::PersistedValueError,
                > {
                    Ok(self.0.get().await?)
                }
                async fn set(
                    &self,
                    value: <$key as ::bitwarden_state::PersistedValueKey>::Value,
                ) -> Result<(), ::bitwarden_state::PersistedValueError> {
                    Ok(self.0.set(value).await?)
                }
                async fn remove(&self) -> Result<(), ::bitwarden_state::PersistedValueError> {
                    Ok(self.0.remove().await?)
                }
            }
        )+
    };
}

pub(super) use create_uniffi_persisted_values;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::platform::repository::RepositoryError;

    bitwarden_state::register_persisted_value!(pub THEME: String = "uniffi_test_theme");

    create_uniffi_persisted_values!(TestPersistedValues; THEME, "string", theme, TestThemeValue);

    #[derive(Default)]
    struct ForeignTheme(Mutex<Option<String>>);

    #[async_trait::async_trait]
    impl TestThemeValue for ForeignTheme {
        async fn get(&self) -> Result<Option<String>, RepositoryError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn set(&self, value: String) -> Result<(), RepositoryError> {
            *self.0.lock().unwrap() = Some(value);
            Ok(())
        }
        async fn remove(&self) -> Result<(), RepositoryError> {
            Err(RepositoryError::Internal("storage unavailable".to_string()))
        }
    }

    #[tokio::test]
    async fn test_registered_value_reads_and_writes_the_foreign_implementation() {
        let client = bitwarden_core::Client::new(None);
        let foreign = Arc::new(ForeignTheme::default());
        TestPersistedValues {
            theme: Some(foreign.clone()),
        }
        .register_all(&client.platform().state());

        let theme = client.platform().state().value::<THEME>();
        theme.set("dark".to_string()).await.unwrap();

        assert_eq!(foreign.0.lock().unwrap().as_deref(), Some("dark"));
        assert_eq!(theme.get().await.unwrap(), "dark");
        assert!(matches!(
            theme.remove().await,
            Err(bitwarden_state::PersistedValueError::Internal(msg)) if msg == "storage unavailable"
        ));
    }
}
