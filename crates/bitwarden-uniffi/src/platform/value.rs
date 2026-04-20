use std::sync::Arc;

pub struct UniffiValueBridge<T>(pub T);

impl<T: ?Sized> UniffiValueBridge<Arc<T>> {
    pub fn new(store: Arc<T>) -> Arc<Self> {
        Arc::new(UniffiValueBridge(store))
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for UniffiValueBridge<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// This macro creates a Uniffi value trait and its implementation for the
/// [bitwarden_state::value::Value] trait
macro_rules! create_uniffi_values {
    ( $container_name:ident ; $( $qualified_type_name:ty, $type_name:ident, $field_name:ident, $value_name:ident );+ $(;)? ) => {

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
                        let bridge = $crate::platform::value::UniffiValueBridge::new(value);
                        client.register_client_managed_value(bridge);
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
                ) -> Result<Option<$qualified_type_name>, $crate::platform::repository::RepositoryError>;
                async fn set(
                    &self,
                    value: $qualified_type_name,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
                async fn remove(
                    &self,
                ) -> Result<(), $crate::platform::repository::RepositoryError>;
            }

            #[async_trait::async_trait]
            impl bitwarden_state::value::Value<$qualified_type_name>
                for $crate::platform::value::UniffiValueBridge<Arc<dyn $value_name>>
            {
                async fn get(
                    &self,
                ) -> Result<Option<$qualified_type_name>, bitwarden_state::repository::RepositoryError> {
                    self.0.get().await.map_err(Into::into)
                }
                async fn set(
                    &self,
                    value: $qualified_type_name,
                ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    self.0.set(value).await.map_err(Into::into)
                }
                async fn remove(
                    &self,
                ) -> Result<(), bitwarden_state::repository::RepositoryError> {
                    self.0.remove().await.map_err(Into::into)
                }
            }
        )+
    };
}

pub(super) use create_uniffi_values;
