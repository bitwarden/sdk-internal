use std::any::TypeId;

use serde::{Serialize, de::DeserializeOwned};

use crate::repository::RepositoryError;

/// This trait represents a single-value store: one value per type, with no key.
///
/// Use [`Value`] when state is naturally a singleton (e.g. a session snapshot,
/// a feature-flag blob, or a current-user profile), rather than a keyed collection.
/// For keyed collections, use [`crate::repository::Repository`] instead.
#[async_trait::async_trait]
pub trait Value<V: ValueItem>: Send + Sync {
    /// Retrieve the current value, if any has been set.
    async fn get(&self) -> Result<Option<V>, RepositoryError>;
    /// Store the value, replacing any previous value.
    async fn set(&self, value: V) -> Result<(), RepositoryError>;
    /// Remove the stored value, if present.
    async fn remove(&self) -> Result<(), RepositoryError>;
}

/// This trait is used to mark types that can be stored as a single value.
/// It should not be implemented manually; instead, users should
/// use the [crate::register_value_item] macro to register their value types.
pub trait ValueItem: Internal + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The name of the type implementing this trait.
    const NAME: &'static str;

    /// Returns the `TypeId` of the type implementing this trait.
    fn type_id() -> TypeId {
        TypeId::of::<Self>()
    }
}

/// Register a type for use as a single-value state item. The type must only be registered once
/// in the crate where it's defined. The provided name must be unique and not be changed.
#[macro_export]
macro_rules! register_value_item {
    ($ty:ty, $name:literal) => {
        const _: () = {
            impl $crate::value::___internal::Internal for $ty {}
            impl $crate::value::ValueItem for $ty {
                const NAME: &'static str = $name;
            }
            assert!(
                $crate::repository::validate_registry_name($name),
                concat!(
                    "Value name '",
                    $name,
                    "' must contain only alphabetic characters and underscores"
                )
            )
        };
    };
}

/// This code is not meant to be used directly, users of this crate should use the
/// [crate::register_value_item] macro to register their types.
#[doc(hidden)]
pub mod ___internal {

    // This trait is in an internal module to try to forbid users from implementing `ValueItem`
    // directly.
    pub trait Internal {}
}
pub(crate) use ___internal::Internal;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::registry::StateRegistry;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Session {
        user: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Flags {
        enabled: bool,
    }

    register_value_item!(Session, "Session");
    register_value_item!(Flags, "Flags");

    struct InMemoryValue<T: ValueItem + Clone>(Mutex<Option<T>>);

    #[async_trait::async_trait]
    impl<T: ValueItem + Clone> Value<T> for InMemoryValue<T> {
        async fn get(&self) -> Result<Option<T>, RepositoryError> {
            Ok(self.0.lock().unwrap().clone())
        }
        async fn set(&self, value: T) -> Result<(), RepositoryError> {
            *self.0.lock().unwrap() = Some(value);
            Ok(())
        }
        async fn remove(&self) -> Result<(), RepositoryError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    #[tokio::test]
    async fn register_and_get_value() {
        let registry = StateRegistry::new();
        let store: Arc<dyn Value<Session>> = Arc::new(InMemoryValue::<Session>(Mutex::new(None)));
        registry.register_client_managed_value(store);

        let handle = registry.get_value::<Session>().unwrap();
        assert_eq!(handle.get().await.unwrap(), None);

        handle
            .set(Session {
                user: "alice".into(),
            })
            .await
            .unwrap();
        assert_eq!(
            handle.get().await.unwrap(),
            Some(Session {
                user: "alice".into()
            })
        );

        handle.remove().await.unwrap();
        assert_eq!(handle.get().await.unwrap(), None);
    }

    #[tokio::test]
    async fn missing_value_returns_error() {
        let registry = StateRegistry::new();
        let result = registry.get_value::<Session>();
        assert!(matches!(
            result,
            Err(crate::registry::StateRegistryError::ValueNotRegistered)
        ));
    }

    #[tokio::test]
    async fn different_value_types_are_isolated() {
        let registry = StateRegistry::new();
        registry.register_client_managed_value::<Session>(Arc::new(InMemoryValue::<Session>(
            Mutex::new(None),
        )));
        registry.register_client_managed_value::<Flags>(Arc::new(InMemoryValue::<Flags>(
            Mutex::new(None),
        )));

        let session = registry.get_value::<Session>().unwrap();
        let flags = registry.get_value::<Flags>().unwrap();

        session.set(Session { user: "bob".into() }).await.unwrap();
        flags.set(Flags { enabled: true }).await.unwrap();

        assert_eq!(
            session.get().await.unwrap(),
            Some(Session { user: "bob".into() })
        );
        assert_eq!(flags.get().await.unwrap(), Some(Flags { enabled: true }));
    }
}
