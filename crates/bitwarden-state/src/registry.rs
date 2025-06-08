use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, RwLock},
};

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::repository::RepositoryItemRegistration;
use crate::repository::{Repository, RepositoryItem};

/// A registry that contains repositories for different types of items.
/// These repositories can be either managed by the client or by the SDK itself.
pub struct StateRegistry {
    client_managed: RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>,
}

impl std::fmt::Debug for StateRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateRegistry").finish()
    }
}

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum StateRegistryError {
    #[error("Repository for type {0} is not registered as client-managed")]
    RepositoryNotClientManaged(&'static str),

    #[error("Not all client-managed repositories are registered")]
    NotAllRepositoriesRegistered,
}

impl StateRegistry {
    /// Creates a new empty `StateRegistry`.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        StateRegistry {
            client_managed: RwLock::new(HashMap::new()),
        }
    }

    /// Registers a client-managed repository into the map, associating it with its type.
    pub fn register_client_managed<T: RepositoryItem>(
        &self,
        value: Arc<dyn Repository<T>>,
    ) -> Result<(), StateRegistryError> {
        let mut possible_registrations = RepositoryItemRegistration::iter();
        match possible_registrations.find(|reg| reg.type_id() == TypeId::of::<T>()) {
            Some(reg) => {
                if !reg.rtype.is_client_managed() {
                    return Err(StateRegistryError::RepositoryNotClientManaged(reg.name));
                }
            }
            // This should never happen, as we have tests to ensure all repositories are registered.
            _ => {
                return Err(StateRegistryError::NotAllRepositoriesRegistered);
            }
        }

        self.client_managed
            .write()
            .expect("RwLock should not be poisoned")
            .insert(TypeId::of::<T>(), Box::new(value));

        Ok(())
    }

    /// Retrieves a client-managed repository from the map given its type.
    pub fn get_client_managed<T: RepositoryItem>(&self) -> Option<Arc<dyn Repository<T>>> {
        self.client_managed
            .read()
            .expect("RwLock should not be poisoned")
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<Arc<dyn Repository<T>>>())
            .map(Arc::clone)
    }

    /// Validates that all repositories registered in the client-managed state registry.
    /// This should only be called after all the repositories have been registered by the clients.
    pub fn validate_repositories(&self) -> Result<(), StateRegistryError> {
        let possible_registrations = RepositoryItemRegistration::iter();
        let mut missing_repository = false;

        let client_managed = self
            .client_managed
            .read()
            .expect("RwLock should not be poisoned");

        for reg in possible_registrations {
            if reg.rtype.is_client_managed() && !client_managed.contains_key(&reg.type_id()) {
                log::error!(
                    "Repository for type {} is not registered in the client-managed state registry",
                    reg.name
                );
                missing_repository = true;
            }
        }

        if missing_repository {
            return Err(StateRegistryError::NotAllRepositoriesRegistered);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        register_repository_item,
        repository::{RepositoryError, RepositoryItem},
    };

    macro_rules! impl_repository {
        ($name:ident, $ty:ty) => {
            #[async_trait::async_trait]
            impl Repository<$ty> for $name {
                async fn get(&self, _key: String) -> Result<Option<$ty>, RepositoryError> {
                    Ok(Some(TestItem(self.0.clone())))
                }
                async fn list(&self) -> Result<Vec<$ty>, RepositoryError> {
                    unimplemented!()
                }
                async fn set(&self, _key: String, _value: $ty) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
                async fn remove(&self, _key: String) -> Result<(), RepositoryError> {
                    unimplemented!()
                }
            }
        };
    }

    #[derive(PartialEq, Eq, Debug)]
    struct TestA(usize);
    #[derive(PartialEq, Eq, Debug)]
    struct TestB(String);
    #[derive(PartialEq, Eq, Debug)]
    struct TestC(Vec<u8>);
    #[derive(PartialEq, Eq, Debug)]
    struct TestItem<T>(T);

    register_repository_item!(TestItem<usize>, "TestItem<usize>", ClientManaged);
    register_repository_item!(TestItem<String>, "TestItem<String>", ClientManaged);
    register_repository_item!(TestItem<Vec<u8>>, "TestItem<Vec<u8>>", ClientManaged);

    impl_repository!(TestA, TestItem<usize>);
    impl_repository!(TestB, TestItem<String>);
    impl_repository!(TestC, TestItem<Vec<u8>>);

    #[tokio::test]
    async fn test_repository_map() {
        let a = Arc::new(TestA(145832));
        let b = Arc::new(TestB("test".to_string()));
        let c = Arc::new(TestC(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));

        let map = StateRegistry::new();

        async fn get<T: RepositoryItem>(map: &StateRegistry) -> Option<T> {
            map.get_client_managed::<T>()
                .unwrap()
                .get(String::new())
                .await
                .unwrap()
        }

        assert!(map.get_client_managed::<TestItem<usize>>().is_none());
        assert!(map.get_client_managed::<TestItem<String>>().is_none());
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_none());

        map.register_client_managed(a.clone()).unwrap();
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert!(map.get_client_managed::<TestItem<String>>().is_none());
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_none());

        map.register_client_managed(b.clone()).unwrap();
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert_eq!(get(&map).await, Some(TestItem(b.0.clone())));
        assert!(map.get_client_managed::<TestItem<Vec<u8>>>().is_none());

        map.register_client_managed(c.clone()).unwrap();
        assert_eq!(get(&map).await, Some(TestItem(a.0)));
        assert_eq!(get(&map).await, Some(TestItem(b.0.clone())));
        assert_eq!(get(&map).await, Some(TestItem(c.0.clone())));
    }
}
