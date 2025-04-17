use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::Arc,
};

#[async_trait::async_trait]
pub trait DataStore<T>: Send + Sync {
    async fn get(&self, key: String) -> Option<T>;
    async fn list(&self) -> Vec<T>;
    async fn set(&self, key: String, value: T);
    async fn remove(&self, key: String);
}

#[derive(Default)]
pub struct DataStoreMap {
    stores: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl std::fmt::Debug for DataStoreMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataStoreMap")
            .field("stores", &self.stores.keys())
            .finish()
    }
}

impl DataStoreMap {
    pub fn new() -> Self {
        DataStoreMap {
            stores: HashMap::new(),
        }
    }

    pub fn insert<T: 'static>(&mut self, value: Arc<dyn DataStore<T>>) {
        self.stores.insert(TypeId::of::<T>(), Box::new(value));
    }

    pub fn get<T: 'static>(&self) -> Option<Arc<dyn DataStore<T>>> {
        self.stores
            .get(&TypeId::of::<T>())
            .and_then(|boxed| boxed.downcast_ref::<Arc<dyn DataStore<T>>>())
            .map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! impl_data_store {
        ($name:ident, $ty:ty) => {
            #[async_trait::async_trait]
            impl DataStore<$ty> for $name {
                async fn get(&self, _key: String) -> Option<$ty> {
                    Some(self.0.clone())
                }
                async fn list(&self) -> Vec<$ty> {
                    unimplemented!()
                }
                async fn set(&self, _key: String, _value: $ty) {
                    unimplemented!()
                }
                async fn remove(&self, _key: String) {
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

    impl_data_store!(TestA, usize);
    impl_data_store!(TestB, String);
    impl_data_store!(TestC, Vec<u8>);

    #[tokio::test]
    async fn test_data_stores_map() {
        let a = Arc::new(TestA(145832));
        let b = Arc::new(TestB("test".to_string()));
        let c = Arc::new(TestC(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));

        let mut map = DataStoreMap::new();

        async fn get<T: 'static>(map: &DataStoreMap) -> Option<T> {
            map.get::<T>().unwrap().get(String::new()).await
        }

        assert!(map.get::<usize>().is_none());
        assert!(map.get::<String>().is_none());
        assert!(map.get::<Vec<u8>>().is_none());

        map.insert(a.clone());
        assert_eq!(get(&map).await, Some(a.0));
        assert!(map.get::<String>().is_none());
        assert!(map.get::<Vec<u8>>().is_none());

        map.insert(b.clone());
        assert_eq!(get(&map).await, Some(a.0));
        assert_eq!(get(&map).await, Some(b.0.clone()));
        assert!(map.get::<Vec<u8>>().is_none());

        map.insert(c.clone());
        assert_eq!(get(&map).await, Some(a.0));
        assert_eq!(get(&map).await, Some(b.0.clone()));
        assert_eq!(get(&map).await, Some(c.0.clone()));
    }
}
