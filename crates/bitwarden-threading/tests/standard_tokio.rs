use bitwarden_threading::ThreadBoundRunner;
use tokio::sync::Mutex;

#[derive(Default)]
struct CipherService {
    _un_send_marker: std::marker::PhantomData<*const ()>,
    ciphers: std::collections::HashMap<String, Cipher>,
}

#[async_trait::async_trait]
trait Store<T> {
    async fn get(&self, id: String) -> Option<T>;
    async fn save(&self, item: T);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cipher {
    id: String,
    name: String,
    password: String,
}

/// Utility function to run a test in a local context (allows using tokio::..::spawn_local)
async fn run_test<F>(test: F) -> F::Output
where
    F: std::future::Future,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        let local_set = tokio::task::LocalSet::new();
        local_set.run_until(test).await
    }

    #[cfg(target_arch = "wasm32")]
    {
        test.await
    }
}

#[tokio::test]
pub async fn test_get_cipher() {
    run_test(async {
        let cipher_service = CipherService::default();
        let bound_cipher_service = ThreadBoundRunner::new(Mutex::new(cipher_service));

        struct CipherStore(ThreadBoundRunner<Mutex<CipherService>>);

        #[async_trait::async_trait]
        impl Store<Cipher> for CipherStore {
            async fn get(&self, id: String) -> Option<Cipher> {
                self.0
                    .run_in_thread(
                        |state| async move { state.lock().await.ciphers.get(&id).cloned() },
                    )
                    .await
                    .unwrap()
            }

            async fn save(&self, item: Cipher) {
                self.0
                    .run_in_thread(|state| async move {
                        state.lock().await.ciphers.insert(item.id.clone(), item)
                    })
                    .await
                    .unwrap();
            }
        }

        let store = CipherStore(bound_cipher_service);
        let cipher = Cipher {
            id: "id".to_owned(),
            name: "name".to_owned(),
            password: "password".to_owned(),
        };

        store.save(cipher).await;
        let result = store.get("id".to_owned()).await;

        assert_eq!(result, result);
    })
    .await;
}
