use allocator_api2::alloc::Global;

use super::StoreBackend;
use crate::store::{backend::implementation::custom_alloc::CustomAllocBackend, KeyId};

#[cfg(any(target_os = "linux", all(not(target_arch = "wasm32"), not(windows))))]
mod custom_alloc;

/// Initializes a key store backend with the best available implementation for the current platform
pub fn create_store<Key: KeyId>() -> Box<dyn StoreBackend<Key>> {
    if !cfg!(feature = "no-memory-hardening") {
        #[cfg(target_os = "linux")]
        if let Some(alloc) = custom_alloc::linux_memfd_secret::LinuxMemfdSecretAlloc::new() {
            return Box::new(CustomAllocBackend::new(alloc));
        }

        #[cfg(all(not(target_arch = "wasm32"), not(windows)))]
        return Box::new(CustomAllocBackend::new(
            custom_alloc::malloc::MlockAlloc::new(),
        ));
    }

    Box::new(CustomAllocBackend::new(Global))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{traits::tests::TestSymmKey, SymmetricCryptoKey};

    #[test]
    fn test_creates_a_valid_store() {
        let mut store = create_store::<TestSymmKey>();

        let key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        store.upsert(TestSymmKey::A(0), key.clone());

        assert_eq!(
            store.get(TestSymmKey::A(0)).unwrap().to_base64(),
            key.to_base64()
        );
    }

    #[cfg(all(not(target_arch = "wasm32"), not(windows)))]
    #[test]
    fn validate_mlock_store() {
        let basic_store = CustomAllocBackend::new(Global);
        let mlock_store = CustomAllocBackend::new(custom_alloc::malloc::MlockAlloc::new());
        compare_stores(100_000, basic_store, mlock_store);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn validate_memfd_store() {
        let basic_store = CustomAllocBackend::new(Global);
        let memfd_store = CustomAllocBackend::new(
            custom_alloc::linux_memfd_secret::LinuxMemfdSecretAlloc::new().unwrap(),
        );
        compare_stores(100_000, basic_store, memfd_store);
    }

    /// This function will perform a number of random operations on two stores,
    /// and compare the results between them to make sure they match.
    fn compare_stores<
        AllocA: allocator_api2::alloc::Allocator + Send + Sync,
        AllocB: allocator_api2::alloc::Allocator + Send + Sync,
    >(
        num_iterations: usize,
        mut a: CustomAllocBackend<TestSymmKey, AllocA>,
        mut b: CustomAllocBackend<TestSymmKey, AllocB>,
    ) {
        use rand::{distributions::Standard, prelude::*};

        #[derive(Debug)]
        enum Operation {
            Upsert(TestSymmKey, SymmetricCryptoKey),
            Get(TestSymmKey),
            Remove(TestSymmKey),
            Clear,
            Retain(fn(TestSymmKey) -> bool),
        }

        impl Distribution<Operation> for Standard {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Operation {
                match rng.gen_range(0..=4) {
                    0 => Operation::Upsert(
                        TestSymmKey::A(rng.gen_range(0..=1000)),
                        SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
                    ),
                    1 => Operation::Get(TestSymmKey::A(rng.gen_range(0..=1000))),
                    2 => Operation::Remove(TestSymmKey::A(rng.gen_range(0..=1000))),
                    3 => Operation::Clear,
                    // This one has to be constant as we can't capture variables
                    4 => Operation::Retain(|key| match key {
                        TestSymmKey::A(a) => a % 9 == 0,
                        TestSymmKey::B((a, b)) => (a + b) % 10 == 3,
                        TestSymmKey::C(a) => a % 11 == 6,
                    }),
                    _ => unreachable!(),
                }
            }
        }

        for _ in 0..num_iterations {
            let operation = rand::random::<Operation>();

            match operation {
                Operation::Upsert(key, value) => {
                    a.upsert(key, value.clone());
                    b.upsert(key, value);
                }
                Operation::Get(key) => {
                    assert_eq!(
                        a.get(key),
                        b.get(key),
                        "Get operation for {key:?} has different results"
                    );
                    // This doesn't modify the store, so we can skip the comparison after
                    continue;
                }
                Operation::Remove(key) => {
                    a.remove(key);
                    b.remove(key);
                }
                Operation::Clear => {
                    a.clear();
                    b.clear();
                }
                Operation::Retain(f) => {
                    a.retain(f);
                    b.retain(f);
                }
            }

            // Get all the elements from both stores and sort them the same way
            let mut a_elements = a.elements();
            let mut b_elements = b.elements();
            a_elements.sort_by(|a, b| a.0.cmp(&b.0));
            b_elements.sort_by(|a, b| a.0.cmp(&b.0));

            // Compare the two stores, as they should be the same
            assert_eq!(
                a_elements.len(),
                b_elements.len(),
                "The two stores have different number of elements"
            );

            for ((akey, avalue), (bkey, bvalue)) in a_elements.iter().zip(b_elements.iter()) {
                assert_eq!(akey, bkey, "The keys are different");
                assert_eq!(
                    avalue.to_base64(),
                    bvalue.to_base64(),
                    "The values are different"
                );
            }
        }
    }
}
