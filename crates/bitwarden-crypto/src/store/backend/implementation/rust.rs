use super::{
    slice_backend::{SliceBackend, SliceLike},
    KeyRef,
};

// This is a basic in-memory key store for the cases where we don't have a secure key store
// available. We still make use mlock to protect the memory from being swapped to disk, and we
// zeroize the values when dropped.
pub(crate) type RustBackend<Key> = SliceBackend<Key, RustBackendImpl<Key>>;

pub(crate) struct RustBackendImpl<Key: KeyRef> {
    #[allow(clippy::type_complexity)]
    data: Box<[Option<(Key, Key::KeyValue)>]>,
}

impl<Key: KeyRef> Drop for RustBackendImpl<Key> {
    fn drop(&mut self) {
        munlock_data(self.data.as_mut());
    }
}

impl<Key: KeyRef> SliceLike<Key> for RustBackendImpl<Key> {
    fn is_available() -> bool {
        true
    }

    fn with_capacity(capacity: usize) -> Self {
        #[allow(unused_mut)]
        let mut data: Box<_> = std::iter::repeat_with(|| None).take(capacity).collect();
        mlock_data(data.as_mut());
        RustBackendImpl { data }
    }

    fn get_key_data(&self) -> &[Option<(Key, Key::KeyValue)>] {
        self.data.as_ref()
    }

    fn get_key_data_mut(&mut self) -> &mut [Option<(Key, Key::KeyValue)>] {
        self.data.as_mut()
    }
}

#[allow(unused_variables)]
fn mlock_data<T>(data: &mut [T]) {
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(windows),
        not(feature = "no-memory-hardening")
    ))]
    {
        unsafe {
            memsec::mlock(data.as_mut_ptr() as *mut u8, std::mem::size_of_val(data));
        }
    }
}

#[allow(unused_variables)]
fn munlock_data<T: Default>(data: &mut [T]) {
    #[cfg(all(
        not(target_arch = "wasm32"),
        not(windows),
        not(feature = "no-memory-hardening")
    ))]
    {
        use std::mem::MaybeUninit;
        unsafe {
            memsec::munlock(data.as_mut_ptr() as *mut u8, std::mem::size_of_val(data));

            // Note: munlock is zeroing the memory, which leaves the data in an undefined
            // state, so we set it to None/Default again to avoid UB in the Drop implementation.
            let uninit_slice: &mut [MaybeUninit<_>] = std::slice::from_raw_parts_mut(
                data.as_mut_ptr() as *mut MaybeUninit<T>,
                data.len(),
            );
            for elem in uninit_slice {
                elem.write(T::default());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::{slice_backend::tests::*, StoreBackend as _};

    #[test]
    fn test_resize() {
        let mut store = RustBackend::<TestKey>::with_capacity(1).unwrap();

        for (idx, key) in [
            TestKey::A,
            TestKey::B(10),
            TestKey::C,
            TestKey::B(7),
            TestKey::A,
            TestKey::C,
        ]
        .into_iter()
        .enumerate()
        {
            store.insert(key, TestKeyValue::new(idx));
        }

        assert_eq!(store.get(TestKey::A), Some(&TestKeyValue::new(4)));
        assert_eq!(store.get(TestKey::B(10)), Some(&TestKeyValue::new(1)));
        assert_eq!(store.get(TestKey::C), Some(&TestKeyValue::new(5)));
        assert_eq!(store.get(TestKey::B(7)), Some(&TestKeyValue::new(3)));
        assert_eq!(store.get(TestKey::B(20)), None);
    }
}
