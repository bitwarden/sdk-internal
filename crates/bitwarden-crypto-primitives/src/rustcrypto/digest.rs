use sha2::Digest;

/// Generates an incremental hasher over a RustCrypto digest with a fixed output length.
macro_rules! hasher {
    ($name:ident, $inner:ty, $len:expr) => {
        #[derive(Clone, Default)]
        pub(crate) struct $name($inner);

        impl $name {
            pub(crate) fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            pub(crate) fn finalize(self) -> [u8; $len] {
                self.0.finalize().into()
            }
        }
    };
}

hasher!(Sha1, sha1::Sha1, 20);
hasher!(Sha256, sha2::Sha256, 32);
hasher!(Sha384, sha2::Sha384, 48);
hasher!(Sha512, sha2::Sha512, 64);
