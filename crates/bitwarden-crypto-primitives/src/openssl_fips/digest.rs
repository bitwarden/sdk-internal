use ::openssl::hash::{Hasher, MessageDigest};

/// Generates an incremental hasher over an OpenSSL digest with a fixed output length.
macro_rules! hasher {
    ($name:ident, $md:expr, $len:expr) => {
        #[derive(Clone)]
        pub(crate) struct $name(Hasher);

        impl Default for $name {
            fn default() -> Self {
                Self(Hasher::new($md).expect("OpenSSL provides the digest"))
            }
        }

        impl $name {
            pub(crate) fn update(&mut self, data: &[u8]) {
                self.0
                    .update(data)
                    .expect("hashing in-memory data does not fail");
            }

            pub(crate) fn finalize(mut self) -> [u8; $len] {
                let digest = self
                    .0
                    .finish()
                    .expect("hashing in-memory data does not fail");
                (*digest)
                    .try_into()
                    .expect("digest length matches the algorithm")
            }
        }
    };
}

hasher!(Sha1, MessageDigest::sha1(), 20);
hasher!(Sha256, MessageDigest::sha256(), 32);
hasher!(Sha384, MessageDigest::sha384(), 48);
hasher!(Sha512, MessageDigest::sha512(), 64);
