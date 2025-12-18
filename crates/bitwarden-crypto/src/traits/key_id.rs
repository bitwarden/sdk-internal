use std::{fmt::Debug, hash::Hash};

use zeroize::ZeroizeOnDrop;

use crate::{CryptoKey, PrivateKey, SigningKey, SymmetricCryptoKey};

/// Represents a key identifier that can be used to identify cryptographic keys in the
/// key store. It is used to avoid exposing the key material directly in the public API.
///
/// This trait is user-implemented, and the recommended implementation is using enums with variants
/// for each expected key purpose. We provide a macro ([crate::key_ids]) that simplifies the trait
/// implementation
///
/// To implement it manually, note that you need a few types:
/// - One implementing [KeyId<KeyValue = SymmetricCryptoKey>]
/// - One implementing [KeyId<KeyValue = AsymmetricCryptoKey>]
/// - One implementing [KeyIds]
pub trait KeyId:
    Debug + Clone + Copy + Hash + Eq + PartialEq + Ord + PartialOrd + Send + Sync + 'static
{
    #[allow(missing_docs)]
    type KeyValue: CryptoKey + Send + Sync + ZeroizeOnDrop;

    /// Returns whether the key is local to the current context or shared globally by the
    /// key store. See [crate::store::KeyStoreContext] for more information.
    fn is_local(&self) -> bool;

    /// Creates a new unique local key identifier.
    fn new_local(id: LocalId) -> Self;
}

/// Represents a set of all the key identifiers that need to be defined to use a key store.
/// At the moment it's just symmetric and asymmetric keys.
pub trait KeyIds {
    #[allow(missing_docs)]
    type Symmetric: KeyId<KeyValue = SymmetricCryptoKey>;
    #[allow(missing_docs)]
    type Private: KeyId<KeyValue = PrivateKey>;
    /// Signing keys are used to create detached signatures and to sign objects.
    type Signing: KeyId<KeyValue = SigningKey>;
}

/// An opaque identifier for a local key. Currently only contains a unique ID, but it can be
/// extended to contain scope information to allow cleanup on scope exit.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LocalId(pub(crate) uuid::Uuid);

impl LocalId {
    pub(crate) fn new() -> Self {
        LocalId(uuid::Uuid::new_v4())
    }
}

/// Just a small derive_like macro that can be used to generate the key identifier enums.
/// Example usage:
/// ```rust
/// use bitwarden_crypto::key_ids;
/// key_ids! {
///     #[symmetric]
///     pub enum SymmKeyId {
///         User,
///         Org(uuid::Uuid),
///         #[local]
///         Local(LocalId),
///     }
///
///     #[private]
///     pub enum PrivateKeyId {
///         PrivateKey,
///         #[local]
///         Local(LocalId),
///     }
///
///     #[signing]
///     pub enum SigningKeyId {
///        SigningKey,
///        #[local]
///        Local(LocalId),
///     }
///
///     pub Ids => SymmKeyId, PrivateKeyId, SigningKeyId;
/// }
#[macro_export]
macro_rules! key_ids {
    ( $(
        #[$meta_type:tt]
        $vis:vis enum $name:ident {
            $(
                $( #[$variant_tag:tt] )?
                $variant:ident $( ( $inner:ty ) )?
            ),*
            $(,)?
        }
    )+
    $ids_vis:vis $ids_name:ident => $symm_name:ident, $private_name:ident, $signing_name:ident;
    ) => {

        use $crate::LocalId;

        $(
            #[derive(std::fmt::Debug, Clone, Copy, std::hash::Hash, Eq, PartialEq, Ord, PartialOrd)]
            #[allow(missing_docs)]
            $vis enum $name { $(
                $variant  $( ($inner) )?,
            )* }

            impl $crate::KeyId for $name {
                type KeyValue = key_ids!(@key_type $meta_type);

                fn is_local(&self) -> bool {
                    use $name::*;
                    match self { $(
                        key_ids!(@variant_match $variant $( ( $inner ) )?) =>
                            key_ids!(@variant_value $( $variant_tag )? ),
                    )* }
                }

                fn new_local(id: LocalId) -> Self {
                    $(
                        { key_ids!(@new_local $variant  id $( $variant_tag )? ) }
                    )*
                }
            }
        )+

        #[allow(missing_docs)]
        $ids_vis struct $ids_name;
        impl $crate::KeyIds for $ids_name {
            type Symmetric = $symm_name;
            type Private = $private_name;
            type Signing = $signing_name;
        }
    };

    ( @key_type symmetric ) => { $crate::SymmetricCryptoKey };
    ( @key_type private ) => { $crate::PrivateKey };
    ( @key_type signing ) => { $crate::SigningKey };

    ( @variant_match $variant:ident ( $inner:ty ) ) => { $variant (_) };
    ( @variant_match $variant:ident ) => { $variant };

    ( @variant_value local ) => { true };
    ( @variant_value ) => { false };

    ( @new_local $variant:ident $id:ident local  ) => { Self::$variant($id) };
    ( @new_local $variant:ident $id:ident ) => {{}};
}

#[cfg(test)]
pub(crate) mod tests {

    use crate::{
        KeyId, LocalId,
        traits::tests::{TestPrivateKey, TestSigningKey, TestSymmKey},
    };

    #[test]
    fn test_local() {
        let local = LocalId::new();

        assert!(!TestSymmKey::A(0).is_local());
        assert!(!TestSymmKey::B((4, 10)).is_local());
        assert!(TestSymmKey::C(local).is_local());

        assert!(!TestPrivateKey::A(0).is_local());
        assert!(!TestPrivateKey::B.is_local());
        assert!(TestPrivateKey::C(local).is_local());

        assert!(!TestSigningKey::A(0).is_local());
        assert!(!TestSigningKey::B.is_local());
        assert!(TestSigningKey::C(local).is_local());
    }
}
