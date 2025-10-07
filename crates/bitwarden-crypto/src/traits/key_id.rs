use std::{fmt::Debug, hash::Hash};

use zeroize::ZeroizeOnDrop;

use crate::{AsymmetricCryptoKey, CryptoKey, SigningKey, SymmetricCryptoKey};

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
}

/// Represents a set of all the key identifiers that need to be defined to use a key store.
/// At the moment it's just symmetric and asymmetric keys.
pub trait KeyIds {
    #[allow(missing_docs)]
    type Symmetric: KeyId<KeyValue = SymmetricCryptoKey>;
    #[allow(missing_docs)]
    type Asymmetric: KeyId<KeyValue = AsymmetricCryptoKey>;
    /// Signing keys are used to create detached signatures and to sign objects.
    type Signing: KeyId<KeyValue = SigningKey>;
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
///         Local(&'static str),
///     }
///
///     #[asymmetric]
///     pub enum AsymmKeyId {
///         PrivateKey,
///     }
///
///     #[signing]
///     pub enum SigningKeyId {
///        SigningKey,
///     }
///
///     pub Ids => SymmKeyId, AsymmKeyId, SigningKeyId;
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
    $ids_vis:vis $ids_name:ident => $symm_name:ident, $asymm_name:ident, $signing_name:ident;
    ) => {
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
            }
        )+

        #[allow(missing_docs)]
        $ids_vis struct $ids_name;
        impl $crate::KeyIds for $ids_name {
            type Symmetric = $symm_name;
            type Asymmetric = $asymm_name;
            type Signing = $signing_name;
        }
    };

    ( @key_type symmetric ) => { $crate::SymmetricCryptoKey };
    ( @key_type asymmetric ) => { $crate::AsymmetricCryptoKey };
    ( @key_type signing ) => { $crate::SigningKey };

    ( @variant_match $variant:ident ( $inner:ty ) ) => { $variant (_) };
    ( @variant_match $variant:ident ) => { $variant };

    ( @variant_value local ) => { true };
    ( @variant_value ) => { false };
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        KeyId,
        traits::tests::{TestAsymmKey, TestSigningKey, TestSymmKey},
    };

    #[test]
    fn test_local() {
        assert!(!TestSymmKey::A(0).is_local());
        assert!(!TestSymmKey::B((4, 10)).is_local());
        assert!(TestSymmKey::C(8).is_local());

        assert!(!TestAsymmKey::A(0).is_local());
        assert!(!TestAsymmKey::B.is_local());
        assert!(TestAsymmKey::C("test").is_local());

        assert!(!TestSigningKey::A(0).is_local());
        assert!(!TestSigningKey::B.is_local());
        assert!(TestSigningKey::C("test").is_local());
    }
}
