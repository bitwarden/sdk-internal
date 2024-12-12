use std::{fmt::Debug, hash::Hash};

use zeroize::ZeroizeOnDrop;

use crate::{AsymmetricCryptoKey, CryptoKey, SymmetricCryptoKey};

/// Represents a key reference that can be used to identify cryptographic keys in the
/// key store. It is used to avoid exposing the key material directly in the public API.
///
/// This trait is user-implemented, and our recommended implementation is using enums with variants
/// for each expected key purpose. We provide a macro ([key_refs]) that simplifies the trait
/// implementation
///
/// To implement it manually, note that you need a few types:
/// - One implementing [KeyRef<KeyValue = SymmetricCryptoKey>]
/// - One implementing [KeyRef<KeyValue = AsymmetricCryptoKey>]
/// - One implementing [KeyRefs]
pub trait KeyRef:
    Debug + Clone + Copy + Hash + Eq + PartialEq + Ord + PartialOrd + Send + Sync + 'static
{
    type KeyValue: CryptoKey + Send + Sync + ZeroizeOnDrop;

    /// Returns whether the key is local to the current context or shared globally by the
    /// key store. See [crate::store::KeyStoreContext] for more information.
    fn is_local(&self) -> bool;
}

/// Represents a set of all the key references that need to be defined to use a key store.
/// At the moment it's just symmetric and asymmetric keys.
pub trait KeyRefs {
    type Symmetric: KeyRef<KeyValue = SymmetricCryptoKey>;
    type Asymmetric: KeyRef<KeyValue = AsymmetricCryptoKey>;
}

/// Just a small derive_like macro that can be used to generate the key reference enums.
/// Example usage:
/// ```rust
/// use bitwarden_crypto::key_refs;
/// key_refs! {
///     #[symmetric]
///     pub enum SymmKeyRef {
///         User,
///         Org(uuid::Uuid),
///         #[local]
///         Local(&'static str),
///     }
///
///     #[asymmetric]
///     pub enum AsymmKeyRef {
///         PrivateKey,
///     }
///     pub Refs => SymmKeyRef, AsymmKeyRef;
/// }
#[macro_export]
macro_rules! key_refs {
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
    $refs_vis:vis $refs_name:ident => $symm_name:ident, $asymm_name:ident;
    ) => {
        $(
            #[derive(std::fmt::Debug, Clone, Copy, std::hash::Hash, Eq, PartialEq, Ord, PartialOrd)]
            $vis enum $name { $(
                $variant  $( ($inner) )?,
            )* }

            impl $crate::KeyRef for $name {
                type KeyValue = key_refs!(@key_type $meta_type);

                fn is_local(&self) -> bool {
                    use $name::*;
                    match self { $(
                        key_refs!(@variant_match $variant $( ( $inner ) )?) =>
                            key_refs!(@variant_value $( $variant_tag )? ),
                    )* }
                }
            }
        )+

        $refs_vis struct $refs_name;
        impl $crate::KeyRefs for $refs_name {
            type Symmetric = $symm_name;
            type Asymmetric = $asymm_name;
        }
    };

    ( @key_type symmetric ) => { $crate::SymmetricCryptoKey };
    ( @key_type asymmetric ) => { $crate::AsymmetricCryptoKey };

    ( @variant_match $variant:ident ( $inner:ty ) ) => { $variant (_) };
    ( @variant_match $variant:ident ) => { $variant };

    ( @variant_value local ) => { true };
    ( @variant_value ) => { false };
}
