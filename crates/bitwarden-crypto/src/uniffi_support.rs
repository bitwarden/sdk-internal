use std::{num::NonZeroU32, str::FromStr};

use crate::{AsymmetricEncString, CryptoError, EncString, EncryptionContext, NoContext, UniffiCustomTypeConverter};

uniffi::custom_type!(NonZeroU32, u32);

impl UniffiCustomTypeConverter for NonZeroU32 {
    type Builtin = u32;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Self::new(val).ok_or(CryptoError::ZeroNumber.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.get()
    }
}

type NoContextEncString = EncString<NoContext>;

uniffi::custom_type!(NoContextEncString, String);

impl<T: EncryptionContext> UniffiCustomTypeConverter for EncString<T> {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        val.parse().map_err(|e: CryptoError| e.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}

uniffi::custom_type!(AsymmetricEncString, String);

impl UniffiCustomTypeConverter for AsymmetricEncString {
    type Builtin = String;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Self::from_str(&val).map_err(|e| e.into())
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.to_string()
    }
}
