use std::{fmt::Display, pin::Pin, str::FromStr};

use bitwarden_encoding::{B64, FromStrVisitor};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePublicKey};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tracing::instrument;
#[cfg(feature = "wasm")]
use wasm_bindgen::convert::FromWasmAbi;

use super::key_encryptable::CryptoKey;
use crate::{
    Pkcs8PrivateKeyBytes, SpkiPublicKeyBytes,
    error::{CryptoError, Result},
};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type PublicKey = Tagged<string, "PublicKey">;
"#;

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for PublicKey {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl FromWasmAbi for PublicKey {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;

        let s = unsafe { String::from_abi(abi) };
        let bytes: Vec<u8> = s.parse::<bitwarden_encoding::B64>().unwrap_throw().into();
        PublicKey::from_der(&SpkiPublicKeyBytes::from(bytes)).unwrap_throw()
    }
}

/// Algorithm / public key encryption scheme used for encryption/decryption.
#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum PublicKeyEncryptionAlgorithm {
    /// RSA with OAEP padding and SHA-1 hashing.
    RsaOaepSha1 = 0,
}

#[derive(Clone, PartialEq)]
pub(crate) enum RawPublicKey {
    RsaOaepSha1(RsaPublicKey),
}

/// Public key of a key pair used in a public key encryption scheme. It is used for
/// encrypting data.
#[derive(Clone, PartialEq)]
pub struct PublicKey {
    inner: RawPublicKey,
}

impl PublicKey {
    pub(crate) fn inner(&self) -> &RawPublicKey {
        &self.inner
    }

    /// Build a public key from the SubjectPublicKeyInfo DER.
    #[instrument(skip_all, err)]
    pub fn from_der(der: &SpkiPublicKeyBytes) -> Result<Self> {
        Ok(PublicKey {
            inner: RawPublicKey::RsaOaepSha1(
                RsaPublicKey::from_public_key_der(der.as_ref())
                    .map_err(|_| CryptoError::InvalidKey)?,
            ),
        })
    }

    /// Makes a SubjectPublicKeyInfo DER serialized version of the public key.
    #[instrument(skip_all, err)]
    pub fn to_der(&self) -> Result<SpkiPublicKeyBytes> {
        use rsa::pkcs8::EncodePublicKey;
        match &self.inner {
            RawPublicKey::RsaOaepSha1(public_key) => Ok(public_key
                .to_public_key_der()
                .map_err(|_| CryptoError::InvalidKey)?
                .as_bytes()
                .to_owned()
                .into()),
        }
    }
}

impl FromStr for PublicKey {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: Vec<u8> = s.parse::<B64>().map_err(|_| ())?.into();
        Self::from_der(&SpkiPublicKeyBytes::from(bytes)).map_err(|_| ())
    }
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.to_der() {
            Ok(der) => write!(f, "{}", B64::from(der.as_ref()).to_string()),
            Err(_) => write!(f, ""),
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let der = self.to_der().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&B64::from(der.as_ref()).to_string())
    }
}

#[derive(Clone)]
pub(crate) enum RawPrivateKey {
    // RsaPrivateKey is not a Copy type so this isn't completely necessary, but
    // to keep the compiler from making stack copies when moving this struct around,
    // we use a Box to keep the values on the heap. We also pin the box to make sure
    // that the contents can't be pulled out of the box and moved
    RsaOaepSha1(Pin<Box<RsaPrivateKey>>),
}

/// Private key of a key pair used in a public key encryption scheme. It is used for
/// decrypting data that was encrypted with the corresponding public key.
#[derive(Clone)]
pub struct PrivateKey {
    inner: RawPrivateKey,
}

// Note that RsaPrivateKey already implements ZeroizeOnDrop, so we don't need to do anything
// We add this assertion to make sure that this is still true in the future
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<RsaPrivateKey>();
};
impl zeroize::ZeroizeOnDrop for PrivateKey {}
impl CryptoKey for PrivateKey {}

impl PrivateKey {
    /// Generate a random PrivateKey (RSA-2048).
    pub fn make(algorithm: PublicKeyEncryptionAlgorithm) -> Self {
        Self::make_internal(algorithm, &mut rand::thread_rng())
    }

    fn make_internal<R: rand::CryptoRng + rand::RngCore>(
        algorithm: PublicKeyEncryptionAlgorithm,
        rng: &mut R,
    ) -> Self {
        match algorithm {
            PublicKeyEncryptionAlgorithm::RsaOaepSha1 => Self {
                inner: RawPrivateKey::RsaOaepSha1(Box::pin(
                    RsaPrivateKey::new(rng, 2048).expect("failed to generate a key"),
                )),
            },
        }
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "dangerous-crypto-debug", instrument(err))]
    #[cfg_attr(not(feature = "dangerous-crypto-debug"), instrument(skip_all, err))]
    pub fn from_pem(pem: &str) -> Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;
        Ok(Self {
            inner: RawPrivateKey::RsaOaepSha1(Box::pin(
                RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| CryptoError::InvalidKey)?,
            )),
        })
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "dangerous-crypto-debug", instrument(err))]
    #[cfg_attr(not(feature = "dangerous-crypto-debug"), instrument(skip_all, err))]
    pub fn from_der(der: &Pkcs8PrivateKeyBytes) -> Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;
        Ok(Self {
            inner: RawPrivateKey::RsaOaepSha1(Box::pin(
                RsaPrivateKey::from_pkcs8_der(der.as_ref()).map_err(|_| CryptoError::InvalidKey)?,
            )),
        })
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "dangerous-crypto-debug", instrument(err))]
    #[cfg_attr(not(feature = "dangerous-crypto-debug"), instrument(skip_all, err))]
    pub fn to_der(&self) -> Result<Pkcs8PrivateKeyBytes> {
        match &self.inner {
            RawPrivateKey::RsaOaepSha1(private_key) => {
                use rsa::pkcs8::EncodePrivateKey;
                Ok(private_key
                    .to_pkcs8_der()
                    .map_err(|_| CryptoError::InvalidKey)?
                    .as_bytes()
                    .to_owned()
                    .into())
            }
        }
    }

    /// Derives the public key corresponding to this private key. This is deterministic
    /// and always derives the same public key.
    pub fn to_public_key(&self) -> PublicKey {
        match &self.inner {
            RawPrivateKey::RsaOaepSha1(private_key) => PublicKey {
                inner: RawPublicKey::RsaOaepSha1(private_key.to_public_key()),
            },
        }
    }

    pub(crate) fn inner(&self) -> &RawPrivateKey {
        &self.inner
    }
}

// We manually implement these to make sure we don't print any sensitive data
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("PrivateKey");
        #[cfg(feature = "dangerous-crypto-debug")]
        match &self.inner {
            RawPrivateKey::RsaOaepSha1(_key) => {
                debug_struct.field("algorithm", &"RsaOaepSha1");
                if let Ok(der) = self.to_der() {
                    debug_struct.field("private_key_der", &der.as_ref());
                }
            }
        }
        debug_struct.finish()
    }
}

#[cfg(test)]
mod tests {

    use bitwarden_encoding::B64;

    use crate::{
        Pkcs8PrivateKeyBytes, PrivateKey, PublicKey, SpkiPublicKeyBytes, SymmetricCryptoKey,
        UnsignedSharedKey,
        content_format::{Bytes, Pkcs8PrivateKeyDerContentFormat},
    };

    #[test]
    fn test_asymmetric_crypto_key() {
        let pem_key_str = "-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDiTQVuzhdygFz5
qv14i+XFDGTnDravzUQT1hPKPGUZOUSZ1gwdNgkWqOIaOnR65BHEnL0sp4bnuiYc
afeK2JAW5Sc8Z7IxBNSuAwhQmuKx3RochMIiuCkI2/p+JvUQoJu6FBNm8OoJ4Cwm
qqHGZESMfnpQDCuDrB3JdJEdXhtmnl0C48sGjOk3WaBMcgGqn8LbJDUlyu1zdqyv
b0waJf0iV4PJm2fkUl7+57D/2TkpbCqURVnZK1FFIEg8mr6FzSN1F2pOfktkNYZw
P7MSNR7o81CkRSCMr7EkIVa+MZYMBx106BMK7FXgWB7nbSpsWKxBk7ZDHkID2fam
rEcVtrzDAgMBAAECggEBAKwq9OssGGKgjhvUnyrLJHAZ0dqIMyzk+dotkLjX4gKi
szJmyqiep6N5sStLNbsZMPtoU/RZMCW0VbJgXFhiEp2YkZU/Py5UAoqw++53J+kx
0d/IkPphKbb3xUec0+1mg5O6GljDCQuiZXS1dIa/WfeZcezclW6Dz9WovY6ePjJ+
8vEBR1icbNKzyeINd6MtPtpcgQPHtDwHvhPyUDbKDYGbLvjh9nui8h4+ZUlXKuVR
jB0ChxiKV1xJRjkrEVoulOOicd5r597WfB2ghax3pvRZ4MdXemCXm3gQYqPVKach
vGU+1cPQR/MBJZpxT+EZA97xwtFS3gqwbxJaNFcoE8ECgYEA9OaeYZhQPDo485tI
1u/Z7L/3PNape9hBQIXoW7+MgcQ5NiWqYh8Jnj43EIYa0wM/ECQINr1Za8Q5e6KR
J30FcU+kfyjuQ0jeXdNELGU/fx5XXNg/vV8GevHwxRlwzqZTCg6UExUZzbYEQqd7
l+wPyETGeua5xCEywA1nX/D101kCgYEA7I6aMFjhEjO71RmzNhqjKJt6DOghoOfQ
TjhaaanNEhLYSbenFz1mlb21mW67ulmz162saKdIYLxQNJIP8ZPmxh4ummOJI8w9
ClHfo8WuCI2hCjJ19xbQJocSbTA5aJg6lA1IDVZMDbQwsnAByPRGpaLHBT/Q9Bye
KvCMB+9amXsCgYEAx65yXSkP4sumPBrVHUub6MntERIGRxBgw/drKcPZEMWp0FiN
wEuGUBxyUWrG3F69QK/gcqGZE6F/LSu0JvptQaKqgXQiMYJsrRvhbkFvsHpQyUcZ
UZL1ebFjm5HOxPAgrQaN/bEqxOwwNRjSUWEMzUImg3c06JIZCzbinvudtKECgYEA
kY3JF/iIPI/yglP27lKDlCfeeHSYxI3+oTKRhzSAxx8rUGidenJAXeDGDauR/T7W
pt3pGNfddBBK9Z3uC4Iq3DqUCFE4f/taj7ADAJ1Q0Vh7/28/IJM77ojr8J1cpZwN
Zy2o6PPxhfkagaDjqEeN9Lrs5LD4nEvDkr5CG1vOjmMCgYEAvIBFKRm31NyF8jLi
CVuPwC5PzrW5iThDmsWTaXFpB3esUsbICO2pEz872oeQS+Em4GO5vXUlpbbFPzup
PFhA8iMJ8TAvemhvc7oM0OZqpU6p3K4seHf6BkwLxumoA3vDJfovu9RuXVcJVOnf
DnqOsltgPomWZ7xVfMkm9niL2OA=
-----END PRIVATE KEY-----";

        let der_key: B64 = "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQDiTQVuzhdygFz5qv14i+XFDGTnDravzUQT1hPKPGUZOUSZ1gwdNgkWqOIaOnR65BHEnL0sp4bnuiYcafeK2JAW5Sc8Z7IxBNSuAwhQmuKx3RochMIiuCkI2/p+JvUQoJu6FBNm8OoJ4CwmqqHGZESMfnpQDCuDrB3JdJEdXhtmnl0C48sGjOk3WaBMcgGqn8LbJDUlyu1zdqyvb0waJf0iV4PJm2fkUl7+57D/2TkpbCqURVnZK1FFIEg8mr6FzSN1F2pOfktkNYZwP7MSNR7o81CkRSCMr7EkIVa+MZYMBx106BMK7FXgWB7nbSpsWKxBk7ZDHkID2famrEcVtrzDAgMBAAECggEBAKwq9OssGGKgjhvUnyrLJHAZ0dqIMyzk+dotkLjX4gKiszJmyqiep6N5sStLNbsZMPtoU/RZMCW0VbJgXFhiEp2YkZU/Py5UAoqw++53J+kx0d/IkPphKbb3xUec0+1mg5O6GljDCQuiZXS1dIa/WfeZcezclW6Dz9WovY6ePjJ+8vEBR1icbNKzyeINd6MtPtpcgQPHtDwHvhPyUDbKDYGbLvjh9nui8h4+ZUlXKuVRjB0ChxiKV1xJRjkrEVoulOOicd5r597WfB2ghax3pvRZ4MdXemCXm3gQYqPVKachvGU+1cPQR/MBJZpxT+EZA97xwtFS3gqwbxJaNFcoE8ECgYEA9OaeYZhQPDo485tI1u/Z7L/3PNape9hBQIXoW7+MgcQ5NiWqYh8Jnj43EIYa0wM/ECQINr1Za8Q5e6KRJ30FcU+kfyjuQ0jeXdNELGU/fx5XXNg/vV8GevHwxRlwzqZTCg6UExUZzbYEQqd7l+wPyETGeua5xCEywA1nX/D101kCgYEA7I6aMFjhEjO71RmzNhqjKJt6DOghoOfQTjhaaanNEhLYSbenFz1mlb21mW67ulmz162saKdIYLxQNJIP8ZPmxh4ummOJI8w9ClHfo8WuCI2hCjJ19xbQJocSbTA5aJg6lA1IDVZMDbQwsnAByPRGpaLHBT/Q9ByeKvCMB+9amXsCgYEAx65yXSkP4sumPBrVHUub6MntERIGRxBgw/drKcPZEMWp0FiNwEuGUBxyUWrG3F69QK/gcqGZE6F/LSu0JvptQaKqgXQiMYJsrRvhbkFvsHpQyUcZUZL1ebFjm5HOxPAgrQaN/bEqxOwwNRjSUWEMzUImg3c06JIZCzbinvudtKECgYEAkY3JF/iIPI/yglP27lKDlCfeeHSYxI3+oTKRhzSAxx8rUGidenJAXeDGDauR/T7Wpt3pGNfddBBK9Z3uC4Iq3DqUCFE4f/taj7ADAJ1Q0Vh7/28/IJM77ojr8J1cpZwNZy2o6PPxhfkagaDjqEeN9Lrs5LD4nEvDkr5CG1vOjmMCgYEAvIBFKRm31NyF8jLiCVuPwC5PzrW5iThDmsWTaXFpB3esUsbICO2pEz872oeQS+Em4GO5vXUlpbbFPzupPFhA8iMJ8TAvemhvc7oM0OZqpU6p3K4seHf6BkwLxumoA3vDJfovu9RuXVcJVOnfDnqOsltgPomWZ7xVfMkm9niL2OA=".parse().unwrap();
        let der_key_vec: Vec<u8> = der_key.into();

        // Load the two different formats and check they are the same key
        let pem_key = PrivateKey::from_pem(pem_key_str).unwrap();
        let der_key = PrivateKey::from_der(&Bytes::<Pkcs8PrivateKeyDerContentFormat>::from(
            der_key_vec.clone(),
        ))
        .unwrap();
        assert_eq!(pem_key.to_der().unwrap(), der_key.to_der().unwrap());

        // Check that the keys can be converted back to DER

        assert_eq!(der_key.to_der().unwrap().to_vec(), der_key_vec.clone());
        assert_eq!(pem_key.to_der().unwrap().to_vec(), der_key_vec);
    }

    #[test]
    fn test_encrypt_public_decrypt_private() {
        let private_key: B64 = concat!(
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu9xd+vmkIPoqH",
            "NejsFZzkd1xuCn1TqGTT7ANhAEnbI/yaVt3caI30kwUC2WIToFpNgu7Ej0x2TteY",
            "OgrLrdcC4jy1SifmKYv/v3ZZxrd/eqttmH2k588panseRwHK3LVk7xA+URhQ/bjL",
            "gPM59V0uR1l+z1fmooeJPFz5WSXNObc9Jqnh45FND+U/UYHXTLSomTn7jgZFxJBK",
            "veS7q6Lat7wAnYZCF2dnPmhZoJv+SKPltA8HAGsgQGWBF1p5qxV1HrAUk8kBBnG2",
            "paj0w8p5UM6RpDdCuvKH7j1LiuWffn3b9Z4dgzmE7jsMmvzoQtypzIKaSxhqzvFO",
            "od9V8dJdAgMBAAECggEAGGIYjOIB1rOKkDHP4ljXutI0mCRPl3FMDemiBeppoIfZ",
            "G/Q3qpAKmndDt0Quwh/yfcNdvZhf1kwCCTWri/uPz5fSUIyDV3TaTRu0ZWoHaBVj",
            "Hxylg+4HRZUQj+Vi50/PWr/jQmAAVMcrMfcoTl82q2ynmP/R1vM3EsXOCjTliv5B",
            "XlMPRjj/9PDBH0dnnVcAPDOpflzOTL2f4HTFEMlmg9/tZBnd96J/cmfhjAv9XpFL",
            "FBAFZzs5pz0rwCNSR8QZNonnK7pngVUlGDLORK58y84tGmxZhGdne3CtCWey/sJ4",
            "7QF0Pe8YqWBU56926IY6DcSVBuQGZ6vMCNlU7J8D2QKBgQDXyh3t2TicM/n1QBLk",
            "zLoGmVUmxUGziHgl2dnJiGDtyOAU3+yCorPgFaCie29s5qm4b0YEGxUxPIrRrEro",
            "h0FfKn9xmr8CdmTPTcjJW1+M7bxxq7oBoU/QzKXgIHlpeCjjnvPJt0PcNkNTjCXv",
            "shsrINh2rENoe/x79eEfM/N5eQKBgQDPkYSmYyALoNq8zq0A4BdR+F5lb5Fj5jBH",
            "Jk68l6Uti+0hRbJ2d1tQTLkU+eCPQLGBl6fuc1i4K5FV7v14jWtRPdD7wxrkRi3j",
            "ilqQwLBOU6Bj3FK4DvlLF+iYTuBWj2/KcxflXECmsjitKHLK6H7kFEiuJql+NAHU",
            "U9EFXepLBQKBgQDQ+HCnZ1bFHiiP8m7Zl9EGlvK5SwlnPV9s+F1KJ4IGhCNM09UM",
            "ZVfgR9F5yCONyIrPiyK40ylgtwqQJlOcf281I8irUXpsfg7+Gou5Q31y0r9NLUpC",
            "Td8niyePtqMdGjouxD2+OHXFCd+FRxFt4IMi7vnxYr0csAVAXkqWlw7PsQKBgH/G",
            "/PnQm7GM3BrOwAGB8dksJDAddkshMScblezTDYP0V43b8firkTLliCo5iNum357/",
            "VQmdSEhXyag07yR/Kklg3H2fpbZQ3X7tdMMXW3FcWagfwWw9C4oGtdDM/Z1Lv23J",
            "XDR9je8QV4OBGul+Jl8RfYx3kG94ZIfo8Qt0vP5hAoGARjAzdCGYz42NwaUk8n94",
            "W2RuKHtTV9vtjaAbfPFbZoGkT7sXNJVlrA0C+9f+H9rOTM3mX59KrjmLVzde4Vhs",
            "avWMShuK4vpAiDQLU7GyABvi5CR6Ld+AT+LSzxHhVe0ASOQPNCA2SOz3RQvgPi7R",
            "GDgRMUB6cL3IRVzcR0dC6cY=",
        )
        .parse()
        .unwrap();

        let public_key: B64 = concat!(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvcXfr5pCD6KhzXo7BWc",
            "5Hdcbgp9U6hk0+wDYQBJ2yP8mlbd3GiN9JMFAtliE6BaTYLuxI9Mdk7XmDoKy63X",
            "AuI8tUon5imL/792Wca3f3qrbZh9pOfPKWp7HkcByty1ZO8QPlEYUP24y4DzOfVd",
            "LkdZfs9X5qKHiTxc+VklzTm3PSap4eORTQ/lP1GB10y0qJk5+44GRcSQSr3ku6ui",
            "2re8AJ2GQhdnZz5oWaCb/kij5bQPBwBrIEBlgRdaeasVdR6wFJPJAQZxtqWo9MPK",
            "eVDOkaQ3Qrryh+49S4rln3592/WeHYM5hO47DJr86ELcqcyCmksYas7xTqHfVfHS",
            "XQIDAQAB",
        )
        .parse()
        .unwrap();

        let private_key = Pkcs8PrivateKeyBytes::from(private_key.as_bytes());
        let private_key = PrivateKey::from_der(&private_key).unwrap();
        let public_key = PublicKey::from_der(&SpkiPublicKeyBytes::from(&public_key)).unwrap();

        let raw_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();
        #[expect(deprecated)]
        let encrypted = UnsignedSharedKey::encapsulate_key_unsigned(&raw_key, &public_key).unwrap();
        #[expect(deprecated)]
        let decrypted = encrypted.decapsulate_key_unsigned(&private_key).unwrap();

        assert_eq!(raw_key, decrypted);
    }

    #[test]
    fn test_asymmetric_public_crypto_key_from_str() {
        let public_key_b64 = concat!(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvcXfr5pCD6KhzXo7BWc",
            "5Hdcbgp9U6hk0+wDYQBJ2yP8mlbd3GiN9JMFAtliE6BaTYLuxI9Mdk7XmDoKy63X",
            "AuI8tUon5imL/792Wca3f3qrbZh9pOfPKWp7HkcByty1ZO8QPlEYUP24y4DzOfVd",
            "LkdZfs9X5qKHiTxc+VklzTm3PSap4eORTQ/lP1GB10y0qJk5+44GRcSQSr3ku6ui",
            "2re8AJ2GQhdnZz5oWaCb/kij5bQPBwBrIEBlgRdaeasVdR6wFJPJAQZxtqWo9MPK",
            "eVDOkaQ3Qrryh+49S4rln3592/WeHYM5hO47DJr86ELcqcyCmksYas7xTqHfVfHS",
            "XQIDAQAB",
        );

        // Test FromStr
        let parsed_key: PublicKey = public_key_b64.parse().expect("should parse");

        // Verify the key can be converted back to DER and then to B64
        let der = parsed_key.to_der().expect("should convert to DER");
        let b64_str = B64::from(der.as_ref()).to_string();
        assert_eq!(b64_str, public_key_b64);
    }

    #[test]
    fn test_asymmetric_public_crypto_key_from_str_invalid() {
        // Invalid base64
        let result: Result<PublicKey, _> = "not-valid-base64!!!".parse();
        assert!(result.is_err());

        // Valid base64 but invalid key data
        let result: Result<PublicKey, _> = "aGVsbG8gd29ybGQ=".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_asymmetric_public_crypto_key_serialize_deserialize() {
        let public_key_b64 = concat!(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArvcXfr5pCD6KhzXo7BWc",
            "5Hdcbgp9U6hk0+wDYQBJ2yP8mlbd3GiN9JMFAtliE6BaTYLuxI9Mdk7XmDoKy63X",
            "AuI8tUon5imL/792Wca3f3qrbZh9pOfPKWp7HkcByty1ZO8QPlEYUP24y4DzOfVd",
            "LkdZfs9X5qKHiTxc+VklzTm3PSap4eORTQ/lP1GB10y0qJk5+44GRcSQSr3ku6ui",
            "2re8AJ2GQhdnZz5oWaCb/kij5bQPBwBrIEBlgRdaeasVdR6wFJPJAQZxtqWo9MPK",
            "eVDOkaQ3Qrryh+49S4rln3592/WeHYM5hO47DJr86ELcqcyCmksYas7xTqHfVfHS",
            "XQIDAQAB",
        );

        // Parse the key
        let key: PublicKey = public_key_b64.parse().expect("should parse");

        // Serialize to JSON
        let serialized = serde_json::to_string(&key).expect("should serialize");
        assert_eq!(serialized, format!("\"{}\"", public_key_b64));

        // Deserialize from JSON
        let deserialized: PublicKey =
            serde_json::from_str(&serialized).expect("should deserialize");

        // Verify the keys are equal by comparing their DER representations
        assert_eq!(
            key.to_der().expect("should convert to DER"),
            deserialized.to_der().expect("should convert to DER")
        );
    }

    #[test]
    fn test_asymmetric_public_crypto_key_deserialize_invalid() {
        // Invalid base64
        let result: Result<PublicKey, _> = serde_json::from_str("\"not-valid-base64!!!\"");
        assert!(result.is_err());

        // Valid base64 but invalid key data
        let result: Result<PublicKey, _> = serde_json::from_str("\"aGVsbG8gd29ybGQ=\"");
        assert!(result.is_err());

        // Not a string
        let result: Result<PublicKey, _> = serde_json::from_str("123");
        assert!(result.is_err());
    }
}
