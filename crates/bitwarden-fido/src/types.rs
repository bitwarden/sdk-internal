use std::{borrow::Cow, collections::HashMap};

use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{CryptoError, KeyStoreContext};
use bitwarden_encoding::{B64Url, NotB64UrlEncodedError};
use bitwarden_vault::{CipherListView, CipherListViewType, CipherView, LoginListView};
use passkey::types::{
    Bytes,
    crypto::sha256,
    ctap2::{
        extensions::{AuthenticatorPrfInputs, AuthenticatorPrfValues},
        get_assertion, make_credential,
    },
    webauthn::UserVerificationRequirement,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    InvalidGuidError, SelectedCredential, UnknownEnumError, Verification,
    get_enum_from_string_name, string_to_guid_bytes,
};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Fido2CredentialAutofillView {
    pub credential_id: Vec<u8>,
    pub cipher_id: uuid::Uuid,
    pub rp_id: String,
    pub user_name_for_ui: Option<String>,
    pub user_handle: Vec<u8>,
    /// Indicates if this credential uses a signature counter (legacy passkeys).
    /// When true, mobile clients must sync before authentication to ensure
    /// counter values are current. Modern passkeys (counter = 0) can work offline.
    pub has_counter: bool,
}

trait NoneWhitespace {
    /// Convert only whitespace to None
    fn none_whitespace(&self) -> Option<String>;
}

impl NoneWhitespace for String {
    fn none_whitespace(&self) -> Option<String> {
        match self.trim() {
            "" => None,
            s => Some(s.to_owned()),
        }
    }
}

impl NoneWhitespace for Option<String> {
    fn none_whitespace(&self) -> Option<String> {
        self.as_ref().and_then(|s| s.none_whitespace())
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum Fido2CredentialAutofillViewError {
    #[error("Autofill credentials can only be created from existing ciphers that have a cipher id")]
    MissingCipherId,

    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Base64Decode(#[from] NotB64UrlEncodedError),
}

impl Fido2CredentialAutofillView {
    #[allow(missing_docs)]
    pub fn from_cipher_view(
        cipher: &CipherView,
        ctx: &mut KeyStoreContext<KeyIds>,
        key_id: Option<SymmetricKeyId>,
    ) -> Result<Vec<Fido2CredentialAutofillView>, Fido2CredentialAutofillViewError> {
        let credentials = cipher.decrypt_fido2_credentials(ctx, key_id)?;

        credentials
            .iter()
            .filter_map(|c| -> Option<Result<_, Fido2CredentialAutofillViewError>> {
                c.user_handle
                    .as_ref()
                    .map(|u| B64Url::try_from(u.as_str()))
                    .map(|user_handle| {
                        Ok(Fido2CredentialAutofillView {
                            credential_id: string_to_guid_bytes(&c.credential_id)?,
                            cipher_id: cipher
                                .id
                                .ok_or(Fido2CredentialAutofillViewError::MissingCipherId)?
                                .into(),
                            rp_id: c.rp_id.clone(),
                            user_handle: user_handle?.into_bytes(),
                            user_name_for_ui: c
                                .user_name
                                .none_whitespace()
                                .or(c.user_display_name.none_whitespace())
                                .or(cipher
                                    .login
                                    .as_ref()
                                    .and_then(|l| l.username.none_whitespace()))
                                .or(cipher.name.none_whitespace()),
                            has_counter: Self::has_signature_counter(&c.counter),
                        })
                    })
            })
            .collect()
    }

    #[allow(missing_docs)]
    pub fn from_cipher_list_view(
        cipher: &CipherListView,
    ) -> Result<Vec<Fido2CredentialAutofillView>, Fido2CredentialAutofillViewError> {
        match &cipher.r#type {
            CipherListViewType::Login(LoginListView {
                fido2_credentials: Some(fido2_credentials),
                username,
                ..
            }) => fido2_credentials
                .iter()
                .filter_map(|c| -> Option<Result<_, Fido2CredentialAutofillViewError>> {
                    c.user_handle
                        .as_ref()
                        .map(|u| B64Url::try_from(u.as_str()))
                        .map(|user_handle| {
                            Ok(Fido2CredentialAutofillView {
                                credential_id: string_to_guid_bytes(&c.credential_id)?,
                                cipher_id: cipher
                                    .id
                                    .ok_or(Fido2CredentialAutofillViewError::MissingCipherId)?
                                    .into(),
                                rp_id: c.rp_id.clone(),
                                user_handle: user_handle?.into_bytes(),
                                user_name_for_ui: c
                                    .user_name
                                    .none_whitespace()
                                    .or(c.user_display_name.none_whitespace())
                                    .or(username.none_whitespace())
                                    .or(cipher.name.none_whitespace()),
                                has_counter: Self::has_signature_counter(&c.counter),
                            })
                        })
                })
                .collect(),
            _ => Ok(vec![]),
        }
    }

    fn has_signature_counter(str: &String) -> bool {
        str.none_whitespace()
            .is_some_and(|counter_str| counter_str.parse::<u64>().is_ok_and(|counter| counter > 0))
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: Option<String>,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub display_name: String,
    pub name: String,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialParameters {
    pub ty: String,
    pub alg: i64,
}

#[derive(Debug, Error)]
pub enum PublicKeyCredentialParametersError {
    #[error("Invalid algorithm")]
    InvalidAlgorithm,

    #[error("Unknown type")]
    UnknownEnum(#[from] UnknownEnumError),
}

impl TryFrom<PublicKeyCredentialParameters>
    for passkey::types::webauthn::PublicKeyCredentialParameters
{
    type Error = PublicKeyCredentialParametersError;

    fn try_from(value: PublicKeyCredentialParameters) -> Result<Self, Self::Error> {
        use coset::iana::EnumI64;
        Ok(Self {
            ty: get_enum_from_string_name(&value.ty)?,
            alg: coset::iana::Algorithm::from_i64(value.alg)
                .ok_or(PublicKeyCredentialParametersError::InvalidAlgorithm)?,
        })
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialDescriptor {
    pub ty: String,
    pub id: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

impl TryFrom<PublicKeyCredentialDescriptor>
    for passkey::types::webauthn::PublicKeyCredentialDescriptor
{
    type Error = UnknownEnumError;

    fn try_from(value: PublicKeyCredentialDescriptor) -> Result<Self, Self::Error> {
        Ok(Self {
            ty: get_enum_from_string_name(&value.ty)?,
            id: value.id.into(),
            transports: value
                .transports
                .map(|tt| {
                    tt.into_iter()
                        .map(|t| get_enum_from_string_name(&t))
                        .collect::<Result<Vec<_>, Self::Error>>()
                })
                .transpose()?,
        })
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MakeCredentialRequest {
    pub client_data_hash: Vec<u8>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub options: Options,
    pub extensions: Option<MakeCredentialExtensionsInput>,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MakeCredentialResult {
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub credential_id: Vec<u8>,
    /// Mix of CTAP unsigned extension output and WebAuthn client extensions
    /// output returned by the authenticator
    pub extensions: MakeCredentialExtensionsOutput,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialExtensionsInput {
    prf: Option<MakeCredentialPrfInput>,
}

impl From<MakeCredentialExtensionsInput>
    for passkey::types::ctap2::make_credential::ExtensionInputs
{
    fn from(value: MakeCredentialExtensionsInput) -> Self {
        Self {
            hmac_secret: None,
            hmac_secret_mc: None,
            prf: value.prf.map(AuthenticatorPrfInputs::from),
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialExtensionsOutput {
    pub prf: Option<MakeCredentialPrfOutput>,
}

impl From<Option<make_credential::UnsignedExtensionOutputs>> for MakeCredentialExtensionsOutput {
    fn from(value: Option<make_credential::UnsignedExtensionOutputs>) -> Self {
        if let Some(ext) = value {
            MakeCredentialExtensionsOutput::from(ext)
        } else {
            MakeCredentialExtensionsOutput { prf: None }
        }
    }
}

impl From<make_credential::UnsignedExtensionOutputs> for MakeCredentialExtensionsOutput {
    fn from(value: make_credential::UnsignedExtensionOutputs) -> Self {
        let prf = value.prf.map(|prf| MakeCredentialPrfOutput {
            enabled: prf.enabled,
            results: prf.results.map(|v| PrfValues {
                first: v.first.to_vec(),
                second: v.second.map(|second| second.to_vec()),
            }),
        });
        MakeCredentialExtensionsOutput { prf }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialPrfInput {
    eval: Option<PrfValues>,
}

impl From<MakeCredentialPrfInput> for AuthenticatorPrfInputs {
    fn from(value: MakeCredentialPrfInput) -> Self {
        Self {
            eval: value.eval.map(AuthenticatorPrfValues::from),
            eval_by_credential: None,
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialPrfOutput {
    pub enabled: bool,
    pub results: Option<PrfValues>,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub options: Options,
    pub extensions: Option<GetAssertionExtensionsInput>,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct Options {
    pub rk: bool,
    pub uv: UV,
}

impl From<super::CheckUserOptions> for Options {
    fn from(value: super::CheckUserOptions) -> Self {
        Self {
            rk: value.require_presence,
            uv: value.require_verification.into(),
        }
    }
}

impl From<Options> for super::CheckUserOptions {
    fn from(value: Options) -> Self {
        Self {
            require_presence: value.rk,
            require_verification: value.uv.into(),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Copy)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UV {
    Discouraged,
    Preferred,
    Required,
}

impl From<UV> for Verification {
    fn from(value: UV) -> Self {
        match value {
            UV::Discouraged => Verification::Discouraged,
            UV::Preferred => Verification::Preferred,
            UV::Required => Verification::Required,
        }
    }
}

impl From<Verification> for UV {
    fn from(value: Verification) -> Self {
        match value {
            Verification::Discouraged => UV::Discouraged,
            Verification::Preferred => UV::Preferred,
            Verification::Required => UV::Required,
        }
    }
}

impl From<UserVerificationRequirement> for UV {
    fn from(value: UserVerificationRequirement) -> Self {
        match value {
            UserVerificationRequirement::Discouraged => UV::Discouraged,
            UserVerificationRequirement::Preferred => UV::Preferred,
            UserVerificationRequirement::Required => UV::Required,
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GetAssertionResult {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,

    pub selected_credential: SelectedCredential,
    /// Mix of CTAP unsigned extension output and WebAuthn client extension output.
    /// Signed extensions can be retrieved from authenticator data.
    pub extensions: GetAssertionExtensionsOutput,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionExtensionsInput {
    prf: Option<GetAssertionPrfInput>,
}

impl From<GetAssertionExtensionsInput> for get_assertion::ExtensionInputs {
    fn from(value: GetAssertionExtensionsInput) -> Self {
        Self {
            hmac_secret: None,
            prf: value.prf.map(AuthenticatorPrfInputs::from),
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionExtensionsOutput {
    pub prf: Option<GetAssertionPrfOutput>,
}

impl From<Option<get_assertion::UnsignedExtensionOutputs>> for GetAssertionExtensionsOutput {
    fn from(value: Option<get_assertion::UnsignedExtensionOutputs>) -> Self {
        if let Some(value) = value {
            value.into()
        } else {
            Self { prf: None }
        }
    }
}

impl From<get_assertion::UnsignedExtensionOutputs> for GetAssertionExtensionsOutput {
    fn from(value: get_assertion::UnsignedExtensionOutputs) -> Self {
        let prf = value.prf.map(|prf| GetAssertionPrfOutput {
            results: PrfValues {
                first: prf.results.first.to_vec(),
                second: prf.results.second.map(|second| second.to_vec()),
            },
        });
        GetAssertionExtensionsOutput { prf }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionPrfInput {
    eval: Option<PrfValues>,
    eval_by_credential: Option<HashMap<Vec<u8>, PrfValues>>,
}

impl From<GetAssertionPrfInput> for AuthenticatorPrfInputs {
    fn from(value: GetAssertionPrfInput) -> Self {
        let eval_by_credential = if let Some(values) = value.eval_by_credential {
            let map: HashMap<Bytes, AuthenticatorPrfValues> = values
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            Some(map)
        } else {
            None
        };
        Self {
            eval: value.eval.map(AuthenticatorPrfValues::from),
            eval_by_credential,
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionPrfOutput {
    pub results: PrfValues,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum ClientData {
    DefaultWithExtraData { android_package_name: String },
    DefaultWithCustomHash { hash: Vec<u8> },
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct AndroidClientData {
    android_package_name: String,
}

impl passkey::client::ClientData<Option<AndroidClientData>> for ClientData {
    fn extra_client_data(&self) -> Option<AndroidClientData> {
        match self {
            ClientData::DefaultWithExtraData {
                android_package_name,
            } => Some(AndroidClientData {
                android_package_name: android_package_name.clone(),
            }),
            ClientData::DefaultWithCustomHash { .. } => None,
        }
    }

    fn client_data_hash(&self) -> Option<Vec<u8>> {
        match self {
            ClientData::DefaultWithExtraData { .. } => None,
            ClientData::DefaultWithCustomHash { hash } => Some(hash.clone()),
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct PrfValues {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

impl From<PrfValues> for AuthenticatorPrfValues {
    fn from(value: PrfValues) -> Self {
        // passkey-rs expects the salt to be hashed already according to
        // WebAuthn PRF extension client processing rules.
        let prefix = b"WebAuthn PRF\0".as_slice();
        let first = sha256(&[prefix, value.first.as_ref()].concat());
        let second = value
            .second
            .map(|second| sha256(&[prefix, second.as_ref()].concat()));
        Self { first, second }
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ClientExtensionResults {
    pub cred_props: Option<CredPropsResult>,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CredPropsResult {
    pub rk: Option<bool>,
}

impl From<passkey::types::webauthn::CredentialPropertiesOutput> for CredPropsResult {
    fn from(value: passkey::types::webauthn::CredentialPropertiesOutput) -> Self {
        Self {
            rk: value.discoverable,
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialAuthenticatorAttestationResponse {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub ty: String,
    pub authenticator_attachment: Option<String>,
    pub client_extension_results: ClientExtensionResults,
    pub response: AuthenticatorAttestationResponse,
    pub selected_credential: SelectedCredential,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    pub public_key_algorithm: i64,
    pub attestation_object: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialAuthenticatorAssertionResponse {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub ty: String,
    pub authenticator_attachment: Option<String>,
    pub client_extension_results: ClientExtensionResults,
    pub response: AuthenticatorAssertionResponse,
    pub selected_credential: SelectedCredential,
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

#[derive(Debug, Error)]
#[error("Invalid origin: {0}")]
pub struct InvalidOriginError(String);

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// An Unverified asset link.
pub struct UnverifiedAssetLink {
    /// Application package name.
    package_name: String,
    /// Fingerprint to compare.
    sha256_cert_fingerprint: String,
    /// Host to lookup the well known asset link.
    host: String,
    /// When sourced from the application statement list or parsed from host for passkeys.
    /// Will be generated from `host` if not provided.
    asset_link_url: Option<String>,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
/// The origin of a WebAuthn request.
pub enum Origin {
    /// A Url, meant for a request in the web browser.
    Web(String),
    /// An android digital asset fingerprint.
    /// Meant for a request coming from an android application.
    Android(UnverifiedAssetLink),
}

impl TryFrom<Origin> for passkey::client::Origin<'_> {
    type Error = InvalidOriginError;

    fn try_from(value: Origin) -> Result<Self, Self::Error> {
        Ok(match value {
            Origin::Web(url) => {
                let url = Url::parse(&url).map_err(|e| InvalidOriginError(format!("{e}")))?;
                passkey::client::Origin::Web(Cow::Owned(url))
            }
            Origin::Android(link) => passkey::client::Origin::Android(link.try_into()?),
        })
    }
}

impl TryFrom<UnverifiedAssetLink> for passkey::client::UnverifiedAssetLink<'_> {
    type Error = InvalidOriginError;

    fn try_from(value: UnverifiedAssetLink) -> Result<Self, Self::Error> {
        let asset_link_url = {
            let url = value
                .asset_link_url
                .unwrap_or_else(|| format!("https://{}/.well-known/assetlinks.json", value.host));
            Url::parse(&url).map_err(|e| InvalidOriginError(e.to_string()))?
        };

        passkey::client::UnverifiedAssetLink::new(
            Cow::from(value.package_name),
            value.sha256_cert_fingerprint.as_str(),
            Cow::from(value.host),
            asset_link_url,
        )
        .map_err(|e| InvalidOriginError(format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use passkey::types::ctap2::{
        extensions::{
            AuthenticatorPrfGetOutputs, AuthenticatorPrfMakeOutputs, AuthenticatorPrfValues,
        },
        get_assertion, make_credential,
    };
    use serde::{Deserialize, Serialize};

    use super::AndroidClientData;
    use crate::types::{
        GetAssertionExtensionsInput, GetAssertionExtensionsOutput, GetAssertionPrfInput,
        MakeCredentialExtensionsInput, MakeCredentialExtensionsOutput, MakeCredentialPrfInput,
        PrfValues,
    };

    // This is a stripped down of the passkey-rs implementation, to test the
    // serialization of the `ClientData` enum, and to make sure that () and None
    // are serialized the same way when going through #[serde(flatten)].
    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CollectedClientData<E = ()>
    where
        E: Serialize,
    {
        pub origin: String,

        #[serde(flatten)]
        pub extra_data: E,
    }

    #[test]
    fn test_serialize_unit_data() {
        let data = CollectedClientData {
            origin: "https://example.com".to_owned(),
            extra_data: (),
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#"{"origin":"https://example.com"}"#);
    }

    #[test]
    fn test_serialize_none_data() {
        let data = CollectedClientData {
            origin: "https://example.com".to_owned(),
            extra_data: Option::<AndroidClientData>::None,
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(serialized, r#"{"origin":"https://example.com"}"#);
    }

    #[test]
    fn test_serialize_android_data() {
        let data = CollectedClientData {
            origin: "https://example.com".to_owned(),
            extra_data: Some(AndroidClientData {
                android_package_name: "com.example.app".to_owned(),
            }),
        };

        let serialized = serde_json::to_string(&data).unwrap();
        assert_eq!(
            serialized,
            r#"{"origin":"https://example.com","androidPackageName":"com.example.app"}"#
        );
    }

    #[test]
    fn test_transform_make_credential_extension_input() {
        let salt1 = b"salt1".to_vec();
        let salt2 = b"salt2".to_vec();
        let input = MakeCredentialExtensionsInput {
            prf: Some(MakeCredentialPrfInput {
                eval: Some(PrfValues {
                    first: salt1.clone(),
                    second: Some(salt2.clone()),
                }),
            }),
        };
        let transformed = make_credential::ExtensionInputs::from(input);
        // SHA-256(UTF-8("WebAuthn PRF") || 0x00 || salt1)
        let hashed_first = [
            0x2A, 0x19, 0x90, 0xF9, 0xC9, 0xBB, 0xFE, 0x1B, 0xBF, 0x56, 0xAB, 0xEE, 0x2B, 0x5A,
            0x0F, 0x59, 0xBE, 0x5F, 0x63, 0x3A, 0x35, 0xC2, 0xA5, 0xF0, 0x7D, 0x85, 0x53, 0x3E,
            0xEE, 0xCB, 0xDD, 0x3C,
        ];
        assert_eq!(
            hashed_first,
            transformed
                .prf
                .as_ref()
                .unwrap()
                .eval
                .as_ref()
                .unwrap()
                .first
        );
        // SHA-256(UTF-8("WebAuthn PRF") || 0x00 || salt2)
        let hashed_second = [
            0xA6, 0x42, 0xFA, 0x8B, 0x6E, 0xAC, 0x68, 0xD3, 0x73, 0xCF, 0x08, 0xEA, 0xC8, 0x5E,
            0x1D, 0x62, 0x9B, 0x50, 0x10, 0x6D, 0x60, 0xEB, 0x92, 0x48, 0xEC, 0xB6, 0x54, 0xE2,
            0x94, 0x9A, 0xDD, 0x65,
        ];
        assert_eq!(
            hashed_second,
            transformed.prf.unwrap().eval.unwrap().second.unwrap()
        );
    }

    #[test]
    fn test_transform_make_credential_extension_output() {
        let prf1: Vec<u8> = (0..32).collect();
        let output = make_credential::UnsignedExtensionOutputs {
            prf: Some(AuthenticatorPrfMakeOutputs {
                enabled: true,
                results: Some(AuthenticatorPrfValues {
                    first: prf1.clone().try_into().unwrap(),
                    second: None,
                }),
            }),
        };
        let transformed = MakeCredentialExtensionsOutput::from(output);
        assert!(transformed.prf.as_ref().unwrap().enabled);
        assert_eq!(prf1, transformed.prf.unwrap().results.unwrap().first);
    }

    #[test]
    fn test_transform_get_assertion_extension_input() {
        let salt1 = b"salt1".to_vec();
        let salt2 = b"salt2".to_vec();
        let input = GetAssertionExtensionsInput {
            prf: Some(GetAssertionPrfInput {
                eval: Some(PrfValues {
                    first: salt1.clone(),
                    second: Some(salt2.clone()),
                }),
                eval_by_credential: None,
            }),
        };
        let transformed = get_assertion::ExtensionInputs::from(input);
        // SHA-256(UTF-8("WebAuthn PRF") || 0x00 || salt1)
        let hashed_first = [
            0x2A, 0x19, 0x90, 0xF9, 0xC9, 0xBB, 0xFE, 0x1B, 0xBF, 0x56, 0xAB, 0xEE, 0x2B, 0x5A,
            0x0F, 0x59, 0xBE, 0x5F, 0x63, 0x3A, 0x35, 0xC2, 0xA5, 0xF0, 0x7D, 0x85, 0x53, 0x3E,
            0xEE, 0xCB, 0xDD, 0x3C,
        ];
        assert_eq!(
            hashed_first,
            transformed
                .prf
                .as_ref()
                .unwrap()
                .eval
                .as_ref()
                .unwrap()
                .first
        );
        // SHA-256(UTF-8("WebAuthn PRF") || 0x00 || salt2)
        let hashed_second = [
            0xA6, 0x42, 0xFA, 0x8B, 0x6E, 0xAC, 0x68, 0xD3, 0x73, 0xCF, 0x08, 0xEA, 0xC8, 0x5E,
            0x1D, 0x62, 0x9B, 0x50, 0x10, 0x6D, 0x60, 0xEB, 0x92, 0x48, 0xEC, 0xB6, 0x54, 0xE2,
            0x94, 0x9A, 0xDD, 0x65,
        ];
        assert_eq!(
            hashed_second,
            transformed.prf.unwrap().eval.unwrap().second.unwrap()
        );
    }

    #[test]
    fn test_transform_get_assertion_extension_output() {
        let prf1: Vec<u8> = (0..32).collect();
        let output = get_assertion::UnsignedExtensionOutputs {
            prf: Some(AuthenticatorPrfGetOutputs {
                results: AuthenticatorPrfValues {
                    first: prf1.clone().try_into().unwrap(),
                    second: None,
                },
            }),
        };
        let transformed = GetAssertionExtensionsOutput::from(output);
        assert_eq!(prf1, transformed.prf.unwrap().results.first);
    }
}
