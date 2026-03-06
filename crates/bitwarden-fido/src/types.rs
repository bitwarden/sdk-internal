use std::{borrow::Cow, collections::HashMap};

use bitwarden_core::key_management::KeyIds;
use bitwarden_crypto::{CryptoError, KeyStoreContext};
use bitwarden_encoding::{B64Url, NotB64UrlEncodedError};
use bitwarden_vault::{CipherListView, CipherListViewType, CipherView, LoginListView};
use passkey::types::webauthn::UserVerificationRequirement;
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
    ) -> Result<Vec<Fido2CredentialAutofillView>, Fido2CredentialAutofillViewError> {
        let credentials = cipher.decrypt_fido2_credentials(ctx)?;

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

impl From<PublicKeyCredentialRpEntity>
    for passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity
{
    fn from(value: PublicKeyCredentialRpEntity) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}

impl TryFrom<&bitwarden_api_api::models::PublicKeyCredentialRpEntity>
    for PublicKeyCredentialRpEntity
{
    type Error = WebAuthnEntityError;
    fn try_from(
        value: &bitwarden_api_api::models::PublicKeyCredentialRpEntity,
    ) -> Result<Self, Self::Error> {
        let id = value
            .id
            .as_ref()
            .ok_or(WebAuthnEntityError::InvalidRpId)?
            .clone();
        Ok(Self {
            id,
            name: value.name.clone(),
        })
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialUserEntity {
    pub id: Vec<u8>,
    pub display_name: String,
    pub name: String,
}

impl From<PublicKeyCredentialUserEntity>
    for passkey::types::webauthn::PublicKeyCredentialUserEntity
{
    fn from(value: PublicKeyCredentialUserEntity) -> Self {
        Self {
            id: value.id.into(),
            name: value.name,
            display_name: value.display_name,
        }
    }
}

impl TryFrom<&bitwarden_api_api::models::Fido2User> for PublicKeyCredentialUserEntity {
    type Error = WebAuthnEntityError;
    fn try_from(value: &bitwarden_api_api::models::Fido2User) -> Result<Self, Self::Error> {
        let mut missing_fields = Vec::with_capacity(0);
        if value.id.is_none() {
            missing_fields.push("id".to_string())
        }
        if value.display_name.is_none() {
            missing_fields.push("displayName".to_string())
        }
        if value.name.is_none() {
            missing_fields.push("name".to_string())
        }
        if missing_fields.is_empty() {
            Ok(Self {
                id: value.id.as_ref().expect("checked manually").clone(),
                display_name: value
                    .display_name
                    .as_ref()
                    .expect("checked manually")
                    .clone(),
                name: value.name.as_ref().expect("checked manually").clone(),
            })
        } else {
            Err(WebAuthnEntityError::MissingRequiredFields(missing_fields))
        }
    }
}

#[derive(Debug, Error)]
pub enum WebAuthnEntityError {
    #[error("Missing required fields: {0:?}")]
    MissingRequiredFields(Vec<String>),

    #[error("Invalid RP ID")]
    InvalidRpId,

    #[error("Invalid public key credential parameters")]
    PublicKeyCredentialParmametersError(#[from] PublicKeyCredentialParametersError),

    #[error("Unknown type")]
    UnknownEnum(#[from] UnknownEnumError),
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PublicKeyCredentialParameters {
    pub ty: String,
    pub alg: i64,
}

impl TryFrom<&bitwarden_api_api::models::PubKeyCredParam> for PublicKeyCredentialParameters {
    type Error = PublicKeyCredentialParametersError;
    fn try_from(value: &bitwarden_api_api::models::PubKeyCredParam) -> Result<Self, Self::Error> {
        let ty = value
            .r#type
            .as_ref()
            .ok_or(PublicKeyCredentialParametersError::UnknownEnum(
                UnknownEnumError,
            ))?
            .to_string();
        let alg = value
            .alg
            .ok_or(PublicKeyCredentialParametersError::InvalidAlgorithm)?
            .as_i64();
        Ok(Self { ty, alg })
    }
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

impl TryFrom<&PublicKeyCredentialDescriptor>
    for passkey::types::webauthn::PublicKeyCredentialDescriptor
{
    type Error = UnknownEnumError;

    fn try_from(value: &PublicKeyCredentialDescriptor) -> Result<Self, Self::Error> {
        Ok(Self {
            ty: get_enum_from_string_name(&value.ty)?,
            id: value.id.clone().into(),
            transports: value
                .transports
                .as_ref()
                .map(|tt| {
                    tt.iter()
                        .map(|t| get_enum_from_string_name(t))
                        .collect::<Result<Vec<_>, Self::Error>>()
                })
                .transpose()?,
        })
    }
}

impl TryFrom<&bitwarden_api_api::models::PublicKeyCredentialDescriptor>
    for PublicKeyCredentialDescriptor
{
    type Error = WebAuthnEntityError;
    fn try_from(
        value: &bitwarden_api_api::models::PublicKeyCredentialDescriptor,
    ) -> Result<Self, Self::Error> {
        let ty = value
            .r#type
            .as_ref()
            .ok_or(WebAuthnEntityError::UnknownEnum(UnknownEnumError))?
            .to_string();
        let id = value
            .id
            .as_ref()
            .ok_or(WebAuthnEntityError::MissingRequiredFields(vec![
                "id".to_string(),
            ]))?
            .clone();
        let transports = value
            .transports
            .as_ref()
            .map(|l| l.iter().map(|t| t.to_string()).collect());
        Ok(Self { ty, id, transports })
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

    /// WebAuthn client extension inputs for credential creation requests.
    ///
    /// Cf. <https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions>.
    pub extensions: Option<MakeCredentialExtensionsInput>,
}

/// Fields corresponding to a WebAuthn [PublicKeyCredential][pub-key-cred]
/// with an [AuthenticatorAttestationResponse][authenticator-attestation-response].
///
/// [pub-key-cred]: https://www.w3.org/TR/webauthn-3/#publickeycredential
/// [authenticator-attestation-response]: https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct MakeCredentialResult {
    /// The authenticator data extracted from within the
    /// [`attestation_object`][Self::attestation_object].
    pub authenticator_data: Vec<u8>,

    /// [WebAuthn attestation object][webauthn-attestation-object] for the
    /// authenticator response containing both the authenticator data and
    /// attestation statement for the credential.
    ///
    /// [webauthn-attestation-object]: https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-attestationobject
    pub attestation_object: Vec<u8>,

    /// ID for this credential, corresponding to [PublicKeyCredential.rawId][raw-id].
    ///
    /// [raw-id]: https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid
    pub credential_id: Vec<u8>,

    /// Mix of CTAP [unsigned extension output][unsigned-extensions] and
    /// [WebAuthn client extensions][webauthn-client-extensions] output returned
    /// by the authenticator.
    ///
    /// [unsigned-extensions]: https://www.w3.org/TR/webauthn-3/#unsigned-extension-outputs
    /// [webauthn-client-extensions]: https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-clientextensionsresults-slot
    pub extensions: MakeCredentialExtensionsOutput,
}

impl TryFrom<passkey::types::ctap2::make_credential::Response> for MakeCredentialResult {
    type Error = WebAuthnEntityError;

    fn try_from(
        value: passkey::types::ctap2::make_credential::Response,
    ) -> Result<Self, Self::Error> {
        let authenticator_data = value.auth_data.to_vec();
        let attestation_object = value.as_webauthn_bytes().to_vec();
        let attested_credential_data = value.auth_data.attested_credential_data.ok_or(
            WebAuthnEntityError::MissingRequiredFields(vec!["attestedCredentialData".to_string()]),
        )?;
        let credential_id = attested_credential_data.credential_id().to_vec();
        let extensions: MakeCredentialExtensionsOutput = value.unsigned_extension_outputs.into();
        Ok(MakeCredentialResult {
            authenticator_data,
            attestation_object,
            credential_id,
            extensions,
        })
    }
}

/// WebAuthn extension input for WebAuthn registration extensions.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Default)]
pub struct MakeCredentialExtensionsInput {
    /// PRF input for WebAuthn registration request.
    pub prf: Option<MakeCredentialPrfInput>,
}

impl From<MakeCredentialExtensionsInput>
    for passkey::types::ctap2::make_credential::ExtensionInputs
{
    fn from(value: MakeCredentialExtensionsInput) -> Self {
        Self {
            hmac_secret: None,
            hmac_secret_mc: None,
            prf: value
                .prf
                .map(passkey::types::ctap2::extensions::AuthenticatorPrfInputs::from),
        }
    }
}

impl From<bitwarden_api_api::models::AuthenticationExtensionsClientInputs>
    for MakeCredentialExtensionsInput
{
    fn from(_value: bitwarden_api_api::models::AuthenticationExtensionsClientInputs) -> Self {
        MakeCredentialExtensionsInput {
            // The server doesn't support sending the PRF extension, but at this
            // time we only use it for the device auth key, which uses a static,
            // hard-coded value, so set it to `None` here.
            prf: None,
        }
    }
}

/// WebAuthn extension output for registration extensions.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialExtensionsOutput {
    /// PRF output for registration extensions.
    pub prf: Option<MakeCredentialPrfOutput>,
}

impl From<Option<passkey::types::ctap2::make_credential::UnsignedExtensionOutputs>>
    for MakeCredentialExtensionsOutput
{
    fn from(
        value: Option<passkey::types::ctap2::make_credential::UnsignedExtensionOutputs>,
    ) -> Self {
        if let Some(ext) = value {
            MakeCredentialExtensionsOutput::from(ext)
        } else {
            MakeCredentialExtensionsOutput { prf: None }
        }
    }
}

impl From<passkey::types::ctap2::make_credential::UnsignedExtensionOutputs>
    for MakeCredentialExtensionsOutput
{
    fn from(value: passkey::types::ctap2::make_credential::UnsignedExtensionOutputs) -> Self {
        let prf = value.prf.map(|prf| MakeCredentialPrfOutput {
            enabled: prf.enabled,
            results: prf.results.map(|results| results.into()),
        });
        MakeCredentialExtensionsOutput { prf }
    }
}

/// WebAuthn PRF extension input for use during registration.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialPrfInput {
    /// PRF inputs.
    pub eval: Option<PrfInputValues>,
}

impl From<MakeCredentialPrfInput> for passkey::types::ctap2::extensions::AuthenticatorPrfInputs {
    fn from(value: MakeCredentialPrfInput) -> Self {
        Self {
            eval: value.eval.map(|v| v.into()),
            eval_by_credential: None,
        }
    }
}

/// WebAuthn PRF extension output used during registration.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct MakeCredentialPrfOutput {
    /// Whether PRF is successfully processed for the newly created credential.
    pub enabled: bool,

    /// PRF outputs.
    pub results: Option<PrfOutputValues>,
}

#[allow(missing_docs)]
/// Type representing data from WebAuthn's
/// [`PublicKeyCredentialRequestOptions`][pubkey-cred-request-options].
///
/// [pubkey-cred-request-options]: https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GetAssertionRequest {
    /// The RP ID for the request used to select credentials.
    pub rp_id: String,

    /// Hash of the clientDataJSON for the request.
    pub client_data_hash: Vec<u8>,

    /// Credential IDs known to the RP. If specified, it is a list of
    /// credentials to filter by, ordered from most to least preferable. If
    /// empty, only discoverable credentials will be returned.
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,

    pub options: Options,

    /// WebAuthn extension input for use during assertion.
    pub extensions: Option<GetAssertionExtensionsInput>,
}

/// Fields corresponding to a WebAuthn [PublicKeyCredential][pub-key-cred]
/// with an [AuthenticatorAssertionResponse][authenticator-assertion-response].
///
/// [pub-key-cred]: https://www.w3.org/TR/webauthn-3/#publickeycredential
/// [authenticator-assertion-response]: https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct GetAssertionResult {
    /// ID for this credential, corresponding to [PublicKeyCredential.rawId][raw-id].
    ///
    /// [raw-id]: https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid
    pub credential_id: Vec<u8>,

    /// The authenticator data from the authenticator response.
    pub authenticator_data: Vec<u8>,

    /// Signature over the authenticator data.
    pub signature: Vec<u8>,

    /// The user handle returned from the authenticator.
    pub user_handle: Vec<u8>,

    /// A reference to the Bitwarden cipher for the selected credential.
    pub selected_credential: SelectedCredential,

    /// Mix of CTAP unsigned extension output and WebAuthn client extension output.
    /// Signed extensions can be retrieved from authenticator data.
    pub extensions: GetAssertionExtensionsOutput,
}

/// WebAuthn extension input for WebAuthn authentication extensions.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionExtensionsInput {
    /// PRF input for the authentication ceremony.
    pub prf: Option<GetAssertionPrfInput>,
}

impl From<GetAssertionExtensionsInput> for passkey::types::ctap2::get_assertion::ExtensionInputs {
    fn from(value: GetAssertionExtensionsInput) -> Self {
        Self {
            hmac_secret: None,
            prf: value
                .prf
                .map(passkey::types::ctap2::extensions::AuthenticatorPrfInputs::from),
        }
    }
}

/// WebAuthn extension output of an authentication ceremony.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionExtensionsOutput {
    /// PRF output for an authentication ceremony.
    pub prf: Option<GetAssertionPrfOutput>,
}

impl From<Option<passkey::types::ctap2::get_assertion::UnsignedExtensionOutputs>>
    for GetAssertionExtensionsOutput
{
    fn from(value: Option<passkey::types::ctap2::get_assertion::UnsignedExtensionOutputs>) -> Self {
        if let Some(value) = value {
            value.into()
        } else {
            Self { prf: None }
        }
    }
}

impl From<passkey::types::ctap2::get_assertion::UnsignedExtensionOutputs>
    for GetAssertionExtensionsOutput
{
    fn from(value: passkey::types::ctap2::get_assertion::UnsignedExtensionOutputs) -> Self {
        let prf = value.prf.map(|prf| GetAssertionPrfOutput {
            results: prf.results.into(),
        });
        GetAssertionExtensionsOutput { prf }
    }
}

/// Input for WebAuthn PRF extension during authentication ceremonies.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionPrfInput {
    /// A PRF input to use for authentication. If a map of credential IDs to PRF
    /// inputs is specified in [`Self::eval_by_credential`] along with this
    /// value, the extension will fallback to this
    /// value if the returned credential ID is not contained in the map.
    pub eval: Option<PrfInputValues>,

    /// A map of credential IDs to PRF input for a set of credentials specified in the
    /// [`GetAssertionRequest::allow_list`] field of the request. If a key of
    /// this map does not exist in the allow list, the extension will fail.
    pub eval_by_credential: Option<HashMap<Vec<u8>, PrfInputValues>>,
}

impl From<GetAssertionPrfInput> for passkey::types::ctap2::extensions::AuthenticatorPrfInputs {
    fn from(value: GetAssertionPrfInput) -> Self {
        let eval_by_credential = if let Some(values) = value.eval_by_credential {
            let map: HashMap<
                passkey::types::Bytes,
                passkey::types::ctap2::extensions::AuthenticatorPrfValues,
            > = values
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            Some(map)
        } else {
            None
        };
        Self {
            eval: value.eval.map(|v| v.into()),
            eval_by_credential,
        }
    }
}

/// WebAuthn PRF extension output during an authentication ceremony.
#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct GetAssertionPrfOutput {
    /// The PRF output for the ceremony.
    pub results: PrfOutputValues,
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

impl From<bitwarden_api_api::models::UserVerificationRequirement> for UV {
    fn from(value: bitwarden_api_api::models::UserVerificationRequirement) -> Self {
        match value {
            bitwarden_api_api::models::UserVerificationRequirement::Discouraged => UV::Discouraged,
            bitwarden_api_api::models::UserVerificationRequirement::Preferred => UV::Preferred,
            bitwarden_api_api::models::UserVerificationRequirement::Required => UV::Required,
            bitwarden_api_api::models::UserVerificationRequirement::__Unknown(_) => UV::Preferred,
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

/// Salt inputs for WebAuthn PRF extension.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PrfInputValues {
    /// An input on which to evaluate PRF. Required.
    pub first: Vec<u8>,

    /// An optional secondary input on which to evaluate PRF.
    pub second: Option<Vec<u8>>,
}

impl PrfInputValues {
    const WEBAUTHN_PRF_CONTEXT_STRING: &[u8] = b"WebAuthn PRF\0";

    fn hash_webauthn_prf_input(input: &[u8]) -> [u8; 32] {
        passkey::types::crypto::sha256(&[Self::WEBAUTHN_PRF_CONTEXT_STRING, input].concat())
    }
}

impl std::fmt::Debug for PrfInputValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrfInputValues")
            .field("first", &"********")
            .field("second", &self.second.as_ref().map(|_| "********"))
            .finish()
    }
}

impl From<PrfInputValues> for passkey::types::ctap2::extensions::AuthenticatorPrfValues {
    /// This converts PRF input received from a client into the format that
    /// passkey-rs expects. This is not valid for converting output received from passkey-rs.
    fn from(value: PrfInputValues) -> Self {
        // passkey-rs expects the salt input to be hashed already according to
        // WebAuthn PRF extension client processing rules.
        let first = PrfInputValues::hash_webauthn_prf_input(value.first.as_ref());
        let second = value
            .second
            .as_deref()
            .map(PrfInputValues::hash_webauthn_prf_input);
        Self { first, second }
    }
}

/// WebAuthn PRF output values.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PrfOutputValues {
    /// The output of the PRF evaluation of the first PRF input.
    pub first: Vec<u8>,

    /// The output of the PRF evaluation of the second PRF input, if it was specified.
    pub second: Option<Vec<u8>>,
}

impl std::fmt::Debug for PrfOutputValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrfOutputValues")
            .field("first", &"********")
            .field("second", &self.second.as_ref().map(|_| "********"))
            .finish()
    }
}

impl From<passkey::types::ctap2::extensions::AuthenticatorPrfValues> for PrfOutputValues {
    fn from(value: passkey::types::ctap2::extensions::AuthenticatorPrfValues) -> Self {
        Self {
            first: value.first.to_vec(),
            second: value.second.map(|s| s.to_vec()),
        }
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
    use std::collections::HashMap;

    use passkey::types::ctap2::{
        extensions::{
            AuthenticatorPrfGetOutputs, AuthenticatorPrfMakeOutputs, AuthenticatorPrfValues,
        },
        get_assertion, make_credential,
    };
    use serde::{Deserialize, Serialize};

    use super::{
        AndroidClientData, GetAssertionExtensionsInput, GetAssertionExtensionsOutput,
        GetAssertionPrfInput, MakeCredentialExtensionsInput, MakeCredentialExtensionsOutput,
        MakeCredentialPrfInput, PrfInputValues,
    };

    /// Raw PRF input for testing.
    static TEST_SALT1_RAW_INPUT: &[u8] = b"salt1";

    /// PRF input of after applying WebAuthn PRF domain separation to [TEST_SALT1_RAW_INPUT].
    // SHA-256(UTF-8("WebAuthn PRF") || 0x00 || TEST_SALT1_RAW_INPUT)
    static TEST_SALT1_WEBAUTHN_INPUT: [u8; 32] = [
        0x2A, 0x19, 0x90, 0xF9, 0xC9, 0xBB, 0xFE, 0x1B, 0xBF, 0x56, 0xAB, 0xEE, 0x2B, 0x5A, 0x0F,
        0x59, 0xBE, 0x5F, 0x63, 0x3A, 0x35, 0xC2, 0xA5, 0xF0, 0x7D, 0x85, 0x53, 0x3E, 0xEE, 0xCB,
        0xDD, 0x3C,
    ];

    /// Raw PRF input for testing.
    static TEST_SALT2_RAW_INPUT: &[u8] = b"salt2";

    /// PRF input after applying WebAuthn PRF domain separation to [TEST_SALT2_RAW_INPUT].
    ///
    /// SHA-256(UTF-8("WebAuthn PRF") || 0x00 || TEST_SALT2_RAW_INPUT)
    static TEST_SALT2_WEBAUTHN_INPUT: [u8; 32] = [
        0xA6, 0x42, 0xFA, 0x8B, 0x6E, 0xAC, 0x68, 0xD3, 0x73, 0xCF, 0x08, 0xEA, 0xC8, 0x5E, 0x1D,
        0x62, 0x9B, 0x50, 0x10, 0x6D, 0x60, 0xEB, 0x92, 0x48, 0xEC, 0xB6, 0x54, 0xE2, 0x94, 0x9A,
        0xDD, 0x65,
    ];

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
        let input = MakeCredentialExtensionsInput {
            prf: Some(MakeCredentialPrfInput {
                eval: Some(PrfInputValues {
                    first: TEST_SALT1_RAW_INPUT.to_vec(),
                    second: Some(TEST_SALT2_RAW_INPUT.to_vec()),
                }),
            }),
        };
        let transformed = make_credential::ExtensionInputs::from(input);
        let eval = transformed.prf.unwrap().eval.unwrap();
        assert_eq!(TEST_SALT1_WEBAUTHN_INPUT, eval.first);
        assert_eq!(TEST_SALT2_WEBAUTHN_INPUT, eval.second.unwrap());
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
        let input = GetAssertionExtensionsInput {
            prf: Some(GetAssertionPrfInput {
                eval: Some(PrfInputValues {
                    first: TEST_SALT1_RAW_INPUT.to_vec(),
                    second: Some(TEST_SALT2_RAW_INPUT.to_vec()),
                }),
                eval_by_credential: None,
            }),
        };
        let transformed = get_assertion::ExtensionInputs::from(input);
        let eval = transformed.prf.unwrap().eval.unwrap();
        assert_eq!(TEST_SALT1_WEBAUTHN_INPUT, eval.first);
        assert_eq!(TEST_SALT2_WEBAUTHN_INPUT, eval.second.unwrap());
    }

    #[test]
    fn test_transform_get_assertion_extension_input_with_eval_by_credential() {
        let cred_id = b"credential_id1".to_vec();
        let input = GetAssertionExtensionsInput {
            prf: Some(GetAssertionPrfInput {
                eval: None,
                eval_by_credential: Some(HashMap::from([(
                    cred_id.clone(),
                    PrfInputValues {
                        first: TEST_SALT1_RAW_INPUT.to_vec(),
                        second: Some(TEST_SALT2_RAW_INPUT.to_vec()),
                    },
                )])),
            }),
        };
        let transformed = get_assertion::ExtensionInputs::from(input);
        let output = transformed.prf.unwrap().eval_by_credential.unwrap();
        let results = output.get(&cred_id.into()).unwrap();
        assert_eq!(TEST_SALT1_WEBAUTHN_INPUT, results.first);
        assert_eq!(TEST_SALT2_WEBAUTHN_INPUT, results.second.unwrap());
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
