use argon2::Params;
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::{errors::InternalError, CipherSuite};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct CipherConfiguration {
    pub oprf_cs: OprfCs,
    pub ke_group: KeGroup,
    pub key_exchange: KeyExchange,
    pub ksf: Ksf,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum OprfCs {
    #[serde(rename = "ristretto255")]
    Ristretto255,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeGroup {
    #[serde(rename = "ristretto255")]
    Ristretto255,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyExchange {
    #[serde(rename = "triple-dh")]
    TripleDh,
}

#[derive(Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Ksf {
    #[serde(rename = "argon2id")]
    Argon2id(u32, u32, u32),
}

#[derive(Serialize, Deserialize, Default, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct Argon2Id {
    /// Memory cost in kibibytes
    pub memory_kib: u32,
    /// Time cost in number of iterations
    pub iterations: u32,
    /// Number of threads that may be used
    pub parallelism: u32,
}

impl opaque_ke::ksf::Ksf for Argon2Id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            Params::new(
                self.memory_kib,
                self.iterations,
                self.parallelism,
                Some(output.len()),
            )
            .map_err(|_| InternalError::KsfError)?,
        )
        .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
        .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct RistrettoTripleDhArgonSuite {
    pub ksf_params: Argon2Id,
}

impl CipherSuite for RistrettoTripleDhArgonSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2Id;
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ClientRegistrationStartResult {
    /// The client side, serialized state of the registration process.
    /// MUST NOT BE SHARED WITH THE SERVER and must be cleared from memory after registration
    /// finish.
    pub state: ByteBuf,
    /// The serialized message to be sent to the server.
    pub registration_request: ByteBuf,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ClientRegistrationFinishResult {
    /// The serialized message to be sent to the server.
    pub registration_upload: ByteBuf,
    /// The public key of the server.
    pub server_public_key: ByteBuf,
    /// The client-side only export key result from the AKE.
    pub export_key: ByteBuf,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ClientLoginStartResult {
    /// The client side, serialized state of the login process.
    /// MUST NOT BE SHARED WITH THE SERVER and must be cleared from memory after registration
    /// finish.
    pub state: ByteBuf,
    /// The serialized LoginStart message from the client to be sent to the server
    pub credential_request: ByteBuf,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ClientLoginFinishResult {
    /// The serialized LoginFinish message from the client to be sent to the server
    pub credential_finalization: ByteBuf,
    /// The client-side only export key result from the AKE. Note: This is limited to 256 bits,
    /// if the cipher parameters have a larger key size, the key will be truncated.
    /// This key is consistent between authentications.
    pub export_key: ByteBuf,

    /// The server-client shared established session key. This key is unique
    /// to the session.
    pub session_key: ByteBuf,

    /// The public key of the server.
    pub server_public_key: ByteBuf,
}

#[allow(dead_code)]
pub struct ServerRegistrationStartResult {
    pub(crate) registration_response: Vec<u8>,
    pub(crate) server_setup: Vec<u8>,
}

#[allow(dead_code)]
pub struct ServerRegistrationFinishResult {
    pub(crate) server_registration: Vec<u8>,
}

#[allow(dead_code)]
pub struct ServerLoginStartResult {
    pub(crate) credential_response: Vec<u8>,
    pub(crate) state: Vec<u8>,
}

#[allow(dead_code)]
pub struct ServerLoginFinishResult {
    pub(crate) session_key: Vec<u8>,
}
