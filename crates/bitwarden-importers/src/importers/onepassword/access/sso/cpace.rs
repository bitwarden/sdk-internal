//! The CPace exchange that hands the credentials of an enrolled device to a new one, reverse
//! engineered from 1Password's WASM module: the local crypto, and the requests that carry it.
//!
//! The new device proves it knows the verification code the user reads off the enrolled device, and
//! both sides end up with the same key to move the credential bundle through the server.

use bitwarden_threading::time;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha384, Sha512};
use zeroize::Zeroizing;

use super::{
    super::{
        error::OnePasswordError,
        kdf,
        opdata::{AesKey, Encrypted, decode64_loose},
        rest::RestClient,
        wire::{self, CredentialBundle, EncryptedEnvelope, SuccessStatus},
    },
    Timing,
};

const PASSCODE_ITERATIONS: u32 = 100_000;

/// Pads the second hash input through the passcode hash to one 128 byte SHA-512 block.
const PADDING_LENGTH: usize = 76;

/// The key id of the exchange key, which also keys the first step of deriving it.
const TRANSPORT_KEY_ID: &str = "1P_SSO_ENROLLMENT_TRANSPORT_KEY";
const EXCHANGE_KEY_INFO: &[u8] = b"1P_SSO_CREDENTIAL_BUNDLE_KEY:ENROLL\x01";
const CREDENTIAL_BUNDLE_AAD: &[u8] = b"1P_SSO_CREDENTIAL_BUNDLE:ENROLL";

/// The first CPace message, from the enrolled device.
#[derive(Debug)]
pub(super) struct MsgA {
    /// The enrolled device's public point.
    pub ya: RistrettoPoint,
    pub ad: Ad,
    /// The message as received, which goes into the transcript hash byte for byte.
    pub original_message: Vec<u8>,
}

/// The associated data of a CPace message.
#[derive(Debug)]
pub(super) struct Ad {
    #[cfg_attr(not(test), allow(dead_code))]
    pub version: i32,
    pub salt: Vec<u8>,
    pub session_id: Vec<u8>,
}

/// Parses the JSON of `msga`, after its base64 layer is removed.
///
/// Rejects a `ya` that is not the canonical encoding of a point, or is the identity, before
/// anything is sent back.
pub(super) fn parse_msg_a(json: &[u8]) -> Result<MsgA, OnePasswordError> {
    let msg_a: wire::MsgA = serde_json::from_slice(json).map_err(|_| OnePasswordError::Parse)?;
    let ya = decompress_point(&decode64_loose(&msg_a.ya)?)?;
    if ya == RistrettoPoint::identity() {
        return Err(OnePasswordError::Internal(
            "the CPace point must not be the identity".into(),
        ));
    }

    Ok(MsgA {
        ya,
        ad: Ad {
            version: msg_a.ad.version,
            salt: decode64_loose(&msg_a.ad.salt)?,
            session_id: msg_a.ad.session_id,
        },
        original_message: json.to_vec(),
    })
}

/// Fails for anything but the canonical encoding of a point.
fn decompress_point(bytes: &[u8]) -> Result<RistrettoPoint, OnePasswordError> {
    CompressedRistretto::from_slice(bytes)
        .ok()
        .and_then(|point| point.decompress())
        .ok_or_else(|| OnePasswordError::Internal("invalid CPace point".into()))
}

/// Calculates `msgb`, the new device's answer to `msga`.
pub(super) fn calculate_msg_b(
    username: &str,
    sign_in_address: &str,
    enrollment_uuid: &str,
    verification_code: &str,
    msg_a: &MsgA,
    client_secret: &[u8; 64],
) -> [u8; 32] {
    let passcode_hash = calculate_passcode_hash(verification_code, &msg_a.ad.salt);
    let first_hash = calculate_first_hash(username, sign_in_address, enrollment_uuid, msg_a);
    let second_hash = Zeroizing::new(calculate_second_hash(
        &first_hash,
        passcode_hash.as_slice(),
        msg_a,
    ));
    let generator = RistrettoPoint::from_uniform_bytes(&second_hash);
    multiply_by_client_scalar(&generator, client_secret)
}

/// Stretches the verification code, salted by the enrolled device.
fn calculate_passcode_hash(passcode: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(kdf::pbes2(passcode, salt, PASSCODE_ITERATIONS))
}

/// Binds the exchange to the user, the sign-in address and the enrollment.
fn calculate_first_hash(
    email: &str,
    sign_in_address: &str,
    enrollment_uuid: &str,
    msg_a: &MsgA,
) -> [u8; 64] {
    sha512(&leb128_prefixed(&[
        b"1P-SSO-TRUSTED-DEVICE",
        b"1P-SSO-NEW-DEVICE",
        email.as_bytes(),
        sign_in_address.as_bytes(),
        enrollment_uuid.as_bytes(),
        &msg_a.ad.salt,
        &[1],
    ]))
}

/// The input of the CPace generator, which binds the passcode to the first hash and the session.
fn calculate_second_hash(first_hash: &[u8], passcode_hash: &[u8], msg_a: &MsgA) -> [u8; 64] {
    sha512(&leb128_prefixed(&[
        b"CPaceRistretto255",
        passcode_hash,
        &[0; PADDING_LENGTH],
        first_hash,
        &msg_a.ad.session_id,
    ]))
}

/// Multiplies by the scalar the client secret reduces to, and compresses the result.
fn multiply_by_client_scalar(point: &RistrettoPoint, client_secret: &[u8; 64]) -> [u8; 32] {
    let scalar = Zeroizing::new(Scalar::from_bytes_mod_order_wide(client_secret));
    (point * *scalar).compress().to_bytes()
}

/// Prefixes every field with its length as LEB128, and concatenates them.
fn leb128_prefixed(fields: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut buffer = Zeroizing::new(Vec::new());
    for field in fields {
        write_leb128_prefixed(&mut buffer, field);
    }
    buffer
}

/// Writes `data` after its length, as the little endian base 128 varint the WASM module uses.
fn write_leb128_prefixed(buffer: &mut Vec<u8>, data: &[u8]) {
    let mut length = data.len();
    loop {
        let byte = (length & 0x7f) as u8;
        length >>= 7;
        if length == 0 {
            buffer.push(byte);
            break;
        }
        buffer.push(byte | 0x80);
    }
    buffer.extend_from_slice(data);
}

/// Would check `taga`, which proves the enrolled device knows the verification code too.
///
/// Not implemented: the server is trusted to relay an honest device.
pub(super) fn verify_tag_a(_tag_a: &[u8]) {}

/// Calculates the shared secret `authB` and the `tagb` that proves knowing it.
pub(super) fn calculate_auth_b_tag_b(
    client_secret: &[u8; 64],
    msg_a: &MsgA,
    msg_b: &[u8],
) -> (Zeroizing<[u8; 64]>, [u8; 64]) {
    let auth_a = calculate_auth_a_hash(msg_a, client_secret);
    let auth_b = calculate_auth_b_hash(auth_a.as_slice(), msg_a, msg_b);
    let tag_b = calculate_tag_b(auth_b.as_slice(), msg_b);
    (auth_b, tag_b)
}

/// The point both sides agree on: `ya` times the client scalar.
fn calculate_auth_a_hash(msg_a: &MsgA, client_secret: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(multiply_by_client_scalar(&msg_a.ya, client_secret))
}

/// The session secret, hashed over the whole transcript.
fn calculate_auth_b_hash(auth_a: &[u8], msg_a: &MsgA, msg_b: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut buffer = leb128_prefixed(&[b"CPaceRistretto255_ISK", &msg_a.ad.session_id, auth_a]);
    buffer.extend_from_slice(&msg_a.original_message);
    buffer.extend_from_slice(msg_b);
    Zeroizing::new(sha512(&buffer))
}

/// The MAC of `msgb` under a key derived from `authB`.
fn calculate_tag_b(auth_b: &[u8], msg_b: &[u8]) -> [u8; 64] {
    let mac_key = Zeroizing::new(<[u8; 64]>::from(
        Sha512::new()
            .chain_update(b"CPaceMac")
            .chain_update(auth_b)
            .finalize(),
    ));
    hmac_sha512(mac_key.as_slice(), msg_b)
}

/// Derives the key that encrypts the credential bundle in transit from `authB`.
pub(super) fn derive_exchange_key(auth_b: &[u8]) -> Zeroizing<[u8; 32]> {
    let transport_key = hmac_sha384(TRANSPORT_KEY_ID.as_bytes(), auth_b);
    let exchange_key = hmac_sha384(transport_key.as_slice(), EXCHANGE_KEY_INFO);

    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&exchange_key[..32]);
    key
}

/// Decrypts the credential bundle the enrolled device shared.
pub(super) fn decrypt_credentials(
    encrypted_credentials: &EncryptedEnvelope,
    exchange_key: &[u8],
) -> Result<CredentialBundle, OnePasswordError> {
    let key = AesKey::new(TRANSPORT_KEY_ID, exchange_key.to_vec());
    let encrypted = Encrypted::parse(encrypted_credentials)?;
    let credentials = Zeroizing::new(key.decrypt_with_aad(&encrypted, CREDENTIAL_BUNDLE_AAD)?);

    // The error is dropped, serde echoes the offending value.
    serde_json::from_slice(&credentials).map_err(|_| OnePasswordError::Parse)
}

fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

fn hmac_sha384(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 48]> {
    let mut mac =
        <Hmac<Sha384> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut mac =
        <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Runs the whole exchange over `rest` with a fresh random client secret and returns the
/// credentials the enrolled device shared.
pub(super) async fn perform_cpace(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    enrollment_uuid: &str,
    verification_code: &str,
    rest: &RestClient,
    timing: &Timing,
) -> Result<CredentialBundle, OnePasswordError> {
    let mut client_secret = Zeroizing::new([0u8; 64]);
    bitwarden_random::rng().fill_bytes(&mut *client_secret);

    perform_cpace_with_client_secret(
        username,
        sign_in_address,
        sign_in_token,
        enrollment_uuid,
        verification_code,
        &client_secret,
        rest,
        timing,
    )
    .await
}

/// The CPace exchange with the client secret injected so the test vectors can pin it.
#[allow(clippy::too_many_arguments)]
async fn perform_cpace_with_client_secret(
    username: &str,
    sign_in_address: &str,
    sign_in_token: &str,
    enrollment_uuid: &str,
    verification_code: &str,
    client_secret: &[u8; 64],
    rest: &RestClient,
    timing: &Timing,
) -> Result<CredentialBundle, OnePasswordError> {
    let msg_a = request_msg_a(sign_in_token, enrollment_uuid, rest).await?;

    let msg_b = calculate_msg_b(
        username,
        sign_in_address,
        enrollment_uuid,
        verification_code,
        &msg_a,
        client_secret,
    );
    send_msg_b(&msg_b, sign_in_token, enrollment_uuid, rest).await?;

    let tag_a = get_tag_a(sign_in_token, enrollment_uuid, rest, timing).await?;
    verify_tag_a(&tag_a);

    let (auth_b, tag_b) = calculate_auth_b_tag_b(client_secret, &msg_a, &msg_b);
    send_tag_b(&tag_b, sign_in_token, enrollment_uuid, rest).await?;

    let encrypted_credentials =
        request_encrypted_credentials(sign_in_token, enrollment_uuid, rest, timing).await?;
    let exchange_key = derive_exchange_key(auth_b.as_slice());

    decrypt_credentials(&encrypted_credentials, exchange_key.as_slice())
}

/// Fetches and parses the enrolled device's first message.
async fn request_msg_a(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<MsgA, OnePasswordError> {
    let response: wire::CpaceMsgA = rest
        .post_json(
            &cpace_endpoint(enrollment_uuid, "msga"),
            sign_in_body(sign_in_token),
        )
        .await?;

    parse_msg_a(&decode64_loose(&response.msga)?)
}

/// Replies with `msgb` and expects the server to accept it.
async fn send_msg_b(
    msg_b: &[u8],
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: SuccessStatus = rest
        .put_json(
            &cpace_endpoint(enrollment_uuid, "msgb"),
            json!({
                "signInToken": sign_in_token,
                "msgb": BASE64URL_NOPAD.encode(msg_b),
            }),
        )
        .await?;

    expect_success(&response, "exchange credentials")
}

/// Waits for the enrolled device's `taga`, which only `verify_tag_a` looks at.
async fn get_tag_a(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
    timing: &Timing,
) -> Result<Vec<u8>, OnePasswordError> {
    let result: wire::CpaceTagA = post_json_until_result(
        &cpace_endpoint(enrollment_uuid, "taga"),
        sign_in_body(sign_in_token),
        rest,
        timing,
    )
    .await?;

    decode64_loose(&result.taga)
}

/// Replies with `tagb` and expects the server to accept it.
async fn send_tag_b(
    tag_b: &[u8],
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let response: SuccessStatus = rest
        .put_json(
            &cpace_endpoint(enrollment_uuid, "tagb"),
            json!({
                "signInToken": sign_in_token,
                "tagb": BASE64URL_NOPAD.encode(tag_b),
            }),
        )
        .await?;

    expect_success(&response, "submit tagb")
}

/// Waits for the credential bundle, still encrypted for the exchange key and so invisible to the
/// server that relays it.
async fn request_encrypted_credentials(
    sign_in_token: &str,
    enrollment_uuid: &str,
    rest: &RestClient,
    timing: &Timing,
) -> Result<EncryptedEnvelope, OnePasswordError> {
    let result: wire::SharedCredentials = post_json_until_result(
        &enrollment_endpoint(enrollment_uuid, "share/credentials"),
        sign_in_body(sign_in_token),
        rest,
        timing,
    )
    .await?;

    Ok(result.encrypted_credentials)
}

/// POSTs until the endpoint answers a body instead of the empty 200 it sends while the enrolled
/// device has not replied yet. The web frontend retries the same way.
async fn post_json_until_result<T: DeserializeOwned>(
    endpoint: &str,
    body: Value,
    rest: &RestClient,
    timing: &Timing,
) -> Result<T, OnePasswordError> {
    for _ in 0..timing.until_result_attempts {
        match rest.post_json_or_empty(endpoint, body.clone()).await? {
            Some(result) => return Ok(result),
            None => time::sleep(timing.until_result_delay).await,
        }
    }

    Err(OnePasswordError::Internal(format!(
        "failed to get a response from the server (endpoint: {endpoint})"
    )))
}

/// The body every CPace request carries besides the messages themselves.
fn sign_in_body(sign_in_token: &str) -> Value {
    json!({ "signInToken": sign_in_token })
}

/// The server confirms each CPace message with `success: 1`.
fn expect_success(response: &SuccessStatus, action: &str) -> Result<(), OnePasswordError> {
    if response.success != 1 {
        return Err(OnePasswordError::Internal(format!("failed to {action}")));
    }
    Ok(())
}

/// `v3/device/enrollments/{enrollmentUuid}/{method}`
fn enrollment_endpoint(enrollment_uuid: &str, method: &str) -> String {
    format!("v3/device/enrollments/{enrollment_uuid}/{method}")
}

/// The CPace endpoints, under the enrollment's `cpace` prefix.
fn cpace_endpoint(enrollment_uuid: &str, method: &str) -> String {
    enrollment_endpoint(enrollment_uuid, &format!("cpace/{method}"))
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use serde_json::{Value, json};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{
        super::test_support::{
            CpaceVectors, SIGN_IN_TOKEN, hex, hex_array, mock_enrolled_device, mock_msga, path,
            quick_timing, rest_client, vectors,
        },
        *,
    };

    fn msg_a() -> MsgA {
        parse_msg_a(vectors().cpace.msga_json.as_bytes()).expect("valid msga")
    }

    #[test]
    fn parses_msg_a() {
        let vectors = vectors().cpace;
        let msg_a = msg_a();

        assert_eq!(msg_a.original_message, vectors.msga_json.as_bytes());
        assert_eq!(msg_a.ad.version, 1);
        assert_eq!(msg_a.ad.salt, (1..=16).collect::<Vec<u8>>());
        assert_eq!(msg_a.ad.session_id, (100..116).collect::<Vec<u8>>());
        assert_eq!(
            BASE64URL_NOPAD.encode(&msg_a.ya.compress().to_bytes()),
            "IrCugkEa6t7w1_c8A8rYXtk4flTBrMStgtMSEf7qFUE"
        );
    }

    /// The vector's `msga_json` with the value at `pointer` replaced, or removed for `None`.
    fn edited_msg_a(pointer: &str, replacement: Option<Value>) -> Vec<u8> {
        let mut msg_a: Value =
            serde_json::from_str(&vectors().cpace.msga_json).expect("valid json");
        let (parent, key) = pointer.rsplit_once('/').expect("a pointer to a member");
        let parent = msg_a
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .expect("an existing object");
        match replacement {
            Some(value) => parent.insert(key.into(), value),
            None => parent.remove(key),
        };
        serde_json::to_vec(&msg_a).expect("serializes")
    }

    #[test]
    fn rejects_malformed_msg_a() {
        let point = |bytes: &[u8]| Some(json!(BASE64URL_NOPAD.encode(bytes)));

        let cases = [
            ("not json", b"not json".to_vec()),
            ("empty", Vec::new()),
            ("ya is not base64", edited_msg_a("/ya", Some(json!("***")))),
            ("ya is null", edited_msg_a("/ya", Some(Value::Null))),
            (
                "ya is not canonical",
                edited_msg_a("/ya", point(&[0xff; 32])),
            ),
            ("ya is too short", edited_msg_a("/ya", point(&[1; 31]))),
            ("ya is too long", edited_msg_a("/ya", point(&[1; 33]))),
            ("ya is the identity", edited_msg_a("/ya", point(&[0; 32]))),
            (
                "salt is not base64",
                edited_msg_a("/ad/salt", Some(json!("***"))),
            ),
            (
                "session id is above 255",
                edited_msg_a("/ad/session_id", Some(json!([100, 256]))),
            ),
            (
                "session id is negative",
                edited_msg_a("/ad/session_id", Some(json!([-1]))),
            ),
            (
                "session id is not an array",
                edited_msg_a("/ad/session_id", Some(json!("abc"))),
            ),
            ("ya is missing", edited_msg_a("/ya", None)),
            ("ad is missing", edited_msg_a("/ad", None)),
            ("version is missing", edited_msg_a("/ad/version", None)),
            ("salt is missing", edited_msg_a("/ad/salt", None)),
            (
                "session id is missing",
                edited_msg_a("/ad/session_id", None),
            ),
        ];

        for (name, json) in cases {
            assert!(parse_msg_a(&json).is_err(), "{name}");
        }
    }

    #[test]
    fn rejects_an_invalid_point_with_an_internal_error() {
        let json = edited_msg_a("/ya", Some(json!(BASE64URL_NOPAD.encode(&[0xff; 32]))));

        assert!(matches!(
            parse_msg_a(&json),
            Err(OnePasswordError::Internal(_))
        ));
    }

    #[test]
    fn writes_leb128_length_prefixes() {
        let table = vectors().leb128_prefix;
        assert!(!table.is_empty());

        for (length, prefix) in table {
            let data = vec![0xab; length];
            let mut buffer = Vec::new();
            write_leb128_prefixed(&mut buffer, &data);

            let (written_prefix, written_data) = buffer.split_at(buffer.len() - length);
            assert_eq!(HEXLOWER.encode(written_prefix), prefix, "length {length}");
            assert_eq!(written_data, data, "length {length}");
        }
    }

    #[test]
    fn calculates_passcode_hash() {
        let vectors = vectors().cpace;

        assert_eq!(
            HEXLOWER.encode(
                calculate_passcode_hash(&vectors.verification_code, &msg_a().ad.salt).as_slice()
            ),
            vectors.passcode_hash
        );
    }

    #[test]
    fn calculates_first_hash() {
        let vectors = vectors().cpace;

        let hash = calculate_first_hash(
            &vectors.username,
            &vectors.sign_in_address,
            &vectors.enrollment_uuid,
            &msg_a(),
        );

        assert_eq!(HEXLOWER.encode(&hash), vectors.first_hash);
    }

    #[test]
    fn calculates_second_hash() {
        let vectors = vectors().cpace;

        let hash = calculate_second_hash(
            &hex(&vectors.first_hash),
            &hex(&vectors.passcode_hash),
            &msg_a(),
        );

        assert_eq!(HEXLOWER.encode(&hash), vectors.second_hash);
    }

    #[test]
    fn calculates_msg_b() {
        let vectors = vectors().cpace;

        let msg_b = calculate_msg_b(
            &vectors.username,
            &vectors.sign_in_address,
            &vectors.enrollment_uuid,
            &vectors.verification_code,
            &msg_a(),
            &hex_array(&vectors.client_secret),
        );

        assert_eq!(HEXLOWER.encode(&msg_b), vectors.msgb);
    }

    #[test]
    fn calculates_auth_a() {
        let vectors = vectors().cpace;

        let auth_a = calculate_auth_a_hash(&msg_a(), &hex_array(&vectors.client_secret));

        assert_eq!(HEXLOWER.encode(auth_a.as_slice()), vectors.auth_a);
    }

    #[test]
    fn calculates_auth_b() {
        let vectors = vectors().cpace;

        let auth_b = calculate_auth_b_hash(&hex(&vectors.auth_a), &msg_a(), &hex(&vectors.msgb));

        assert_eq!(HEXLOWER.encode(auth_b.as_slice()), vectors.auth_b);
    }

    #[test]
    fn calculates_tag_b() {
        let vectors = vectors().cpace;

        let tag_b = calculate_tag_b(&hex(&vectors.auth_b), &hex(&vectors.msgb));

        assert_eq!(HEXLOWER.encode(&tag_b), vectors.tag_b);
    }

    #[test]
    fn calculates_auth_b_and_tag_b_together() {
        let vectors = vectors().cpace;

        let (auth_b, tag_b) = calculate_auth_b_tag_b(
            &hex_array(&vectors.client_secret),
            &msg_a(),
            &hex(&vectors.msgb),
        );

        assert_eq!(HEXLOWER.encode(auth_b.as_slice()), vectors.auth_b);
        assert_eq!(HEXLOWER.encode(&tag_b), vectors.tag_b);
    }

    #[test]
    fn derives_exchange_key() {
        let vectors = vectors().cpace;

        let key = derive_exchange_key(&hex(&vectors.auth_b));

        assert_eq!(HEXLOWER.encode(key.as_slice()), vectors.exchange_key);
    }

    #[test]
    fn decrypts_credentials() {
        let vectors = vectors().cpace;

        let bundle =
            decrypt_credentials(&vectors.encrypted_credentials, &hex(&vectors.exchange_key))
                .expect("decrypts");

        assert_eq!(*bundle.srpx, "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8");
        assert_eq!(*bundle.auk.k, "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM");
    }

    #[test]
    fn decrypting_credentials_fails_with_another_key() {
        let vectors = vectors().cpace;

        assert!(decrypt_credentials(&vectors.encrypted_credentials, &[0; 32]).is_err());
    }

    #[test]
    fn decrypting_credentials_fails_with_another_associated_data() {
        let vectors = vectors().cpace;
        let key = AesKey::new(TRANSPORT_KEY_ID, hex(&vectors.exchange_key));
        let envelope = key
            .encrypt_with_aad(
                vectors.credential_bundle_json.as_bytes(),
                &[7; 12],
                b"other",
            )
            .expect("encrypts");

        assert!(decrypt_credentials(&envelope, &key.key).is_err());
    }

    #[test]
    fn decrypting_credentials_fails_on_malformed_bundle() {
        let vectors = vectors().cpace;
        let key = AesKey::new(TRANSPORT_KEY_ID, hex(&vectors.exchange_key));
        let envelope = key
            .encrypt_with_aad(br#"{"srpx":"x"}"#, &[7; 12], CREDENTIAL_BUNDLE_AAD)
            .expect("encrypts");

        assert!(matches!(
            decrypt_credentials(&envelope, &key.key),
            Err(OnePasswordError::Parse)
        ));
    }

    /// The enrolled device holds `ya_secret`, and the vectors have to be consistent with it.
    #[test]
    fn ya_is_the_generator_times_the_enrolled_secret() {
        let vectors = vectors().cpace;
        let ya_scalar = Scalar::from_bytes_mod_order_wide(&hex_array(&vectors.ya_secret));
        let generator = RistrettoPoint::from_uniform_bytes(&hex_array(&vectors.second_hash));

        assert_eq!((generator * ya_scalar).compress(), msg_a().ya.compress());
    }

    #[test]
    fn enrolled_device_derives_the_same_auth_a() {
        let vectors = vectors().cpace;
        let ya_scalar = Scalar::from_bytes_mod_order_wide(&hex_array(&vectors.ya_secret));
        let msg_b = decompress_point(&hex(&vectors.msgb)).expect("a valid point");

        assert_eq!(
            HEXLOWER.encode(&(msg_b * ya_scalar).compress().to_bytes()),
            vectors.auth_a
        );
    }

    async fn run_cpace(
        server: &MockServer,
        vectors: &CpaceVectors,
        timing: &Timing,
    ) -> Result<CredentialBundle, OnePasswordError> {
        perform_cpace_with_client_secret(
            &vectors.username,
            &vectors.sign_in_address,
            SIGN_IN_TOKEN,
            &vectors.enrollment_uuid,
            &vectors.verification_code,
            &hex_array(&vectors.client_secret),
            &rest_client(server),
            timing,
        )
        .await
    }

    #[tokio::test]
    async fn perform_cpace_sends_the_vector_messages_and_returns_the_bundle() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_enrolled_device(&server, &vectors).await;

        let bundle = run_cpace(&server, &vectors, &quick_timing())
            .await
            .expect("the exchange succeeds");

        assert_eq!(*bundle.srpx, "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8");
        assert_eq!(*bundle.auk.k, "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM");
        server.verify().await;
    }

    #[tokio::test]
    async fn a_rejected_msgb_is_an_error() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_msga(&server, &vectors).await;
        server
            .register(
                Mock::given(matchers::method("PUT"))
                    .and(matchers::path(path(&vectors, "cpace/msgb")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 0})))
                    .expect(1),
            )
            .await;

        let error = run_cpace(&server, &vectors, &quick_timing())
            .await
            .err()
            .expect("the exchange fails");

        assert!(matches!(
            &error,
            OnePasswordError::Internal(message) if message.contains("exchange credentials")
        ));
        server.verify().await;
    }

    #[tokio::test]
    async fn an_error_status_on_msga_is_returned_as_is() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path(path(&vectors, "cpace/msga")))
                    .respond_with(ResponseTemplate::new(503))
                    .expect(1),
            )
            .await;

        let error = run_cpace(&server, &vectors, &quick_timing())
            .await
            .err()
            .expect("the exchange fails");

        assert!(matches!(
            &error,
            OnePasswordError::UnexpectedStatus { endpoint, status: 503 }
                if *endpoint == format!("v3/device/enrollments/{}/cpace/msga", vectors.enrollment_uuid)
        ));
        server.verify().await;
    }

    #[tokio::test]
    async fn exhausting_the_empty_answers_is_an_error() {
        let vectors = vectors().cpace;
        let server = MockServer::start().await;
        mock_msga(&server, &vectors).await;
        server
            .register(
                Mock::given(matchers::method("PUT"))
                    .and(matchers::path(path(&vectors, "cpace/msgb")))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                    .expect(1),
            )
            .await;
        server
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path(path(&vectors, "cpace/taga")))
                    .respond_with(ResponseTemplate::new(200))
                    .expect(3),
            )
            .await;

        let timing = Timing {
            until_result_attempts: 3,
            ..quick_timing()
        };
        let error = run_cpace(&server, &vectors, &timing)
            .await
            .err()
            .expect("the exchange fails");

        assert!(matches!(
            &error,
            OnePasswordError::Internal(message)
                if message.contains(&format!("v3/device/enrollments/{}/cpace/taga", vectors.enrollment_uuid))
        ));
        server.verify().await;
    }
}
