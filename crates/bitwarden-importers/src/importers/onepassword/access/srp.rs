//! SRP-4096: the A/B exchange with the server and the crypto behind it.

use std::sync::LazyLock;

use crypto_bigint::{
    BoxedUint, ConcatenatingMul, Odd, Resize,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rand::Rng;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{
    account_key::AccountKey,
    credentials::Credentials,
    error::OnePasswordError,
    kdf,
    opdata::AesKey,
    rest::RestClient,
    wire::{AForB, ServerHash},
};

const SRP_METHOD: &str = "SRPg-4096";
const AUTH_ENDPOINT: &str = "v2/auth";
const CONFIRM_KEY_ENDPOINT: &str = "v2/auth/confirm-key";

/// The width of the SRP group, and so of every value reduced modulo it.
const N_BITS: u32 = 4096;

/// The width of the SHA-256 values SRP uses as scalars: `u`, `k` and `x`.
const SCALAR_BITS: u32 = 256;

/// The 4096-bit SRP group prime (RFC 3526).
static N: LazyLock<Odd<BoxedUint>> = LazyLock::new(|| {
    Odd::new(BoxedUint::from_be_hex(N_HEX, N_BITS).expect("N_HEX is a compile-time hex constant"))
        .expect("the SRP group prime is odd")
});

/// The Montgomery form of [`N`], built once.
static N_PARAMS: LazyLock<BoxedMontyParams> =
    LazyLock::new(|| BoxedMontyParams::new_vartime(N.clone()));

/// The SRP group generator.
static G: LazyLock<BoxedUint> = LazyLock::new(|| BoxedUint::from(5u32));

const N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22",
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6",
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D",
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB",
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603",
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D",
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864",
    "D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C",
    "1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D",
    "99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9",
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF",
);

/// The account's public SRP parameters, as returned by `v3/auth/start`.
///
/// Validated on construction, so [`compute_x`] cannot fail on an unsupported method or a zero
/// iteration count. These are public KDF parameters and carry no secret.
#[derive(Debug, PartialEq)]
pub(super) struct SrpInfo {
    srp_method: String,
    key_method: String,
    iterations: u32,
    salt: Vec<u8>,
}

impl SrpInfo {
    /// Rejects parameters this module cannot honour.
    pub(super) fn new(
        srp_method: String,
        key_method: String,
        iterations: u32,
        salt: Vec<u8>,
    ) -> Result<SrpInfo, OnePasswordError> {
        if srp_method != SRP_METHOD {
            return Err(OnePasswordError::Unsupported(format!(
                "Method '{srp_method}' is not supported"
            )));
        }
        if iterations < kdf::MIN_PBKDF2_ITERATIONS {
            return Err(OnePasswordError::Unsupported(format!(
                "{iterations} iterations is below the minimum of {}",
                kdf::MIN_PBKDF2_ITERATIONS
            )));
        }

        kdf::validate_pbes2(&key_method)?;

        Ok(SrpInfo {
            srp_method,
            key_method,
            iterations,
            salt,
        })
    }

    /// The salt, also mixed into the client verification hash.
    pub(super) fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// Runs the SRP exchange and labels the resulting key with the session id.
pub(super) async fn perform_and_verify(
    credentials: &Credentials,
    account_key: &AccountKey,
    srp_info: &SrpInfo,
    session_id: &str,
    rest: &RestClient,
) -> Result<AesKey, OnePasswordError> {
    let key = perform(
        &generate_secret_a(),
        credentials,
        account_key,
        srp_info,
        rest,
    )
    .await?;
    Ok(AesKey::new(session_id, key.to_vec()))
}

/// The exchange itself, with `secret_a` taken as an argument so tests can pin it.
async fn perform(
    secret_a: &BoxedUint,
    credentials: &Credentials,
    account_key: &AccountKey,
    srp_info: &SrpInfo,
    rest: &RestClient,
) -> Result<[u8; 32], OnePasswordError> {
    // The password and the Secret Key stretched into the SRP private value.
    let srp_x = compute_x(credentials, account_key, srp_info)?;

    // Trade our public ephemeral for the server's.
    let shared_a = compute_shared_a(secret_a);
    let shared_b = exchange_a_for_b(&shared_a, rest).await?;

    // A B divisible by N would collapse the session key to a value the server picked.
    validate_b(&shared_b)?;

    // Both sides reach the same key without the password ever crossing the wire.
    let session_key = compute_key(secret_a, &shared_a, &shared_b, &srp_x);

    // Prove to the server that we hold it.
    verify_key(
        &session_key,
        &credentials.username,
        &account_key.uuid,
        srp_info.salt(),
        &shared_a,
        &shared_b,
        rest,
    )
    .await?;

    Ok(session_key)
}

/// Generates the ephemeral secret `a` as a random 256-bit value.
fn generate_secret_a() -> BoxedUint {
    let mut bytes = [0u8; 32];
    bitwarden_random::rng().fill_bytes(&mut bytes);
    scalar(&bytes)
}

/// `A = g^a mod N`.
fn compute_shared_a(secret_a: &BoxedUint) -> BoxedUint {
    mod_pow(&G, secret_a)
}

/// Rejects a server `B` that is 0 or 1 modulo `N`, the two values the web client refuses.
fn validate_b(shared_b: &BoxedUint) -> Result<(), OnePasswordError> {
    let reduced = shared_b.rem(N.as_nz_ref());
    if bool::from(reduced.is_zero() | reduced.is_one()) {
        return Err(OnePasswordError::Internal(
            "Shared B validation failed".into(),
        ));
    }
    Ok(())
}

/// Sends `userA` and returns the server's `userB`.
async fn exchange_a_for_b(
    shared_a: &BoxedUint,
    rest: &RestClient,
) -> Result<BoxedUint, OnePasswordError> {
    let response: AForB = rest
        .post_json(AUTH_ENDPOINT, json!({ "userA": to_server_hex(shared_a) }))
        .await?;
    from_server_hex(&response.b)
}

/// `base ^ exponent mod N`, constant time in `exponent`.
fn mod_pow(base: &BoxedUint, exponent: &BoxedUint) -> BoxedUint {
    BoxedMontyForm::new(base.resize(N_BITS), &N_PARAMS)
        .pow(exponent)
        .retrieve()
}

/// A SHA-256 output as an SRP scalar.
fn scalar(hash: &[u8]) -> BoxedUint {
    BoxedUint::from_be_slice(hash, SCALAR_BITS).expect("an SRP scalar is a 32-byte hash")
}

/// Computes the SRP session key `K`.
fn compute_key(
    secret_a: &BoxedUint,
    shared_a: &BoxedUint,
    shared_b: &BoxedUint,
    srp_x: &[u8],
) -> [u8; 32] {
    // The multiplier k = H(N, g), always
    // 3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2 for this group.
    let mut g_mod_n_input = to_compatible_byte_array(&N);
    g_mod_n_input.extend_from_slice(&mod_n_bytes(&G));
    let g_mod_n = sha256(&g_mod_n_input);

    // The scrambling parameter u = H(A, B), which ties the key to both ephemerals.
    let mut ab = mod_n_bytes(shared_a);
    ab.extend_from_slice(&mod_n_bytes(shared_b));
    let ab_sha256 = sha256(&ab);

    // a + u*x, the half only we can build.
    let x = scalar(srp_x);
    let exponent = scalar(&ab_sha256)
        .concatenating_mul(&x)
        .wrapping_add(secret_a);

    // shared_b - k*g^x strips the verifier term out of the server's ephemeral, leaving g^b. The
    // difference is almost always negative, so each operand is reduced mod N first and `sub_mod`
    // adds N back when the subtraction underflows.
    let k_g_pow_x = mod_pow(&G, &x)
        .concatenating_mul(&scalar(&g_mod_n))
        .rem(N.as_nz_ref());
    let base = shared_b
        .rem(N.as_nz_ref())
        .sub_mod(&k_g_pow_x, N.as_nz_ref());

    // K is the premaster secret hashed in the server's hex encoding.
    sha256(to_server_hex(&mod_pow(&base, &exponent)).as_bytes())
}

/// Hex in the exact format 1Password's server expects: lowercase, with all leading zero nibbles
/// stripped. The output may be odd-length; that is intentional. Both `userA` (sent over the wire)
/// and `u` (the SRP shared secret hashed into the session key) use this encoding, and changing it
/// would break wire compatibility or session-key agreement with the server.
///
/// Mirrors the official 1Password JS client (webapi bundle):
///   `q = e => e.toString(16).replace(/^(0x)?0*/, "")`
fn to_server_hex(value: &BoxedUint) -> String {
    let hex = HEXLOWER.encode(&value.to_be_bytes());
    match hex.trim_start_matches('0') {
        "" => "0".to_string(),
        trimmed => trimmed.to_string(),
    }
}

/// Parses a value the server sent in the encoding above.
fn from_server_hex(hex: &str) -> Result<BoxedUint, OnePasswordError> {
    let invalid = || OnePasswordError::Internal("invalid shared value from server".into());

    // The ASCII check is load bearing: padding below counts characters while `from_be_hex` asserts
    // on byte length, so a multi-byte character would overshoot the width and panic.
    if hex.is_empty() || hex.len() > N_HEX.len() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }

    // The server strips leading zeros, `from_be_hex` wants the full width of the group.
    let padded = format!("{hex:0>width$}", width = N_HEX.len());
    BoxedUint::from_be_hex(&padded, N_BITS)
        .into_option()
        .ok_or_else(invalid)
}

/// `value mod N` as big-endian bytes, always the full width of `N`.
fn mod_n_bytes(value: &BoxedUint) -> Vec<u8> {
    value.rem(N.as_nz_ref()).to_be_bytes().into_vec()
}

/// Big-endian bytes with leading zeros stripped, the encoding the server hashes over.
fn to_compatible_byte_array(value: &BoxedUint) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    match bytes.iter().position(|byte| *byte != 0) {
        Some(first_significant) => bytes[first_significant..].to_vec(),
        None => vec![0],
    }
}

/// `SHA256(SHA256(uuid) || SHA256(lower(nfkd(username))))`, url-safe base64.
fn calculate_identity(username: &str, key_uuid: &str) -> String {
    let username = kdf::normalize_identity_username(username);

    let mut buffer = Vec::with_capacity(64);
    buffer.extend_from_slice(&sha256(key_uuid.as_bytes()));
    buffer.extend_from_slice(&sha256(username.as_bytes()));
    BASE64URL_NOPAD.encode(&sha256(&buffer))
}

/// Sends the client verification hash to confirm the session key, then checks the server's answer.
async fn verify_key(
    session_key: &[u8],
    username: &str,
    key_uuid: &str,
    salt: &[u8],
    shared_a: &BoxedUint,
    shared_b: &BoxedUint,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let client_hash =
        calculate_client_hash(session_key, username, key_uuid, salt, shared_a, shared_b);
    let response: ServerHash = rest
        .post_json(
            CONFIRM_KEY_ENDPOINT,
            json!({ "clientVerifyHash": BASE64URL_NOPAD.encode(&client_hash) }),
        )
        .await?;

    // The only step that authenticates the server: nothing but a party holding the same session key
    // can produce this hash.
    let expected = calculate_server_hash(shared_a, &client_hash, session_key);
    if response.server_verify_hash != BASE64URL_NOPAD.encode(&expected) {
        return Err(OnePasswordError::Internal(
            "the server verification hash does not match".into(),
        ));
    }
    Ok(())
}

/// The server's answer to [`calculate_client_hash`]: `H(A || M1 || K)`, where `M1` is the client
/// hash we just sent. `A` uses the same leading-zero-stripped encoding as the client hash.
fn calculate_server_hash(shared_a: &BoxedUint, client_hash: &[u8], session_key: &[u8]) -> [u8; 32] {
    let mut buffer = to_compatible_byte_array(shared_a);
    buffer.extend_from_slice(client_hash);
    buffer.extend_from_slice(session_key);

    sha256(&buffer)
}

/// The client verification hash sent to `v2/auth/confirm-key`:
/// `H(H(N) xor H(g) || H(I) || s || A || B || K)`.
fn calculate_client_hash(
    session_key: &[u8],
    username: &str,
    key_uuid: &str,
    salt: &[u8],
    shared_a: &BoxedUint,
    shared_b: &BoxedUint,
) -> [u8; 32] {
    let sirp_n = sha256(&to_compatible_byte_array(&N));
    let sirp_g = sha256(&to_compatible_byte_array(&G));
    let identity = sha256(calculate_identity(username, key_uuid).as_bytes());

    // Opens with the group both sides agreed on.
    let mut buffer = Vec::new();
    for (a, b) in sirp_n.iter().zip(sirp_g.iter()) {
        buffer.push(a ^ b);
    }

    // Then who we are, the salt, both ephemerals, and the key only we and the server derived.
    buffer.extend_from_slice(&identity);
    buffer.extend_from_slice(salt);
    buffer.extend_from_slice(&to_compatible_byte_array(shared_a));
    buffer.extend_from_slice(&to_compatible_byte_array(shared_b));
    buffer.extend_from_slice(session_key);

    sha256(&buffer)
}

/// Derives SRP `x`, which proves we know the password without sending it.
fn compute_x(
    credentials: &Credentials,
    account_key: &AccountKey,
    srp_info: &SrpInfo,
) -> Result<[u8; 32], OnePasswordError> {
    let k1 = kdf::hkdf_sha256(
        &srp_info.srp_method,
        &srp_info.salt,
        kdf::normalize_username(&credentials.username).as_bytes(),
    );
    let k2 = kdf::pbes2(
        &kdf::normalize_password(&credentials.password),
        &k1,
        srp_info.iterations,
    );
    account_key.combine_with(&k2)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::new_http_client;
    use data_encoding::HEXLOWER;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{
        super::sign_in::{SignInAddress, SignInDomain},
        *,
    };

    const SHARED_A: &str = "843c9c4977cf9c767452c90708c3dbdf3508c0016f8a56abc20c2e654dbd74c2c04b9412528a0927f499b245f9ad6742052662de2f725bf2a6c84913062842b4b2aaa8d41598c0d11424745bbae928d8e00e3c2c831c5ae90e128b719adb8be3845561186826462f0dbbdba272666c039f075b3da18c866c61a208cb9aed5ade03e6570818b7146c789f2e2928958ec7bebffbf2cc06cbb83b77ed80eae95e194502dead2e945e885d145d4521b74b8669211ffe718b20f04253d19550e0f9e8f1f0381caa2200223904a94d1e70f7db7cfa7d10d415bf7571f656a2e7bac3d142a2fa60b5a4e2fec4a82348fb46e03b65938f960373eefb95e50b1dd38134593b2f3ed0a19ae8684b4b54a04e0e022e01abc03072aa2e0096b209eaadb8dae57acd607a46e27bc5bfa66c3887e03441b4628135f830d1d78c7a60366d88cb42ed7ddd2dc32049f9dd3a1f459b610d41d25e8615f3271fcadcd37bf1b13c84c049d57d14ded500290b430c33d1d1dc3b04af66862ca3b4d501e2827355f68eaaf063a131c2436aa0a75519b7ac4d79845b6235898dcd9bef1093618b7c5bc5d73a7fc2a5ef8bca638e922152e459e89652b4a7d7d19cfd24de93f72f20e3a6f4325abf5ca1aec3ef3f392cc356c80b72e43a577775d2bf613b60d9f46d130e9881534e7548241e612901f61d5c5acb62100b8371c8dc42747437cd9ddcf9debf";
    const SHARED_B: &str = "7112742e3035eca37656e1ad2171516e3e154bcbabbcb5f52787aa53ad882cffd8e952bd67dbc8059025be23a0b86914bf8ec4c08cac0b3448a99d8c097e4b0c6942870b2cd2c56a58499c81c294bf2f64de408535f0a36ba416177519dcb5a54b7a403459abb1bfe8aecb92048e84a55ba48f1672f6ee3f30abff81868e88c8bb25c7c17292e535f91debda167af8f12d1e1073a48a9257b443dacd8ba47270051b03940117d2cec29f6521a3e78e575634db5bc87d479a4327db1b30578c90553edd3de58af08e9157a11b352b0bd7fca70d469809b3d516fed4edc989b78c6f330e553947111c563cb8c8ff184179cf7b8733494e16f3e38ed7cd42651c5bb4d81548c4b320996445b6f1a4c34a6211b5f65e561c04009c7422e289d7035085e21258513040b16bea0d3e91304879fa61f48af4daefce65d0917e4af106d868c6189dfd9031c8a3b2d97fa2a50445d6a818341fed7ad2a986f5aa691626426dc2b1047e1db8a1984f8fda526f21e825df6b4cc60cd31300181a3782e53d039f85164e417b419cde581826b08887f25277f9f7c0933aa596f5a4bb27af7bffb095027e326d1c02544357eaa553ac93b564bb5953b8fc498044d65b8003ad93f95c319ce6af0a0327151935e860c3e5dad17cd65ae4318e76905ce2a3ae239c12ab207313af3c0c7744e7aee2584043ae71dfc3e376bf747f92fa5a94bd36cb";

    fn big(hex: &str) -> BoxedUint {
        from_server_hex(hex).expect("valid hex")
    }

    #[test]
    fn to_server_hex_returns_hex_string() {
        let cases: [(u32, &str); 8] = [
            (0, "0"),
            (1, "1"),
            (0xD, "d"),
            (0xDE, "de"),
            (0xDEA, "dea"),
            (0xDEAD, "dead"),
            (0x80, "80"),
            (0xFF, "ff"),
        ];
        for (number, expected) in cases {
            assert_eq!(to_server_hex(&BoxedUint::from(number)), expected);
        }
    }

    #[test]
    fn from_server_hex_rejects_malformed_values() {
        for input in ["", "not hex", "é", &"f".repeat(N_HEX.len() + 1)] {
            from_server_hex(input).expect_err("malformed values are rejected");
        }
    }

    /// A `B` congruent to 0 or 1 collapses the session key to a value the server picked.
    #[test]
    fn validate_b_rejects_zero_and_one_mod_n() {
        let n = big(N_HEX);
        for value in [big("0"), big("1"), n.clone(), n.wrapping_add(big("1"))] {
            validate_b(&value).expect_err("B must not be 0 or 1 mod N");
        }

        validate_b(&big(SHARED_B)).expect("a normal B is accepted");
    }

    #[test]
    fn compute_key_returns_key() {
        let secret_a = BoxedUint::from_be_hex(
            "37bbf7bf6a51f902673556ea6a2db91dd9987554ab74c3bc089b213693d9c06e",
            SCALAR_BITS,
        )
        .expect("valid hex");
        let srp_x = HEXLOWER
            .decode(b"9559afc0581390b1190a57dd281729baa237760982c7369c4c14d42157703a0f")
            .expect("valid hex");

        let key = compute_key(&secret_a, &big(SHARED_A), &big(SHARED_B), &srp_x);

        assert_eq!(
            HEXLOWER.encode(&key),
            "9d17458228928fc1107668113026390d502a40954e3e6a83513acbb2e1f8fedc"
        );
    }

    #[test]
    fn calculate_client_hash_returns_hash() {
        let session_key = HEXLOWER
            .decode(b"9d17458228928fc1107668113026390d502a40954e3e6a83513acbb2e1f8fedc")
            .expect("valid hex");
        let salt = HEXLOWER
            .decode(b"c813e48eb6e88c7557c9a70fcbda0fbc")
            .expect("valid hex");

        let hash = calculate_client_hash(
            &session_key,
            "user@example.com",
            "P9JQCW",
            &salt,
            &big(SHARED_A),
            &big(SHARED_B),
        );

        assert_eq!(
            HEXLOWER.encode(&hash),
            "e74d30467ccdfdf7d61973b9a94f88bd2b7155ba304138f5d02e2078c3a124fa"
        );
    }

    #[test]
    fn compute_x_returns_x() {
        let salt =
            super::super::opdata::decode64_loose("-JLqTVQLjQg08LWZ0gyuUA").expect("valid salt");
        let account_key =
            AccountKey::parse("A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9").expect("valid account key");

        let srp_info = SrpInfo::new("SRPg-4096".into(), "PBES2g-HS256".into(), 100000, salt)
            .expect("supported parameters");

        let credentials = Credentials {
            username: "username".into(),
            password: "password".into(),
            account_key: "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9".into(),
            sign_in_address: SignInAddress::new("my", SignInDomain::Global)
                .expect("a valid subdomain"),
            device_uuid: "device-uuid".into(),
        };

        let x = compute_x(&credentials, &account_key, &srp_info).expect("derivation succeeds");

        assert_eq!(
            HEXLOWER.encode(&x),
            "e7e14f282b01332cc193dc42f8501e3ffe8afdbf4b431ed4bfd885ff0bdfecf3"
        );
    }

    /// Pinned against the web client's `recieveServerHash`, which hashes
    /// `z(bigA) || m || rawKey`.
    #[test]
    fn calculate_server_hash_returns_hash() {
        let client_hash = HEXLOWER
            .decode(b"e74d30467ccdfdf7d61973b9a94f88bd2b7155ba304138f5d02e2078c3a124fa")
            .expect("valid hex");
        let session_key = HEXLOWER
            .decode(b"9d17458228928fc1107668113026390d502a40954e3e6a83513acbb2e1f8fedc")
            .expect("valid hex");

        let hash = calculate_server_hash(&big(SHARED_A), &client_hash, &session_key);

        assert_eq!(
            HEXLOWER.encode(&hash),
            "e3ebd2e43efdc593960267f26b8a149e4368a5d5e963995ef9ceb6820307d6f9"
        );
    }

    const VERIFY_SESSION_KEY: [u8; 32] = [0u8; 32];
    const VERIFY_USERNAME: &str = "user@example.com";
    const VERIFY_KEY_UUID: &str = "RTN9SA";
    const VERIFY_SALT: &[u8] = b"salt";

    fn verify_ephemerals() -> (BoxedUint, BoxedUint) {
        (BoxedUint::from(2u32), BoxedUint::from(3u32))
    }

    /// Runs `verify_key` against a server that answers with `server_hash`.
    async fn run_verify_key(server_hash: &str) -> Result<(), OnePasswordError> {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v2/auth/confirm-key"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({ "serverVerifyHash": server_hash })),
                    )
                    .expect(1),
            )
            .await;
        let rest = RestClient::new(
            new_http_client(),
            format!("http://{}/api", server.address()),
            "client-id",
            "user-agent",
            "op-user-agent",
        )
        .expect("valid headers");

        let (shared_a, shared_b) = verify_ephemerals();
        let result = verify_key(
            &VERIFY_SESSION_KEY,
            VERIFY_USERNAME,
            VERIFY_KEY_UUID,
            VERIFY_SALT,
            &shared_a,
            &shared_b,
            &rest,
        )
        .await;

        server.verify().await;
        result
    }

    #[tokio::test]
    async fn verify_key_accepts_a_matching_server_hash() {
        let (shared_a, shared_b) = verify_ephemerals();
        let client_hash = calculate_client_hash(
            &VERIFY_SESSION_KEY,
            VERIFY_USERNAME,
            VERIFY_KEY_UUID,
            VERIFY_SALT,
            &shared_a,
            &shared_b,
        );
        let server_hash = BASE64URL_NOPAD.encode(&calculate_server_hash(
            &shared_a,
            &client_hash,
            &VERIFY_SESSION_KEY,
        ));

        run_verify_key(&server_hash)
            .await
            .expect("the server proved it holds the session key");
    }

    #[tokio::test]
    async fn verify_key_rejects_a_server_hash_it_did_not_expect() {
        for server_hash in ["", "not-the-hash"] {
            let error = run_verify_key(server_hash)
                .await
                .expect_err("the server did not prove it holds the session key");

            assert!(
                error.to_string().contains("does not match"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn srp_info_rejects_unsupported_parameters() {
        let bad_method = SrpInfo::new("SRPg-2048".into(), "PBES2g-HS256".into(), 100000, vec![])
            .expect_err("only SRPg-4096 is supported");
        assert!(bad_method.to_string().contains("SRPg-2048"));

        let too_few = SrpInfo::new("SRPg-4096".into(), "PBES2g-HS256".into(), 9999, vec![])
            .expect_err("a count below the floor is rejected");
        assert!(too_few.to_string().contains("9999 iterations"));

        let bad_key_method =
            SrpInfo::new("SRPg-4096".into(), "PBES2g-HS512".into(), 100000, vec![])
                .expect_err("only the SHA-256 variants are supported");
        assert!(bad_key_method.to_string().contains("PBES2g-HS512"));
    }
}
