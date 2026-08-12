//! SRP-4096: the A/B exchange with the server and the crypto behind it.

use std::sync::LazyLock;

use data_encoding::BASE64URL_NOPAD;
use num_bigint::{BigInt, BigUint, Sign};
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
const G: u32 = 5;
const AUTH_ENDPOINT: &str = "v2/auth";
const CONFIRM_KEY_ENDPOINT: &str = "v2/auth/confirm-key";

/// The 4096-bit SRP group prime (RFC 3526).
static N: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("N_HEX is a compile-time hex constant")
});

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
pub struct SrpInfo {
    srp_method: String,
    key_method: String,
    iterations: u32,
    salt: Vec<u8>,
}

impl SrpInfo {
    /// Rejects parameters this module cannot honour.
    pub fn new(
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
        if iterations == 0 {
            return Err(OnePasswordError::Unsupported(
                "0 iterations is not supported".into(),
            ));
        }

        Ok(SrpInfo {
            srp_method,
            key_method,
            iterations,
            salt,
        })
    }

    /// The salt, also mixed into the client verification hash.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// Runs the SRP exchange and labels the resulting key with the session id.
pub async fn perform_and_verify(
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
    secret_a: &BigUint,
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
fn generate_secret_a() -> BigUint {
    let mut bytes = [0u8; 32];
    bitwarden_random::rng().fill_bytes(&mut bytes);
    BigUint::from_bytes_be(&bytes)
}

/// `A = g^a mod N`.
fn compute_shared_a(secret_a: &BigUint) -> BigUint {
    BigUint::from(G).modpow(secret_a, &N)
}

/// Rejects a server `B` that is a multiple of `N`.
fn validate_b(shared_b: &BigUint) -> Result<(), OnePasswordError> {
    if shared_b % &*N == BigUint::from(0u32) {
        return Err(OnePasswordError::Internal(
            "Shared B validation failed".into(),
        ));
    }
    Ok(())
}

/// Sends `userA` and returns the server's `userB`.
async fn exchange_a_for_b(
    shared_a: &BigUint,
    rest: &RestClient,
) -> Result<BigUint, OnePasswordError> {
    let response: AForB = rest
        .post_json(
            AUTH_ENDPOINT,
            json!({ "userA": to_server_hex(&BigInt::from(shared_a.clone())) }),
        )
        .await?;
    from_server_hex(&response.b)
}

/// Computes the SRP session key `K`.
fn compute_key(
    secret_a: &BigUint,
    shared_a: &BigUint,
    shared_b: &BigUint,
    srp_x: &[u8],
) -> [u8; 32] {
    let n = &*N;

    // The multiplier k = H(N, g), always
    // 3509477ea9fca66eadb7cf7b1bd0eb508f54d3989a9c988006a7d0b338374dd2 for this group.
    let mut g_mod_n_input = to_compatible_byte_array(n);
    g_mod_n_input.extend_from_slice(&mod_bytes(&BigUint::from(G), n));
    let g_mod_n = sha256(&g_mod_n_input);

    // The scrambling parameter u = H(A, B), which ties the key to both ephemerals.
    let mut ab = mod_bytes(shared_a, n);
    ab.extend_from_slice(&mod_bytes(shared_b, n));
    let ab_sha256 = sha256(&ab);

    // a + u*x, the half only we can build.
    let x = BigUint::from_bytes_be(srp_x);
    let exponent = secret_a.clone() + BigUint::from_bytes_be(&ab_sha256) * &x;

    // B - k*g^x, which strips the server's verifier back out of B.
    let g_pow_x = BigUint::from(G).modpow(&x, n);
    let g_mod_n_int = BigUint::from_bytes_be(&g_mod_n);
    let base = BigInt::from(shared_b.clone()) - BigInt::from(&g_pow_x * &g_mod_n_int);

    // That subtraction can go negative, and modpow needs a base in [0, N).
    let n_int = BigInt::from(n.clone());
    let base = ((&base % &n_int) + &n_int) % &n_int;
    let base = base
        .to_biguint()
        .expect("value reduced into [0, N) is non-negative");

    // K is the premaster secret hashed in the server's hex encoding.
    let premaster = base.modpow(&exponent, n);
    sha256(to_server_hex(&BigInt::from(premaster)).as_bytes())
}

/// `BigInt` to hex in the exact format 1Password's server expects: lowercase, with all leading zero
/// nibbles stripped. The output may be odd-length; that is intentional. Both `userA` (sent over the
/// wire) and `u` (the SRP shared secret hashed into the session key) use this encoding, and
/// changing it would break wire compatibility or session-key agreement with the server.
///
/// Mirrors the official 1Password JS client (webapi bundle):
///   `q = e => e.toString(16).replace(/^(0x)?0*/, "")`
fn to_server_hex(value: &BigInt) -> String {
    match value.sign() {
        Sign::NoSign => "0".to_string(),
        Sign::Plus => format!("{:x}", value.magnitude()),
        Sign::Minus => format!("-{:x}", value.magnitude()),
    }
}

/// Parses a value the server sent in the encoding above.
fn from_server_hex(hex: &str) -> Result<BigUint, OnePasswordError> {
    BigUint::parse_bytes(hex.as_bytes(), 16)
        .ok_or_else(|| OnePasswordError::Internal("invalid shared value from server".into()))
}

/// Fixed-width big-endian bytes of `dividend mod divisor`, padded to the divisor's byte length.
fn mod_bytes(dividend: &BigUint, divisor: &BigUint) -> Vec<u8> {
    let divisor_size = divisor.to_bytes_be().len();
    let remainder = (dividend % divisor).to_bytes_be();
    let remainder_size = remainder.len();

    if divisor_size == remainder_size {
        remainder
    } else if divisor_size < remainder_size {
        remainder[remainder_size - 2..].to_vec()
    } else {
        let mut padded = vec![0u8; divisor_size - remainder_size];
        padded.extend_from_slice(&remainder);
        padded
    }
}

/// Big-endian minimal bytes of a non-negative integer.
fn to_compatible_byte_array(value: &BigUint) -> Vec<u8> {
    value.to_bytes_be()
}

/// `SHA256(SHA256(uuid) || SHA256(lower(username)))`, url-safe base64.
fn calculate_identity(username: &str, key_uuid: &str) -> String {
    let mut buffer = Vec::with_capacity(64);
    buffer.extend_from_slice(&sha256(key_uuid.as_bytes()));
    buffer.extend_from_slice(&sha256(username.to_lowercase().as_bytes()));
    BASE64URL_NOPAD.encode(&sha256(&buffer))
}

/// Sends the client verification hash to confirm the session key.
async fn verify_key(
    session_key: &[u8],
    username: &str,
    key_uuid: &str,
    salt: &[u8],
    shared_a: &BigUint,
    shared_b: &BigUint,
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

    // TODO: Verify the server hash here. For now, we trust the server.
    if response.server_verify_hash.is_empty() {
        return Err(OnePasswordError::Parse);
    }
    Ok(())
}

/// The client verification hash sent to `v2/auth/confirm-key`:
/// `H(H(N) xor H(g) || H(I) || s || A || B || K)`.
fn calculate_client_hash(
    session_key: &[u8],
    username: &str,
    key_uuid: &str,
    salt: &[u8],
    shared_a: &BigUint,
    shared_b: &BigUint,
) -> [u8; 32] {
    let sirp_n = sha256(&to_compatible_byte_array(&N));
    let sirp_g = sha256(&to_compatible_byte_array(&BigUint::from(G)));
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

/// Derives SRP `x` from the password and account key.
///
/// Unlike the master key, the HKDF `info` is the SRP method and the password is used raw (not NFC).
fn compute_x(
    credentials: &Credentials,
    account_key: &AccountKey,
    srp_info: &SrpInfo,
) -> Result<[u8; 32], OnePasswordError> {
    let k1 = kdf::hkdf_sha256(
        &srp_info.srp_method,
        &srp_info.salt,
        credentials.username.to_lowercase().as_bytes(),
    );
    let k2 = kdf::pbes2(
        &srp_info.key_method,
        &credentials.password,
        &k1,
        srp_info.iterations,
    )?;
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

    use super::*;

    const SHARED_A: &str = "843c9c4977cf9c767452c90708c3dbdf3508c0016f8a56abc20c2e654dbd74c2c04b9412528a0927f499b245f9ad6742052662de2f725bf2a6c84913062842b4b2aaa8d41598c0d11424745bbae928d8e00e3c2c831c5ae90e128b719adb8be3845561186826462f0dbbdba272666c039f075b3da18c866c61a208cb9aed5ade03e6570818b7146c789f2e2928958ec7bebffbf2cc06cbb83b77ed80eae95e194502dead2e945e885d145d4521b74b8669211ffe718b20f04253d19550e0f9e8f1f0381caa2200223904a94d1e70f7db7cfa7d10d415bf7571f656a2e7bac3d142a2fa60b5a4e2fec4a82348fb46e03b65938f960373eefb95e50b1dd38134593b2f3ed0a19ae8684b4b54a04e0e022e01abc03072aa2e0096b209eaadb8dae57acd607a46e27bc5bfa66c3887e03441b4628135f830d1d78c7a60366d88cb42ed7ddd2dc32049f9dd3a1f459b610d41d25e8615f3271fcadcd37bf1b13c84c049d57d14ded500290b430c33d1d1dc3b04af66862ca3b4d501e2827355f68eaaf063a131c2436aa0a75519b7ac4d79845b6235898dcd9bef1093618b7c5bc5d73a7fc2a5ef8bca638e922152e459e89652b4a7d7d19cfd24de93f72f20e3a6f4325abf5ca1aec3ef3f392cc356c80b72e43a577775d2bf613b60d9f46d130e9881534e7548241e612901f61d5c5acb62100b8371c8dc42747437cd9ddcf9debf";
    const SHARED_B: &str = "7112742e3035eca37656e1ad2171516e3e154bcbabbcb5f52787aa53ad882cffd8e952bd67dbc8059025be23a0b86914bf8ec4c08cac0b3448a99d8c097e4b0c6942870b2cd2c56a58499c81c294bf2f64de408535f0a36ba416177519dcb5a54b7a403459abb1bfe8aecb92048e84a55ba48f1672f6ee3f30abff81868e88c8bb25c7c17292e535f91debda167af8f12d1e1073a48a9257b443dacd8ba47270051b03940117d2cec29f6521a3e78e575634db5bc87d479a4327db1b30578c90553edd3de58af08e9157a11b352b0bd7fca70d469809b3d516fed4edc989b78c6f330e553947111c563cb8c8ff184179cf7b8733494e16f3e38ed7cd42651c5bb4d81548c4b320996445b6f1a4c34a6211b5f65e561c04009c7422e289d7035085e21258513040b16bea0d3e91304879fa61f48af4daefce65d0917e4af106d868c6189dfd9031c8a3b2d97fa2a50445d6a818341fed7ad2a986f5aa691626426dc2b1047e1db8a1984f8fda526f21e825df6b4cc60cd31300181a3782e53d039f85164e417b419cde581826b08887f25277f9f7c0933aa596f5a4bb27af7bffb095027e326d1c02544357eaa553ac93b564bb5953b8fc498044d65b8003ad93f95c319ce6af0a0327151935e860c3e5dad17cd65ae4318e76905ce2a3ae239c12ab207313af3c0c7744e7aee2584043ae71dfc3e376bf747f92fa5a94bd36cb";

    fn big(hex: &str) -> BigUint {
        BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid hex")
    }

    #[test]
    fn to_server_hex_returns_hex_string() {
        let cases: [(i32, &str); 15] = [
            (0, "0"),
            (1, "1"),
            (0xD, "d"),
            (0xDE, "de"),
            (0xDEA, "dea"),
            (0xDEAD, "dead"),
            (0x80, "80"),
            (0xFF, "ff"),
            (-1, "-1"),
            (-0xD, "-d"),
            (-0xDE, "-de"),
            (-0xDEA, "-dea"),
            (-0xDEAD, "-dead"),
            (-0x80, "-80"),
            (-0xFF, "-ff"),
        ];
        for (number, expected) in cases {
            assert_eq!(to_server_hex(&BigInt::from(number)), expected);
        }
    }

    #[test]
    fn compute_key_returns_key() {
        let secret_a = big("37bbf7bf6a51f902673556ea6a2db91dd9987554ab74c3bc089b213693d9c06e");
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
            domain: "my.1password.com".into(),
            device_uuid: "device-uuid".into(),
        };

        let x = compute_x(&credentials, &account_key, &srp_info).expect("derivation succeeds");

        assert_eq!(
            BigUint::from_bytes_be(&x).to_string(),
            "104882354933197857481625453411657638660079750214611069684692024916274069892339"
        );
    }

    #[tokio::test]
    async fn verify_key_requires_a_server_hash() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v2/auth/confirm-key"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(json!({"serverVerifyHash": ""})),
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

        let error = verify_key(
            &[0u8; 32],
            "user@example.com",
            "RTN9SA",
            b"salt",
            &BigUint::from(2u32),
            &BigUint::from(3u32),
            &rest,
        )
        .await
        .expect_err("an empty hash is rejected");

        assert!(matches!(error, OnePasswordError::Parse));
        server.verify().await;
    }

    #[test]
    fn srp_info_rejects_unsupported_parameters() {
        let bad_method = SrpInfo::new("SRPg-2048".into(), "PBES2g-HS256".into(), 100000, vec![])
            .expect_err("only SRPg-4096 is supported");
        assert!(bad_method.to_string().contains("SRPg-2048"));

        let no_iterations = SrpInfo::new("SRPg-4096".into(), "PBES2g-HS256".into(), 0, vec![])
            .expect_err("0 iterations is rejected");
        assert!(no_iterations.to_string().contains("0 iterations"));
    }
}
