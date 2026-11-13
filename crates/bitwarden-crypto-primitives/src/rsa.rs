//! RSA with OAEP padding.

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Hash used for OAEP and MGF1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OaepHash {
    /// SHA-1. Legacy use only.
    Sha1,
    /// SHA-256.
    Sha256,
}

/// Modulus size for key generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySize {
    /// 2048-bit modulus.
    Rsa2048,
}

/// Big-endian, minimal-length private key components. Secret parts are zeroized on drop.
pub struct PrivateComponents {
    /// Modulus.
    pub n: Vec<u8>,
    /// Public exponent.
    pub e: Vec<u8>,
    /// Private exponent.
    pub d: Zeroizing<Vec<u8>>,
    /// First prime.
    pub p: Zeroizing<Vec<u8>>,
    /// Second prime.
    pub q: Zeroizing<Vec<u8>>,
    /// CRT coefficient `q^-1 mod p`.
    pub iqmp: Zeroizing<Vec<u8>>,
}

/// RSA private key.
#[derive(Clone)]
pub struct PrivateKey(backend::rsa::PrivateKey);

impl zeroize::ZeroizeOnDrop for PrivateKey where backend::rsa::PrivateKey: zeroize::ZeroizeOnDrop {}

impl PrivateKey {
    /// Generates a fresh key.
    pub fn generate(size: KeySize) -> Self {
        Self(backend::rsa::PrivateKey::generate(size))
    }

    /// Parses a PKCS#8 `PrivateKeyInfo`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_pkcs8_der(der).map(Self)
    }

    /// Parses a PEM-armored PKCS#8 `PrivateKeyInfo` (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_pkcs8_pem(pem).map(Self)
    }

    /// Parses a PKCS#1 `RSAPrivateKey`.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_pkcs1_der(der).map(Self)
    }

    /// Builds a two-prime key from big-endian components and validates it. `primes` must hold
    /// exactly `p` and `q`.
    pub fn from_components(n: &[u8], e: &[u8], d: &[u8], primes: &[&[u8]]) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_components(n, e, d, primes).map(Self)
    }

    /// Serializes as PKCS#8 `PrivateKeyInfo`.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0.to_pkcs8_der()
    }

    /// Returns the key components.
    pub fn components(&self) -> PrivateComponents {
        self.0.components()
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// RSAES-OAEP decryption with an empty label.
    pub fn decrypt_oaep(
        &self,
        hash: OaepHash,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0.decrypt_oaep(hash, ciphertext)
    }
}

/// RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(backend::rsa::PublicKey);

impl PublicKey {
    /// Parses a `SubjectPublicKeyInfo`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        backend::rsa::PublicKey::from_spki_der(der).map(Self)
    }

    /// Serializes as `SubjectPublicKeyInfo`.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        self.0.to_spki_der()
    }

    /// Big-endian, minimal-length modulus `n`.
    pub fn modulus(&self) -> Vec<u8> {
        self.0.modulus()
    }

    /// Big-endian, minimal-length public exponent `e`.
    pub fn exponent(&self) -> Vec<u8> {
        self.0.exponent()
    }

    /// Modulus length in bytes.
    pub fn modulus_len(&self) -> usize {
        self.0.modulus_len()
    }

    /// RSAES-OAEP encryption with an empty label.
    pub fn encrypt_oaep(&self, hash: OaepHash, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.encrypt_oaep(hash, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitwarden_encoding::B64;

    use super::*;
    use crate::test_vectors::bytes;

    static KEY: LazyLock<PrivateKey> = LazyLock::new(|| PrivateKey::generate(KeySize::Rsa2048));

    #[test]
    fn oaep_roundtrip() {
        let public = KEY.public_key();
        assert_eq!(public.modulus_len(), 256);

        for hash in [OaepHash::Sha1, OaepHash::Sha256] {
            let ct = public.encrypt_oaep(hash, b"secret").expect("fits");
            assert_eq!(
                KEY.decrypt_oaep(hash, &ct).expect("valid").as_slice(),
                b"secret"
            );
        }
    }

    #[test]
    fn oaep_hash_mismatch_fails() {
        let ct = KEY
            .public_key()
            .encrypt_oaep(OaepHash::Sha1, b"secret")
            .expect("fits");
        assert_eq!(
            KEY.decrypt_oaep(OaepHash::Sha256, &ct).err(),
            Some(Error::DecryptionFailed)
        );
    }

    #[test]
    fn der_roundtrips() {
        let der = KEY.to_pkcs8_der().expect("encodes");
        let parsed = PrivateKey::from_pkcs8_der(&der).expect("parses");
        assert!(parsed.public_key() == KEY.public_key());

        let spki = KEY.public_key().to_spki_der().expect("encodes");
        assert!(PublicKey::from_spki_der(&spki).expect("parses") == KEY.public_key());

        assert_eq!(
            PrivateKey::from_pkcs8_der(b"junk").err(),
            Some(Error::InvalidKey)
        );
    }

    /// 48 raw bytes encode to one 64-character PEM line (RFC 7468).
    const PEM_LINE_BYTES: usize = 48;

    #[test]
    fn pem_parses() {
        let der = KEY.to_pkcs8_der().expect("encodes");
        let body = der
            .chunks(PEM_LINE_BYTES)
            .map(|line| B64::from(line).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");

        let parsed = PrivateKey::from_pkcs8_pem(&pem).expect("parses");
        assert!(parsed.public_key() == KEY.public_key());
        assert_eq!(
            PrivateKey::from_pkcs8_pem("junk").err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn components_roundtrip() {
        let c = KEY.components();
        assert_eq!(hex::encode(&c.e), "010001");
        assert_eq!(c.n, KEY.public_key().modulus());

        let rebuilt = PrivateKey::from_components(&c.n, &c.e, &c.d, &[&c.p, &c.q]).expect("valid");
        assert!(rebuilt.public_key() == KEY.public_key());
    }

    /// A fixed RSA-2048 key (PKCS#8) with recorded OAEP ciphertexts. OAEP is randomized, so the
    /// vectors are checked by decryption.
    const VECTOR_KEY: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201\
        000282010100c324444443985b238056c325be35ec395c69a33a56b2f8517ee5\
        f6b0ebdc3056bfbe19bff1fb746472eb2dcd8da753fd682c64efb16be6bf1094\
        cb49fe96e40d4d2b5892a0be9bcceb3383c05036d0e1190a32cf80faeba80038\
        3e623123a48da33caa9e9064eabfcef081286029288c65494d5eab04a0423541\
        b54dba3e4a54988b72a2edc69cd2f902dfcc3efa89b1ab7954f03b8d0f93184f\
        9a0f97df7d3ee78121a7982d28e0aceac5666ebf898d4c0db281a003dda97f6d\
        b44de6aec70dc4b02042e9c23f4f6d6d1f35acf47b269faca9d760408f7994ff\
        5da86deb5af6dbb94921474f57dee20b45dc56c788d8e007b50643f56fb825b9\
        62a6f378594902030100010282010024e5eea299c56d3641462690346f2dc38a\
        ddcea7714d55f6d2efd8bd8b5b8f2858093205415432a5ebb4dc6c49a4a21500\
        65a4904e1401058fb512db62f0551ecec0ab76ce3e3c677af1baafda7b02f40d\
        30087b83ffee1f4e2b54606cba389b2f8a81188a650a9e4a1adfd12a9d9db52e\
        51b5f7788edf5ea5834f2ceb526beb4e596cb8ab3a0b22e7f929678796bd187c\
        c3a5848687e8647547b9f86d68f11a2b228c9e830233d88d82a6e708b0920f21\
        4e861aae3f9601cd6b82da672d6723080eaff8c010f3e048405665ff654c995d\
        44a88a85d4823b26a64e66fb5d3cc26902a84fd4779c7a3137411fc0906b5ffe\
        a30d367cbda0dd3b0b4d0b66478c8102818100ee620010131965c3e7569b169a\
        b001a002f0bf313c6c9ab35ec624c6e7c69c8685847e7ae4db3bd05fb5f480d9\
        a30e7e984cef9c7481e86a21941048ecd4745b25db5e0255238ca0483e26f052\
        974194ed14680422eb1a34608fe7c6efef496fa61afdaeac6fcdfab82160d447\
        e1f9f7a4cc74344c19216c37cfdc70bce0939502818100d1902e465613626c0c\
        f61d5c8ab5dbe0346e184ddea48720e36db5679b147241cc526aa18d757b77bb\
        3562cb25e4e4d5c7cc81eb8686007502044630bae3c733e0682d5b84b8115b6f\
        35f05f587a650fec7ab82c849594ada2cde3acbc34177c2ebcd78b2193fddf40\
        db2331571d80a880bf0eb653febb262ae294c83dcdc1e502818100c7239f21ce\
        92bcecb6e9268def93710816ecbf0b868ac3816c7ee26237653785392cc1ec30\
        1ae510e1a3c32990a62289a6f93e81d8e25d21ac0360c74af10072d461395b81\
        7c3d11f8c7d30798373b5609e7ae2d266e7869a0f116929e05abb7556fded478\
        c0bdb5e0f4214bb4f1163cc6b2f5b06a91e3d5df9a09713497f7310281801e7f\
        bf5c5936a50258b890f960eeaabb6ca6013f8401a9f0ed6890182e07c1c135bd\
        60eb762cfcf525f7d512ffc6da4f0aaf06d182588a447d30a60e7d849cff3dcf\
        ab9a402c91ca1edb58ca6794189542b3718e791553f81953a1a9081304bffc05\
        5bd151e7b9f0fdfd6697cdb7eb7b9a9133d0f15487643ca59145bb48f0c90281\
        807417f119fa737609b10fbaec007fbbf92731bf3a7722ee12dbf4b406ce5fd9\
        40fc682bd0b8e4b3c4d372ce9aaf7c9ae5fff9c677dd92bf7bf11c8f5e71ddf4\
        0e70257f0c59b5b55bf5250820889b0563d441a482cc64cba67c092202cb8917\
        03876a7e84ae657b0e73c4339e9daeea4db470d2c2ca3650398974edd72d857c\
        bb";
    const VECTOR_SPKI: &str = "30820122300d06092a864886f70d01010105000382010f003082010a02820101\
        00c324444443985b238056c325be35ec395c69a33a56b2f8517ee5f6b0ebdc30\
        56bfbe19bff1fb746472eb2dcd8da753fd682c64efb16be6bf1094cb49fe96e4\
        0d4d2b5892a0be9bcceb3383c05036d0e1190a32cf80faeba800383e623123a4\
        8da33caa9e9064eabfcef081286029288c65494d5eab04a0423541b54dba3e4a\
        54988b72a2edc69cd2f902dfcc3efa89b1ab7954f03b8d0f93184f9a0f97df7d\
        3ee78121a7982d28e0aceac5666ebf898d4c0db281a003dda97f6db44de6aec7\
        0dc4b02042e9c23f4f6d6d1f35acf47b269faca9d760408f7994ff5da86deb5a\
        f6dbb94921474f57dee20b45dc56c788d8e007b50643f56fb825b962a6f37859\
        490203010001";
    /// "The quick brown fox jumps over the lazy dog".
    const FOX: &str = "54686520717569636b2062726f776e20666f78206a756d7073206f7665722074\
        6865206c617a7920646f67";
    /// Longest OAEP plaintexts for a 256-byte modulus (`k - 2 * hLen - 2`: 214 for SHA-1, 190 for
    /// SHA-256), and one byte past each limit.
    const MAX_SHA1_PLAINTEXT: &str = "1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        11111111111111111111111111111111111111111111";
    const MAX_SHA256_PLAINTEXT: &str = "1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        111111111111111111111111111111111111111111111111111111111111";
    const OVERSIZED_SHA1_PLAINTEXT: &str = "1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111";
    const OVERSIZED_SHA256_PLAINTEXT: &str = "1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        1111111111111111111111111111111111111111111111111111111111111111\
        11111111111111111111111111111111111111111111111111111111111111";

    fn vector_key() -> PrivateKey {
        PrivateKey::from_pkcs8_der(&bytes(VECTOR_KEY)).expect("valid key")
    }

    #[test]
    fn known_answers_oaep() {
        let key = vector_key();
        // (hash, plaintext, ciphertext), all hex
        let cases = [
            (
                OaepHash::Sha1,
                FOX,
                "ab035063f78ea5380a07a19e7b19ff7bd056b12af09e0524268db5c755707ca4\
                5f703c8283a1a47b9143bfa6c396508e0d7f565289380f2cfc0add6e7b465a08\
                f3980813bae338b09d72ff04739dd6dd2ebc89a3274831f498aa7e49bed8a1b8\
                66ecc70885214c2c332238403dc1ddb468af7a6c7ae25d001c57b462d7126e22\
                c2c258d3136a8a273b4105fca18299d65e64e06d5ecb05c2a515395c2d9740b7\
                c9c140976d57f1229ba6af9778a30a4e3ec85cbea128cfa203df5b6de7845e39\
                1c7c32d420805dc0e2ffd028a1c1027402d5f64a078965a191bd3b9c3fe937f0\
                bc920eacae46dc124ce851bd54b47b1ba74eab47313747b0ba8071d466bfb62d",
            ),
            (
                OaepHash::Sha256,
                FOX,
                "97ee0e08483b959f5540365359a7811929a4fc0faee4834b2886f6de23c2e4fa\
                f284f84d062c5c58ba3d46f99d0a41846c78c0b3db508d7ace097fe0413971b8\
                dc4eb85d973ce828be2b4fdb0dadcdc9c0b597f115bcfa3bda3a5e8d5eff33e6\
                d67effafba27e7b7c0c473a130cc981bb66835539837bd80c8610f8483a9f7db\
                8a4ab2be4a3ae4492cb5e18da042c1229b22581170d6be3e8b5190e0694fbcbb\
                e753c29235b878e4e2a3250a5715e02cee199e4f2600bdacc11ceb624212bfe9\
                362a2a0f90cd3af4e050559c087102e1e588358cfd5e9fe4c66d54527b281d9c\
                3cba64a451e2382ce0b55f29f56a86cde402ebce7af5f6b377d28567ae737cde",
            ),
            (
                OaepHash::Sha256,
                "",
                "5c08d62ae6e10f1d49a7c0efe9bcb60bef8f98170ece95ae4ebc2ef21ddb669e\
                181639324de13edd20af9dbc924189f5ee4799deb9b24d0d5c11e00675338535\
                80a54be4ed6c21c4838e3a6fc5f38588879ae08ce0bf7c41e468cb898838e340\
                41ab2bc4a3f9d8279785d8c13151534170e93347aebbb3b2fb9d261b900bd599\
                336ab5da6724c305c8d52e0fcad83a6448027a0f2ed4454be726d01b9b28b5d3\
                9c89abaef1c38ba9daa1f2c15446ad96cbaabf3b50339d4f458ca989c459aa25\
                874e0aabf0ac2fab0fb73a0c81af6c2b1f1f7ca4aefdc871f732b4a23a15df01\
                0a23fef4f33ca6eb60677f03d64e83e6bc1b9be0f719343d926a528c3c067592",
            ),
            (
                OaepHash::Sha1,
                MAX_SHA1_PLAINTEXT,
                "bed8b27a955dc39dc24617b5238c1d5b9855e6fcca28e2580ab5ba9a3ba9b61b\
                09dc145044baa6cc1a48798547e705be63cc539458acd99af4b3f27007630c98\
                505becd2aa4251d41394c2b0c21fd77f4de9bfcce9cabf0a8860f50cfd7e30d9\
                d45d1e58c9821238856b5fa18abba15ec7dd560c071b9c0246877e7302b9e901\
                132b3420a925b3fcb14eb058b4dee8febeef2d2e110fab946826c8fa221bfd36\
                1e40aaddb69308b5ef668a0208ce0c4d6d0a527870bb537d228c0bb15ec46be4\
                b9f685905a5169e402462ef2aebd183179fb01d831a4e0da1c5bda975447a16c\
                1bcdf13d8243e6bcb0ceafc0f8346d66462845cda6c9b2f708bf62c27d11c3ce",
            ),
            (
                OaepHash::Sha256,
                MAX_SHA256_PLAINTEXT,
                "b36c694a7c8b264766fc5427174a83045ad9e405256c5a5b8ad5bb7d5fb9c302\
                f538c0aebf069ccbcc33b3008165f385dc769fe3d7a8c009d27a76657be1a245\
                8521d4b26a38b037563a0f5f3ebb0298affc930bec707ca2b60e2652c6600d0d\
                21096fab70fdeff22a284b12412b7ad3d231426b94ab9c1dfa7f8b410a8fb686\
                51d0a8df22bd6e940556c636dec5849a2b9e6b791031bdfedba7c2df5484200e\
                bb631b71f32b0ac6d8e01fbfe24092cf421e0a14dfa94feefb54d752cc5a0115\
                2cc7fd686742aa2d25d5bd4dc4322eaa14c61dabe1d8e77ed3e9e04399bbdf48\
                e3224d8ab68805d801efa81a9437f097703e767da4124616ee36e644ff4b0a69",
            ),
        ];
        for (hash, plaintext, ciphertext) in cases {
            let decrypted = key
                .decrypt_oaep(hash, &bytes(ciphertext))
                .expect("valid ciphertext");
            assert_eq!(hex::encode(decrypted.as_slice()), plaintext);
        }
    }

    /// One byte past the OAEP limit is rejected.
    #[test]
    fn oaep_rejects_oversized_plaintext() {
        let public = vector_key().public_key();
        assert_eq!(
            public
                .encrypt_oaep(OaepHash::Sha1, &bytes(OVERSIZED_SHA1_PLAINTEXT))
                .err(),
            Some(Error::InvalidParameters)
        );
        assert_eq!(
            public
                .encrypt_oaep(OaepHash::Sha256, &bytes(OVERSIZED_SHA256_PLAINTEXT))
                .err(),
            Some(Error::InvalidParameters)
        );
    }

    #[test]
    fn known_answer_spki_and_reencoding() {
        let key = vector_key();
        assert_eq!(
            hex::encode(key.public_key().to_spki_der().expect("encodes")),
            VECTOR_SPKI
        );
        assert_eq!(
            hex::encode(key.to_pkcs8_der().expect("encodes").as_slice()),
            VECTOR_KEY
        );
    }
}
