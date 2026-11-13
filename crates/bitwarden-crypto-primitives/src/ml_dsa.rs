//! ML-DSA-44 signatures (FIPS 204).

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Seed length in bytes.
pub const SEED_LEN: usize = 32;

/// ML-DSA-44 signing key. Holds the seed and the expanded key; zeroized on drop.
#[derive(Clone)]
pub struct SigningKey(backend::ml_dsa::SigningKey);

impl zeroize::ZeroizeOnDrop for SigningKey where backend::ml_dsa::SigningKey: zeroize::ZeroizeOnDrop {}

impl SigningKey {
    /// Generates a fresh key.
    pub fn generate() -> Self {
        Self(backend::ml_dsa::SigningKey::generate())
    }

    /// Expands a key from its 32-byte seed.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self(backend::ml_dsa::SigningKey::from_seed(seed))
    }

    /// Returns the 32-byte seed.
    pub fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        self.0.seed()
    }

    /// Returns the matching verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    /// Signs `msg` with hedged randomness and an empty context.
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign(msg)
    }
}

/// ML-DSA-44 verifying key.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey(backend::ml_dsa::VerifyingKey);

impl VerifyingKey {
    /// Parses an encoded verifying key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        backend::ml_dsa::VerifyingKey::from_bytes(bytes).map(Self)
    }

    /// Returns the encoded verifying key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Verifies `sig` over `msg` with an empty context.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.0.verify(msg, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ML-DSA-44 encoded verifying key length (FIPS 204 Table 2).
    const PUBLIC_KEY_LEN: usize = 1312;
    /// ML-DSA-44 signature length (FIPS 204 Table 2).
    const SIGNATURE_LEN: usize = 2420;

    #[test]
    fn sign_verify_roundtrip() {
        let key = SigningKey::generate();
        let sig = key.sign(b"msg");
        assert_eq!(sig.len(), SIGNATURE_LEN);

        let vk = key.verifying_key();
        assert_eq!(vk.verify(b"msg", &sig), Ok(()));
        assert_eq!(vk.verify(b"other", &sig), Err(Error::InvalidSignature));
        assert_eq!(vk.verify(b"msg", &sig[..10]), Err(Error::InvalidSignature));
    }

    #[test]
    fn seed_is_deterministic() {
        let a = SigningKey::from_seed(&[3; SEED_LEN]);
        let b = SigningKey::from_seed(&a.seed());
        assert!(a.verifying_key() == b.verifying_key());

        let bytes = a.verifying_key().to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_LEN);
        assert!(VerifyingKey::from_bytes(&bytes).expect("valid") == a.verifying_key());
        assert_eq!(
            VerifyingKey::from_bytes(&bytes[1..]).err(),
            Some(Error::InvalidKey)
        );
    }

    /// SHA-256 of the verifying key expanded from edge-case seeds (all zero, all one bits) and a
    /// fixed seed. Hashed because the encoding is 1312 bytes.
    #[test]
    fn known_answers_seed_expansion() {
        let cases = [
            (
                [0x00; SEED_LEN],
                "eb4e7302842153b0fa19e8620739ad258af4929c26dd89079a7ec7d4282208e1",
            ),
            (
                [0xff; SEED_LEN],
                "62c4f1b3164db7fa896a3343e900eb3e13c9f76de122020feba37ee063d49ef0",
            ),
            (
                [0x42; SEED_LEN],
                "19506c63f504c175013cf1b459397bbbc2ce6a3fd841bab68b3898f6f2fddc2f",
            ),
        ];
        for (seed, expected) in cases {
            let public = SigningKey::from_seed(&seed).verifying_key().to_bytes();
            assert_eq!(hex::encode(crate::sha256::digest(&public)), expected);
        }
    }

    /// Signing is hedged, so a recorded signature is checked by verification only.
    #[test]
    fn recorded_signature_verifies() {
        const FOX: &[u8] = b"The quick brown fox jumps over the lazy dog";
        const SIGNATURE: &str = "b4c7c13ff8cbc02df30ee1c82cb0b1656c74974a36248fd0d45a0357498eb007\
        08ccc224550edc59343dabda6ab44e0ed175c58c1546004f12776518e86a3a94\
        652867fc7f4e5b1b97c10ffb0a7c979d2fe5b4a573ebac785b8090f754fd69f8\
        59c93b4180d985f96a18a3bee3f37a26f72c8c4fb20b286b49fb3d8b967afa6a\
        66bd702b7cf571bfd5d88a671f4d790b100f44459fddb55bee3c201b18401a1d\
        4d52b0873ffd489d215e41580396f94e25c2a4d7dcbe8373d126e0a6b3299fac\
        15138d918e19afae7c6cf3ce8e1d49457afd4c5eab879f3bd616f4fa2d9195c5\
        2bd62b3d64904dda57c8774ce6d27fdf52e549691a172b0902e0df8ae0cf1d6b\
        604dfcbcd121b1be5751c7896cb7c17e3608e2e631e3e89639355450ec1a51e6\
        3442c7940227dafe67a1bf92cc26e70c41082229c907074b229259622dd83cc2\
        60cd25efc60b596cf40ae12f76decd70f2aa1f4cf3ad0725a0924a3d8dbcfcd1\
        2b6ca166e39199d58a8222c539680ea724fff02c8909227661aa4a68ec7febf5\
        981111cd94edd9d714d17430fd7264c7ba196b10b311009d3c431ea64e9c03eb\
        a617ba5a349eb87159e895d211be484198f0350d83e559e444e6c4263cedbfa7\
        eb954757ab3472c888db707558ebbc40cff50f2af137b25b34934c187f223d3d\
        008966cf392a3fb1f8add0fdc9d9fffe5a538f519874043f65ef676edbc3a705\
        41d39d1450285bf8d5597b06e8288b1524218002202e1160c88e841e340c5e1d\
        74d44ac0afdea3458344e99af5e76fc2f125c875194d1ad5ebc4ca2931a61571\
        9a20c1e17c66764225c8d6a9914828cf803aa7446937d6aeed9b9d55e5239056\
        00c40e69fe076ea0f6f9413c4df8db3664d9194a009fd5f64b3004c85326c894\
        2d9e5c0619108b08d9357362b13ac3f131f8a232ecdc74d190234ffca88093ec\
        c212b4cdd1718a8a39df14e91d43cb524efafbef655ab44a8e119ef95743ff15\
        2816e5b916d80c83c7e11e0e5c5b6059212bd30880417d7e28ba3eab9a8ae066\
        71edb278d7bea0e0c04057e6bfceff72e9ecc34cd148cb0f2aabf3f07db8253c\
        9de3ebb7d2df3bbe21d1e877af5db3a306c64504f1a81d5246ce173824f47a2d\
        5f3512430f47afecce0bb9cfadf7f7c88e847049aa6331c7580ec95d52d99994\
        5114c2f7f66e134ef88ead1ed454d69229c0995dc79b377b92910666d5571faf\
        d01a7293c5f9bafe5eb5ca03ba832c29d52c7639da0af48b52be88df27c79f37\
        55409b1f1cb67eb745e7c9de1d5cd483d44e9ffd87748e272fb655512d4ff45b\
        80ff60d3922db521e3e227df89fbf945dfd33f2cfd02e342cdebdaed55a3ce92\
        6a6a14c2df3865d109653aabf58a6c432c01a36d196b6094ddaebc39b226a6a5\
        218101f1c1d34640c1bc6d1f157f8e2667cda0e8403447ad5ab8b88e6cd13b2c\
        91922e1a64a79afb3b4b26e4c301b6a6a6942bcd9af7c4b3395164bb5366563f\
        c08ee7b973c9e1a5c37de01bcb584187e5a2e760f2ba41b41e00ae4f7402991c\
        0d398264583de40bf4f1cc09140494d20a01e6add87519b278fdf13c7fc9875d\
        147dafc493435ef61a2b58a5aab372f311839f3a9f9c0c9468361b488ef74ad1\
        4b6eeb1e476946486d2de2cdbd134701dac1d981e3e70f6efe551ccda4da9ab6\
        1d4521e3e586bf12c4a34ed2e304c593ef95bc01579760b4943fb42d10374c86\
        6eaa3627d2d82da02e5f4cd6cba48f5385550b4decbfaa9e0f64a4d1845c9573\
        a678e02d951e558feb1422d2bc8e7c5849cf8ca5f689856fd7af0aad4758c2e4\
        91de04aed04a365b512dfaf9f303608d624cb2e8275d248d3f355d99da597723\
        393280aa66c84bee351c1d522c136f3a7d9626e1ba86e11ffa57f0011988d72b\
        3c3b17926de2770bd77d6f6dcbb1cc351d4de5171b47c1199adb13ff0c2a37ed\
        42e08bbf997781428ede48c30a5fd8db2ce749e9d059276d35458fdb0634c908\
        30273fc58a0875b8cc314a9fedd1263e167855e35f3e10d6e96e5d4ef3866898\
        4c50e78eb53c8eb366afbd69671f5417167c63d432a5a5efd1a24b86a1245d72\
        053662a916000774ddd2924b0390cc0ac9f40a2ff4aa117a2bb44b8af3a50475\
        3146a9061087d0a279b3ec9c945d5a0182e50695f94abfdd09b1eb1bc228edb4\
        cb47aa4862817fd03e49a9cf0dce7e61cb0c00bf1dd2f0c2fb774068335aac75\
        3d452736e4a0bf871ba7e00bdd7c625687fb5ce42b807852faca2700dc8708e8\
        4cb47c8fbc8ed1e4f3124527da448d16da8d8fc02daba03cfc57c7aa0b219bdc\
        50ae18406459eeabe52c5b2d0751d23c3e1f384edbfaf5b9286b14f975b67622\
        8ae9d81014634393abbe47cc1d1d8ab982ffe05a8cbc387f1c7e8366c16addf8\
        1fe427eaf9f43ef158a88c4874b0313eae73fedfa1f3a681804189ae299d9071\
        032259999997dd720871614a365a14c1c5dae30a19dbec552d092569efe8b21f\
        79b7c30d1bf26f4f45515d99f5d17462a64722c9a578697ec6e717cf69e8c1f2\
        39a9666b656e09c95f892a95246e4bd5eb114cff4d9a33c7a757356a249483ef\
        01e4f92abf3d8ad616a712956bcd3cd548c7ec1b3aa33b521a0f25a2cc1aad1e\
        e25b035e94923ac7f2d0e7d69080219437d29cfc66f898c5023e65decffdbad5\
        e0107639476a133c132c784c2812748832ec459047df210a2fc102ba379dbf75\
        9caa84a567a4885bc65a1df94b08dc60c8e80877898cde06280dc662c15ea9c0\
        5864594a721e7bbf9738fdb4b4e609259e800d087fcf4f58d1112a56440ef975\
        083cfae44124e7c3cf9f017ceb4f1ec68a4552db2e80f14aefbdd9fe6a5ee5ea\
        7d31c3371e5f9be5758042a0b08f39e6494a7e2b82108d9e07951fc9e6345206\
        b479451a1a6d5f8e33d6a654845c3fd04b9c1762d46fd7c26665a1b991d6a530\
        bed10d2f8e2877b10696fd225c76714ea4961ab714bd33b2cfcf7332356c3193\
        a59f83603e939448d4c991f8190366697c457f1981a54f1d6d98948bf2797331\
        ec4010916e86208780d6fa5b90e61837e1842e355bb993926793578078d89b96\
        5e2a22bc61c8e308462cae114ed560bf21bf706dc431ce87e1bfec8951cde1a0\
        c7fc7c21e57fa0d596722b9462d7ca8bdfac770bba376868a56a872f66108480\
        6cf5461ab73dd8cf7f84bb7f7d829481e3edeab26133794788a019a1c4d1f9d2\
        ad166d7bcbe2ee074d46e8567b09661f2cbe6a13500f0bda0988efa1166b64e5\
        2d5b3cffdc7802034d45a91d205c44eab74307fd3bfb19d0582ccba74c726132\
        161720242b30323a3d6b7987a8c4c6f6fc151c2953677e929cb6bee81a212628\
        375687959aa3adb3bfd6e1f4f9191c383d446570788a92999cb8c0cce7eff800\
        00000000000000000000000000000000111c2d3f";

        let public = SigningKey::from_seed(&[0x42; SEED_LEN]).verifying_key();
        let mut sig = hex::decode(SIGNATURE).expect("hex");
        assert_eq!(public.verify(FOX, &sig), Ok(()));

        sig[0] ^= 1;
        assert_eq!(public.verify(FOX, &sig), Err(Error::InvalidSignature));
    }
}
