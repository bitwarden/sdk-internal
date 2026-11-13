use ::openssl::{
    bn::{BigNum, BigNumContext},
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
};
use zeroize::Zeroizing;

use crate::{
    Error,
    p256::{SCALAR_LEN, SEC1_UNCOMPRESSED_LEN},
};

#[derive(Clone)]
pub(crate) struct SecretKey(PKey<Private>);

// OpenSSL frees the private scalar with `BN_clear_free`.
impl zeroize::ZeroizeOnDrop for SecretKey {}

impl SecretKey {
    pub(crate) fn generate() -> Self {
        const INFALLIBLE: &str = "P-256 key generation does not fail";

        let ec = EcKey::generate(&group()).expect(INFALLIBLE);
        Self(PKey::from_ec_key(ec).expect(INFALLIBLE))
    }

    pub(crate) fn from_bytes(scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        let group = group();
        let mut ctx = BigNumContext::new_secure().map_err(|_| Error::InvalidKey)?;

        let mut d = BigNum::new_secure().map_err(|_| Error::InvalidKey)?;
        d.copy_from_slice(scalar).map_err(|_| Error::InvalidKey)?;
        d.set_const_time();

        let mut public = EcPoint::new(&group).map_err(|_| Error::InvalidKey)?;
        public
            .mul_generator2(&group, &d, &mut ctx)
            .map_err(|_| Error::InvalidKey)?;

        // `check_key` rejects a zero scalar and any scalar >= n.
        let ec =
            EcKey::from_private_components(&group, &d, &public).map_err(|_| Error::InvalidKey)?;
        ec.check_key().map_err(|_| Error::InvalidKey)?;

        PKey::from_ec_key(ec)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; SCALAR_LEN]> {
        let ec = self.ec_key();
        let bytes = Zeroizing::new(
            ec.private_key()
                .to_vec_padded(SCALAR_LEN as i32)
                .expect("P-256 scalar fits in 32 bytes"),
        );
        Zeroizing::new(bytes.as_slice().try_into().expect("padded to 32 bytes"))
    }

    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let pkey = PKey::private_key_from_pkcs8(der).map_err(|_| Error::InvalidKey)?;
        if pkey.id() != Id::EC {
            return Err(Error::InvalidKey);
        }

        let ec = pkey.ec_key().map_err(|_| Error::InvalidKey)?;
        if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(Error::InvalidKey);
        }
        ec.check_key().map_err(|_| Error::InvalidKey)?;

        Ok(Self(pkey))
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0
            .private_key_to_pkcs8()
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        const INFALLIBLE: &str = "a valid key's public point is a valid public key";

        let ec = self.ec_key();
        let public = EcKey::from_public_key(ec.group(), ec.public_key()).expect(INFALLIBLE);
        PublicKey(PKey::from_ec_key(public).expect(INFALLIBLE))
    }

    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Zeroizing<[u8; SCALAR_LEN]> {
        const INFALLIBLE: &str = "ECDH between validated P-256 keys does not fail";

        let mut deriver = Deriver::new(&self.0).expect(INFALLIBLE);
        deriver.set_peer(&peer.0).expect(INFALLIBLE);

        let mut shared = Zeroizing::new([0u8; SCALAR_LEN]);
        let len = deriver.derive(shared.as_mut_slice()).expect(INFALLIBLE);
        assert_eq!(len, SCALAR_LEN, "P-256 shared secret is 32 bytes");
        shared
    }

    fn ec_key(&self) -> EcKey<Private> {
        self.0.ec_key().expect("SecretKey always wraps an EC key")
    }
}

#[derive(Clone)]
pub(crate) struct PublicKey(PKey<Public>);

/// Public data: compare points.
impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.public_eq(&other.0)
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    pub(crate) fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let group = group();
        let mut ctx = BigNumContext::new().map_err(|_| Error::InvalidKey)?;

        // Decoding checks the point is on the curve. OpenSSL also decodes `0x00` as the identity,
        // which is not a valid public key.
        let point = EcPoint::from_bytes(&group, bytes, &mut ctx).map_err(|_| Error::InvalidKey)?;
        if point.is_infinity(&group) {
            return Err(Error::InvalidKey);
        }

        let ec = EcKey::from_public_key(&group, &point).map_err(|_| Error::InvalidKey)?;
        ec.check_key().map_err(|_| Error::InvalidKey)?;
        PKey::from_ec_key(ec)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn to_sec1_uncompressed(&self) -> [u8; SEC1_UNCOMPRESSED_LEN] {
        const INFALLIBLE: &str = "encoding a valid P-256 point does not fail";

        let ec = self.0.ec_key().expect("PublicKey always wraps an EC key");
        let mut ctx = BigNumContext::new().expect(INFALLIBLE);
        let bytes = ec
            .public_key()
            .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .expect(INFALLIBLE);
        let encoded: [u8; SEC1_UNCOMPRESSED_LEN] = bytes
            .try_into()
            .expect("uncompressed P-256 point is 65 bytes");
        encoded
    }
}

fn group() -> EcGroup {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("OpenSSL provides P-256")
}
