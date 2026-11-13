use ::openssl::{
    base64,
    bn::{BigNum, BigNumContext, BigNumRef},
    md::{Md, MdRef},
    pkey::{Id, PKey, Private, Public},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
};
use zeroize::Zeroizing;

use crate::{
    Error,
    rsa::{KeySize, OaepHash, PrivateComponents},
};

/// Public exponent bounds and maximum modulus size enforced by the RustCrypto backend, applied
/// here too so both backends accept the same keys.
const MIN_PUB_EXPONENT: u64 = 2;
const MAX_PUB_EXPONENT: u64 = (1 << 33) - 1;
const MAX_MODULUS_BITS: i32 = 8192;
/// RFC 7468 armor of a PKCS#8 `PrivateKeyInfo`.
const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

#[derive(Clone)]
pub(crate) struct PrivateKey(PKey<Private>);

// OpenSSL frees the private components with `BN_clear_free`.
impl zeroize::ZeroizeOnDrop for PrivateKey {}

impl PrivateKey {
    pub(crate) fn generate(size: KeySize) -> Self {
        const INFALLIBLE: &str = "RSA key generation does not fail";

        let bits = match size {
            KeySize::Rsa2048 => 2048,
        };
        let rsa = Rsa::generate(bits).expect(INFALLIBLE);
        Self(PKey::from_rsa(rsa).expect(INFALLIBLE))
    }

    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let pkey = PKey::private_key_from_pkcs8(der).map_err(|_| Error::InvalidKey)?;

        // PKCS#8 also carries RSA-PSS and non-RSA keys; accept `rsaEncryption` only.
        if pkey.id() != Id::RSA {
            return Err(Error::InvalidKey);
        }

        let rsa = pkey.rsa().map_err(|_| Error::InvalidKey)?;
        Self::validated(rsa)
    }

    /// Strict RFC 7468 armor only: OpenSSL's PEM reader would also accept legacy and encrypted
    /// formats, and prompt for a passphrase on the terminal.
    pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let body = pem
            .trim()
            .strip_prefix(PEM_BEGIN)
            .and_then(|rest| rest.strip_suffix(PEM_END))
            .ok_or(Error::InvalidKey)?;
        let b64 = Zeroizing::new(
            body.chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>(),
        );
        let der = Zeroizing::new(base64::decode_block(&b64).map_err(|_| Error::InvalidKey)?);
        Self::from_pkcs8_der(&der)
    }

    pub(crate) fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        let rsa = Rsa::private_key_from_der(der).map_err(|_| Error::InvalidKey)?;
        Self::validated(rsa)
    }

    /// Two-prime keys only.
    pub(crate) fn from_components(
        n: &[u8],
        e: &[u8],
        d: &[u8],
        primes: &[&[u8]],
    ) -> Result<Self, Error> {
        let [p, q] = primes else {
            return Err(Error::InvalidKey);
        };

        let mut ctx = BigNumContext::new_secure().map_err(|_| Error::InvalidKey)?;
        let (n, e) = (public_bn(n)?, public_bn(e)?);
        let (d, p, q) = (secret_bn(d)?, secret_bn(p)?, secret_bn(q)?);

        // CRT parameters: d mod (p - 1), d mod (q - 1), q^-1 mod p.
        let dmp1 = crt_exponent(&d, &p, &mut ctx)?;
        let dmq1 = crt_exponent(&d, &q, &mut ctx)?;
        let mut iqmp = BigNum::new_secure().map_err(|_| Error::InvalidKey)?;
        iqmp.mod_inverse(&q, &p, &mut ctx)
            .map_err(|_| Error::InvalidKey)?;

        let rsa = Rsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)
            .map_err(|_| Error::InvalidKey)?;
        Self::validated(rsa)
    }

    pub(crate) fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0
            .private_key_to_pkcs8()
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn components(&self) -> PrivateComponents {
        const INFALLIBLE: &str = "validated two-prime keys carry every component";

        let rsa = self.rsa();
        PrivateComponents {
            n: rsa.n().to_vec(),
            e: rsa.e().to_vec(),
            d: Zeroizing::new(rsa.d().to_vec()),
            p: Zeroizing::new(rsa.p().expect(INFALLIBLE).to_vec()),
            q: Zeroizing::new(rsa.q().expect(INFALLIBLE).to_vec()),
            iqmp: Zeroizing::new(rsa.iqmp().expect(INFALLIBLE).to_vec()),
        }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        const INFALLIBLE: &str = "copying public components does not fail";

        let rsa = self.rsa();
        let public = Rsa::from_public_components(
            rsa.n().to_owned().expect(INFALLIBLE),
            rsa.e().to_owned().expect(INFALLIBLE),
        )
        .expect(INFALLIBLE);
        PublicKey(PKey::from_rsa(public).expect(INFALLIBLE))
    }

    pub(crate) fn decrypt_oaep(
        &self,
        hash: OaepHash,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut ctx = PkeyCtx::new(&self.0).map_err(|_| Error::DecryptionFailed)?;
        ctx.decrypt_init().map_err(|_| Error::DecryptionFailed)?;
        set_oaep(&mut ctx, hash).map_err(|_| Error::DecryptionFailed)?;

        // Decrypt into a wiped buffer sized to the modulus, then trim.
        let max_len = ctx
            .decrypt(ciphertext, None)
            .map_err(|_| Error::DecryptionFailed)?;
        let mut out = Zeroizing::new(vec![0u8; max_len]);
        let len = ctx
            .decrypt(ciphertext, Some(out.as_mut_slice()))
            .map_err(|_| Error::DecryptionFailed)?;
        out.truncate(len);
        Ok(out)
    }

    /// Rejects inconsistent keys (`RSA_check_key`) and public parts RustCrypto would reject.
    fn validated(rsa: Rsa<Private>) -> Result<Self, Error> {
        if !rsa.check_key().map_err(|_| Error::InvalidKey)? {
            return Err(Error::InvalidKey);
        }
        check_public(rsa.n(), rsa.e())?;

        PKey::from_rsa(rsa).map(Self).map_err(|_| Error::InvalidKey)
    }

    fn rsa(&self) -> Rsa<Private> {
        self.0.rsa().expect("PrivateKey always wraps an RSA key")
    }
}

#[derive(Clone)]
pub(crate) struct PublicKey(PKey<Public>);

/// Public data: compare `n` and `e`.
impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.public_eq(&other.0)
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    pub(crate) fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let pkey = PKey::public_key_from_der(der).map_err(|_| Error::InvalidKey)?;
        if pkey.id() != Id::RSA {
            return Err(Error::InvalidKey);
        }

        let rsa = pkey.rsa().map_err(|_| Error::InvalidKey)?;
        check_public(rsa.n(), rsa.e())?;
        Ok(Self(pkey))
    }

    pub(crate) fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        self.0.public_key_to_der().map_err(|_| Error::InvalidKey)
    }

    pub(crate) fn modulus(&self) -> Vec<u8> {
        self.rsa().n().to_vec()
    }

    pub(crate) fn exponent(&self) -> Vec<u8> {
        self.rsa().e().to_vec()
    }

    pub(crate) fn modulus_len(&self) -> usize {
        usize::try_from(self.rsa().size()).expect("u32 fits in usize")
    }

    pub(crate) fn encrypt_oaep(&self, hash: OaepHash, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut ctx = PkeyCtx::new(&self.0).map_err(|_| Error::InvalidParameters)?;
        ctx.encrypt_init().map_err(|_| Error::InvalidParameters)?;
        set_oaep(&mut ctx, hash).map_err(|_| Error::InvalidParameters)?;

        let mut out = Vec::new();
        ctx.encrypt_to_vec(plaintext, &mut out)
            .map_err(|_| Error::InvalidParameters)?;
        Ok(out)
    }

    fn rsa(&self) -> Rsa<Public> {
        self.0.rsa().expect("PublicKey always wraps an RSA key")
    }
}

/// OAEP with an empty label and MGF1 over the same hash.
fn set_oaep<T>(ctx: &mut PkeyCtx<T>, hash: OaepHash) -> Result<(), ::openssl::error::ErrorStack> {
    let md: &MdRef = match hash {
        OaepHash::Sha1 => Md::sha1(),
        OaepHash::Sha256 => Md::sha256(),
    };
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(md)?;
    ctx.set_rsa_mgf1_md(md)
}

/// Same bounds as `rsa::RsaPublicKey::new`.
fn check_public(n: &BigNumRef, e: &BigNumRef) -> Result<(), Error> {
    if n.num_bits() > MAX_MODULUS_BITS {
        return Err(Error::InvalidKey);
    }

    let min = BigNum::from_slice(&MIN_PUB_EXPONENT.to_be_bytes()).map_err(|_| Error::InvalidKey)?;
    let max = BigNum::from_slice(&MAX_PUB_EXPONENT.to_be_bytes()).map_err(|_| Error::InvalidKey)?;
    if e < &*min || e > &*max {
        return Err(Error::InvalidKey);
    }

    Ok(())
}

/// `d mod (prime - 1)`.
fn crt_exponent(
    d: &BigNumRef,
    prime: &BigNumRef,
    ctx: &mut BigNumContext,
) -> Result<BigNum, Error> {
    // `BN_dup` keeps the secure flag of `prime`.
    let mut prime_minus_1 = prime.to_owned().map_err(|_| Error::InvalidKey)?;
    prime_minus_1.sub_word(1).map_err(|_| Error::InvalidKey)?;

    let mut exponent = BigNum::new_secure().map_err(|_| Error::InvalidKey)?;
    exponent
        .nnmod(d, &prime_minus_1, ctx)
        .map_err(|_| Error::InvalidKey)?;
    Ok(exponent)
}

fn public_bn(bytes: &[u8]) -> Result<BigNum, Error> {
    BigNum::from_slice(bytes).map_err(|_| Error::InvalidKey)
}

/// Secret big number: allocated with `BN_FLG_SECURE` so it is wiped on free, and flagged for
/// constant-time arithmetic.
fn secret_bn(bytes: &[u8]) -> Result<BigNum, Error> {
    let mut bn = BigNum::new_secure().map_err(|_| Error::InvalidKey)?;
    bn.copy_from_slice(bytes).map_err(|_| Error::InvalidKey)?;
    bn.set_const_time();
    Ok(bn)
}
