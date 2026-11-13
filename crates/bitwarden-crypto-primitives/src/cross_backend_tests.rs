//! Cross-checks the OpenSSL driver against the RustCrypto driver: equal outputs where the
//! primitive is deterministic, interoperability where it is randomized.

use std::{num::NonZeroU32, sync::LazyLock};

use crate::{
    argon2::Params,
    hmac::HashAlg,
    openssl_fips as ossl,
    rsa::{KeySize, OaepHash},
    rustcrypto as rc,
};

const KEY: [u8; 32] = [7; 32];
const SEED: [u8; 32] = [3; 32];
/// Spans several blocks and a partial one.
const MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog, then naps for a while.";

/// RSA key generation is slow; share one key per backend.
static RC_RSA: LazyLock<rc::rsa::PrivateKey> =
    LazyLock::new(|| rc::rsa::PrivateKey::generate(KeySize::Rsa2048));
static OSSL_RSA: LazyLock<ossl::rsa::PrivateKey> =
    LazyLock::new(|| ossl::rsa::PrivateKey::generate(KeySize::Rsa2048));

#[test]
fn digests_match() {
    for len in [0, 1, 64, MESSAGE.len()] {
        let data = &MESSAGE[..len];

        let (mut a, mut b) = (rc::digest::Sha1::default(), ossl::digest::Sha1::default());
        a.update(data);
        b.update(data);
        assert_eq!(a.finalize(), b.finalize());

        let (mut a, mut b) = (
            rc::digest::Sha256::default(),
            ossl::digest::Sha256::default(),
        );
        a.update(data);
        b.update(data);
        assert_eq!(a.finalize(), b.finalize());

        let (mut a, mut b) = (
            rc::digest::Sha384::default(),
            ossl::digest::Sha384::default(),
        );
        a.update(data);
        b.update(data);
        assert_eq!(a.finalize(), b.finalize());

        let (mut a, mut b) = (
            rc::digest::Sha512::default(),
            ossl::digest::Sha512::default(),
        );
        a.update(data);
        b.update(data);
        assert_eq!(a.finalize(), b.finalize());
    }
}

#[test]
fn hmac_matches() {
    // Empty, short, block-sized and longer-than-block keys.
    let long_key = [0xab; 200];
    let keys: [&[u8]; 5] = [b"", b"key", &[1; 64], &[2; 128], &long_key];
    let algs = [
        HashAlg::Sha1,
        HashAlg::Sha256,
        HashAlg::Sha384,
        HashAlg::Sha512,
    ];

    for alg in algs {
        for key in keys {
            let mut a = rc::hmac::Hmac::new(alg, key);
            let mut b = ossl::hmac::Hmac::new(alg, key);
            a.update(MESSAGE);
            b.update(MESSAGE);
            assert_eq!(a.clone().finalize(), b.clone().finalize());

            // Clones keep absorbing independently.
            a.update(b"more");
            b.update(b"more");
            assert_eq!(a.finalize(), b.finalize());
        }
    }
}

#[test]
fn hkdf_matches() {
    for salt in [None, Some(b"salt".as_slice())] {
        let (a, b) = (
            rc::hkdf::extract(salt, MESSAGE),
            ossl::hkdf::extract(salt, MESSAGE),
        );
        assert_eq!(*a, *b);

        for len in [0, 1, 32, 100, 255 * 32] {
            let (mut x, mut y) = (vec![0u8; len], vec![0u8; len]);
            assert_eq!(rc::hkdf::expand(a.as_slice(), b"info", &mut x), Ok(()));
            assert_eq!(ossl::hkdf::expand(b.as_slice(), b"info", &mut y), Ok(()));
            assert_eq!(x, y);
        }
    }

    let mut too_long = vec![0u8; 255 * 32 + 1];
    assert_eq!(
        rc::hkdf::expand(&KEY, b"", &mut too_long),
        ossl::hkdf::expand(&KEY, b"", &mut too_long)
    );
    let mut out = [0u8; 32];
    assert_eq!(
        rc::hkdf::expand(&[0; 16], b"", &mut out),
        ossl::hkdf::expand(&[0; 16], b"", &mut out)
    );
}

#[test]
fn pbkdf2_matches() {
    for rounds in [1, 2, 1000] {
        let rounds = NonZeroU32::new(rounds).expect("non-zero");
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        rc::pbkdf2::pbkdf2_hmac_sha256(MESSAGE, b"salt", rounds, &mut a);
        ossl::pbkdf2::pbkdf2_hmac_sha256(MESSAGE, b"salt", rounds, &mut b);
        assert_eq!(a, b);
    }
}

#[test]
fn argon2_matches() {
    let params = Params {
        memory_kib: 64,
        iterations: 3,
        parallelism: 4,
    };
    let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
    assert_eq!(
        rc::argon2::argon2id_v13(MESSAGE, b"somesalt", &params, &mut a),
        Ok(())
    );
    assert_eq!(
        ossl::argon2::argon2id_v13(MESSAGE, b"somesalt", &params, &mut b),
        Ok(())
    );
    assert_eq!(a, b);

    // Both backends reject the same out-of-range inputs.
    let rejected = [
        (
            Params {
                iterations: 0,
                ..params
            },
            b"somesalt".as_slice(),
            32,
        ),
        (
            Params {
                parallelism: 0,
                ..params
            },
            b"somesalt",
            32,
        ),
        (
            Params {
                memory_kib: 31,
                ..params
            },
            b"somesalt",
            32,
        ),
        (params, b"short", 32),
        (params, b"somesalt", 3),
    ];
    for (params, salt, len) in rejected {
        let (mut a, mut b) = (vec![0u8; len], vec![0u8; len]);
        let rc_result = rc::argon2::argon2id_v13(MESSAGE, salt, &params, &mut a);
        assert!(rc_result.is_err());
        assert_eq!(
            rc_result,
            ossl::argon2::argon2id_v13(MESSAGE, salt, &params, &mut b)
        );
    }
}

#[test]
fn aes_gcm_matches() {
    let nonce = [9u8; 12];
    for len in [0, 1, 16, MESSAGE.len()] {
        let pt = &MESSAGE[..len];
        let ct = rc::aes_gcm::encrypt(&KEY, &nonce, b"aad", pt);
        assert_eq!(ct, ossl::aes_gcm::encrypt(&KEY, &nonce, b"aad", pt));
        assert_eq!(
            ossl::aes_gcm::decrypt(&KEY, &nonce, b"aad", &ct),
            Ok(pt.to_vec())
        );
    }
}

#[test]
fn aes_cbc_matches() {
    let iv = [9u8; 16];
    for len in [0, 1, 16, MESSAGE.len()] {
        let pt = &MESSAGE[..len];
        let ct = rc::aes_cbc::encrypt_pkcs7(&KEY, &iv, pt);
        assert_eq!(ct, ossl::aes_cbc::encrypt_pkcs7(&KEY, &iv, pt));
        assert_eq!(
            ossl::aes_cbc::decrypt_pkcs7(&KEY, &iv, &ct),
            Ok(pt.to_vec())
        );
    }

    let mut bad_padding = rc::aes_cbc::encrypt_pkcs7(&KEY, &iv, b"x");
    bad_padding[15] ^= 1;
    assert_eq!(
        rc::aes_cbc::decrypt_pkcs7(&KEY, &iv, &bad_padding),
        ossl::aes_cbc::decrypt_pkcs7(&KEY, &iv, &bad_padding)
    );

    let (mut enc_a, mut enc_b) = (
        rc::aes_cbc::Encryptor::new(&KEY, &iv),
        ossl::aes_cbc::Encryptor::new(&KEY, &iv),
    );
    let (mut dec_a, mut dec_b) = (
        rc::aes_cbc::Decryptor::new(&KEY, &iv),
        ossl::aes_cbc::Decryptor::new(&KEY, &iv),
    );
    for chunk in MESSAGE.chunks_exact(16) {
        let mut a: [u8; 16] = chunk.try_into().expect("block");
        let mut b = a;
        enc_a.encrypt_block(&mut a);
        enc_b.encrypt_block(&mut b);
        assert_eq!(a, b);

        dec_a.decrypt_block(&mut a);
        dec_b.decrypt_block(&mut b);
        assert_eq!(a, b);
        assert_eq!(a.as_slice(), chunk);
    }
}

#[test]
fn xaes_matches() {
    // Nonces that exercise both outcomes of the CMAC subkey reduction across keys.
    for key in [[1u8; 32], KEY, [0xff; 32], [0; 32]] {
        let nonce = *b"ABCDEFGHIJKLMNOPQRSTUVWX";
        let ct = rc::xaes_256_gcm::encrypt(&key, &nonce, b"aad", MESSAGE);
        assert_eq!(
            ct,
            ossl::xaes_256_gcm::encrypt(&key, &nonce, b"aad", MESSAGE)
        );
        assert_eq!(
            ossl::xaes_256_gcm::decrypt(&key, &nonce, b"aad", &ct),
            Ok(MESSAGE.to_vec())
        );
    }
}

#[test]
fn ed25519_matches() {
    let (a, b) = (
        rc::ed25519::SigningKey::from_seed(&SEED),
        ossl::ed25519::SigningKey::from_seed(&SEED),
    );
    assert_eq!(*a.seed(), *b.seed());
    assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());

    let sig = a.sign(MESSAGE);
    assert_eq!(sig, b.sign(MESSAGE));
    assert_eq!(b.verifying_key().verify(MESSAGE, &sig), Ok(()));

    let generated = ossl::ed25519::SigningKey::generate();
    let vk = rc::ed25519::VerifyingKey::from_bytes(&generated.verifying_key().to_bytes())
        .expect("valid point");
    assert_eq!(vk.verify(MESSAGE, &generated.sign(MESSAGE)), Ok(()));
}

#[test]
fn ed25519_rejects_like_verify_strict() {
    // Small-order point (order 4): (0, -1) encodes as y = p - 1.
    let mut weak = [0xff; 32];
    weak[0] = 0xec;
    weak[31] = 0x7f;
    // Identity: y = 1.
    let mut identity = [0u8; 32];
    identity[0] = 1;

    for key in [weak, identity] {
        let rc_vk = rc::ed25519::VerifyingKey::from_bytes(&key).expect("decodes");
        let ossl_vk = ossl::ed25519::VerifyingKey::from_bytes(&key).expect("decodes");

        // R = identity with s = 0 verifies under cofactorless rules for the identity key.
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity);
        let rc_result = rc_vk.verify(MESSAGE, &sig);
        assert!(rc_result.is_err());
        assert_eq!(rc_result, ossl_vk.verify(MESSAGE, &sig));
    }

    // y = 2 is not on the curve.
    let mut off_curve = [0u8; 32];
    off_curve[0] = 2;
    assert_eq!(
        rc::ed25519::VerifyingKey::from_bytes(&off_curve).is_err(),
        ossl::ed25519::VerifyingKey::from_bytes(&off_curve).is_err()
    );

    // Non-canonical s (s + L) is rejected by both.
    let key = rc::ed25519::SigningKey::from_seed(&SEED);
    let mut sig = key.sign(MESSAGE);
    add_group_order(&mut sig[32..]);
    let ossl_vk = ossl::ed25519::SigningKey::from_seed(&SEED).verifying_key();
    assert!(key.verifying_key().verify(MESSAGE, &sig).is_err());
    assert!(ossl_vk.verify(MESSAGE, &sig).is_err());
}

/// Adds the Ed25519 group order `L` to a little-endian scalar.
fn add_group_order(scalar: &mut [u8]) {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut carry = 0u16;
    for (s, l) in scalar.iter_mut().zip(L) {
        let sum = u16::from(*s) + u16::from(l) + carry;
        *s = sum as u8;
        carry = sum >> 8;
    }
}

#[test]
fn ml_dsa_interoperates() {
    let (a, b) = (
        rc::ml_dsa_44::SigningKey::from_seed(&SEED),
        ossl::ml_dsa_44::SigningKey::from_seed(&SEED),
    );
    assert_eq!(*a.seed(), *b.seed());

    let (vk_a, vk_b) = (a.verifying_key(), b.verifying_key());
    assert_eq!(vk_a.to_bytes(), vk_b.to_bytes());

    // Hedged signatures differ, but each backend verifies the other's.
    assert_eq!(vk_b.verify(MESSAGE, &a.sign(MESSAGE)), Ok(()));
    assert_eq!(vk_a.verify(MESSAGE, &b.sign(MESSAGE)), Ok(()));
    assert_ne!(b.sign(MESSAGE), b.sign(MESSAGE));

    let generated = ossl::ml_dsa_44::SigningKey::generate();
    let from_seed = rc::ml_dsa_44::SigningKey::from_seed(&generated.seed());
    assert_eq!(
        from_seed.verifying_key().to_bytes(),
        generated.verifying_key().to_bytes()
    );
}

#[test]
fn rsa_interoperates() {
    // Each backend's key, loaded into the other through PKCS#8.
    let pairs = [
        (
            RC_RSA.clone(),
            ossl::rsa::PrivateKey::from_pkcs8_der(&RC_RSA.to_pkcs8_der().expect("encodes"))
                .expect("parses"),
        ),
        (
            rc::rsa::PrivateKey::from_pkcs8_der(&OSSL_RSA.to_pkcs8_der().expect("encodes"))
                .expect("parses"),
            OSSL_RSA.clone(),
        ),
    ];

    for (a, b) in pairs {
        let (ca, cb) = (a.components(), b.components());
        assert_eq!((ca.n, ca.e), (cb.n.clone(), cb.e.clone()));
        assert_eq!(
            (&*ca.d, &*ca.p, &*ca.q, &*ca.iqmp),
            (&*cb.d, &*cb.p, &*cb.q, &*cb.iqmp)
        );

        let (pa, pb) = (a.public_key(), b.public_key());
        assert_eq!(pa.to_spki_der(), pb.to_spki_der());
        assert_eq!(pa.modulus_len(), pb.modulus_len());

        // OAEP is randomized: encrypt with one backend, decrypt with the other.
        for hash in [OaepHash::Sha1, OaepHash::Sha256] {
            let ct = pa.encrypt_oaep(hash, MESSAGE).expect("fits");
            assert_eq!(*b.decrypt_oaep(hash, &ct).expect("valid"), MESSAGE);

            let ct = pb.encrypt_oaep(hash, MESSAGE).expect("fits");
            assert_eq!(*a.decrypt_oaep(hash, &ct).expect("valid"), MESSAGE);
        }

        // Components rebuilt by OpenSSL (computing the CRT parameters) give the same key.
        let rebuilt = ossl::rsa::PrivateKey::from_components(&cb.n, &cb.e, &cb.d, &[&cb.p, &cb.q])
            .expect("valid");
        assert_eq!(rebuilt.to_pkcs8_der(), b.to_pkcs8_der());
    }
}

#[test]
fn p256_interoperates() {
    let (a, b) = (
        rc::p256::SecretKey::generate(),
        ossl::p256::SecretKey::generate(),
    );

    // Each backend's key, loaded into the other through the raw scalar and PKCS#8.
    let a_in_ossl = ossl::p256::SecretKey::from_bytes(&a.to_bytes()).expect("valid");
    let b_in_rc =
        rc::p256::SecretKey::from_pkcs8_der(&b.to_pkcs8_der().expect("encodes")).expect("parses");
    let a_from_der =
        ossl::p256::SecretKey::from_pkcs8_der(&a.to_pkcs8_der().expect("encodes")).expect("parses");
    assert_eq!(*a_from_der.to_bytes(), *a.to_bytes());
    assert_eq!(*b_in_rc.to_bytes(), *b.to_bytes());
    assert_eq!(
        a_in_ossl.public_key().to_sec1_uncompressed(),
        a.public_key().to_sec1_uncompressed()
    );

    // ECDH across backends agrees.
    let b_pub_in_rc = rc::p256::PublicKey::from_sec1_bytes(&b.public_key().to_sec1_uncompressed())
        .expect("valid");
    let a_pub_in_ossl =
        ossl::p256::PublicKey::from_sec1_bytes(&a.public_key().to_sec1_uncompressed())
            .expect("valid");
    assert_eq!(
        *a.diffie_hellman(&b_pub_in_rc),
        *b.diffie_hellman(&a_pub_in_ossl)
    );

    // Identity and off-curve encodings are rejected by both.
    for bad in [[0u8; 1].as_slice(), &[4; 65]] {
        assert!(rc::p256::PublicKey::from_sec1_bytes(bad).is_err());
        assert!(ossl::p256::PublicKey::from_sec1_bytes(bad).is_err());
    }
}
