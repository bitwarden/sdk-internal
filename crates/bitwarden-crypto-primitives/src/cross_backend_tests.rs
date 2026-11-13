//! Cross-checks the OpenSSL driver against the RustCrypto driver: equal outputs where the
//! primitive is deterministic, interoperability where it is randomized.

use std::{num::NonZeroU32, sync::LazyLock};

use crate::{
    argon2::Params,
    hmac::HashAlg,
    openssl_fips as ossl,
    rsa::{KeySize, OaepHash},
    rustcrypto as rc,
    test_vectors::{array, bytes},
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

/// The 12 Ed25519 edge cases from "Taming the many EdDSAs" (Chalkias et al., 2020), from
/// <https://github.com/novifinancial/ed25519-speccheck>: (message, public key, signature, accepted).
/// Both backends implement dalek's `verify_strict`, which accepts only case 3.
const ED25519_SPECCHECK: [(&str, &str, &str, bool); 12] = [
    // 0: S = 0, small-order A and R.
    (
        "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a\
        0000000000000000000000000000000000000000000000000000000000000000",
        false,
    ),
    // 1: small-order A.
    (
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43\
        a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        false,
    ),
    // 2: small-order R.
    (
        "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa\
        8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        false,
    ),
    // 3: mixed-order A and R; only full-order checks reject it.
    (
        "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f\
        87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        true,
    ),
    // 4: mixed-order A and R; passes cofactored, fails cofactorless.
    (
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512\
        5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        false,
    ),
    // 5: R of order L; passes cofactored only if 8h is prereduced.
    (
        "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7\
        e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        false,
    ),
    // 6: S > L.
    (
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e\
        547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        false,
    ),
    // 7: S >> L.
    (
        "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942\
        7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        false,
    ),
    // 8: non-canonical R, reduced for hash.
    (
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        false,
    ),
    // 9: non-canonical R, not reduced for hash.
    (
        "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
        ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        false,
    ),
    // 10: non-canonical A, reduced for hash.
    (
        "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc\
        a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        false,
    ),
    // 11: non-canonical A, not reduced for hash.
    (
        "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc\
        a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        false,
    ),
];

#[test]
fn ed25519_speccheck_vectors() {
    for (case, (msg, public, sig, accepted)) in ED25519_SPECCHECK.into_iter().enumerate() {
        let (msg, sig) = (bytes(msg), array::<{ crate::ed25519::SIGNATURE_LEN }>(sig));
        let public = array::<{ crate::ed25519::PUBLIC_KEY_LEN }>(public);

        let rc = rc::ed25519::VerifyingKey::from_bytes(&public).and_then(|k| k.verify(&msg, &sig));
        let ossl =
            ossl::ed25519::VerifyingKey::from_bytes(&public).and_then(|k| k.verify(&msg, &sig));
        assert_eq!(rc.is_ok(), accepted, "RustCrypto, case {case}");
        assert_eq!(ossl.is_ok(), accepted, "OpenSSL, case {case}");
    }
}
