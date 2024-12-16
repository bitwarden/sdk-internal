use dhkem::{DhDecapsulator, DhEncapsulator, DhKem, X25519Kem};

pub(crate) fn keypair() -> (
    DhDecapsulator<x25519_dalek::ReusableSecret>,
    DhEncapsulator<x25519_dalek::PublicKey>,
    [u8; 32],
) {
    let mut rng = rand::thread_rng();
    let (dec, enc): (
        DhDecapsulator<x25519_dalek::ReusableSecret>,
        DhEncapsulator<x25519_dalek::PublicKey>,
    ) = X25519Kem::random_keypair(&mut rng);
    let hash = {
        let public_key = enc.into_inner();
        blake3::hash(public_key.as_bytes()).into()
    };
    (dec, enc, hash)
}
