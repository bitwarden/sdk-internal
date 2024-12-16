pub trait CryptoProvider {
    type Session;

    fn establish_session(&self) -> Self::Session;

    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

pub struct NoEncryptionCryptoProvider;

impl CryptoProvider for NoEncryptionCryptoProvider {
    type Session = ();

    fn establish_session(&self) {}

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }
}
