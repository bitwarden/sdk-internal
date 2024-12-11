pub trait CryptoProvider {
    type Session;

    fn establish_session(&self) -> Self::Session;

    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}
