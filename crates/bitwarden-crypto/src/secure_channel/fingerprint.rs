pub(super) trait Fingerprint {
    fn fingerprint(&self) -> [u8; 32];
}
