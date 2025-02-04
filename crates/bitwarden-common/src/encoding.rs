pub enum DecodeError {
    Err,
}

impl std::fmt::Debug for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecodeError")
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DecodeError")
    }
}

impl std::error::Error for DecodeError {}

mod private {
    // We can't easily add blanket impls for Encodable and Decodable to ensure the reverse impls are
    // available, but we can mark the traits as sealed to ensure that only the intended types
    // can implement them.
    pub trait Sealed {}
    impl Sealed for Vec<u8> {}
    impl Sealed for &[u8] {}
    impl Sealed for String {}
    impl Sealed for &str {}
}

pub trait Encodable<To>: private::Sealed {
    fn encode(self) -> To;
}

pub trait Decodable<To>: private::Sealed {
    fn try_decode(self) -> Result<To, DecodeError>;
}

impl Encodable<Vec<u8>> for Vec<u8> {
    fn encode(self) -> Vec<u8> {
        self
    }
}

impl Encodable<Vec<u8>> for &[u8] {
    fn encode(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Decodable<Vec<u8>> for Vec<u8> {
    fn try_decode(self) -> Result<Vec<u8>, DecodeError> {
        Ok(self)
    }
}

impl Encodable<Vec<u8>> for String {
    fn encode(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl Encodable<Vec<u8>> for &str {
    fn encode(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Decodable<String> for Vec<u8> {
    fn try_decode(self) -> Result<String, DecodeError> {
        String::from_utf8(self).map_err(|_| DecodeError::Err)
    }
}
