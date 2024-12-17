use crate::destination::Destination;

/// A wrapper around a "physical" connection (e.g. a TCP connection) between two IPC endpoints.
/// This is a low-level struct that is used to send and receive data between two endpoints
/// it is not meant to be used directly by consumers of this library.
pub trait Link {
    fn send(&self, data: &[u8]) -> impl std::future::Future<Output = ()>;
    fn receive(&self) -> impl std::future::Future<Output = Vec<u8>>;

    fn available_destinations(&self) -> Vec<Destination>;
}
