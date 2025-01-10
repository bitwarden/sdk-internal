use crate::link::{self, Link};

pub trait CryptoProvider {
    type Session;
    type SendError;
    type ReceiveError;

    fn send(
        &self,
        session: Option<Self::Session>,
        link: &Link,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<Option<Self::Session>, Self::SendError>>;
    fn receive(
        &self,
        session: Option<Self::Session>,
        link: &Link,
    ) -> impl std::future::Future<Output = Result<(Vec<u8>, Option<Self::Session>), Self::ReceiveError>>;
}

pub struct NoEncryptionCryptoProvider;

impl CryptoProvider for NoEncryptionCryptoProvider {
    type Session = ();
    type SendError = link::SendError;
    type ReceiveError = link::ReceiveError;

    async fn send(
        &self,
        _session: Option<Self::Session>,
        link: &Link,
        data: &[u8],
    ) -> Result<Option<Self::Session>, link::SendError> {
        // TODO: Should we change &[u8] to Vec<u8>?
        link.send(data.to_vec()).await?;
        Ok(None)
    }

    async fn receive(
        &self,
        _session: Option<Self::Session>,
        link: &Link,
    ) -> Result<(Vec<u8>, Option<Self::Session>), link::ReceiveError> {
        let data = link.receive().await?;
        Ok((data, None))
    }
}
