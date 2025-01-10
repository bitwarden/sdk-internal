use crate::{destination::Destination, link_repository::LinkRepository, providers::CryptoProvider};

#[derive(Debug)]
pub enum SendError<T> {
    DestinationUnreachable,
    CryptoError(T),
}

#[derive(Debug)]
pub enum ReceiveError<T> {
    DestinationUnreachable,
    CryptoError(T),
}

pub struct Manager<C, L>
where
    C: CryptoProvider,
    L: LinkRepository,
{
    crypto: C,
    link_repository: L,
}

impl<C, L> Manager<C, L>
where
    C: CryptoProvider,
    L: LinkRepository,
{
    pub fn new(crypto: C, link_repository: L) -> Self {
        Self {
            crypto,
            link_repository,
        }
    }

    pub async fn send(
        &self,
        destination: Destination,
        data: &[u8],
    ) -> Result<(), SendError<C::SendError>> {
        let link = self
            .link_repository
            .get(destination)
            .ok_or(SendError::DestinationUnreachable)?;
        // TODO: Fetch session from some kind of session store
        let session = None;
        // TODO: Store new session if changed
        let _new_session = self
            .crypto
            .send(session, link, data)
            .await
            .map_err(|e| SendError::CryptoError(e))?;

        Ok(())
    }

    pub async fn receive(
        &self,
        destination: Destination,
    ) -> Result<Vec<u8>, ReceiveError<C::ReceiveError>> {
        let link = self
            .link_repository
            .get(destination)
            .ok_or(ReceiveError::DestinationUnreachable)?;
        let session = None;
        let (data, _new_session) = self
            .crypto
            .receive(session, link)
            .await
            .map_err(|e| ReceiveError::CryptoError(e))?;

        Ok(data)
    }
}
