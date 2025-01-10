use thiserror::Error;
use tokio::sync::broadcast;

#[derive(Debug, Error)]
#[error(transparent)]
pub struct SendError(#[from] broadcast::error::SendError<Vec<u8>>);

#[derive(Debug, Error)]
#[error(transparent)]
pub struct ReceiveError(#[from] broadcast::error::RecvError);

pub struct Link {
    tx: broadcast::Sender<Vec<u8>>,
    // Store a receiver to keep the channel alive
    _rx: broadcast::Receiver<Vec<u8>>,
    // destinations: Vec<Destination>,
}

impl Link {
    // pub fn new(destinations: Vec<Destination>) -> Self {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);

        Self {
            tx,
            _rx,
            // destinations,
        }
    }

    pub async fn send(&self, data: Vec<u8>) -> Result<(), SendError> {
        self.tx.send(data)?;
        Ok(())
    }

    pub async fn receive(&self) -> Result<Vec<u8>, ReceiveError> {
        let tx = self.tx.clone();
        let mut rx = tx.subscribe();
        let data = rx.recv().await?;
        Ok(data)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.tx.subscribe()
    }

    // pub fn available_destinations(&self) -> &Vec<Destination> {
    //     &self.destinations
    // }
}
