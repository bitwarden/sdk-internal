use std::rc::Rc;

use crate::{link::Link, providers::CryptoProvider};

/// An end-to-end channel between two IPC endpoints, possibly traversing multiple links across processes.
/// A channel is a stateful object that can provide a secure and trusted communication path between two endpoints.
pub struct Channel<C, L>
where
    C: CryptoProvider,
    L: Link,
{
    link: Box<L>,
    crypto: Rc<C>,
    session: C::Session,
}

impl<C, L> Channel<C, L>
where
    C: CryptoProvider,
    L: Link,
{
    async fn send(&self, data: &[u8]) {
        self.link.send(data).await;
    }

    async fn receive(&self) -> Vec<u8> {
        self.link.receive().await
    }
}
