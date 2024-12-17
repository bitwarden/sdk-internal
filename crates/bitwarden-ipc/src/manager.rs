use crate::{destination::Destination, link::Link, providers::CryptoProvider};

pub struct Manager<C, L>
where
    C: CryptoProvider,
    L: Link,
{
    crypto: C,
    links: Vec<L>,
}

impl<C, L> Manager<C, L>
where
    C: CryptoProvider,
    L: Link,
{
    pub fn new(crypto: C) -> Self {
        Self {
            crypto,
            links: Vec::new(),
        }
    }

    pub fn register_link(&mut self, link: L) {
        self.links.push(link);
    }

    pub async fn send(&self, destination: Destination, data: &[u8]) {
        let link = self
            .links
            .iter()
            .find(|link| link.available_destinations().contains(&destination))
            // TODO: Use proper error handling
            .expect("No link available for destination");
        link.send(data).await;
    }

    pub async fn receive(&self, destination: Destination) -> Vec<u8> {
        let link = self
            .links
            .iter()
            .find(|link| link.available_destinations().contains(&destination))
            // TODO: Use proper error handling
            .expect("No link available for destination");
        link.receive().await
    }
}
