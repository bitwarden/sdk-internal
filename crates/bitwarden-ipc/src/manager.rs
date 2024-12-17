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

    pub fn get_channel(&mut self, destination: Destination) {
        todo!()
    }
}
