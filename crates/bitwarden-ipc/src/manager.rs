use crate::{destination::Destination, link::Link, providers::CryptoProvider};

pub struct Manager<C>
where
    C: CryptoProvider,
{
    crypto: C,
    links: Vec<Box<dyn Link>>,
}

impl<C> Manager<C>
where
    C: CryptoProvider,
{
    pub fn new(crypto: C) -> Self {
        Self {
            crypto,
            links: Vec::new(),
        }
    }

    pub fn register_link(&mut self, link: Box<dyn Link>) {
        self.links.push(link);
    }

    pub fn get_channel(&mut self, destination: Destination) {
        todo!()
    }
}
