use std::rc::Rc;

use crate::{destination::Destination, link::Link, providers::CryptoProvider};

pub struct Manager<C>
where
    C: CryptoProvider,
{
    crypto: Rc<C>,
    links: Vec<Box<dyn Link>>,
}

impl<C> Manager<C>
where
    C: CryptoProvider,
{
    pub fn new() -> Self {
        todo!()
    }

    pub fn register_link(&mut self) {
        todo!()
    }

    pub fn get_channel(&mut self, destination: Destination) {
        todo!()
    }
}
