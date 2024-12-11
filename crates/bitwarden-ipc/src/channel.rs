use std::rc::Rc;

use crate::{link::Link, providers::CryptoProvider};

/// An end-to-end channel between two IPC endpoints, possibly traversing multiple links across processes.
/// A channel is a stateful object that can provide a secure and trusted communication path between two endpoints.
pub struct Channel<C>
where
    C: CryptoProvider,
{
    link: Box<dyn Link>,
    crypto: Rc<C>,
    session: C::Session,
}

impl<C> Channel<C>
where
    C: CryptoProvider,
{
    fn send(&self, data: &[u8]) {
        todo!()
    }
    fn receive(&self) -> Vec<u8> {
        todo!()
    }
}
