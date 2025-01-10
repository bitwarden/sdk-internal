use crate::{destination::Destination, link::Link};

pub trait LinkRepository {
    fn get(&self, destination: Destination) -> Option<&Link>;
}
