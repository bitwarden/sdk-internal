use crate::destination::Destination;

pub trait SessionProvider {
    type Session;

    fn get(&self, destination: Destination) -> Option<Self::Session>;
    fn save(&mut self, destination: Destination, session: Self::Session);
    fn remove(&mut self, destination: Destination);
}
