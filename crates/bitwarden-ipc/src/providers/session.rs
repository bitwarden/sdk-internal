use std::collections::HashMap;

use crate::destination::Destination;

pub trait SessionProvider {
    type Session;

    fn get(&self, destination: Destination) -> Option<Self::Session>;
    fn save(&mut self, destination: Destination, session: Self::Session);
    fn remove(&mut self, destination: Destination);
}

pub type InMemorySessionProvider<Session> = HashMap<Destination, Session>;
impl<Session> SessionProvider for InMemorySessionProvider<Session>
where
    Session: Clone,
{
    type Session = Session;

    fn get(&self, destination: Destination) -> Option<Self::Session> {
        self.get(&destination).cloned()
    }

    fn save(&mut self, destination: Destination, session: Self::Session) {
        self.insert(destination, session);
    }

    fn remove(&mut self, destination: Destination) {
        self.remove(&destination);
    }
}
