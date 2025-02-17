use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::destination::Destination;

// TODO: Might want to allow the operations to fail with an error
pub trait SessionRepository {
    type Session;

    fn get(
        &self,
        destination: Destination,
    ) -> impl std::future::Future<Output = Option<Self::Session>>;
    fn save(
        &self,
        destination: Destination,
        session: Self::Session,
    ) -> impl std::future::Future<Output = ()>;
    fn remove(&self, destination: Destination) -> impl std::future::Future<Output = ()>;
}

pub type InMemorySessionRepository<Session> = RwLock<HashMap<Destination, Session>>;
impl<Session> SessionRepository for InMemorySessionRepository<Session>
where
    Session: Clone,
{
    type Session = Session;

    async fn get(&self, destination: Destination) -> Option<Self::Session> {
        self.read().await.get(&destination).cloned()
    }

    async fn save(&self, destination: Destination, session: Self::Session) {
        self.write().await.insert(destination, session);
    }

    async fn remove(&self, destination: Destination) {
        self.write().await.remove(&destination);
    }
}
