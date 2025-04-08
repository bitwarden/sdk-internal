use std::collections::HashMap;

use tokio::sync::RwLock;

use crate::endpoint::Endpoint;

pub trait SessionRepository {
    type Session;
    type GetError;
    type SaveError;
    type RemoveError;

    fn get(
        &self,
        destination: Endpoint,
    ) -> impl std::future::Future<Output = Result<Option<Self::Session>, Self::GetError>>;
    fn save(
        &self,
        destination: Endpoint,
        session: Self::Session,
    ) -> impl std::future::Future<Output = Result<(), Self::SaveError>>;
    fn remove(
        &self,
        destination: Endpoint,
    ) -> impl std::future::Future<Output = Result<(), Self::RemoveError>>;
}

pub type InMemorySessionRepository<Session> = RwLock<HashMap<Endpoint, Session>>;
impl<Session> SessionRepository for InMemorySessionRepository<Session>
where
    Session: Clone,
{
    type Session = Session;
    type GetError = ();
    type SaveError = ();
    type RemoveError = ();

    async fn get(&self, destination: Endpoint) -> Result<Option<Self::Session>, ()> {
        Ok(self.read().await.get(&destination).cloned())
    }

    async fn save(&self, destination: Endpoint, session: Self::Session) -> Result<(), ()> {
        self.write().await.insert(destination, session);
        Ok(())
    }

    async fn remove(&self, destination: Endpoint) -> Result<(), ()> {
        self.write().await.remove(&destination);
        Ok(())
    }
}
