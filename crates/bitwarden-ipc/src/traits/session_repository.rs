use std::{collections::HashMap, fmt::Debug};

use tokio::sync::RwLock;

use crate::endpoint::Endpoint;

pub trait SessionRepository<Session>: Send + Sync + 'static {
    type GetError: Debug + Send + Sync + 'static;
    type SaveError: Debug + Send + Sync + 'static;
    type RemoveError: Debug + Send + Sync + 'static;

    fn get(
        &self,
        destination: Endpoint,
    ) -> impl std::future::Future<Output = Result<Option<Session>, Self::GetError>> + Send + Sync;
    fn save(
        &self,
        destination: Endpoint,
        session: Session,
    ) -> impl std::future::Future<Output = Result<(), Self::SaveError>> + Send + Sync;
    fn remove(
        &self,
        destination: Endpoint,
    ) -> impl std::future::Future<Output = Result<(), Self::RemoveError>> + Send + Sync;
}

pub type InMemorySessionRepository<Session> = RwLock<HashMap<Endpoint, Session>>;
impl<Session> SessionRepository<Session> for InMemorySessionRepository<Session>
where
    Session: Clone + Send + Sync + 'static,
{
    type GetError = ();
    type SaveError = ();
    type RemoveError = ();

    async fn get(&self, destination: Endpoint) -> Result<Option<Session>, ()> {
        Ok(self.read().await.get(&destination).cloned())
    }

    async fn save(&self, destination: Endpoint, session: Session) -> Result<(), ()> {
        self.write().await.insert(destination, session);
        Ok(())
    }

    async fn remove(&self, destination: Endpoint) -> Result<(), ()> {
        self.write().await.remove(&destination);
        Ok(())
    }
}
