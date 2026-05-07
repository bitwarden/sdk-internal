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

/// An in-memory session repository implementation that stores sessions in a `HashMap` protected by
/// an `RwLock`. This is a simple implementation that can be used for testing or in scenarios where
/// persistence is not required.
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
