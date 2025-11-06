use std::sync::Arc;

use crate::{
    traits::{InMemorySessionRepository, SessionRepository},
    wasm::JsSessionRepository,
};

// TODO: Change session type when implementing encryption
type Session = ();

pub enum GenericSessionRepository {
    InMemory(Arc<InMemorySessionRepository<Session>>),
    JsSessionRepository(Arc<JsSessionRepository>),
}

impl SessionRepository<Session> for GenericSessionRepository {
    type GetError = String;
    type SaveError = String;
    type RemoveError = String;

    async fn get(
        &self,
        endpoint: crate::endpoint::Endpoint,
    ) -> Result<Option<Session>, Self::GetError> {
        match self {
            GenericSessionRepository::InMemory(repo) => repo
                .get(endpoint)
                .await
                .map_err(|_| "Unreachable".to_string()),
            GenericSessionRepository::JsSessionRepository(repo) => {
                <JsSessionRepository as SessionRepository<Session>>::get(repo.as_ref(), endpoint)
                    .await
            }
        }
    }

    async fn save(
        &self,
        endpoint: crate::endpoint::Endpoint,
        session: Session,
    ) -> Result<(), Self::SaveError> {
        match self {
            GenericSessionRepository::InMemory(repo) => repo
                .save(endpoint, session)
                .await
                .map_err(|_| "Unreachable".to_string()),
            GenericSessionRepository::JsSessionRepository(repo) => {
                <JsSessionRepository as SessionRepository<Session>>::save(
                    repo.as_ref(),
                    endpoint,
                    session,
                )
                .await
            }
        }
    }

    async fn remove(&self, endpoint: crate::endpoint::Endpoint) -> Result<(), Self::RemoveError> {
        match self {
            GenericSessionRepository::InMemory(repo) => repo
                .remove(endpoint)
                .await
                .map_err(|_| "Unreachable".to_string()),
            GenericSessionRepository::JsSessionRepository(repo) => {
                <JsSessionRepository as SessionRepository<Session>>::remove(repo.as_ref(), endpoint)
                    .await
            }
        }
    }
}
