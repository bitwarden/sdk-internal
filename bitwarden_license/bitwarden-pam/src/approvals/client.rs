use std::sync::Arc;

use bitwarden_api_api::models::AccessDecisionRequestModel;
use bitwarden_core::{FromClient, client::ApiConfigurations};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{error::AccessDecisionError, models::AccessDecisionRequest};
use crate::{AccessRequestId, PamReadError, access_requests::AccessRequestView};

/// Client for a PAM approver's queue.
///
/// Covers the approver side of the request lifecycle: reading the pending requests awaiting the
/// caller's decision ([`list_inbox`](ApprovalsClient::list_inbox)), reading the ones the caller has
/// already decided ([`list_history`](ApprovalsClient::list_history)), and
/// [`decide`](ApprovalsClient::decide)ing a pending request. The requester side of the same
/// lifecycle is [`AccessRequestsClient`](crate::AccessRequestsClient).
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct ApprovalsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ApprovalsClient {
    /// Lists the pending access requests awaiting the caller's decision.
    ///
    /// `GET /access-requests/inbox`. The server scopes this by Manage permission on the request's
    /// collection and returns only pending requests, so an empty list is the normal answer for a
    /// member who approves nothing.
    pub async fn list_inbox(&self) -> Result<Vec<AccessRequestView>, PamReadError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .get_inbox()
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessRequestView::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Lists the decided access requests for collections the caller manages.
    ///
    /// `GET /access-requests/history`. Same response shape as [`list_inbox`](Self::list_inbox),
    /// not an audit-event shape.
    pub async fn list_history(&self) -> Result<Vec<AccessRequestView>, PamReadError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .get_history()
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessRequestView::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Records a decision on a pending access request.
    ///
    /// `POST /access-requests/{id}/decision`. Only `status`, `resolved_at`, and the decision just
    /// recorded are guaranteed populated on the response, so callers should merge it onto the row
    /// they already hold rather than replacing it.
    pub async fn decide(
        &self,
        id: AccessRequestId,
        request: AccessDecisionRequest,
    ) -> Result<AccessRequestView, AccessDecisionError> {
        let model = AccessDecisionRequestModel::try_from(request)?;

        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .decide(id.into(), model)
            .await?;

        Ok(AccessRequestView::try_from(response)?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AccessDecisionVerdict as ApiAccessDecisionVerdict, AccessRequestDetailsResponseModel,
            AccessRequestDetailsResponseModelListResponseModel,
            AccessRequestStatus as ApiAccessRequestStatus,
        },
    };
    use uuid::uuid;

    use super::*;
    use crate::{AccessDecisionVerdict, AccessRequestStatus};

    fn request_id() -> AccessRequestId {
        AccessRequestId::new(uuid!("44444444-4444-4444-4444-444444444444"))
    }

    fn client(api_client: ApiClient) -> ApprovalsClient {
        ApprovalsClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn sample_request() -> AccessRequestDetailsResponseModel {
        AccessRequestDetailsResponseModel {
            id: Some(request_id().into()),
            cipher_id: Some(uuid!("55555555-5555-5555-5555-555555555555")),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
            status: Some(ApiAccessRequestStatus::Pending),
            lease_not_before: Some("2025-01-01T00:00:00Z".to_string()),
            lease_not_after: Some("2025-01-01T01:00:00Z".to_string()),
            submitted_at: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_inbox_returns_views() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_inbox()
                .returning(move || {
                    let mut list = AccessRequestDetailsResponseModelListResponseModel::new();
                    list.data = Some(vec![sample_request()]);
                    Ok(list)
                })
                .once();
        });

        let result = client(api_client).list_inbox().await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, request_id());
        assert_eq!(result[0].status, AccessRequestStatus::Pending);
    }

    #[tokio::test]
    async fn list_inbox_returns_empty_vec_when_server_sends_no_data() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_inbox()
                .returning(move || Ok(AccessRequestDetailsResponseModelListResponseModel::new()))
                .once();
        });

        let result = client(api_client).list_inbox().await.unwrap();

        assert_eq!(result, Vec::new());
    }

    #[tokio::test]
    async fn list_history_returns_views() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_history()
                .returning(move || {
                    let mut list = AccessRequestDetailsResponseModelListResponseModel::new();
                    list.data = Some(vec![sample_request()]);
                    Ok(list)
                })
                .once();
        });

        let result = client(api_client).list_history().await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, request_id());
    }

    #[tokio::test]
    async fn decide_returns_updated_view_and_sends_approve_verdict() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_decide()
                .returning(move |_id, model| {
                    assert_eq!(model.verdict, ApiAccessDecisionVerdict::Approve);
                    assert_eq!(model.comment.as_deref(), Some("Looks fine"));

                    Ok(AccessRequestDetailsResponseModel {
                        status: Some(ApiAccessRequestStatus::Approved),
                        resolved_at: Some("2025-01-01T00:30:00Z".to_string()),
                        ..sample_request()
                    })
                })
                .once();
        });

        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Approve,
            comment: Some("Looks fine".to_string()),
        };

        let result = client(api_client)
            .decide(request_id(), request)
            .await
            .unwrap();

        assert_eq!(result.id, request_id());
        assert_eq!(result.status, AccessRequestStatus::Approved);
    }

    #[tokio::test]
    async fn decide_sends_deny_verdict() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_decide()
                .returning(move |_id, model| {
                    assert_eq!(model.verdict, ApiAccessDecisionVerdict::Deny);
                    assert_eq!(model.comment.as_deref(), Some("Not authorized"));

                    Ok(AccessRequestDetailsResponseModel {
                        status: Some(ApiAccessRequestStatus::Denied),
                        resolved_at: Some("2025-01-01T00:30:00Z".to_string()),
                        ..sample_request()
                    })
                })
                .once();
        });

        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Deny,
            comment: Some("Not authorized".to_string()),
        };

        let result = client(api_client)
            .decide(request_id(), request)
            .await
            .unwrap();

        assert_eq!(result.status, AccessRequestStatus::Denied);
    }

    #[tokio::test]
    async fn decide_rejects_unknown_verdict_without_calling_the_api() {
        let api_client = ApiClient::new_mocked(|mock| {
            mock.access_requests_api.expect_decide().never();
        });

        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Unknown,
            comment: None,
        };

        let result = client(api_client).decide(request_id(), request).await;

        assert!(matches!(
            result,
            Err(AccessDecisionError::UnsubmittableVerdict)
        ));
    }

    #[tokio::test]
    async fn decide_surfaces_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_decide()
                .returning(move |_id, _model| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::CONFLICT,
                            message: "Already decided".to_string(),
                        },
                    ))
                })
                .once();
        });

        let request = AccessDecisionRequest {
            verdict: AccessDecisionVerdict::Approve,
            comment: None,
        };

        let result = client(api_client).decide(request_id(), request).await;

        assert!(matches!(result, Err(AccessDecisionError::Api(_))));
    }
}
