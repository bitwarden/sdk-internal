use std::sync::Arc;

use bitwarden_api_api::models::{AccessDecisionRequestModel, AccessRequestRevokeRequestModel};
use bitwarden_core::{FromClient, client::ApiConfigurations};

use super::{
    error::ApprovalError,
    models::{
        AccessDecisionRequest, AccessRequestHistoryPage, AccessRequestHistoryQuery,
        AccessRequestRevokeRequest,
    },
};
use crate::{AccessRequestId, access_requests::AccessRequestView};

/// Client for a PAM approver's queue. The requester side is
/// [`AccessRequestsClient`](crate::AccessRequestsClient).
#[bitwarden_ffi::wasm_object]
#[derive(FromClient)]
pub struct ApprovalsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[bitwarden_ffi::wasm_export]
impl ApprovalsClient {
    /// Lists the pending access requests awaiting the caller's decision, in collections the caller
    /// can manage.
    pub async fn list_inbox(&self) -> Result<Vec<AccessRequestView>, ApprovalError> {
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

    /// Lists the approved access requests for collections the caller manages that can still give
    /// access: not started and inside their window, or behind a live lease, with that lease's
    /// extension.
    pub async fn list_approved(&self) -> Result<Vec<AccessRequestView>, ApprovalError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .get_approved()
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessRequestView::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Reads one page of the ended access requests on collections the caller manages and among
    /// the caller's own, newest end first, with the total and the filter options.
    pub async fn list_history(
        &self,
        query: AccessRequestHistoryQuery,
    ) -> Result<AccessRequestHistoryPage, ApprovalError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .get_history(
                Some(i32::try_from(query.page).unwrap_or(i32::MAX)),
                Some(i32::try_from(query.page_size).unwrap_or(i32::MAX)),
                non_empty(
                    query
                        .statuses
                        .iter()
                        .map(|status| status.wire_name().to_owned())
                        .collect(),
                ),
                non_empty(query.collection_ids.into_iter().map(Into::into).collect()),
                non_empty(query.requester_ids.into_iter().map(Into::into).collect()),
            )
            .await?;

        Ok(AccessRequestHistoryPage::try_from(response)?)
    }

    /// Records a decision on a pending access request.
    ///
    /// The response guarantees only `status`, `resolved_at` and the new decision, so merge it onto
    /// the row already held instead of replacing it.
    pub async fn decide(
        &self,
        id: AccessRequestId,
        request: AccessDecisionRequest,
    ) -> Result<AccessRequestView, ApprovalError> {
        let model = AccessDecisionRequestModel::try_from(request)?;

        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .decide(id.into(), model)
            .await?;

        Ok(AccessRequestView::try_from(response)?)
    }

    /// Revokes an approved access request the requester has not started. The server records it as
    /// the approver's deny decision, with the reason shown to the requester.
    pub async fn revoke(
        &self,
        id: AccessRequestId,
        request: AccessRequestRevokeRequest,
    ) -> Result<(), ApprovalError> {
        self.api_configurations
            .api_client
            .access_requests_api()
            .revoke(
                id.into(),
                Some(AccessRequestRevokeRequestModel::from(request)),
            )
            .await?;

        Ok(())
    }
}

/// The binding omits an absent list, which the server reads as unfiltered.
fn non_empty<T>(values: Vec<T>) -> Option<Vec<T>> {
    (!values.is_empty()).then_some(values)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AccessDecisionVerdict as ApiAccessDecisionVerdict, AccessRequestDetailsResponseModel,
            AccessRequestDetailsResponseModelListResponseModel,
            AccessRequestHistoryPageResponseModel, AccessRequestHistoryRequesterResponseModel,
            AccessRequestStatus as ApiAccessRequestStatus,
        },
    };
    use bitwarden_collections::collection::CollectionId;
    use bitwarden_core::UserId;
    use uuid::uuid;

    use super::*;
    use crate::{AccessDecisionVerdict, AccessRequestHistoryStatus, AccessRequestStatus};

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
    async fn list_approved_returns_views() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_approved()
                .returning(move || {
                    let mut list = AccessRequestDetailsResponseModelListResponseModel::new();
                    list.data = Some(vec![AccessRequestDetailsResponseModel {
                        status: Some(ApiAccessRequestStatus::Approved),
                        ..sample_request()
                    }]);
                    Ok(list)
                })
                .once();
        });

        let result = client(api_client).list_approved().await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, request_id());
        assert_eq!(result[0].status, AccessRequestStatus::Approved);
    }

    #[tokio::test]
    async fn list_history_sends_the_query_and_returns_the_page() {
        let collection_id = uuid!("00000000-0000-0000-0000-0000000000c1");
        let requester_id = uuid!("00000000-0000-0000-0000-0000000000a1");
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_history()
                .withf(move |page, page_size, status, collections, requesters| {
                    *page == Some(2)
                        && *page_size == Some(25)
                        && status.as_deref()
                            == Some(&["revoked".to_string(), "sessionEnded".to_string()][..])
                        && collections.as_deref() == Some(&[collection_id][..])
                        && requesters.as_deref() == Some(&[requester_id][..])
                })
                .returning(move |_, _, _, _, _| {
                    Ok(AccessRequestHistoryPageResponseModel {
                        data: Some(vec![sample_request()]),
                        total: Some(51),
                        requesters: Some(vec![AccessRequestHistoryRequesterResponseModel {
                            id: Some(requester_id),
                            name: Some("Grace".to_string()),
                            email: Some("grace@example.com".to_string()),
                            ..Default::default()
                        }]),
                        collection_ids: Some(vec![collection_id]),
                        ..Default::default()
                    })
                })
                .once();
        });

        let page = client(api_client)
            .list_history(AccessRequestHistoryQuery {
                page: 2,
                page_size: 25,
                statuses: vec![
                    AccessRequestHistoryStatus::Revoked,
                    AccessRequestHistoryStatus::SessionEnded,
                ],
                collection_ids: vec![CollectionId::new(collection_id)],
                requester_ids: vec![UserId::new(requester_id)],
            })
            .await
            .unwrap();

        assert_eq!(page.requests.len(), 1);
        assert_eq!(page.requests[0].id, request_id());
        assert_eq!(page.total, 51);
        assert_eq!(
            page.requesters[0].email.as_deref(),
            Some("grace@example.com")
        );
        assert_eq!(page.collection_ids, vec![CollectionId::new(collection_id)]);
    }

    #[tokio::test]
    async fn list_history_leaves_empty_filters_out() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_history()
                .withf(|page, page_size, status, collections, requesters| {
                    *page == Some(0)
                        && *page_size == Some(10)
                        && status.is_none()
                        && collections.is_none()
                        && requesters.is_none()
                })
                .returning(move |_, _, _, _, _| {
                    Ok(AccessRequestHistoryPageResponseModel {
                        total: Some(0),
                        ..Default::default()
                    })
                })
                .once();
        });

        let page = client(api_client)
            .list_history(AccessRequestHistoryQuery {
                page: 0,
                page_size: 10,
                statuses: vec![],
                collection_ids: vec![],
                requester_ids: vec![],
            })
            .await
            .unwrap();

        assert_eq!(page.requests, Vec::new());
        assert_eq!(page.total, 0);
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

        assert!(matches!(result, Err(ApprovalError::UnsubmittableVerdict)));
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

        assert!(matches!(result, Err(ApprovalError::Api(_))));
    }

    #[tokio::test]
    async fn revoke_sends_the_reason() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_revoke()
                .returning(move |id, body| {
                    assert_eq!(id, uuid::Uuid::from(request_id()));
                    assert_eq!(
                        body.and_then(|b| b.reason).as_deref(),
                        Some("Approved by mistake")
                    );
                    Ok(())
                })
                .once();
        });

        let request = AccessRequestRevokeRequest {
            reason: "Approved by mistake".to_string(),
        };

        let result = client(api_client).revoke(request_id(), request).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn revoke_surfaces_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_revoke()
                .returning(move |_id, _body| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::CONFLICT,
                            message: "This request has already been resolved.".to_string(),
                        },
                    ))
                })
                .once();
        });

        let request = AccessRequestRevokeRequest {
            reason: "Approved by mistake".to_string(),
        };

        let result = client(api_client).revoke(request_id(), request).await;

        assert!(matches!(result, Err(ApprovalError::Api(_))));
    }
}
