use bitwarden_api_api::models::{
    GroupAccessPolicyResponseModel, ServiceAccountAccessPolicyResponseModel,
    UserAccessPolicyResponseModel,
};
use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{Decryptable, EncString, KeyStoreContext};

use super::types::{
    AccessPolicyResponse, GroupAccessPolicyResponse, ServiceAccountAccessPolicyResponse,
    UserAccessPolicyResponse,
};

pub(super) fn user_from_api(p: UserAccessPolicyResponseModel) -> Option<UserAccessPolicyResponse> {
    Some(UserAccessPolicyResponse {
        organization_user_id: p.organization_user_id?,
        organization_user_name: p.organization_user_name,
        current_user: p.current_user.unwrap_or(false),
        policy: api_permissions(p.read, p.write, p.manage)?,
    })
}

pub(super) fn group_from_api(
    p: GroupAccessPolicyResponseModel,
) -> Option<GroupAccessPolicyResponse> {
    Some(GroupAccessPolicyResponse {
        group_id: p.group_id?,
        group_name: p.group_name,
        current_user_in_group: p.current_user_in_group.unwrap_or(false),
        policy: api_permissions(p.read, p.write, p.manage)?,
    })
}

pub(super) fn service_account_from_api(
    p: ServiceAccountAccessPolicyResponseModel,
    ctx: &mut KeyStoreContext<KeyIds>,
    org_key: SymmetricKeyId,
) -> Option<ServiceAccountAccessPolicyResponse> {
    let decrypted_name = p
        .service_account_name
        .and_then(|n| n.parse::<EncString>().ok()?.decrypt(ctx, org_key).ok());
    Some(ServiceAccountAccessPolicyResponse {
        service_account_id: p.service_account_id?,
        service_account_name: decrypted_name,
        policy: api_permissions(p.read, p.write, p.manage)?,
    })
}

/// Returns `None` if `manage` is absent from the API response.
///
/// `manage` must not default to `false` — an absent field would silently downgrade a policy
/// that has `manage: true` in the database. Instead we drop the policy from the list so the
/// caller can detect the gap (e.g. a missing field from an older server version).
fn api_permissions(
    read: Option<bool>,
    write: Option<bool>,
    manage: Option<bool>,
) -> Option<AccessPolicyResponse> {
    Some(AccessPolicyResponse {
        read: read.unwrap_or(false),
        write: write.unwrap_or(false),
        manage: manage?,
    })
}
