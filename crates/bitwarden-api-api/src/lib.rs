#![allow(unused_imports, unused_variables, unused_mut, non_camel_case_types)]
#![allow(
    clippy::too_many_arguments,
    clippy::empty_docs,
    clippy::to_string_in_format_args,
    clippy::needless_return,
    clippy::uninlined_format_args,
    clippy::new_without_default,
    clippy::derivable_impls
)]

pub mod apis;
pub mod models;

pub use bitwarden_api_base::{Configuration, ContentType, Error, ResponseContent};

#[cfg(test)]
mod manage_field_guard {
    // Compile-time assertions: these functions will fail to compile if manage regresses to
    // Option<bool>
    fn _access_policy_request_manage_is_bool(r: &crate::models::AccessPolicyRequest) -> bool {
        r.manage
    }

    fn _granted_access_policy_request_manage_is_bool(
        r: &crate::models::GrantedAccessPolicyRequest,
    ) -> bool {
        r.manage
    }

    #[test]
    fn access_policy_request_manage_serializes_explicit_false() {
        let r = crate::models::AccessPolicyRequest {
            grantee_id: uuid::Uuid::nil(),
            read: false,
            write: false,
            manage: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["manage"],
            serde_json::Value::Bool(false),
            "manage:false must serialize explicitly — regression to Option<bool> with skip_serializing_if would omit it"
        );
    }

    #[test]
    fn granted_access_policy_request_manage_serializes_explicit_false() {
        let r = crate::models::GrantedAccessPolicyRequest {
            granted_id: uuid::Uuid::nil(),
            read: false,
            write: false,
            manage: false,
        };
        let json = serde_json::to_string(&r).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            v["manage"],
            serde_json::Value::Bool(false),
            "manage:false must serialize explicitly — regression to Option<bool> with skip_serializing_if would omit it"
        );
    }
}
