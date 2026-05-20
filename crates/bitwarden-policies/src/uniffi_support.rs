use uuid::Uuid;

use crate::filter::PolicyType;

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::use_remote_type!(bitwarden_core::DateTime);
uniffi::use_remote_type!(bitwarden_core::Uuid);

uniffi::custom_type!(PolicyType, u8, {
    lower: |p| p.0,
    try_lift: |v| Ok(PolicyType(v)),
});
