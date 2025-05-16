use uuid::Uuid;

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::use_remote_type!(bitwarden_core::DateTime);
uniffi::use_remote_type!(bitwarden_core::Uuid);
