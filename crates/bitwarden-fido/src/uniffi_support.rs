use uuid::Uuid;

type DateTime = jiff::Timestamp;
uniffi::use_remote_type!(bitwarden_core::DateTime);
uniffi::use_remote_type!(bitwarden_core::Uuid);
