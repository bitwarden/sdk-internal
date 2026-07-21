use uuid::Uuid;

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::use_remote_type!(bitwarden_core::DateTime);
type NaiveDate = chrono::NaiveDate;
uniffi::use_remote_type!(bitwarden_core::NaiveDate);
uniffi::use_remote_type!(bitwarden_core::Uuid);
