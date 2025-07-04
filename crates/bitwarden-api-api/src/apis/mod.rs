use std::{error, fmt};

#[derive(Debug, Clone)]
pub struct ResponseContent<T> {
    pub status: reqwest::StatusCode,
    pub content: String,
    pub entity: Option<T>,
}

#[derive(Debug)]
pub enum Error<T> {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent<T>),
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::ResponseError(e) => ("response", format!("status code {}", e.status)),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl<T: fmt::Debug> error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::ResponseError(_) => return None,
        })
    }
}

impl<T> From<reqwest::Error> for Error<T> {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl<T> From<serde_json::Error> for Error<T> {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl<T> From<std::io::Error> for Error<T> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub fn urlencode<T: AsRef<str>>(s: T) -> String {
    ::url::form_urlencoded::byte_serialize(s.as_ref().as_bytes()).collect()
}

pub fn parse_deep_object(prefix: &str, value: &serde_json::Value) -> Vec<(String, String)> {
    if let serde_json::Value::Object(object) = value {
        let mut params = vec![];

        for (key, value) in object {
            match value {
                serde_json::Value::Object(_) => params.append(&mut parse_deep_object(
                    &format!("{}[{}]", prefix, key),
                    value,
                )),
                serde_json::Value::Array(array) => {
                    for (i, value) in array.iter().enumerate() {
                        params.append(&mut parse_deep_object(
                            &format!("{}[{}][{}]", prefix, key, i),
                            value,
                        ));
                    }
                }
                serde_json::Value::String(s) => {
                    params.push((format!("{}[{}]", prefix, key), s.clone()))
                }
                _ => params.push((format!("{}[{}]", prefix, key), value.to_string())),
            }
        }

        return params;
    }

    unimplemented!("Only objects are supported with style=deepObject")
}

/// Internal use only
/// A content type supported by this client.
#[allow(dead_code)]
enum ContentType {
    Json,
    Text,
    Unsupported(String),
}

impl From<&str> for ContentType {
    fn from(content_type: &str) -> Self {
        if content_type.starts_with("application") && content_type.contains("json") {
            return Self::Json;
        } else if content_type.starts_with("text/plain") {
            return Self::Text;
        } else {
            return Self::Unsupported(content_type.to_string());
        }
    }
}

pub mod access_policies_api;
pub mod accounts_api;
pub mod accounts_billing_api;
pub mod accounts_key_management_api;
pub mod auth_requests_api;
pub mod ciphers_api;
pub mod collections_api;
pub mod config_api;
pub mod counts_api;
pub mod devices_api;
pub mod emergency_access_api;
pub mod events_api;
pub mod folders_api;
pub mod groups_api;
pub mod hibp_api;
pub mod import_ciphers_api;
pub mod info_api;
pub mod installations_api;
pub mod invoices_api;
pub mod licenses_api;
pub mod misc_api;
pub mod notifications_api;
pub mod organization_auth_requests_api;
pub mod organization_billing_api;
pub mod organization_connections_api;
pub mod organization_domain_api;
pub mod organization_export_api;
pub mod organization_sponsorships_api;
pub mod organization_users_api;
pub mod organizations_api;
pub mod plans_api;
pub mod policies_api;
pub mod projects_api;
pub mod provider_billing_api;
pub mod provider_clients_api;
pub mod provider_organizations_api;
pub mod provider_users_api;
pub mod providers_api;
pub mod push_api;
pub mod reports_api;
pub mod request_sm_access_api;
pub mod secrets_api;
pub mod secrets_manager_events_api;
pub mod secrets_manager_porting_api;
pub mod security_task_api;
pub mod self_hosted_organization_licenses_api;
pub mod self_hosted_organization_sponsorships_api;
pub mod sends_api;
pub mod service_accounts_api;
pub mod settings_api;
pub mod stripe_api;
pub mod sync_api;
pub mod trash_api;
pub mod two_factor_api;
pub mod users_api;
pub mod web_authn_api;

pub mod configuration;

use std::sync::Arc;

#[cfg_attr(feature = "mockall", mockall::automock)]
pub trait Api {
    fn access_policies_api(&self) -> Box<dyn access_policies_api::AccessPoliciesApi>;
    fn accounts_api(&self) -> Box<dyn accounts_api::AccountsApi>;
    fn accounts_billing_api(&self) -> Box<dyn accounts_billing_api::AccountsBillingApi>;
    fn accounts_key_management_api(
        &self,
    ) -> Box<dyn accounts_key_management_api::AccountsKeyManagementApi>;
    fn auth_requests_api(&self) -> Box<dyn auth_requests_api::AuthRequestsApi>;
    fn ciphers_api(&self) -> Box<dyn ciphers_api::CiphersApi>;
    fn collections_api(&self) -> Box<dyn collections_api::CollectionsApi>;
    fn config_api(&self) -> Box<dyn config_api::ConfigApi>;
    fn counts_api(&self) -> Box<dyn counts_api::CountsApi>;
    fn devices_api(&self) -> Box<dyn devices_api::DevicesApi>;
    fn emergency_access_api(&self) -> Box<dyn emergency_access_api::EmergencyAccessApi>;
    fn events_api(&self) -> Box<dyn events_api::EventsApi>;
    fn folders_api(&self) -> Box<dyn folders_api::FoldersApi>;
    fn groups_api(&self) -> Box<dyn groups_api::GroupsApi>;
    fn hibp_api(&self) -> Box<dyn hibp_api::HibpApi>;
    fn import_ciphers_api(&self) -> Box<dyn import_ciphers_api::ImportCiphersApi>;
    fn info_api(&self) -> Box<dyn info_api::InfoApi>;
    fn installations_api(&self) -> Box<dyn installations_api::InstallationsApi>;
    fn invoices_api(&self) -> Box<dyn invoices_api::InvoicesApi>;
    fn licenses_api(&self) -> Box<dyn licenses_api::LicensesApi>;
    fn misc_api(&self) -> Box<dyn misc_api::MiscApi>;
    fn notifications_api(&self) -> Box<dyn notifications_api::NotificationsApi>;
    fn organization_auth_requests_api(
        &self,
    ) -> Box<dyn organization_auth_requests_api::OrganizationAuthRequestsApi>;
    fn organization_billing_api(&self)
        -> Box<dyn organization_billing_api::OrganizationBillingApi>;
    fn organization_connections_api(
        &self,
    ) -> Box<dyn organization_connections_api::OrganizationConnectionsApi>;
    fn organization_domain_api(&self) -> Box<dyn organization_domain_api::OrganizationDomainApi>;
    fn organization_export_api(&self) -> Box<dyn organization_export_api::OrganizationExportApi>;
    fn organization_sponsorships_api(
        &self,
    ) -> Box<dyn organization_sponsorships_api::OrganizationSponsorshipsApi>;
    fn organization_users_api(&self) -> Box<dyn organization_users_api::OrganizationUsersApi>;
    fn organizations_api(&self) -> Box<dyn organizations_api::OrganizationsApi>;
    fn plans_api(&self) -> Box<dyn plans_api::PlansApi>;
    fn policies_api(&self) -> Box<dyn policies_api::PoliciesApi>;
    fn projects_api(&self) -> Box<dyn projects_api::ProjectsApi>;
    fn provider_billing_api(&self) -> Box<dyn provider_billing_api::ProviderBillingApi>;
    fn provider_clients_api(&self) -> Box<dyn provider_clients_api::ProviderClientsApi>;
    fn provider_organizations_api(
        &self,
    ) -> Box<dyn provider_organizations_api::ProviderOrganizationsApi>;
    fn provider_users_api(&self) -> Box<dyn provider_users_api::ProviderUsersApi>;
    fn providers_api(&self) -> Box<dyn providers_api::ProvidersApi>;
    fn push_api(&self) -> Box<dyn push_api::PushApi>;
    fn reports_api(&self) -> Box<dyn reports_api::ReportsApi>;
    fn request_sm_access_api(&self) -> Box<dyn request_sm_access_api::RequestSmAccessApi>;
    fn secrets_api(&self) -> Box<dyn secrets_api::SecretsApi>;
    fn secrets_manager_events_api(
        &self,
    ) -> Box<dyn secrets_manager_events_api::SecretsManagerEventsApi>;
    fn secrets_manager_porting_api(
        &self,
    ) -> Box<dyn secrets_manager_porting_api::SecretsManagerPortingApi>;
    fn security_task_api(&self) -> Box<dyn security_task_api::SecurityTaskApi>;
    fn self_hosted_organization_licenses_api(
        &self,
    ) -> Box<dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi>;
    fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> Box<dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi>;
    fn sends_api(&self) -> Box<dyn sends_api::SendsApi>;
    fn service_accounts_api(&self) -> Box<dyn service_accounts_api::ServiceAccountsApi>;
    fn settings_api(&self) -> Box<dyn settings_api::SettingsApi>;
    fn stripe_api(&self) -> Box<dyn stripe_api::StripeApi>;
    fn sync_api(&self) -> Box<dyn sync_api::SyncApi>;
    fn trash_api(&self) -> Box<dyn trash_api::TrashApi>;
    fn two_factor_api(&self) -> Box<dyn two_factor_api::TwoFactorApi>;
    fn users_api(&self) -> Box<dyn users_api::UsersApi>;
    fn web_authn_api(&self) -> Box<dyn web_authn_api::WebAuthnApi>;
}

pub struct ApiClient {
    configuration: Arc<configuration::Configuration>,
}

impl ApiClient {
    pub fn new(configuration: Arc<configuration::Configuration>) -> Self {
        Self { configuration }
    }
}

impl Api for ApiClient {
    fn access_policies_api(&self) -> Box<dyn access_policies_api::AccessPoliciesApi> {
        Box::new(access_policies_api::AccessPoliciesApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn accounts_api(&self) -> Box<dyn accounts_api::AccountsApi> {
        Box::new(accounts_api::AccountsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn accounts_billing_api(&self) -> Box<dyn accounts_billing_api::AccountsBillingApi> {
        Box::new(accounts_billing_api::AccountsBillingApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn accounts_key_management_api(
        &self,
    ) -> Box<dyn accounts_key_management_api::AccountsKeyManagementApi> {
        Box::new(
            accounts_key_management_api::AccountsKeyManagementApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn auth_requests_api(&self) -> Box<dyn auth_requests_api::AuthRequestsApi> {
        Box::new(auth_requests_api::AuthRequestsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn ciphers_api(&self) -> Box<dyn ciphers_api::CiphersApi> {
        Box::new(ciphers_api::CiphersApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn collections_api(&self) -> Box<dyn collections_api::CollectionsApi> {
        Box::new(collections_api::CollectionsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn config_api(&self) -> Box<dyn config_api::ConfigApi> {
        Box::new(config_api::ConfigApiClient::new(self.configuration.clone()))
    }
    fn counts_api(&self) -> Box<dyn counts_api::CountsApi> {
        Box::new(counts_api::CountsApiClient::new(self.configuration.clone()))
    }
    fn devices_api(&self) -> Box<dyn devices_api::DevicesApi> {
        Box::new(devices_api::DevicesApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn emergency_access_api(&self) -> Box<dyn emergency_access_api::EmergencyAccessApi> {
        Box::new(emergency_access_api::EmergencyAccessApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn events_api(&self) -> Box<dyn events_api::EventsApi> {
        Box::new(events_api::EventsApiClient::new(self.configuration.clone()))
    }
    fn folders_api(&self) -> Box<dyn folders_api::FoldersApi> {
        Box::new(folders_api::FoldersApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn groups_api(&self) -> Box<dyn groups_api::GroupsApi> {
        Box::new(groups_api::GroupsApiClient::new(self.configuration.clone()))
    }
    fn hibp_api(&self) -> Box<dyn hibp_api::HibpApi> {
        Box::new(hibp_api::HibpApiClient::new(self.configuration.clone()))
    }
    fn import_ciphers_api(&self) -> Box<dyn import_ciphers_api::ImportCiphersApi> {
        Box::new(import_ciphers_api::ImportCiphersApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn info_api(&self) -> Box<dyn info_api::InfoApi> {
        Box::new(info_api::InfoApiClient::new(self.configuration.clone()))
    }
    fn installations_api(&self) -> Box<dyn installations_api::InstallationsApi> {
        Box::new(installations_api::InstallationsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn invoices_api(&self) -> Box<dyn invoices_api::InvoicesApi> {
        Box::new(invoices_api::InvoicesApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn licenses_api(&self) -> Box<dyn licenses_api::LicensesApi> {
        Box::new(licenses_api::LicensesApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn misc_api(&self) -> Box<dyn misc_api::MiscApi> {
        Box::new(misc_api::MiscApiClient::new(self.configuration.clone()))
    }
    fn notifications_api(&self) -> Box<dyn notifications_api::NotificationsApi> {
        Box::new(notifications_api::NotificationsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn organization_auth_requests_api(
        &self,
    ) -> Box<dyn organization_auth_requests_api::OrganizationAuthRequestsApi> {
        Box::new(
            organization_auth_requests_api::OrganizationAuthRequestsApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn organization_billing_api(
        &self,
    ) -> Box<dyn organization_billing_api::OrganizationBillingApi> {
        Box::new(organization_billing_api::OrganizationBillingApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn organization_connections_api(
        &self,
    ) -> Box<dyn organization_connections_api::OrganizationConnectionsApi> {
        Box::new(
            organization_connections_api::OrganizationConnectionsApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn organization_domain_api(&self) -> Box<dyn organization_domain_api::OrganizationDomainApi> {
        Box::new(organization_domain_api::OrganizationDomainApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn organization_export_api(&self) -> Box<dyn organization_export_api::OrganizationExportApi> {
        Box::new(organization_export_api::OrganizationExportApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn organization_sponsorships_api(
        &self,
    ) -> Box<dyn organization_sponsorships_api::OrganizationSponsorshipsApi> {
        Box::new(
            organization_sponsorships_api::OrganizationSponsorshipsApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn organization_users_api(&self) -> Box<dyn organization_users_api::OrganizationUsersApi> {
        Box::new(organization_users_api::OrganizationUsersApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn organizations_api(&self) -> Box<dyn organizations_api::OrganizationsApi> {
        Box::new(organizations_api::OrganizationsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn plans_api(&self) -> Box<dyn plans_api::PlansApi> {
        Box::new(plans_api::PlansApiClient::new(self.configuration.clone()))
    }
    fn policies_api(&self) -> Box<dyn policies_api::PoliciesApi> {
        Box::new(policies_api::PoliciesApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn projects_api(&self) -> Box<dyn projects_api::ProjectsApi> {
        Box::new(projects_api::ProjectsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn provider_billing_api(&self) -> Box<dyn provider_billing_api::ProviderBillingApi> {
        Box::new(provider_billing_api::ProviderBillingApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn provider_clients_api(&self) -> Box<dyn provider_clients_api::ProviderClientsApi> {
        Box::new(provider_clients_api::ProviderClientsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn provider_organizations_api(
        &self,
    ) -> Box<dyn provider_organizations_api::ProviderOrganizationsApi> {
        Box::new(
            provider_organizations_api::ProviderOrganizationsApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn provider_users_api(&self) -> Box<dyn provider_users_api::ProviderUsersApi> {
        Box::new(provider_users_api::ProviderUsersApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn providers_api(&self) -> Box<dyn providers_api::ProvidersApi> {
        Box::new(providers_api::ProvidersApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn push_api(&self) -> Box<dyn push_api::PushApi> {
        Box::new(push_api::PushApiClient::new(self.configuration.clone()))
    }
    fn reports_api(&self) -> Box<dyn reports_api::ReportsApi> {
        Box::new(reports_api::ReportsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn request_sm_access_api(&self) -> Box<dyn request_sm_access_api::RequestSmAccessApi> {
        Box::new(request_sm_access_api::RequestSmAccessApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn secrets_api(&self) -> Box<dyn secrets_api::SecretsApi> {
        Box::new(secrets_api::SecretsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn secrets_manager_events_api(
        &self,
    ) -> Box<dyn secrets_manager_events_api::SecretsManagerEventsApi> {
        Box::new(
            secrets_manager_events_api::SecretsManagerEventsApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn secrets_manager_porting_api(
        &self,
    ) -> Box<dyn secrets_manager_porting_api::SecretsManagerPortingApi> {
        Box::new(
            secrets_manager_porting_api::SecretsManagerPortingApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn security_task_api(&self) -> Box<dyn security_task_api::SecurityTaskApi> {
        Box::new(security_task_api::SecurityTaskApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn self_hosted_organization_licenses_api(
        &self,
    ) -> Box<dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi> {
        Box::new(
            self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient::new(
                self.configuration.clone(),
            ),
        )
    }
    fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> Box<dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi>
    {
        Box::new(self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient::new(self.configuration.clone()))
    }
    fn sends_api(&self) -> Box<dyn sends_api::SendsApi> {
        Box::new(sends_api::SendsApiClient::new(self.configuration.clone()))
    }
    fn service_accounts_api(&self) -> Box<dyn service_accounts_api::ServiceAccountsApi> {
        Box::new(service_accounts_api::ServiceAccountsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn settings_api(&self) -> Box<dyn settings_api::SettingsApi> {
        Box::new(settings_api::SettingsApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn stripe_api(&self) -> Box<dyn stripe_api::StripeApi> {
        Box::new(stripe_api::StripeApiClient::new(self.configuration.clone()))
    }
    fn sync_api(&self) -> Box<dyn sync_api::SyncApi> {
        Box::new(sync_api::SyncApiClient::new(self.configuration.clone()))
    }
    fn trash_api(&self) -> Box<dyn trash_api::TrashApi> {
        Box::new(trash_api::TrashApiClient::new(self.configuration.clone()))
    }
    fn two_factor_api(&self) -> Box<dyn two_factor_api::TwoFactorApi> {
        Box::new(two_factor_api::TwoFactorApiClient::new(
            self.configuration.clone(),
        ))
    }
    fn users_api(&self) -> Box<dyn users_api::UsersApi> {
        Box::new(users_api::UsersApiClient::new(self.configuration.clone()))
    }
    fn web_authn_api(&self) -> Box<dyn web_authn_api::WebAuthnApi> {
        Box::new(web_authn_api::WebAuthnApiClient::new(
            self.configuration.clone(),
        ))
    }
}
