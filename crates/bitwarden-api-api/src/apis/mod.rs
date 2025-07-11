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

pub trait Api {
    fn access_policies_api(&self) -> &dyn access_policies_api::AccessPoliciesApi;
    fn accounts_api(&self) -> &dyn accounts_api::AccountsApi;
    fn accounts_billing_api(&self) -> &dyn accounts_billing_api::AccountsBillingApi;
    fn accounts_key_management_api(
        &self,
    ) -> &dyn accounts_key_management_api::AccountsKeyManagementApi;
    fn auth_requests_api(&self) -> &dyn auth_requests_api::AuthRequestsApi;
    fn ciphers_api(&self) -> &dyn ciphers_api::CiphersApi;
    fn collections_api(&self) -> &dyn collections_api::CollectionsApi;
    fn config_api(&self) -> &dyn config_api::ConfigApi;
    fn counts_api(&self) -> &dyn counts_api::CountsApi;
    fn devices_api(&self) -> &dyn devices_api::DevicesApi;
    fn emergency_access_api(&self) -> &dyn emergency_access_api::EmergencyAccessApi;
    fn events_api(&self) -> &dyn events_api::EventsApi;
    fn folders_api(&self) -> &dyn folders_api::FoldersApi;
    fn groups_api(&self) -> &dyn groups_api::GroupsApi;
    fn hibp_api(&self) -> &dyn hibp_api::HibpApi;
    fn import_ciphers_api(&self) -> &dyn import_ciphers_api::ImportCiphersApi;
    fn info_api(&self) -> &dyn info_api::InfoApi;
    fn installations_api(&self) -> &dyn installations_api::InstallationsApi;
    fn invoices_api(&self) -> &dyn invoices_api::InvoicesApi;
    fn licenses_api(&self) -> &dyn licenses_api::LicensesApi;
    fn misc_api(&self) -> &dyn misc_api::MiscApi;
    fn notifications_api(&self) -> &dyn notifications_api::NotificationsApi;
    fn organization_auth_requests_api(
        &self,
    ) -> &dyn organization_auth_requests_api::OrganizationAuthRequestsApi;
    fn organization_billing_api(&self) -> &dyn organization_billing_api::OrganizationBillingApi;
    fn organization_connections_api(
        &self,
    ) -> &dyn organization_connections_api::OrganizationConnectionsApi;
    fn organization_domain_api(&self) -> &dyn organization_domain_api::OrganizationDomainApi;
    fn organization_export_api(&self) -> &dyn organization_export_api::OrganizationExportApi;
    fn organization_sponsorships_api(
        &self,
    ) -> &dyn organization_sponsorships_api::OrganizationSponsorshipsApi;
    fn organization_users_api(&self) -> &dyn organization_users_api::OrganizationUsersApi;
    fn organizations_api(&self) -> &dyn organizations_api::OrganizationsApi;
    fn plans_api(&self) -> &dyn plans_api::PlansApi;
    fn policies_api(&self) -> &dyn policies_api::PoliciesApi;
    fn projects_api(&self) -> &dyn projects_api::ProjectsApi;
    fn provider_billing_api(&self) -> &dyn provider_billing_api::ProviderBillingApi;
    fn provider_clients_api(&self) -> &dyn provider_clients_api::ProviderClientsApi;
    fn provider_organizations_api(
        &self,
    ) -> &dyn provider_organizations_api::ProviderOrganizationsApi;
    fn provider_users_api(&self) -> &dyn provider_users_api::ProviderUsersApi;
    fn providers_api(&self) -> &dyn providers_api::ProvidersApi;
    fn push_api(&self) -> &dyn push_api::PushApi;
    fn reports_api(&self) -> &dyn reports_api::ReportsApi;
    fn request_sm_access_api(&self) -> &dyn request_sm_access_api::RequestSmAccessApi;
    fn secrets_api(&self) -> &dyn secrets_api::SecretsApi;
    fn secrets_manager_events_api(
        &self,
    ) -> &dyn secrets_manager_events_api::SecretsManagerEventsApi;
    fn secrets_manager_porting_api(
        &self,
    ) -> &dyn secrets_manager_porting_api::SecretsManagerPortingApi;
    fn security_task_api(&self) -> &dyn security_task_api::SecurityTaskApi;
    fn self_hosted_organization_licenses_api(
        &self,
    ) -> &dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi;
    fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> &dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi;
    fn sends_api(&self) -> &dyn sends_api::SendsApi;
    fn service_accounts_api(&self) -> &dyn service_accounts_api::ServiceAccountsApi;
    fn settings_api(&self) -> &dyn settings_api::SettingsApi;
    fn stripe_api(&self) -> &dyn stripe_api::StripeApi;
    fn sync_api(&self) -> &dyn sync_api::SyncApi;
    fn trash_api(&self) -> &dyn trash_api::TrashApi;
    fn two_factor_api(&self) -> &dyn two_factor_api::TwoFactorApi;
    fn users_api(&self) -> &dyn users_api::UsersApi;
    fn web_authn_api(&self) -> &dyn web_authn_api::WebAuthnApi;
}

pub struct ApiClient {
    access_policies_api: Box<dyn access_policies_api::AccessPoliciesApi>,
    accounts_api: Box<dyn accounts_api::AccountsApi>,
    accounts_billing_api: Box<dyn accounts_billing_api::AccountsBillingApi>,
    accounts_key_management_api: Box<dyn accounts_key_management_api::AccountsKeyManagementApi>,
    auth_requests_api: Box<dyn auth_requests_api::AuthRequestsApi>,
    ciphers_api: Box<dyn ciphers_api::CiphersApi>,
    collections_api: Box<dyn collections_api::CollectionsApi>,
    config_api: Box<dyn config_api::ConfigApi>,
    counts_api: Box<dyn counts_api::CountsApi>,
    devices_api: Box<dyn devices_api::DevicesApi>,
    emergency_access_api: Box<dyn emergency_access_api::EmergencyAccessApi>,
    events_api: Box<dyn events_api::EventsApi>,
    folders_api: Box<dyn folders_api::FoldersApi>,
    groups_api: Box<dyn groups_api::GroupsApi>,
    hibp_api: Box<dyn hibp_api::HibpApi>,
    import_ciphers_api: Box<dyn import_ciphers_api::ImportCiphersApi>,
    info_api: Box<dyn info_api::InfoApi>,
    installations_api: Box<dyn installations_api::InstallationsApi>,
    invoices_api: Box<dyn invoices_api::InvoicesApi>,
    licenses_api: Box<dyn licenses_api::LicensesApi>,
    misc_api: Box<dyn misc_api::MiscApi>,
    notifications_api: Box<dyn notifications_api::NotificationsApi>,
    organization_auth_requests_api:
        Box<dyn organization_auth_requests_api::OrganizationAuthRequestsApi>,
    organization_billing_api: Box<dyn organization_billing_api::OrganizationBillingApi>,
    organization_connections_api: Box<dyn organization_connections_api::OrganizationConnectionsApi>,
    organization_domain_api: Box<dyn organization_domain_api::OrganizationDomainApi>,
    organization_export_api: Box<dyn organization_export_api::OrganizationExportApi>,
    organization_sponsorships_api:
        Box<dyn organization_sponsorships_api::OrganizationSponsorshipsApi>,
    organization_users_api: Box<dyn organization_users_api::OrganizationUsersApi>,
    organizations_api: Box<dyn organizations_api::OrganizationsApi>,
    plans_api: Box<dyn plans_api::PlansApi>,
    policies_api: Box<dyn policies_api::PoliciesApi>,
    projects_api: Box<dyn projects_api::ProjectsApi>,
    provider_billing_api: Box<dyn provider_billing_api::ProviderBillingApi>,
    provider_clients_api: Box<dyn provider_clients_api::ProviderClientsApi>,
    provider_organizations_api: Box<dyn provider_organizations_api::ProviderOrganizationsApi>,
    provider_users_api: Box<dyn provider_users_api::ProviderUsersApi>,
    providers_api: Box<dyn providers_api::ProvidersApi>,
    push_api: Box<dyn push_api::PushApi>,
    reports_api: Box<dyn reports_api::ReportsApi>,
    request_sm_access_api: Box<dyn request_sm_access_api::RequestSmAccessApi>,
    secrets_api: Box<dyn secrets_api::SecretsApi>,
    secrets_manager_events_api: Box<dyn secrets_manager_events_api::SecretsManagerEventsApi>,
    secrets_manager_porting_api: Box<dyn secrets_manager_porting_api::SecretsManagerPortingApi>,
    security_task_api: Box<dyn security_task_api::SecurityTaskApi>,
    self_hosted_organization_licenses_api:
        Box<dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi>,
    self_hosted_organization_sponsorships_api:
        Box<dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi>,
    sends_api: Box<dyn sends_api::SendsApi>,
    service_accounts_api: Box<dyn service_accounts_api::ServiceAccountsApi>,
    settings_api: Box<dyn settings_api::SettingsApi>,
    stripe_api: Box<dyn stripe_api::StripeApi>,
    sync_api: Box<dyn sync_api::SyncApi>,
    trash_api: Box<dyn trash_api::TrashApi>,
    two_factor_api: Box<dyn two_factor_api::TwoFactorApi>,
    users_api: Box<dyn users_api::UsersApi>,
    web_authn_api: Box<dyn web_authn_api::WebAuthnApi>,
}

impl ApiClient {
    pub fn new(configuration: Arc<configuration::Configuration>) -> Self {
        Self {
            access_policies_api: Box::new(access_policies_api::AccessPoliciesApiClient::new(configuration.clone())),
            accounts_api: Box::new(accounts_api::AccountsApiClient::new(configuration.clone())),
            accounts_billing_api: Box::new(accounts_billing_api::AccountsBillingApiClient::new(configuration.clone())),
            accounts_key_management_api: Box::new(accounts_key_management_api::AccountsKeyManagementApiClient::new(configuration.clone())),
            auth_requests_api: Box::new(auth_requests_api::AuthRequestsApiClient::new(configuration.clone())),
            ciphers_api: Box::new(ciphers_api::CiphersApiClient::new(configuration.clone())),
            collections_api: Box::new(collections_api::CollectionsApiClient::new(configuration.clone())),
            config_api: Box::new(config_api::ConfigApiClient::new(configuration.clone())),
            counts_api: Box::new(counts_api::CountsApiClient::new(configuration.clone())),
            devices_api: Box::new(devices_api::DevicesApiClient::new(configuration.clone())),
            emergency_access_api: Box::new(emergency_access_api::EmergencyAccessApiClient::new(configuration.clone())),
            events_api: Box::new(events_api::EventsApiClient::new(configuration.clone())),
            folders_api: Box::new(folders_api::FoldersApiClient::new(configuration.clone())),
            groups_api: Box::new(groups_api::GroupsApiClient::new(configuration.clone())),
            hibp_api: Box::new(hibp_api::HibpApiClient::new(configuration.clone())),
            import_ciphers_api: Box::new(import_ciphers_api::ImportCiphersApiClient::new(configuration.clone())),
            info_api: Box::new(info_api::InfoApiClient::new(configuration.clone())),
            installations_api: Box::new(installations_api::InstallationsApiClient::new(configuration.clone())),
            invoices_api: Box::new(invoices_api::InvoicesApiClient::new(configuration.clone())),
            licenses_api: Box::new(licenses_api::LicensesApiClient::new(configuration.clone())),
            misc_api: Box::new(misc_api::MiscApiClient::new(configuration.clone())),
            notifications_api: Box::new(notifications_api::NotificationsApiClient::new(configuration.clone())),
            organization_auth_requests_api: Box::new(organization_auth_requests_api::OrganizationAuthRequestsApiClient::new(configuration.clone())),
            organization_billing_api: Box::new(organization_billing_api::OrganizationBillingApiClient::new(configuration.clone())),
            organization_connections_api: Box::new(organization_connections_api::OrganizationConnectionsApiClient::new(configuration.clone())),
            organization_domain_api: Box::new(organization_domain_api::OrganizationDomainApiClient::new(configuration.clone())),
            organization_export_api: Box::new(organization_export_api::OrganizationExportApiClient::new(configuration.clone())),
            organization_sponsorships_api: Box::new(organization_sponsorships_api::OrganizationSponsorshipsApiClient::new(configuration.clone())),
            organization_users_api: Box::new(organization_users_api::OrganizationUsersApiClient::new(configuration.clone())),
            organizations_api: Box::new(organizations_api::OrganizationsApiClient::new(configuration.clone())),
            plans_api: Box::new(plans_api::PlansApiClient::new(configuration.clone())),
            policies_api: Box::new(policies_api::PoliciesApiClient::new(configuration.clone())),
            projects_api: Box::new(projects_api::ProjectsApiClient::new(configuration.clone())),
            provider_billing_api: Box::new(provider_billing_api::ProviderBillingApiClient::new(configuration.clone())),
            provider_clients_api: Box::new(provider_clients_api::ProviderClientsApiClient::new(configuration.clone())),
            provider_organizations_api: Box::new(provider_organizations_api::ProviderOrganizationsApiClient::new(configuration.clone())),
            provider_users_api: Box::new(provider_users_api::ProviderUsersApiClient::new(configuration.clone())),
            providers_api: Box::new(providers_api::ProvidersApiClient::new(configuration.clone())),
            push_api: Box::new(push_api::PushApiClient::new(configuration.clone())),
            reports_api: Box::new(reports_api::ReportsApiClient::new(configuration.clone())),
            request_sm_access_api: Box::new(request_sm_access_api::RequestSmAccessApiClient::new(configuration.clone())),
            secrets_api: Box::new(secrets_api::SecretsApiClient::new(configuration.clone())),
            secrets_manager_events_api: Box::new(secrets_manager_events_api::SecretsManagerEventsApiClient::new(configuration.clone())),
            secrets_manager_porting_api: Box::new(secrets_manager_porting_api::SecretsManagerPortingApiClient::new(configuration.clone())),
            security_task_api: Box::new(security_task_api::SecurityTaskApiClient::new(configuration.clone())),
            self_hosted_organization_licenses_api: Box::new(self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient::new(configuration.clone())),
            self_hosted_organization_sponsorships_api: Box::new(self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient::new(configuration.clone())),
            sends_api: Box::new(sends_api::SendsApiClient::new(configuration.clone())),
            service_accounts_api: Box::new(service_accounts_api::ServiceAccountsApiClient::new(configuration.clone())),
            settings_api: Box::new(settings_api::SettingsApiClient::new(configuration.clone())),
            stripe_api: Box::new(stripe_api::StripeApiClient::new(configuration.clone())),
            sync_api: Box::new(sync_api::SyncApiClient::new(configuration.clone())),
            trash_api: Box::new(trash_api::TrashApiClient::new(configuration.clone())),
            two_factor_api: Box::new(two_factor_api::TwoFactorApiClient::new(configuration.clone())),
            users_api: Box::new(users_api::UsersApiClient::new(configuration.clone())),
            web_authn_api: Box::new(web_authn_api::WebAuthnApiClient::new(configuration.clone())),
        }
    }
}

impl Api for ApiClient {
    fn access_policies_api(&self) -> &dyn access_policies_api::AccessPoliciesApi {
        self.access_policies_api.as_ref()
    }
    fn accounts_api(&self) -> &dyn accounts_api::AccountsApi {
        self.accounts_api.as_ref()
    }
    fn accounts_billing_api(&self) -> &dyn accounts_billing_api::AccountsBillingApi {
        self.accounts_billing_api.as_ref()
    }
    fn accounts_key_management_api(
        &self,
    ) -> &dyn accounts_key_management_api::AccountsKeyManagementApi {
        self.accounts_key_management_api.as_ref()
    }
    fn auth_requests_api(&self) -> &dyn auth_requests_api::AuthRequestsApi {
        self.auth_requests_api.as_ref()
    }
    fn ciphers_api(&self) -> &dyn ciphers_api::CiphersApi {
        self.ciphers_api.as_ref()
    }
    fn collections_api(&self) -> &dyn collections_api::CollectionsApi {
        self.collections_api.as_ref()
    }
    fn config_api(&self) -> &dyn config_api::ConfigApi {
        self.config_api.as_ref()
    }
    fn counts_api(&self) -> &dyn counts_api::CountsApi {
        self.counts_api.as_ref()
    }
    fn devices_api(&self) -> &dyn devices_api::DevicesApi {
        self.devices_api.as_ref()
    }
    fn emergency_access_api(&self) -> &dyn emergency_access_api::EmergencyAccessApi {
        self.emergency_access_api.as_ref()
    }
    fn events_api(&self) -> &dyn events_api::EventsApi {
        self.events_api.as_ref()
    }
    fn folders_api(&self) -> &dyn folders_api::FoldersApi {
        self.folders_api.as_ref()
    }
    fn groups_api(&self) -> &dyn groups_api::GroupsApi {
        self.groups_api.as_ref()
    }
    fn hibp_api(&self) -> &dyn hibp_api::HibpApi {
        self.hibp_api.as_ref()
    }
    fn import_ciphers_api(&self) -> &dyn import_ciphers_api::ImportCiphersApi {
        self.import_ciphers_api.as_ref()
    }
    fn info_api(&self) -> &dyn info_api::InfoApi {
        self.info_api.as_ref()
    }
    fn installations_api(&self) -> &dyn installations_api::InstallationsApi {
        self.installations_api.as_ref()
    }
    fn invoices_api(&self) -> &dyn invoices_api::InvoicesApi {
        self.invoices_api.as_ref()
    }
    fn licenses_api(&self) -> &dyn licenses_api::LicensesApi {
        self.licenses_api.as_ref()
    }
    fn misc_api(&self) -> &dyn misc_api::MiscApi {
        self.misc_api.as_ref()
    }
    fn notifications_api(&self) -> &dyn notifications_api::NotificationsApi {
        self.notifications_api.as_ref()
    }
    fn organization_auth_requests_api(
        &self,
    ) -> &dyn organization_auth_requests_api::OrganizationAuthRequestsApi {
        self.organization_auth_requests_api.as_ref()
    }
    fn organization_billing_api(&self) -> &dyn organization_billing_api::OrganizationBillingApi {
        self.organization_billing_api.as_ref()
    }
    fn organization_connections_api(
        &self,
    ) -> &dyn organization_connections_api::OrganizationConnectionsApi {
        self.organization_connections_api.as_ref()
    }
    fn organization_domain_api(&self) -> &dyn organization_domain_api::OrganizationDomainApi {
        self.organization_domain_api.as_ref()
    }
    fn organization_export_api(&self) -> &dyn organization_export_api::OrganizationExportApi {
        self.organization_export_api.as_ref()
    }
    fn organization_sponsorships_api(
        &self,
    ) -> &dyn organization_sponsorships_api::OrganizationSponsorshipsApi {
        self.organization_sponsorships_api.as_ref()
    }
    fn organization_users_api(&self) -> &dyn organization_users_api::OrganizationUsersApi {
        self.organization_users_api.as_ref()
    }
    fn organizations_api(&self) -> &dyn organizations_api::OrganizationsApi {
        self.organizations_api.as_ref()
    }
    fn plans_api(&self) -> &dyn plans_api::PlansApi {
        self.plans_api.as_ref()
    }
    fn policies_api(&self) -> &dyn policies_api::PoliciesApi {
        self.policies_api.as_ref()
    }
    fn projects_api(&self) -> &dyn projects_api::ProjectsApi {
        self.projects_api.as_ref()
    }
    fn provider_billing_api(&self) -> &dyn provider_billing_api::ProviderBillingApi {
        self.provider_billing_api.as_ref()
    }
    fn provider_clients_api(&self) -> &dyn provider_clients_api::ProviderClientsApi {
        self.provider_clients_api.as_ref()
    }
    fn provider_organizations_api(
        &self,
    ) -> &dyn provider_organizations_api::ProviderOrganizationsApi {
        self.provider_organizations_api.as_ref()
    }
    fn provider_users_api(&self) -> &dyn provider_users_api::ProviderUsersApi {
        self.provider_users_api.as_ref()
    }
    fn providers_api(&self) -> &dyn providers_api::ProvidersApi {
        self.providers_api.as_ref()
    }
    fn push_api(&self) -> &dyn push_api::PushApi {
        self.push_api.as_ref()
    }
    fn reports_api(&self) -> &dyn reports_api::ReportsApi {
        self.reports_api.as_ref()
    }
    fn request_sm_access_api(&self) -> &dyn request_sm_access_api::RequestSmAccessApi {
        self.request_sm_access_api.as_ref()
    }
    fn secrets_api(&self) -> &dyn secrets_api::SecretsApi {
        self.secrets_api.as_ref()
    }
    fn secrets_manager_events_api(
        &self,
    ) -> &dyn secrets_manager_events_api::SecretsManagerEventsApi {
        self.secrets_manager_events_api.as_ref()
    }
    fn secrets_manager_porting_api(
        &self,
    ) -> &dyn secrets_manager_porting_api::SecretsManagerPortingApi {
        self.secrets_manager_porting_api.as_ref()
    }
    fn security_task_api(&self) -> &dyn security_task_api::SecurityTaskApi {
        self.security_task_api.as_ref()
    }
    fn self_hosted_organization_licenses_api(
        &self,
    ) -> &dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi {
        self.self_hosted_organization_licenses_api.as_ref()
    }
    fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> &dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi {
        self.self_hosted_organization_sponsorships_api.as_ref()
    }
    fn sends_api(&self) -> &dyn sends_api::SendsApi {
        self.sends_api.as_ref()
    }
    fn service_accounts_api(&self) -> &dyn service_accounts_api::ServiceAccountsApi {
        self.service_accounts_api.as_ref()
    }
    fn settings_api(&self) -> &dyn settings_api::SettingsApi {
        self.settings_api.as_ref()
    }
    fn stripe_api(&self) -> &dyn stripe_api::StripeApi {
        self.stripe_api.as_ref()
    }
    fn sync_api(&self) -> &dyn sync_api::SyncApi {
        self.sync_api.as_ref()
    }
    fn trash_api(&self) -> &dyn trash_api::TrashApi {
        self.trash_api.as_ref()
    }
    fn two_factor_api(&self) -> &dyn two_factor_api::TwoFactorApi {
        self.two_factor_api.as_ref()
    }
    fn users_api(&self) -> &dyn users_api::UsersApi {
        self.users_api.as_ref()
    }
    fn web_authn_api(&self) -> &dyn web_authn_api::WebAuthnApi {
        self.web_authn_api.as_ref()
    }
}

#[cfg(feature = "mockall")]
pub struct MockApiClient {
    pub access_policies_api_mock: access_policies_api::MockAccessPoliciesApi,
    pub accounts_api_mock: accounts_api::MockAccountsApi,
    pub accounts_billing_api_mock: accounts_billing_api::MockAccountsBillingApi,
    pub accounts_key_management_api_mock: accounts_key_management_api::MockAccountsKeyManagementApi,
    pub auth_requests_api_mock: auth_requests_api::MockAuthRequestsApi,
    pub ciphers_api_mock: ciphers_api::MockCiphersApi,
    pub collections_api_mock: collections_api::MockCollectionsApi,
    pub config_api_mock: config_api::MockConfigApi,
    pub counts_api_mock: counts_api::MockCountsApi,
    pub devices_api_mock: devices_api::MockDevicesApi,
    pub emergency_access_api_mock: emergency_access_api::MockEmergencyAccessApi,
    pub events_api_mock: events_api::MockEventsApi,
    pub folders_api_mock: folders_api::MockFoldersApi,
    pub groups_api_mock: groups_api::MockGroupsApi,
    pub hibp_api_mock: hibp_api::MockHibpApi,
    pub import_ciphers_api_mock: import_ciphers_api::MockImportCiphersApi,
    pub info_api_mock: info_api::MockInfoApi,
    pub installations_api_mock: installations_api::MockInstallationsApi,
    pub invoices_api_mock: invoices_api::MockInvoicesApi,
    pub licenses_api_mock: licenses_api::MockLicensesApi,
    pub misc_api_mock: misc_api::MockMiscApi,
    pub notifications_api_mock: notifications_api::MockNotificationsApi,
    pub organization_auth_requests_api_mock:
        organization_auth_requests_api::MockOrganizationAuthRequestsApi,
    pub organization_billing_api_mock: organization_billing_api::MockOrganizationBillingApi,
    pub organization_connections_api_mock:
        organization_connections_api::MockOrganizationConnectionsApi,
    pub organization_domain_api_mock: organization_domain_api::MockOrganizationDomainApi,
    pub organization_export_api_mock: organization_export_api::MockOrganizationExportApi,
    pub organization_sponsorships_api_mock:
        organization_sponsorships_api::MockOrganizationSponsorshipsApi,
    pub organization_users_api_mock: organization_users_api::MockOrganizationUsersApi,
    pub organizations_api_mock: organizations_api::MockOrganizationsApi,
    pub plans_api_mock: plans_api::MockPlansApi,
    pub policies_api_mock: policies_api::MockPoliciesApi,
    pub projects_api_mock: projects_api::MockProjectsApi,
    pub provider_billing_api_mock: provider_billing_api::MockProviderBillingApi,
    pub provider_clients_api_mock: provider_clients_api::MockProviderClientsApi,
    pub provider_organizations_api_mock: provider_organizations_api::MockProviderOrganizationsApi,
    pub provider_users_api_mock: provider_users_api::MockProviderUsersApi,
    pub providers_api_mock: providers_api::MockProvidersApi,
    pub push_api_mock: push_api::MockPushApi,
    pub reports_api_mock: reports_api::MockReportsApi,
    pub request_sm_access_api_mock: request_sm_access_api::MockRequestSmAccessApi,
    pub secrets_api_mock: secrets_api::MockSecretsApi,
    pub secrets_manager_events_api_mock: secrets_manager_events_api::MockSecretsManagerEventsApi,
    pub secrets_manager_porting_api_mock: secrets_manager_porting_api::MockSecretsManagerPortingApi,
    pub security_task_api_mock: security_task_api::MockSecurityTaskApi,
    pub self_hosted_organization_licenses_api_mock:
        self_hosted_organization_licenses_api::MockSelfHostedOrganizationLicensesApi,
    pub self_hosted_organization_sponsorships_api_mock:
        self_hosted_organization_sponsorships_api::MockSelfHostedOrganizationSponsorshipsApi,
    pub sends_api_mock: sends_api::MockSendsApi,
    pub service_accounts_api_mock: service_accounts_api::MockServiceAccountsApi,
    pub settings_api_mock: settings_api::MockSettingsApi,
    pub stripe_api_mock: stripe_api::MockStripeApi,
    pub sync_api_mock: sync_api::MockSyncApi,
    pub trash_api_mock: trash_api::MockTrashApi,
    pub two_factor_api_mock: two_factor_api::MockTwoFactorApi,
    pub users_api_mock: users_api::MockUsersApi,
    pub web_authn_api_mock: web_authn_api::MockWebAuthnApi,
}

#[cfg(feature = "mockall")]
impl MockApiClient {
    pub fn new() -> Self {
        Self {
            access_policies_api_mock: access_policies_api::MockAccessPoliciesApi::new(),
            accounts_api_mock: accounts_api::MockAccountsApi::new(),
            accounts_billing_api_mock: accounts_billing_api::MockAccountsBillingApi::new(),
            accounts_key_management_api_mock: accounts_key_management_api::MockAccountsKeyManagementApi::new(),
            auth_requests_api_mock: auth_requests_api::MockAuthRequestsApi::new(),
            ciphers_api_mock: ciphers_api::MockCiphersApi::new(),
            collections_api_mock: collections_api::MockCollectionsApi::new(),
            config_api_mock: config_api::MockConfigApi::new(),
            counts_api_mock: counts_api::MockCountsApi::new(),
            devices_api_mock: devices_api::MockDevicesApi::new(),
            emergency_access_api_mock: emergency_access_api::MockEmergencyAccessApi::new(),
            events_api_mock: events_api::MockEventsApi::new(),
            folders_api_mock: folders_api::MockFoldersApi::new(),
            groups_api_mock: groups_api::MockGroupsApi::new(),
            hibp_api_mock: hibp_api::MockHibpApi::new(),
            import_ciphers_api_mock: import_ciphers_api::MockImportCiphersApi::new(),
            info_api_mock: info_api::MockInfoApi::new(),
            installations_api_mock: installations_api::MockInstallationsApi::new(),
            invoices_api_mock: invoices_api::MockInvoicesApi::new(),
            licenses_api_mock: licenses_api::MockLicensesApi::new(),
            misc_api_mock: misc_api::MockMiscApi::new(),
            notifications_api_mock: notifications_api::MockNotificationsApi::new(),
            organization_auth_requests_api_mock: organization_auth_requests_api::MockOrganizationAuthRequestsApi::new(),
            organization_billing_api_mock: organization_billing_api::MockOrganizationBillingApi::new(),
            organization_connections_api_mock: organization_connections_api::MockOrganizationConnectionsApi::new(),
            organization_domain_api_mock: organization_domain_api::MockOrganizationDomainApi::new(),
            organization_export_api_mock: organization_export_api::MockOrganizationExportApi::new(),
            organization_sponsorships_api_mock: organization_sponsorships_api::MockOrganizationSponsorshipsApi::new(),
            organization_users_api_mock: organization_users_api::MockOrganizationUsersApi::new(),
            organizations_api_mock: organizations_api::MockOrganizationsApi::new(),
            plans_api_mock: plans_api::MockPlansApi::new(),
            policies_api_mock: policies_api::MockPoliciesApi::new(),
            projects_api_mock: projects_api::MockProjectsApi::new(),
            provider_billing_api_mock: provider_billing_api::MockProviderBillingApi::new(),
            provider_clients_api_mock: provider_clients_api::MockProviderClientsApi::new(),
            provider_organizations_api_mock: provider_organizations_api::MockProviderOrganizationsApi::new(),
            provider_users_api_mock: provider_users_api::MockProviderUsersApi::new(),
            providers_api_mock: providers_api::MockProvidersApi::new(),
            push_api_mock: push_api::MockPushApi::new(),
            reports_api_mock: reports_api::MockReportsApi::new(),
            request_sm_access_api_mock: request_sm_access_api::MockRequestSmAccessApi::new(),
            secrets_api_mock: secrets_api::MockSecretsApi::new(),
            secrets_manager_events_api_mock: secrets_manager_events_api::MockSecretsManagerEventsApi::new(),
            secrets_manager_porting_api_mock: secrets_manager_porting_api::MockSecretsManagerPortingApi::new(),
            security_task_api_mock: security_task_api::MockSecurityTaskApi::new(),
            self_hosted_organization_licenses_api_mock: self_hosted_organization_licenses_api::MockSelfHostedOrganizationLicensesApi::new(),
            self_hosted_organization_sponsorships_api_mock: self_hosted_organization_sponsorships_api::MockSelfHostedOrganizationSponsorshipsApi::new(),
            sends_api_mock: sends_api::MockSendsApi::new(),
            service_accounts_api_mock: service_accounts_api::MockServiceAccountsApi::new(),
            settings_api_mock: settings_api::MockSettingsApi::new(),
            stripe_api_mock: stripe_api::MockStripeApi::new(),
            sync_api_mock: sync_api::MockSyncApi::new(),
            trash_api_mock: trash_api::MockTrashApi::new(),
            two_factor_api_mock: two_factor_api::MockTwoFactorApi::new(),
            users_api_mock: users_api::MockUsersApi::new(),
            web_authn_api_mock: web_authn_api::MockWebAuthnApi::new(),
        }
    }
}

#[cfg(feature = "mockall")]
impl Api for MockApiClient {
    fn access_policies_api(&self) -> &dyn access_policies_api::AccessPoliciesApi {
        &self.access_policies_api_mock
    }
    fn accounts_api(&self) -> &dyn accounts_api::AccountsApi {
        &self.accounts_api_mock
    }
    fn accounts_billing_api(&self) -> &dyn accounts_billing_api::AccountsBillingApi {
        &self.accounts_billing_api_mock
    }
    fn accounts_key_management_api(
        &self,
    ) -> &dyn accounts_key_management_api::AccountsKeyManagementApi {
        &self.accounts_key_management_api_mock
    }
    fn auth_requests_api(&self) -> &dyn auth_requests_api::AuthRequestsApi {
        &self.auth_requests_api_mock
    }
    fn ciphers_api(&self) -> &dyn ciphers_api::CiphersApi {
        &self.ciphers_api_mock
    }
    fn collections_api(&self) -> &dyn collections_api::CollectionsApi {
        &self.collections_api_mock
    }
    fn config_api(&self) -> &dyn config_api::ConfigApi {
        &self.config_api_mock
    }
    fn counts_api(&self) -> &dyn counts_api::CountsApi {
        &self.counts_api_mock
    }
    fn devices_api(&self) -> &dyn devices_api::DevicesApi {
        &self.devices_api_mock
    }
    fn emergency_access_api(&self) -> &dyn emergency_access_api::EmergencyAccessApi {
        &self.emergency_access_api_mock
    }
    fn events_api(&self) -> &dyn events_api::EventsApi {
        &self.events_api_mock
    }
    fn folders_api(&self) -> &dyn folders_api::FoldersApi {
        &self.folders_api_mock
    }
    fn groups_api(&self) -> &dyn groups_api::GroupsApi {
        &self.groups_api_mock
    }
    fn hibp_api(&self) -> &dyn hibp_api::HibpApi {
        &self.hibp_api_mock
    }
    fn import_ciphers_api(&self) -> &dyn import_ciphers_api::ImportCiphersApi {
        &self.import_ciphers_api_mock
    }
    fn info_api(&self) -> &dyn info_api::InfoApi {
        &self.info_api_mock
    }
    fn installations_api(&self) -> &dyn installations_api::InstallationsApi {
        &self.installations_api_mock
    }
    fn invoices_api(&self) -> &dyn invoices_api::InvoicesApi {
        &self.invoices_api_mock
    }
    fn licenses_api(&self) -> &dyn licenses_api::LicensesApi {
        &self.licenses_api_mock
    }
    fn misc_api(&self) -> &dyn misc_api::MiscApi {
        &self.misc_api_mock
    }
    fn notifications_api(&self) -> &dyn notifications_api::NotificationsApi {
        &self.notifications_api_mock
    }
    fn organization_auth_requests_api(
        &self,
    ) -> &dyn organization_auth_requests_api::OrganizationAuthRequestsApi {
        &self.organization_auth_requests_api_mock
    }
    fn organization_billing_api(&self) -> &dyn organization_billing_api::OrganizationBillingApi {
        &self.organization_billing_api_mock
    }
    fn organization_connections_api(
        &self,
    ) -> &dyn organization_connections_api::OrganizationConnectionsApi {
        &self.organization_connections_api_mock
    }
    fn organization_domain_api(&self) -> &dyn organization_domain_api::OrganizationDomainApi {
        &self.organization_domain_api_mock
    }
    fn organization_export_api(&self) -> &dyn organization_export_api::OrganizationExportApi {
        &self.organization_export_api_mock
    }
    fn organization_sponsorships_api(
        &self,
    ) -> &dyn organization_sponsorships_api::OrganizationSponsorshipsApi {
        &self.organization_sponsorships_api_mock
    }
    fn organization_users_api(&self) -> &dyn organization_users_api::OrganizationUsersApi {
        &self.organization_users_api_mock
    }
    fn organizations_api(&self) -> &dyn organizations_api::OrganizationsApi {
        &self.organizations_api_mock
    }
    fn plans_api(&self) -> &dyn plans_api::PlansApi {
        &self.plans_api_mock
    }
    fn policies_api(&self) -> &dyn policies_api::PoliciesApi {
        &self.policies_api_mock
    }
    fn projects_api(&self) -> &dyn projects_api::ProjectsApi {
        &self.projects_api_mock
    }
    fn provider_billing_api(&self) -> &dyn provider_billing_api::ProviderBillingApi {
        &self.provider_billing_api_mock
    }
    fn provider_clients_api(&self) -> &dyn provider_clients_api::ProviderClientsApi {
        &self.provider_clients_api_mock
    }
    fn provider_organizations_api(
        &self,
    ) -> &dyn provider_organizations_api::ProviderOrganizationsApi {
        &self.provider_organizations_api_mock
    }
    fn provider_users_api(&self) -> &dyn provider_users_api::ProviderUsersApi {
        &self.provider_users_api_mock
    }
    fn providers_api(&self) -> &dyn providers_api::ProvidersApi {
        &self.providers_api_mock
    }
    fn push_api(&self) -> &dyn push_api::PushApi {
        &self.push_api_mock
    }
    fn reports_api(&self) -> &dyn reports_api::ReportsApi {
        &self.reports_api_mock
    }
    fn request_sm_access_api(&self) -> &dyn request_sm_access_api::RequestSmAccessApi {
        &self.request_sm_access_api_mock
    }
    fn secrets_api(&self) -> &dyn secrets_api::SecretsApi {
        &self.secrets_api_mock
    }
    fn secrets_manager_events_api(
        &self,
    ) -> &dyn secrets_manager_events_api::SecretsManagerEventsApi {
        &self.secrets_manager_events_api_mock
    }
    fn secrets_manager_porting_api(
        &self,
    ) -> &dyn secrets_manager_porting_api::SecretsManagerPortingApi {
        &self.secrets_manager_porting_api_mock
    }
    fn security_task_api(&self) -> &dyn security_task_api::SecurityTaskApi {
        &self.security_task_api_mock
    }
    fn self_hosted_organization_licenses_api(
        &self,
    ) -> &dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi {
        &self.self_hosted_organization_licenses_api_mock
    }
    fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> &dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi {
        &self.self_hosted_organization_sponsorships_api_mock
    }
    fn sends_api(&self) -> &dyn sends_api::SendsApi {
        &self.sends_api_mock
    }
    fn service_accounts_api(&self) -> &dyn service_accounts_api::ServiceAccountsApi {
        &self.service_accounts_api_mock
    }
    fn settings_api(&self) -> &dyn settings_api::SettingsApi {
        &self.settings_api_mock
    }
    fn stripe_api(&self) -> &dyn stripe_api::StripeApi {
        &self.stripe_api_mock
    }
    fn sync_api(&self) -> &dyn sync_api::SyncApi {
        &self.sync_api_mock
    }
    fn trash_api(&self) -> &dyn trash_api::TrashApi {
        &self.trash_api_mock
    }
    fn two_factor_api(&self) -> &dyn two_factor_api::TwoFactorApi {
        &self.two_factor_api_mock
    }
    fn users_api(&self) -> &dyn users_api::UsersApi {
        &self.users_api_mock
    }
    fn web_authn_api(&self) -> &dyn web_authn_api::WebAuthnApi {
        &self.web_authn_api_mock
    }
}
