use std::{error, fmt};

#[derive(Debug, Clone)]
pub struct ResponseContent {
    pub status: reqwest::StatusCode,
    pub content: String,
    pub entity: Option<serde_json::Value>,
}

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent),
}

impl fmt::Display for Error {
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

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::ResponseError(_) => return None,
        })
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<std::io::Error> for Error {
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
pub mod account_billing_v_next_api;
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
pub mod organization_billing_v_next_api;
pub mod organization_connections_api;
pub mod organization_domain_api;
pub mod organization_export_api;
pub mod organization_integration_api;
pub mod organization_integration_configuration_api;
pub mod organization_sponsorships_api;
pub mod organization_users_api;
pub mod organizations_api;
pub mod phishing_domains_api;
pub mod plans_api;
pub mod policies_api;
pub mod projects_api;
pub mod provider_billing_api;
pub mod provider_billing_v_next_api;
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
pub mod slack_integration_api;
pub mod stripe_api;
pub mod sync_api;
pub mod tax_api;
pub mod trash_api;
pub mod two_factor_api;
pub mod users_api;
pub mod web_authn_api;

pub mod configuration;

use std::sync::Arc;

pub struct ApiClient {
    access_policies_api: access_policies_api::AccessPoliciesApiClient,
    account_billing_v_next_api: account_billing_v_next_api::AccountBillingVNextApiClient,
    accounts_api: accounts_api::AccountsApiClient,
    accounts_billing_api: accounts_billing_api::AccountsBillingApiClient,
    accounts_key_management_api: accounts_key_management_api::AccountsKeyManagementApiClient,
    auth_requests_api: auth_requests_api::AuthRequestsApiClient,
    ciphers_api: ciphers_api::CiphersApiClient,
    collections_api: collections_api::CollectionsApiClient,
    config_api: config_api::ConfigApiClient,
    counts_api: counts_api::CountsApiClient,
    devices_api: devices_api::DevicesApiClient,
    emergency_access_api: emergency_access_api::EmergencyAccessApiClient,
    events_api: events_api::EventsApiClient,
    folders_api: folders_api::FoldersApiClient,
    groups_api: groups_api::GroupsApiClient,
    hibp_api: hibp_api::HibpApiClient,
    import_ciphers_api: import_ciphers_api::ImportCiphersApiClient,
    info_api: info_api::InfoApiClient,
    installations_api: installations_api::InstallationsApiClient,
    invoices_api: invoices_api::InvoicesApiClient,
    licenses_api: licenses_api::LicensesApiClient,
    misc_api: misc_api::MiscApiClient,
    notifications_api: notifications_api::NotificationsApiClient,
    organization_auth_requests_api:
        organization_auth_requests_api::OrganizationAuthRequestsApiClient,
    organization_billing_api: organization_billing_api::OrganizationBillingApiClient,
    organization_billing_v_next_api:
        organization_billing_v_next_api::OrganizationBillingVNextApiClient,
    organization_connections_api: organization_connections_api::OrganizationConnectionsApiClient,
    organization_domain_api: organization_domain_api::OrganizationDomainApiClient,
    organization_export_api: organization_export_api::OrganizationExportApiClient,
    organization_integration_api: organization_integration_api::OrganizationIntegrationApiClient,
    organization_integration_configuration_api:
        organization_integration_configuration_api::OrganizationIntegrationConfigurationApiClient,
    organization_sponsorships_api: organization_sponsorships_api::OrganizationSponsorshipsApiClient,
    organization_users_api: organization_users_api::OrganizationUsersApiClient,
    organizations_api: organizations_api::OrganizationsApiClient,
    phishing_domains_api: phishing_domains_api::PhishingDomainsApiClient,
    plans_api: plans_api::PlansApiClient,
    policies_api: policies_api::PoliciesApiClient,
    projects_api: projects_api::ProjectsApiClient,
    provider_billing_api: provider_billing_api::ProviderBillingApiClient,
    provider_billing_v_next_api: provider_billing_v_next_api::ProviderBillingVNextApiClient,
    provider_clients_api: provider_clients_api::ProviderClientsApiClient,
    provider_organizations_api: provider_organizations_api::ProviderOrganizationsApiClient,
    provider_users_api: provider_users_api::ProviderUsersApiClient,
    providers_api: providers_api::ProvidersApiClient,
    push_api: push_api::PushApiClient,
    reports_api: reports_api::ReportsApiClient,
    request_sm_access_api: request_sm_access_api::RequestSmAccessApiClient,
    secrets_api: secrets_api::SecretsApiClient,
    secrets_manager_events_api: secrets_manager_events_api::SecretsManagerEventsApiClient,
    secrets_manager_porting_api: secrets_manager_porting_api::SecretsManagerPortingApiClient,
    security_task_api: security_task_api::SecurityTaskApiClient,
    self_hosted_organization_licenses_api:
        self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient,
    self_hosted_organization_sponsorships_api:
        self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient,
    sends_api: sends_api::SendsApiClient,
    service_accounts_api: service_accounts_api::ServiceAccountsApiClient,
    settings_api: settings_api::SettingsApiClient,
    slack_integration_api: slack_integration_api::SlackIntegrationApiClient,
    stripe_api: stripe_api::StripeApiClient,
    sync_api: sync_api::SyncApiClient,
    tax_api: tax_api::TaxApiClient,
    trash_api: trash_api::TrashApiClient,
    two_factor_api: two_factor_api::TwoFactorApiClient,
    users_api: users_api::UsersApiClient,
    web_authn_api: web_authn_api::WebAuthnApiClient,
}

impl ApiClient {
    pub fn new(configuration: Arc<configuration::Configuration>) -> Self {
        Self {
            access_policies_api: access_policies_api::AccessPoliciesApiClient::new(configuration.clone()),
            account_billing_v_next_api: account_billing_v_next_api::AccountBillingVNextApiClient::new(configuration.clone()),
            accounts_api: accounts_api::AccountsApiClient::new(configuration.clone()),
            accounts_billing_api: accounts_billing_api::AccountsBillingApiClient::new(configuration.clone()),
            accounts_key_management_api: accounts_key_management_api::AccountsKeyManagementApiClient::new(configuration.clone()),
            auth_requests_api: auth_requests_api::AuthRequestsApiClient::new(configuration.clone()),
            ciphers_api: ciphers_api::CiphersApiClient::new(configuration.clone()),
            collections_api: collections_api::CollectionsApiClient::new(configuration.clone()),
            config_api: config_api::ConfigApiClient::new(configuration.clone()),
            counts_api: counts_api::CountsApiClient::new(configuration.clone()),
            devices_api: devices_api::DevicesApiClient::new(configuration.clone()),
            emergency_access_api: emergency_access_api::EmergencyAccessApiClient::new(configuration.clone()),
            events_api: events_api::EventsApiClient::new(configuration.clone()),
            folders_api: folders_api::FoldersApiClient::new(configuration.clone()),
            groups_api: groups_api::GroupsApiClient::new(configuration.clone()),
            hibp_api: hibp_api::HibpApiClient::new(configuration.clone()),
            import_ciphers_api: import_ciphers_api::ImportCiphersApiClient::new(configuration.clone()),
            info_api: info_api::InfoApiClient::new(configuration.clone()),
            installations_api: installations_api::InstallationsApiClient::new(configuration.clone()),
            invoices_api: invoices_api::InvoicesApiClient::new(configuration.clone()),
            licenses_api: licenses_api::LicensesApiClient::new(configuration.clone()),
            misc_api: misc_api::MiscApiClient::new(configuration.clone()),
            notifications_api: notifications_api::NotificationsApiClient::new(configuration.clone()),
            organization_auth_requests_api: organization_auth_requests_api::OrganizationAuthRequestsApiClient::new(configuration.clone()),
            organization_billing_api: organization_billing_api::OrganizationBillingApiClient::new(configuration.clone()),
            organization_billing_v_next_api: organization_billing_v_next_api::OrganizationBillingVNextApiClient::new(configuration.clone()),
            organization_connections_api: organization_connections_api::OrganizationConnectionsApiClient::new(configuration.clone()),
            organization_domain_api: organization_domain_api::OrganizationDomainApiClient::new(configuration.clone()),
            organization_export_api: organization_export_api::OrganizationExportApiClient::new(configuration.clone()),
            organization_integration_api: organization_integration_api::OrganizationIntegrationApiClient::new(configuration.clone()),
            organization_integration_configuration_api: organization_integration_configuration_api::OrganizationIntegrationConfigurationApiClient::new(configuration.clone()),
            organization_sponsorships_api: organization_sponsorships_api::OrganizationSponsorshipsApiClient::new(configuration.clone()),
            organization_users_api: organization_users_api::OrganizationUsersApiClient::new(configuration.clone()),
            organizations_api: organizations_api::OrganizationsApiClient::new(configuration.clone()),
            phishing_domains_api: phishing_domains_api::PhishingDomainsApiClient::new(configuration.clone()),
            plans_api: plans_api::PlansApiClient::new(configuration.clone()),
            policies_api: policies_api::PoliciesApiClient::new(configuration.clone()),
            projects_api: projects_api::ProjectsApiClient::new(configuration.clone()),
            provider_billing_api: provider_billing_api::ProviderBillingApiClient::new(configuration.clone()),
            provider_billing_v_next_api: provider_billing_v_next_api::ProviderBillingVNextApiClient::new(configuration.clone()),
            provider_clients_api: provider_clients_api::ProviderClientsApiClient::new(configuration.clone()),
            provider_organizations_api: provider_organizations_api::ProviderOrganizationsApiClient::new(configuration.clone()),
            provider_users_api: provider_users_api::ProviderUsersApiClient::new(configuration.clone()),
            providers_api: providers_api::ProvidersApiClient::new(configuration.clone()),
            push_api: push_api::PushApiClient::new(configuration.clone()),
            reports_api: reports_api::ReportsApiClient::new(configuration.clone()),
            request_sm_access_api: request_sm_access_api::RequestSmAccessApiClient::new(configuration.clone()),
            secrets_api: secrets_api::SecretsApiClient::new(configuration.clone()),
            secrets_manager_events_api: secrets_manager_events_api::SecretsManagerEventsApiClient::new(configuration.clone()),
            secrets_manager_porting_api: secrets_manager_porting_api::SecretsManagerPortingApiClient::new(configuration.clone()),
            security_task_api: security_task_api::SecurityTaskApiClient::new(configuration.clone()),
            self_hosted_organization_licenses_api: self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient::new(configuration.clone()),
            self_hosted_organization_sponsorships_api: self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient::new(configuration.clone()),
            sends_api: sends_api::SendsApiClient::new(configuration.clone()),
            service_accounts_api: service_accounts_api::ServiceAccountsApiClient::new(configuration.clone()),
            settings_api: settings_api::SettingsApiClient::new(configuration.clone()),
            slack_integration_api: slack_integration_api::SlackIntegrationApiClient::new(configuration.clone()),
            stripe_api: stripe_api::StripeApiClient::new(configuration.clone()),
            sync_api: sync_api::SyncApiClient::new(configuration.clone()),
            tax_api: tax_api::TaxApiClient::new(configuration.clone()),
            trash_api: trash_api::TrashApiClient::new(configuration.clone()),
            two_factor_api: two_factor_api::TwoFactorApiClient::new(configuration.clone()),
            users_api: users_api::UsersApiClient::new(configuration.clone()),
            web_authn_api: web_authn_api::WebAuthnApiClient::new(configuration.clone()),
        }
    }
}

impl ApiClient {
    pub fn access_policies_api(&self) -> &access_policies_api::AccessPoliciesApiClient {
        &self.access_policies_api
    }
    pub fn account_billing_v_next_api(
        &self,
    ) -> &account_billing_v_next_api::AccountBillingVNextApiClient {
        &self.account_billing_v_next_api
    }
    pub fn accounts_api(&self) -> &accounts_api::AccountsApiClient {
        &self.accounts_api
    }
    pub fn accounts_billing_api(&self) -> &accounts_billing_api::AccountsBillingApiClient {
        &self.accounts_billing_api
    }
    pub fn accounts_key_management_api(
        &self,
    ) -> &accounts_key_management_api::AccountsKeyManagementApiClient {
        &self.accounts_key_management_api
    }
    pub fn auth_requests_api(&self) -> &auth_requests_api::AuthRequestsApiClient {
        &self.auth_requests_api
    }
    pub fn ciphers_api(&self) -> &ciphers_api::CiphersApiClient {
        &self.ciphers_api
    }
    pub fn collections_api(&self) -> &collections_api::CollectionsApiClient {
        &self.collections_api
    }
    pub fn config_api(&self) -> &config_api::ConfigApiClient {
        &self.config_api
    }
    pub fn counts_api(&self) -> &counts_api::CountsApiClient {
        &self.counts_api
    }
    pub fn devices_api(&self) -> &devices_api::DevicesApiClient {
        &self.devices_api
    }
    pub fn emergency_access_api(&self) -> &emergency_access_api::EmergencyAccessApiClient {
        &self.emergency_access_api
    }
    pub fn events_api(&self) -> &events_api::EventsApiClient {
        &self.events_api
    }
    pub fn folders_api(&self) -> &folders_api::FoldersApiClient {
        &self.folders_api
    }
    pub fn groups_api(&self) -> &groups_api::GroupsApiClient {
        &self.groups_api
    }
    pub fn hibp_api(&self) -> &hibp_api::HibpApiClient {
        &self.hibp_api
    }
    pub fn import_ciphers_api(&self) -> &import_ciphers_api::ImportCiphersApiClient {
        &self.import_ciphers_api
    }
    pub fn info_api(&self) -> &info_api::InfoApiClient {
        &self.info_api
    }
    pub fn installations_api(&self) -> &installations_api::InstallationsApiClient {
        &self.installations_api
    }
    pub fn invoices_api(&self) -> &invoices_api::InvoicesApiClient {
        &self.invoices_api
    }
    pub fn licenses_api(&self) -> &licenses_api::LicensesApiClient {
        &self.licenses_api
    }
    pub fn misc_api(&self) -> &misc_api::MiscApiClient {
        &self.misc_api
    }
    pub fn notifications_api(&self) -> &notifications_api::NotificationsApiClient {
        &self.notifications_api
    }
    pub fn organization_auth_requests_api(
        &self,
    ) -> &organization_auth_requests_api::OrganizationAuthRequestsApiClient {
        &self.organization_auth_requests_api
    }
    pub fn organization_billing_api(
        &self,
    ) -> &organization_billing_api::OrganizationBillingApiClient {
        &self.organization_billing_api
    }
    pub fn organization_billing_v_next_api(
        &self,
    ) -> &organization_billing_v_next_api::OrganizationBillingVNextApiClient {
        &self.organization_billing_v_next_api
    }
    pub fn organization_connections_api(
        &self,
    ) -> &organization_connections_api::OrganizationConnectionsApiClient {
        &self.organization_connections_api
    }
    pub fn organization_domain_api(&self) -> &organization_domain_api::OrganizationDomainApiClient {
        &self.organization_domain_api
    }
    pub fn organization_export_api(&self) -> &organization_export_api::OrganizationExportApiClient {
        &self.organization_export_api
    }
    pub fn organization_integration_api(
        &self,
    ) -> &organization_integration_api::OrganizationIntegrationApiClient {
        &self.organization_integration_api
    }
    pub fn organization_integration_configuration_api(
        &self,
    ) -> &organization_integration_configuration_api::OrganizationIntegrationConfigurationApiClient
    {
        &self.organization_integration_configuration_api
    }
    pub fn organization_sponsorships_api(
        &self,
    ) -> &organization_sponsorships_api::OrganizationSponsorshipsApiClient {
        &self.organization_sponsorships_api
    }
    pub fn organization_users_api(&self) -> &organization_users_api::OrganizationUsersApiClient {
        &self.organization_users_api
    }
    pub fn organizations_api(&self) -> &organizations_api::OrganizationsApiClient {
        &self.organizations_api
    }
    pub fn phishing_domains_api(&self) -> &phishing_domains_api::PhishingDomainsApiClient {
        &self.phishing_domains_api
    }
    pub fn plans_api(&self) -> &plans_api::PlansApiClient {
        &self.plans_api
    }
    pub fn policies_api(&self) -> &policies_api::PoliciesApiClient {
        &self.policies_api
    }
    pub fn projects_api(&self) -> &projects_api::ProjectsApiClient {
        &self.projects_api
    }
    pub fn provider_billing_api(&self) -> &provider_billing_api::ProviderBillingApiClient {
        &self.provider_billing_api
    }
    pub fn provider_billing_v_next_api(
        &self,
    ) -> &provider_billing_v_next_api::ProviderBillingVNextApiClient {
        &self.provider_billing_v_next_api
    }
    pub fn provider_clients_api(&self) -> &provider_clients_api::ProviderClientsApiClient {
        &self.provider_clients_api
    }
    pub fn provider_organizations_api(
        &self,
    ) -> &provider_organizations_api::ProviderOrganizationsApiClient {
        &self.provider_organizations_api
    }
    pub fn provider_users_api(&self) -> &provider_users_api::ProviderUsersApiClient {
        &self.provider_users_api
    }
    pub fn providers_api(&self) -> &providers_api::ProvidersApiClient {
        &self.providers_api
    }
    pub fn push_api(&self) -> &push_api::PushApiClient {
        &self.push_api
    }
    pub fn reports_api(&self) -> &reports_api::ReportsApiClient {
        &self.reports_api
    }
    pub fn request_sm_access_api(&self) -> &request_sm_access_api::RequestSmAccessApiClient {
        &self.request_sm_access_api
    }
    pub fn secrets_api(&self) -> &secrets_api::SecretsApiClient {
        &self.secrets_api
    }
    pub fn secrets_manager_events_api(
        &self,
    ) -> &secrets_manager_events_api::SecretsManagerEventsApiClient {
        &self.secrets_manager_events_api
    }
    pub fn secrets_manager_porting_api(
        &self,
    ) -> &secrets_manager_porting_api::SecretsManagerPortingApiClient {
        &self.secrets_manager_porting_api
    }
    pub fn security_task_api(&self) -> &security_task_api::SecurityTaskApiClient {
        &self.security_task_api
    }
    pub fn self_hosted_organization_licenses_api(
        &self,
    ) -> &self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient {
        &self.self_hosted_organization_licenses_api
    }
    pub fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> &self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient
    {
        &self.self_hosted_organization_sponsorships_api
    }
    pub fn sends_api(&self) -> &sends_api::SendsApiClient {
        &self.sends_api
    }
    pub fn service_accounts_api(&self) -> &service_accounts_api::ServiceAccountsApiClient {
        &self.service_accounts_api
    }
    pub fn settings_api(&self) -> &settings_api::SettingsApiClient {
        &self.settings_api
    }
    pub fn slack_integration_api(&self) -> &slack_integration_api::SlackIntegrationApiClient {
        &self.slack_integration_api
    }
    pub fn stripe_api(&self) -> &stripe_api::StripeApiClient {
        &self.stripe_api
    }
    pub fn sync_api(&self) -> &sync_api::SyncApiClient {
        &self.sync_api
    }
    pub fn tax_api(&self) -> &tax_api::TaxApiClient {
        &self.tax_api
    }
    pub fn trash_api(&self) -> &trash_api::TrashApiClient {
        &self.trash_api
    }
    pub fn two_factor_api(&self) -> &two_factor_api::TwoFactorApiClient {
        &self.two_factor_api
    }
    pub fn users_api(&self) -> &users_api::UsersApiClient {
        &self.users_api
    }
    pub fn web_authn_api(&self) -> &web_authn_api::WebAuthnApiClient {
        &self.web_authn_api
    }
}
