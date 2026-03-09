// Reexport base types from bitwarden-api-base for backwards compatibility
pub use bitwarden_api_base::*;

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
pub mod licenses_api;
pub mod notifications_api;
pub mod organization_auth_requests_api;
pub mod organization_billing_api;
pub mod organization_billing_v_next_api;
pub mod organization_connections_api;
pub mod organization_domain_api;
pub mod organization_export_api;
pub mod organization_integration_api;
pub mod organization_integration_configuration_api;
pub mod organization_reports_api;
pub mod organization_sponsorships_api;
pub mod organization_users_api;
pub mod organizations_api;
pub mod plans_api;
pub mod policies_api;
pub mod preview_invoice_api;
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
pub mod secret_versions_api;
pub mod secrets_api;
pub mod secrets_manager_events_api;
pub mod secrets_manager_porting_api;
pub mod security_task_api;
pub mod self_hosted_account_billing_v_next_api;
pub mod self_hosted_organization_billing_v_next_api;
pub mod self_hosted_organization_licenses_api;
pub mod self_hosted_organization_sponsorships_api;
pub mod sends_api;
pub mod service_accounts_api;
pub mod settings_api;
pub mod slack_integration_api;
pub mod sso_cookie_vendor_api;
pub mod stripe_api;
pub mod sync_api;
pub mod teams_integration_api;
pub mod trash_api;
pub mod two_factor_api;
pub mod users_api;
pub mod web_authn_api;

// Reexport Configuration type from bitwarden-api-base for backwards compatibility
pub mod configuration {
    pub use bitwarden_api_base::Configuration;
}

use std::sync::Arc;

#[allow(clippy::large_enum_variant, private_interfaces)]
pub enum ApiClient {
    Real(ApiClientReal),
    #[cfg(feature = "mockall")]
    Mock(ApiClientMock),
}

struct ApiClientReal {
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
    licenses_api: licenses_api::LicensesApiClient,
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
    organization_reports_api: organization_reports_api::OrganizationReportsApiClient,
    organization_sponsorships_api: organization_sponsorships_api::OrganizationSponsorshipsApiClient,
    organization_users_api: organization_users_api::OrganizationUsersApiClient,
    organizations_api: organizations_api::OrganizationsApiClient,
    plans_api: plans_api::PlansApiClient,
    policies_api: policies_api::PoliciesApiClient,
    preview_invoice_api: preview_invoice_api::PreviewInvoiceApiClient,
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
    secret_versions_api: secret_versions_api::SecretVersionsApiClient,
    secrets_api: secrets_api::SecretsApiClient,
    secrets_manager_events_api: secrets_manager_events_api::SecretsManagerEventsApiClient,
    secrets_manager_porting_api: secrets_manager_porting_api::SecretsManagerPortingApiClient,
    security_task_api: security_task_api::SecurityTaskApiClient,
    self_hosted_account_billing_v_next_api:
        self_hosted_account_billing_v_next_api::SelfHostedAccountBillingVNextApiClient,
    self_hosted_organization_billing_v_next_api:
        self_hosted_organization_billing_v_next_api::SelfHostedOrganizationBillingVNextApiClient,
    self_hosted_organization_licenses_api:
        self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient,
    self_hosted_organization_sponsorships_api:
        self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient,
    sends_api: sends_api::SendsApiClient,
    service_accounts_api: service_accounts_api::ServiceAccountsApiClient,
    settings_api: settings_api::SettingsApiClient,
    slack_integration_api: slack_integration_api::SlackIntegrationApiClient,
    sso_cookie_vendor_api: sso_cookie_vendor_api::SsoCookieVendorApiClient,
    stripe_api: stripe_api::StripeApiClient,
    sync_api: sync_api::SyncApiClient,
    teams_integration_api: teams_integration_api::TeamsIntegrationApiClient,
    trash_api: trash_api::TrashApiClient,
    two_factor_api: two_factor_api::TwoFactorApiClient,
    users_api: users_api::UsersApiClient,
    web_authn_api: web_authn_api::WebAuthnApiClient,
}

#[cfg(feature = "mockall")]
pub struct ApiClientMock {
    pub access_policies_api: access_policies_api::MockAccessPoliciesApi,
    pub account_billing_v_next_api: account_billing_v_next_api::MockAccountBillingVNextApi,
    pub accounts_api: accounts_api::MockAccountsApi,
    pub accounts_billing_api: accounts_billing_api::MockAccountsBillingApi,
    pub accounts_key_management_api: accounts_key_management_api::MockAccountsKeyManagementApi,
    pub auth_requests_api: auth_requests_api::MockAuthRequestsApi,
    pub ciphers_api: ciphers_api::MockCiphersApi,
    pub collections_api: collections_api::MockCollectionsApi,
    pub config_api: config_api::MockConfigApi,
    pub counts_api: counts_api::MockCountsApi,
    pub devices_api: devices_api::MockDevicesApi,
    pub emergency_access_api: emergency_access_api::MockEmergencyAccessApi,
    pub events_api: events_api::MockEventsApi,
    pub folders_api: folders_api::MockFoldersApi,
    pub groups_api: groups_api::MockGroupsApi,
    pub hibp_api: hibp_api::MockHibpApi,
    pub import_ciphers_api: import_ciphers_api::MockImportCiphersApi,
    pub info_api: info_api::MockInfoApi,
    pub installations_api: installations_api::MockInstallationsApi,
    pub licenses_api: licenses_api::MockLicensesApi,
    pub notifications_api: notifications_api::MockNotificationsApi,
    pub organization_auth_requests_api:
        organization_auth_requests_api::MockOrganizationAuthRequestsApi,
    pub organization_billing_api: organization_billing_api::MockOrganizationBillingApi,
    pub organization_billing_v_next_api:
        organization_billing_v_next_api::MockOrganizationBillingVNextApi,
    pub organization_connections_api: organization_connections_api::MockOrganizationConnectionsApi,
    pub organization_domain_api: organization_domain_api::MockOrganizationDomainApi,
    pub organization_export_api: organization_export_api::MockOrganizationExportApi,
    pub organization_integration_api: organization_integration_api::MockOrganizationIntegrationApi,
    pub organization_integration_configuration_api:
        organization_integration_configuration_api::MockOrganizationIntegrationConfigurationApi,
    pub organization_reports_api: organization_reports_api::MockOrganizationReportsApi,
    pub organization_sponsorships_api:
        organization_sponsorships_api::MockOrganizationSponsorshipsApi,
    pub organization_users_api: organization_users_api::MockOrganizationUsersApi,
    pub organizations_api: organizations_api::MockOrganizationsApi,
    pub plans_api: plans_api::MockPlansApi,
    pub policies_api: policies_api::MockPoliciesApi,
    pub preview_invoice_api: preview_invoice_api::MockPreviewInvoiceApi,
    pub projects_api: projects_api::MockProjectsApi,
    pub provider_billing_api: provider_billing_api::MockProviderBillingApi,
    pub provider_billing_v_next_api: provider_billing_v_next_api::MockProviderBillingVNextApi,
    pub provider_clients_api: provider_clients_api::MockProviderClientsApi,
    pub provider_organizations_api: provider_organizations_api::MockProviderOrganizationsApi,
    pub provider_users_api: provider_users_api::MockProviderUsersApi,
    pub providers_api: providers_api::MockProvidersApi,
    pub push_api: push_api::MockPushApi,
    pub reports_api: reports_api::MockReportsApi,
    pub request_sm_access_api: request_sm_access_api::MockRequestSmAccessApi,
    pub secret_versions_api: secret_versions_api::MockSecretVersionsApi,
    pub secrets_api: secrets_api::MockSecretsApi,
    pub secrets_manager_events_api: secrets_manager_events_api::MockSecretsManagerEventsApi,
    pub secrets_manager_porting_api: secrets_manager_porting_api::MockSecretsManagerPortingApi,
    pub security_task_api: security_task_api::MockSecurityTaskApi,
    pub self_hosted_account_billing_v_next_api:
        self_hosted_account_billing_v_next_api::MockSelfHostedAccountBillingVNextApi,
    pub self_hosted_organization_billing_v_next_api:
        self_hosted_organization_billing_v_next_api::MockSelfHostedOrganizationBillingVNextApi,
    pub self_hosted_organization_licenses_api:
        self_hosted_organization_licenses_api::MockSelfHostedOrganizationLicensesApi,
    pub self_hosted_organization_sponsorships_api:
        self_hosted_organization_sponsorships_api::MockSelfHostedOrganizationSponsorshipsApi,
    pub sends_api: sends_api::MockSendsApi,
    pub service_accounts_api: service_accounts_api::MockServiceAccountsApi,
    pub settings_api: settings_api::MockSettingsApi,
    pub slack_integration_api: slack_integration_api::MockSlackIntegrationApi,
    pub sso_cookie_vendor_api: sso_cookie_vendor_api::MockSsoCookieVendorApi,
    pub stripe_api: stripe_api::MockStripeApi,
    pub sync_api: sync_api::MockSyncApi,
    pub teams_integration_api: teams_integration_api::MockTeamsIntegrationApi,
    pub trash_api: trash_api::MockTrashApi,
    pub two_factor_api: two_factor_api::MockTwoFactorApi,
    pub users_api: users_api::MockUsersApi,
    pub web_authn_api: web_authn_api::MockWebAuthnApi,
}

impl ApiClient {
    pub fn new(configuration: &Arc<bitwarden_api_base::Configuration>) -> Self {
        Self::Real(ApiClientReal {
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
            licenses_api: licenses_api::LicensesApiClient::new(configuration.clone()),
            notifications_api: notifications_api::NotificationsApiClient::new(configuration.clone()),
            organization_auth_requests_api: organization_auth_requests_api::OrganizationAuthRequestsApiClient::new(configuration.clone()),
            organization_billing_api: organization_billing_api::OrganizationBillingApiClient::new(configuration.clone()),
            organization_billing_v_next_api: organization_billing_v_next_api::OrganizationBillingVNextApiClient::new(configuration.clone()),
            organization_connections_api: organization_connections_api::OrganizationConnectionsApiClient::new(configuration.clone()),
            organization_domain_api: organization_domain_api::OrganizationDomainApiClient::new(configuration.clone()),
            organization_export_api: organization_export_api::OrganizationExportApiClient::new(configuration.clone()),
            organization_integration_api: organization_integration_api::OrganizationIntegrationApiClient::new(configuration.clone()),
            organization_integration_configuration_api: organization_integration_configuration_api::OrganizationIntegrationConfigurationApiClient::new(configuration.clone()),
            organization_reports_api: organization_reports_api::OrganizationReportsApiClient::new(configuration.clone()),
            organization_sponsorships_api: organization_sponsorships_api::OrganizationSponsorshipsApiClient::new(configuration.clone()),
            organization_users_api: organization_users_api::OrganizationUsersApiClient::new(configuration.clone()),
            organizations_api: organizations_api::OrganizationsApiClient::new(configuration.clone()),
            plans_api: plans_api::PlansApiClient::new(configuration.clone()),
            policies_api: policies_api::PoliciesApiClient::new(configuration.clone()),
            preview_invoice_api: preview_invoice_api::PreviewInvoiceApiClient::new(configuration.clone()),
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
            secret_versions_api: secret_versions_api::SecretVersionsApiClient::new(configuration.clone()),
            secrets_api: secrets_api::SecretsApiClient::new(configuration.clone()),
            secrets_manager_events_api: secrets_manager_events_api::SecretsManagerEventsApiClient::new(configuration.clone()),
            secrets_manager_porting_api: secrets_manager_porting_api::SecretsManagerPortingApiClient::new(configuration.clone()),
            security_task_api: security_task_api::SecurityTaskApiClient::new(configuration.clone()),
            self_hosted_account_billing_v_next_api: self_hosted_account_billing_v_next_api::SelfHostedAccountBillingVNextApiClient::new(configuration.clone()),
            self_hosted_organization_billing_v_next_api: self_hosted_organization_billing_v_next_api::SelfHostedOrganizationBillingVNextApiClient::new(configuration.clone()),
            self_hosted_organization_licenses_api: self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApiClient::new(configuration.clone()),
            self_hosted_organization_sponsorships_api: self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApiClient::new(configuration.clone()),
            sends_api: sends_api::SendsApiClient::new(configuration.clone()),
            service_accounts_api: service_accounts_api::ServiceAccountsApiClient::new(configuration.clone()),
            settings_api: settings_api::SettingsApiClient::new(configuration.clone()),
            slack_integration_api: slack_integration_api::SlackIntegrationApiClient::new(configuration.clone()),
            sso_cookie_vendor_api: sso_cookie_vendor_api::SsoCookieVendorApiClient::new(configuration.clone()),
            stripe_api: stripe_api::StripeApiClient::new(configuration.clone()),
            sync_api: sync_api::SyncApiClient::new(configuration.clone()),
            teams_integration_api: teams_integration_api::TeamsIntegrationApiClient::new(configuration.clone()),
            trash_api: trash_api::TrashApiClient::new(configuration.clone()),
            two_factor_api: two_factor_api::TwoFactorApiClient::new(configuration.clone()),
            users_api: users_api::UsersApiClient::new(configuration.clone()),
            web_authn_api: web_authn_api::WebAuthnApiClient::new(configuration.clone()),
        })
    }

    #[cfg(feature = "mockall")]
    pub fn new_mocked(func: impl FnOnce(&mut ApiClientMock)) -> Self {
        let mut mock = ApiClientMock {
            access_policies_api: access_policies_api::MockAccessPoliciesApi::new(),
            account_billing_v_next_api: account_billing_v_next_api::MockAccountBillingVNextApi::new(),
            accounts_api: accounts_api::MockAccountsApi::new(),
            accounts_billing_api: accounts_billing_api::MockAccountsBillingApi::new(),
            accounts_key_management_api: accounts_key_management_api::MockAccountsKeyManagementApi::new(),
            auth_requests_api: auth_requests_api::MockAuthRequestsApi::new(),
            ciphers_api: ciphers_api::MockCiphersApi::new(),
            collections_api: collections_api::MockCollectionsApi::new(),
            config_api: config_api::MockConfigApi::new(),
            counts_api: counts_api::MockCountsApi::new(),
            devices_api: devices_api::MockDevicesApi::new(),
            emergency_access_api: emergency_access_api::MockEmergencyAccessApi::new(),
            events_api: events_api::MockEventsApi::new(),
            folders_api: folders_api::MockFoldersApi::new(),
            groups_api: groups_api::MockGroupsApi::new(),
            hibp_api: hibp_api::MockHibpApi::new(),
            import_ciphers_api: import_ciphers_api::MockImportCiphersApi::new(),
            info_api: info_api::MockInfoApi::new(),
            installations_api: installations_api::MockInstallationsApi::new(),
            licenses_api: licenses_api::MockLicensesApi::new(),
            notifications_api: notifications_api::MockNotificationsApi::new(),
            organization_auth_requests_api: organization_auth_requests_api::MockOrganizationAuthRequestsApi::new(),
            organization_billing_api: organization_billing_api::MockOrganizationBillingApi::new(),
            organization_billing_v_next_api: organization_billing_v_next_api::MockOrganizationBillingVNextApi::new(),
            organization_connections_api: organization_connections_api::MockOrganizationConnectionsApi::new(),
            organization_domain_api: organization_domain_api::MockOrganizationDomainApi::new(),
            organization_export_api: organization_export_api::MockOrganizationExportApi::new(),
            organization_integration_api: organization_integration_api::MockOrganizationIntegrationApi::new(),
            organization_integration_configuration_api: organization_integration_configuration_api::MockOrganizationIntegrationConfigurationApi::new(),
            organization_reports_api: organization_reports_api::MockOrganizationReportsApi::new(),
            organization_sponsorships_api: organization_sponsorships_api::MockOrganizationSponsorshipsApi::new(),
            organization_users_api: organization_users_api::MockOrganizationUsersApi::new(),
            organizations_api: organizations_api::MockOrganizationsApi::new(),
            plans_api: plans_api::MockPlansApi::new(),
            policies_api: policies_api::MockPoliciesApi::new(),
            preview_invoice_api: preview_invoice_api::MockPreviewInvoiceApi::new(),
            projects_api: projects_api::MockProjectsApi::new(),
            provider_billing_api: provider_billing_api::MockProviderBillingApi::new(),
            provider_billing_v_next_api: provider_billing_v_next_api::MockProviderBillingVNextApi::new(),
            provider_clients_api: provider_clients_api::MockProviderClientsApi::new(),
            provider_organizations_api: provider_organizations_api::MockProviderOrganizationsApi::new(),
            provider_users_api: provider_users_api::MockProviderUsersApi::new(),
            providers_api: providers_api::MockProvidersApi::new(),
            push_api: push_api::MockPushApi::new(),
            reports_api: reports_api::MockReportsApi::new(),
            request_sm_access_api: request_sm_access_api::MockRequestSmAccessApi::new(),
            secret_versions_api: secret_versions_api::MockSecretVersionsApi::new(),
            secrets_api: secrets_api::MockSecretsApi::new(),
            secrets_manager_events_api: secrets_manager_events_api::MockSecretsManagerEventsApi::new(),
            secrets_manager_porting_api: secrets_manager_porting_api::MockSecretsManagerPortingApi::new(),
            security_task_api: security_task_api::MockSecurityTaskApi::new(),
            self_hosted_account_billing_v_next_api: self_hosted_account_billing_v_next_api::MockSelfHostedAccountBillingVNextApi::new(),
            self_hosted_organization_billing_v_next_api: self_hosted_organization_billing_v_next_api::MockSelfHostedOrganizationBillingVNextApi::new(),
            self_hosted_organization_licenses_api: self_hosted_organization_licenses_api::MockSelfHostedOrganizationLicensesApi::new(),
            self_hosted_organization_sponsorships_api: self_hosted_organization_sponsorships_api::MockSelfHostedOrganizationSponsorshipsApi::new(),
            sends_api: sends_api::MockSendsApi::new(),
            service_accounts_api: service_accounts_api::MockServiceAccountsApi::new(),
            settings_api: settings_api::MockSettingsApi::new(),
            slack_integration_api: slack_integration_api::MockSlackIntegrationApi::new(),
            sso_cookie_vendor_api: sso_cookie_vendor_api::MockSsoCookieVendorApi::new(),
            stripe_api: stripe_api::MockStripeApi::new(),
            sync_api: sync_api::MockSyncApi::new(),
            teams_integration_api: teams_integration_api::MockTeamsIntegrationApi::new(),
            trash_api: trash_api::MockTrashApi::new(),
            two_factor_api: two_factor_api::MockTwoFactorApi::new(),
            users_api: users_api::MockUsersApi::new(),
            web_authn_api: web_authn_api::MockWebAuthnApi::new(),
        };
        func(&mut mock);
        Self::Mock(mock)
    }
}

impl ApiClient {
    pub fn access_policies_api(&self) -> &dyn access_policies_api::AccessPoliciesApi {
        match self {
            ApiClient::Real(real) => &real.access_policies_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.access_policies_api,
        }
    }
    pub fn account_billing_v_next_api(
        &self,
    ) -> &dyn account_billing_v_next_api::AccountBillingVNextApi {
        match self {
            ApiClient::Real(real) => &real.account_billing_v_next_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.account_billing_v_next_api,
        }
    }
    pub fn accounts_api(&self) -> &dyn accounts_api::AccountsApi {
        match self {
            ApiClient::Real(real) => &real.accounts_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.accounts_api,
        }
    }
    pub fn accounts_billing_api(&self) -> &dyn accounts_billing_api::AccountsBillingApi {
        match self {
            ApiClient::Real(real) => &real.accounts_billing_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.accounts_billing_api,
        }
    }
    pub fn accounts_key_management_api(
        &self,
    ) -> &dyn accounts_key_management_api::AccountsKeyManagementApi {
        match self {
            ApiClient::Real(real) => &real.accounts_key_management_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.accounts_key_management_api,
        }
    }
    pub fn auth_requests_api(&self) -> &dyn auth_requests_api::AuthRequestsApi {
        match self {
            ApiClient::Real(real) => &real.auth_requests_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.auth_requests_api,
        }
    }
    pub fn ciphers_api(&self) -> &dyn ciphers_api::CiphersApi {
        match self {
            ApiClient::Real(real) => &real.ciphers_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.ciphers_api,
        }
    }
    pub fn collections_api(&self) -> &dyn collections_api::CollectionsApi {
        match self {
            ApiClient::Real(real) => &real.collections_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.collections_api,
        }
    }
    pub fn config_api(&self) -> &dyn config_api::ConfigApi {
        match self {
            ApiClient::Real(real) => &real.config_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.config_api,
        }
    }
    pub fn counts_api(&self) -> &dyn counts_api::CountsApi {
        match self {
            ApiClient::Real(real) => &real.counts_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.counts_api,
        }
    }
    pub fn devices_api(&self) -> &dyn devices_api::DevicesApi {
        match self {
            ApiClient::Real(real) => &real.devices_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.devices_api,
        }
    }
    pub fn emergency_access_api(&self) -> &dyn emergency_access_api::EmergencyAccessApi {
        match self {
            ApiClient::Real(real) => &real.emergency_access_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.emergency_access_api,
        }
    }
    pub fn events_api(&self) -> &dyn events_api::EventsApi {
        match self {
            ApiClient::Real(real) => &real.events_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.events_api,
        }
    }
    pub fn folders_api(&self) -> &dyn folders_api::FoldersApi {
        match self {
            ApiClient::Real(real) => &real.folders_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.folders_api,
        }
    }
    pub fn groups_api(&self) -> &dyn groups_api::GroupsApi {
        match self {
            ApiClient::Real(real) => &real.groups_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.groups_api,
        }
    }
    pub fn hibp_api(&self) -> &dyn hibp_api::HibpApi {
        match self {
            ApiClient::Real(real) => &real.hibp_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.hibp_api,
        }
    }
    pub fn import_ciphers_api(&self) -> &dyn import_ciphers_api::ImportCiphersApi {
        match self {
            ApiClient::Real(real) => &real.import_ciphers_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.import_ciphers_api,
        }
    }
    pub fn info_api(&self) -> &dyn info_api::InfoApi {
        match self {
            ApiClient::Real(real) => &real.info_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.info_api,
        }
    }
    pub fn installations_api(&self) -> &dyn installations_api::InstallationsApi {
        match self {
            ApiClient::Real(real) => &real.installations_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.installations_api,
        }
    }
    pub fn licenses_api(&self) -> &dyn licenses_api::LicensesApi {
        match self {
            ApiClient::Real(real) => &real.licenses_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.licenses_api,
        }
    }
    pub fn notifications_api(&self) -> &dyn notifications_api::NotificationsApi {
        match self {
            ApiClient::Real(real) => &real.notifications_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.notifications_api,
        }
    }
    pub fn organization_auth_requests_api(
        &self,
    ) -> &dyn organization_auth_requests_api::OrganizationAuthRequestsApi {
        match self {
            ApiClient::Real(real) => &real.organization_auth_requests_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_auth_requests_api,
        }
    }
    pub fn organization_billing_api(
        &self,
    ) -> &dyn organization_billing_api::OrganizationBillingApi {
        match self {
            ApiClient::Real(real) => &real.organization_billing_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_billing_api,
        }
    }
    pub fn organization_billing_v_next_api(
        &self,
    ) -> &dyn organization_billing_v_next_api::OrganizationBillingVNextApi {
        match self {
            ApiClient::Real(real) => &real.organization_billing_v_next_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_billing_v_next_api,
        }
    }
    pub fn organization_connections_api(
        &self,
    ) -> &dyn organization_connections_api::OrganizationConnectionsApi {
        match self {
            ApiClient::Real(real) => &real.organization_connections_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_connections_api,
        }
    }
    pub fn organization_domain_api(&self) -> &dyn organization_domain_api::OrganizationDomainApi {
        match self {
            ApiClient::Real(real) => &real.organization_domain_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_domain_api,
        }
    }
    pub fn organization_export_api(&self) -> &dyn organization_export_api::OrganizationExportApi {
        match self {
            ApiClient::Real(real) => &real.organization_export_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_export_api,
        }
    }
    pub fn organization_integration_api(
        &self,
    ) -> &dyn organization_integration_api::OrganizationIntegrationApi {
        match self {
            ApiClient::Real(real) => &real.organization_integration_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_integration_api,
        }
    }
    pub fn organization_integration_configuration_api(
        &self,
    ) -> &dyn organization_integration_configuration_api::OrganizationIntegrationConfigurationApi
    {
        match self {
            ApiClient::Real(real) => &real.organization_integration_configuration_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_integration_configuration_api,
        }
    }
    pub fn organization_reports_api(
        &self,
    ) -> &dyn organization_reports_api::OrganizationReportsApi {
        match self {
            ApiClient::Real(real) => &real.organization_reports_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_reports_api,
        }
    }
    pub fn organization_sponsorships_api(
        &self,
    ) -> &dyn organization_sponsorships_api::OrganizationSponsorshipsApi {
        match self {
            ApiClient::Real(real) => &real.organization_sponsorships_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_sponsorships_api,
        }
    }
    pub fn organization_users_api(&self) -> &dyn organization_users_api::OrganizationUsersApi {
        match self {
            ApiClient::Real(real) => &real.organization_users_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organization_users_api,
        }
    }
    pub fn organizations_api(&self) -> &dyn organizations_api::OrganizationsApi {
        match self {
            ApiClient::Real(real) => &real.organizations_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.organizations_api,
        }
    }
    pub fn plans_api(&self) -> &dyn plans_api::PlansApi {
        match self {
            ApiClient::Real(real) => &real.plans_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.plans_api,
        }
    }
    pub fn policies_api(&self) -> &dyn policies_api::PoliciesApi {
        match self {
            ApiClient::Real(real) => &real.policies_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.policies_api,
        }
    }
    pub fn preview_invoice_api(&self) -> &dyn preview_invoice_api::PreviewInvoiceApi {
        match self {
            ApiClient::Real(real) => &real.preview_invoice_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.preview_invoice_api,
        }
    }
    pub fn projects_api(&self) -> &dyn projects_api::ProjectsApi {
        match self {
            ApiClient::Real(real) => &real.projects_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.projects_api,
        }
    }
    pub fn provider_billing_api(&self) -> &dyn provider_billing_api::ProviderBillingApi {
        match self {
            ApiClient::Real(real) => &real.provider_billing_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.provider_billing_api,
        }
    }
    pub fn provider_billing_v_next_api(
        &self,
    ) -> &dyn provider_billing_v_next_api::ProviderBillingVNextApi {
        match self {
            ApiClient::Real(real) => &real.provider_billing_v_next_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.provider_billing_v_next_api,
        }
    }
    pub fn provider_clients_api(&self) -> &dyn provider_clients_api::ProviderClientsApi {
        match self {
            ApiClient::Real(real) => &real.provider_clients_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.provider_clients_api,
        }
    }
    pub fn provider_organizations_api(
        &self,
    ) -> &dyn provider_organizations_api::ProviderOrganizationsApi {
        match self {
            ApiClient::Real(real) => &real.provider_organizations_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.provider_organizations_api,
        }
    }
    pub fn provider_users_api(&self) -> &dyn provider_users_api::ProviderUsersApi {
        match self {
            ApiClient::Real(real) => &real.provider_users_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.provider_users_api,
        }
    }
    pub fn providers_api(&self) -> &dyn providers_api::ProvidersApi {
        match self {
            ApiClient::Real(real) => &real.providers_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.providers_api,
        }
    }
    pub fn push_api(&self) -> &dyn push_api::PushApi {
        match self {
            ApiClient::Real(real) => &real.push_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.push_api,
        }
    }
    pub fn reports_api(&self) -> &dyn reports_api::ReportsApi {
        match self {
            ApiClient::Real(real) => &real.reports_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.reports_api,
        }
    }
    pub fn request_sm_access_api(&self) -> &dyn request_sm_access_api::RequestSmAccessApi {
        match self {
            ApiClient::Real(real) => &real.request_sm_access_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.request_sm_access_api,
        }
    }
    pub fn secret_versions_api(&self) -> &dyn secret_versions_api::SecretVersionsApi {
        match self {
            ApiClient::Real(real) => &real.secret_versions_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.secret_versions_api,
        }
    }
    pub fn secrets_api(&self) -> &dyn secrets_api::SecretsApi {
        match self {
            ApiClient::Real(real) => &real.secrets_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.secrets_api,
        }
    }
    pub fn secrets_manager_events_api(
        &self,
    ) -> &dyn secrets_manager_events_api::SecretsManagerEventsApi {
        match self {
            ApiClient::Real(real) => &real.secrets_manager_events_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.secrets_manager_events_api,
        }
    }
    pub fn secrets_manager_porting_api(
        &self,
    ) -> &dyn secrets_manager_porting_api::SecretsManagerPortingApi {
        match self {
            ApiClient::Real(real) => &real.secrets_manager_porting_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.secrets_manager_porting_api,
        }
    }
    pub fn security_task_api(&self) -> &dyn security_task_api::SecurityTaskApi {
        match self {
            ApiClient::Real(real) => &real.security_task_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.security_task_api,
        }
    }
    pub fn self_hosted_account_billing_v_next_api(
        &self,
    ) -> &dyn self_hosted_account_billing_v_next_api::SelfHostedAccountBillingVNextApi {
        match self {
            ApiClient::Real(real) => &real.self_hosted_account_billing_v_next_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.self_hosted_account_billing_v_next_api,
        }
    }
    pub fn self_hosted_organization_billing_v_next_api(
        &self,
    ) -> &dyn self_hosted_organization_billing_v_next_api::SelfHostedOrganizationBillingVNextApi
    {
        match self {
            ApiClient::Real(real) => &real.self_hosted_organization_billing_v_next_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.self_hosted_organization_billing_v_next_api,
        }
    }
    pub fn self_hosted_organization_licenses_api(
        &self,
    ) -> &dyn self_hosted_organization_licenses_api::SelfHostedOrganizationLicensesApi {
        match self {
            ApiClient::Real(real) => &real.self_hosted_organization_licenses_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.self_hosted_organization_licenses_api,
        }
    }
    pub fn self_hosted_organization_sponsorships_api(
        &self,
    ) -> &dyn self_hosted_organization_sponsorships_api::SelfHostedOrganizationSponsorshipsApi {
        match self {
            ApiClient::Real(real) => &real.self_hosted_organization_sponsorships_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.self_hosted_organization_sponsorships_api,
        }
    }
    pub fn sends_api(&self) -> &dyn sends_api::SendsApi {
        match self {
            ApiClient::Real(real) => &real.sends_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.sends_api,
        }
    }
    pub fn service_accounts_api(&self) -> &dyn service_accounts_api::ServiceAccountsApi {
        match self {
            ApiClient::Real(real) => &real.service_accounts_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.service_accounts_api,
        }
    }
    pub fn settings_api(&self) -> &dyn settings_api::SettingsApi {
        match self {
            ApiClient::Real(real) => &real.settings_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.settings_api,
        }
    }
    pub fn slack_integration_api(&self) -> &dyn slack_integration_api::SlackIntegrationApi {
        match self {
            ApiClient::Real(real) => &real.slack_integration_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.slack_integration_api,
        }
    }
    pub fn sso_cookie_vendor_api(&self) -> &dyn sso_cookie_vendor_api::SsoCookieVendorApi {
        match self {
            ApiClient::Real(real) => &real.sso_cookie_vendor_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.sso_cookie_vendor_api,
        }
    }
    pub fn stripe_api(&self) -> &dyn stripe_api::StripeApi {
        match self {
            ApiClient::Real(real) => &real.stripe_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.stripe_api,
        }
    }
    pub fn sync_api(&self) -> &dyn sync_api::SyncApi {
        match self {
            ApiClient::Real(real) => &real.sync_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.sync_api,
        }
    }
    pub fn teams_integration_api(&self) -> &dyn teams_integration_api::TeamsIntegrationApi {
        match self {
            ApiClient::Real(real) => &real.teams_integration_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.teams_integration_api,
        }
    }
    pub fn trash_api(&self) -> &dyn trash_api::TrashApi {
        match self {
            ApiClient::Real(real) => &real.trash_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.trash_api,
        }
    }
    pub fn two_factor_api(&self) -> &dyn two_factor_api::TwoFactorApi {
        match self {
            ApiClient::Real(real) => &real.two_factor_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.two_factor_api,
        }
    }
    pub fn users_api(&self) -> &dyn users_api::UsersApi {
        match self {
            ApiClient::Real(real) => &real.users_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.users_api,
        }
    }
    pub fn web_authn_api(&self) -> &dyn web_authn_api::WebAuthnApi {
        match self {
            ApiClient::Real(real) => &real.web_authn_api,
            #[cfg(feature = "mockall")]
            ApiClient::Mock(mock) => &mock.web_authn_api,
        }
    }
}
