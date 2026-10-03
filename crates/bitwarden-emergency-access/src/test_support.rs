//! Test vectors and helpers shared by the emergency access operation tests.

use bitwarden_api_api::apis::{ApiClient, ApiClientMock};
use bitwarden_core::{Client, client::test_accounts::TestAccount};

use crate::EmergencyAccessId;

// Recorded with the grantor `test_bitwarden_com_account` and the grantee
// `test_bitwarden_com_account_v2`. Never regenerate these to make a test pass: a vector that
// stops decrypting is a backward-compatibility break.

/// Grantor user key encapsulated to the grantee's public key, as the server returns it.
pub(crate) const TEST_VECTOR_GRANTOR_KEY: &str = "4.bbiAjKYUjktIP1PggRJ+ha+O8M0LxWCNkv2bir5QHIYQnAwtx9X3Cta4j0JFnDS2Zy/UFAzRMCpdLR1DgupZ31lZvAhThC86hDvMMa0h84d7o41Rx9tCvqW1FcziuAA0UEr+Gfkc0+qX5yPFEn2eJ2U+ft9J7rSTTDeha1QIMhYnTf2sD2O0nSWSSPoFNLLg2WKoe9uXC5w+MemcK6x6ogG2T77fDr5trXnK7SoWamAWjhK65bYxYrSIpJOtdCR0O9ZIqiITg0lS0I6ACbiFBpHyo+wb+ZUCieUWrNaBjNHHES2XqEWSVVgz1XL2Q0Vh9XNwwPZLbIWZDxbz8FWqeQ==";
/// Grantor user key encapsulated to the grantor's own public key.
pub(crate) const TEST_VECTOR_WRONG_GRANTOR_KEY: &str = "4.PBhgsvKoOu8weZWhRAjPoSrucZneEh0Nc+R3xATSuJQk0GyS+xAagJX3Kh7EuPM2pU2OjGbGJeutDpNbp1EKWyYnPzbgXkMi8VU7dnbT8FmidRr/BcrNdcaNzyzJ06GPnL+wPH047iEhzP6DK7prjd3ufEtRp+x9ZCHPnN/vqzoWJD8AZfbC1c8jQFJSaTV/DfkKrF5rfTH3qoQYUNdfL5HOsbTHM8HTMsR18qtj4w638le1ejsjFFgAihcCdlLRsu6okGWCV6LZK3LyjfzXr/WliJUPV3/lySCHEyZoefK52v3TJ8Xy22Tqo+Y86IA/N/UA58c6tV/Iu1Gv3KQsPA==";

pub(crate) const TEST_EMERGENCY_ACCESS_ID: &str = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d";

pub(crate) fn test_id() -> EmergencyAccessId {
    TEST_EMERGENCY_ACCESS_ID.parse().unwrap()
}

/// Whether a mocked request targets the test emergency access.
pub(crate) fn is_test_id(id: &uuid::Uuid) -> bool {
    id.to_string() == TEST_EMERGENCY_ACCESS_ID
}

/// A transport failure, as the mocked API returns it.
pub(crate) fn api_error<T>() -> Result<T, bitwarden_api_api::apis::Error> {
    Err(bitwarden_api_api::ApiError::Io(std::io::Error::other(
        "server unreachable",
    )))
}

/// Creates a client for the given account whose API is set up by `mock`.
pub(crate) async fn test_client(
    account: TestAccount,
    mock: impl FnOnce(&mut ApiClientMock),
) -> Client {
    Client::init_test_account_with_api_client(account, ApiClient::new_mocked(mock)).await
}
