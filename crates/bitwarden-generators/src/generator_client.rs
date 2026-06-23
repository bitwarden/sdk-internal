use bitwarden_core::Client;
use bitwarden_managed_settings::{ApplyManagedOverride, ManagedSettingsClientExt};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    PassphraseError, PassphraseGeneratorRequest, PasswordError, PasswordGeneratorRequest,
    PasswordRulesError, UsernameError, UsernameGeneratorRequest, passphrase::passphrase,
    password::password, passwordrules::parse_password_rules, username::username,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct GeneratorClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl GeneratorClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Generates a random password.
    ///
    /// The character sets and password length can be customized using the `input` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitwarden_core::Client;
    /// use bitwarden_generators::{GeneratorClientsExt, PassphraseError, PasswordGeneratorRequest};
    ///
    /// async fn test() -> Result<(), PassphraseError> {
    ///     let input = PasswordGeneratorRequest {
    ///         lowercase: true,
    ///         uppercase: true,
    ///         numbers: true,
    ///         length: 20,
    ///         ..Default::default()
    ///     };
    ///     let password = Client::new(None).generator().password(input).unwrap();
    ///     println!("{}", password);
    ///     Ok(())
    /// }
    /// ```
    pub fn password(&self, input: PasswordGeneratorRequest) -> Result<String, PasswordError> {
        // Apply IT-administrator forced settings (managed-settings precedence:
        // managed > org-policy > user-set > sdk-default) before generation.
        let input = match self.client.managed_settings().current_profile() {
            Some(profile) => input.apply_managed_override(&profile),
            None => input,
        };
        password(input)
    }

    /// Parses an HTML `passwordrules` attribute string into a [`PasswordGeneratorRequest`].
    ///
    /// The returned request can be passed to [`GeneratorClient::password`] to produce a
    /// password that satisfies the website's declared constraints.
    pub fn password_rules(
        &self,
        rules: String,
    ) -> Result<PasswordGeneratorRequest, PasswordRulesError> {
        parse_password_rules(&rules)
    }

    /// Generates a random passphrase.
    /// A passphrase is a combination of random words separated by a character.
    /// An example of passphrase is `correct horse battery staple`.
    ///
    /// The number of words and their case, the word separator, and the inclusion of
    /// a number in the passphrase can be customized using the `input` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitwarden_core::Client;
    /// use bitwarden_generators::{GeneratorClientsExt, PassphraseError, PassphraseGeneratorRequest};
    ///
    /// async fn test() -> Result<(), PassphraseError> {
    ///     let input = PassphraseGeneratorRequest {
    ///         num_words: 4,
    ///         ..Default::default()
    ///     };
    ///     let passphrase = Client::new(None).generator().passphrase(input).unwrap();
    ///     println!("{}", passphrase);
    ///     Ok(())
    /// }
    /// ```
    pub fn passphrase(&self, input: PassphraseGeneratorRequest) -> Result<String, PassphraseError> {
        let input = match self.client.managed_settings().current_profile() {
            Some(profile) => input.apply_managed_override(&profile),
            None => input,
        };
        passphrase(input)
    }
}

impl GeneratorClient {
    /// Generates a random username.
    /// There are different username generation strategies, which can be customized using the
    /// `input` parameter.
    ///
    /// Note that most generation strategies will be executed on the client side, but `Forwarded`
    /// will use third-party services, which may require a specific setup or API key.
    ///
    /// ```
    /// use bitwarden_core::Client;
    /// use bitwarden_generators::{GeneratorClientsExt, UsernameError, UsernameGeneratorRequest};
    ///
    /// async fn test() -> Result<(), UsernameError> {
    ///     let input = UsernameGeneratorRequest::Word {
    ///         capitalize: true,
    ///         include_number: true,
    ///     };
    ///     let username = Client::new(None).generator().username(input).await.unwrap();
    ///     println!("{}", username);
    ///     Ok(())
    /// }
    /// ```
    pub async fn username(&self, input: UsernameGeneratorRequest) -> Result<String, UsernameError> {
        username(input, self.client.internal.get_http_client()).await
    }
}

#[allow(missing_docs)]
pub trait GeneratorClientsExt {
    fn generator(&self) -> GeneratorClient;
}

impl GeneratorClientsExt for Client {
    fn generator(&self) -> GeneratorClient {
        GeneratorClient::new(self.clone())
    }
}

#[cfg(test)]
mod managed_override_tests {
    //! End-to-end tests proving the managed-settings override is applied by
    //! [`GeneratorClient`] before generation. These tests touch the
    //! process-global managed-settings store, so they take a shared mutex
    //! to serialize.

    use std::sync::Mutex;

    use bitwarden_core::Client;
    use bitwarden_managed_settings::{
        ManagedSettingsClientExt, ManagementProfile, ManagementSource,
    };

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_and_reset() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Clear any leftover profile from another test.
        Client::new(None).managed_settings().update_profile(None);
        g
    }

    #[test]
    fn no_profile_request_unchanged_password() {
        let _g = lock_and_reset();
        let client = Client::new(None);
        let req = PasswordGeneratorRequest {
            length: 12,
            ..Default::default()
        };
        let result = client.generator().password(req).unwrap();
        // With no admin profile, the request's length should be honored.
        assert_eq!(result.chars().count(), 12);
    }

    #[test]
    fn managed_length_overrides_request() {
        let _g = lock_and_reset();
        let client = Client::new(None);
        let mut p = ManagementProfile::empty(ManagementSource::PolicyLinux);
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        client.managed_settings().update_profile(Some(p));

        let req = PasswordGeneratorRequest {
            length: 12,
            ..Default::default()
        };
        let result = client.generator().password(req).unwrap();
        assert_eq!(
            result.chars().count(),
            20,
            "admin-forced length 20 must override request length 12"
        );
    }

    #[test]
    fn managed_wins_over_policy_derived_length() {
        // Simulates the precedence rule: managed > org-policy > user-set.
        // PasswordGeneratorPolicy from bitwarden-policies is filter-only;
        // by the time the request reaches the generator, any policy-derived
        // minimum has already been baked into the request fields. So we
        // simulate that here as `policy_applied_length = 14`. The admin
        // override (20) must then take precedence.
        let _g = lock_and_reset();
        let client = Client::new(None);

        let policy_applied_length: u8 = 14;
        let request = PasswordGeneratorRequest {
            length: policy_applied_length,
            ..Default::default()
        };

        // No managed profile yet — confirm the policy-derived length is honored.
        let pwd_policy_only = client.generator().password(PasswordGeneratorRequest {
            length: policy_applied_length,
            ..Default::default()
        }).unwrap();
        assert_eq!(pwd_policy_only.chars().count(), policy_applied_length as usize);

        // Now push an admin profile that forces length=20.
        let mut p = ManagementProfile::empty(ManagementSource::ExtensionManagedStorage);
        p.settings
            .insert("generator.password.length".to_owned(), "20".to_owned());
        client.managed_settings().update_profile(Some(p));

        let pwd_managed = client.generator().password(request).unwrap();
        assert_eq!(
            pwd_managed.chars().count(),
            20,
            "managed > policy: admin-forced length 20 must beat policy-derived 14"
        );
    }

    #[test]
    fn passphrase_managed_num_words_overrides_request() {
        let _g = lock_and_reset();
        let client = Client::new(None);
        let mut p = ManagementProfile::empty(ManagementSource::MdmApple);
        p.settings
            .insert("generator.passphrase.numWords".to_owned(), "7".to_owned());
        p.settings.insert(
            "generator.passphrase.wordSeparator".to_owned(),
            "\"-\"".to_owned(),
        );
        client.managed_settings().update_profile(Some(p));

        let req = PassphraseGeneratorRequest {
            num_words: 3,
            ..Default::default()
        };
        let phrase = client.generator().passphrase(req).unwrap();
        // 7 words separated by '-' → 6 separators in the rendered phrase.
        assert_eq!(phrase.matches('-').count(), 6);
    }
}
