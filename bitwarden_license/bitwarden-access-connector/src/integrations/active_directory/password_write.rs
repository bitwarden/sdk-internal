use async_trait::async_trait;
use ldap3::{LdapError, result::LdapResult};

use super::classify::{Phase, RC_INVALID_CREDENTIALS, classify_ldap_error};
use crate::{
    error::Retry,
    integrations::{IntegrationError, TargetEffect},
};

/// The directory operations the write needs, so [`apply_password_write`] can be tested without a
/// domain controller.
#[async_trait]
pub(super) trait PasswordWriter: Send {
    /// A directory rejection comes back in the [`LdapResult`]; `Err` means there was no answer.
    async fn replace_password(
        &mut self,
        account_dn: &str,
        encoded: &[u8],
    ) -> Result<LdapResult, LdapError>;

    async fn bind_as_account(&mut self, account_dn: &str, password: &str) -> Result<(), LdapError>;
}

/// A rejected write doesn't prove the old password still stands: a retry re-sends the same
/// password, which password history refuses if an earlier, unobserved write had landed. So a
/// permanent rejection is settled by binding as the account with the new password. Transient ones
/// aren't probed, since every failed probe counts towards locking out the account.
pub(super) async fn apply_password_write(
    writer: &mut impl PasswordWriter,
    account_dn: &str,
    new_password: &str,
) -> Result<(), IntegrationError> {
    let answer = writer
        .replace_password(account_dn, &encode_unicode_pwd(new_password))
        .await
        .map_err(|e| classify_ldap_error(&e, Phase::Write))?;
    let Err(rejection) = answer.success() else {
        return Ok(());
    };

    let mut err = classify_ldap_error(&rejection, Phase::Write);
    err.effect = if err.retry == Retry::Permanent {
        effect_from_probe(&writer.bind_as_account(account_dn, new_password).await)
    } else {
        TargetEffect::Unknown
    };
    Err(err)
}

/// Only `invalidCredentials` proves the write didn't land; any other answer says nothing. A locked
/// out or disabled account also answers `invalidCredentials`, so it reads as not applied.
fn effect_from_probe(probe: &Result<(), LdapError>) -> TargetEffect {
    match probe {
        Ok(()) => TargetEffect::Applied,
        Err(LdapError::LdapResult { result }) if result.rc == RC_INVALID_CREDENTIALS => {
            TargetEffect::NotApplied
        }
        Err(_) => TargetEffect::Unknown,
    }
}

/// The quoted password as little-endian UTF-16 without a byte-order mark, which is the only shape
/// Active Directory accepts.
fn encode_unicode_pwd(password: &str) -> Vec<u8> {
    const QUOTE: u16 = b'"' as u16;

    let mut buf = Vec::with_capacity(password.len() * 2 + 4);
    for unit in std::iter::once(QUOTE)
        .chain(password.encode_utf16())
        .chain(std::iter::once(QUOTE))
    {
        buf.extend_from_slice(&unit.to_le_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use bitwarden_pam::RotationFailureCode;

    use super::*;
    use crate::integrations::active_directory::test_support::{SECRET, ldap_result};

    const ACCOUNT_DN: &str = "CN=svc-app,OU=Managed,DC=corp,DC=example";

    /// Answers from a script and records each call, so a test can also assert whether the probe
    /// was issued.
    struct FakeDirectory {
        write: Option<Result<LdapResult, LdapError>>,
        probe: Option<Result<(), LdapError>>,
        written: Vec<(String, Vec<u8>)>,
        binds: Vec<(String, String)>,
    }

    impl FakeDirectory {
        /// Any probe fails the test unless [`Self::probed_with`] scripts one.
        fn answering(write: Result<LdapResult, LdapError>) -> Self {
            Self {
                write: Some(write),
                probe: None,
                written: Vec::new(),
                binds: Vec::new(),
            }
        }

        fn probed_with(mut self, probe: Result<(), LdapError>) -> Self {
            self.probe = Some(probe);
            self
        }
    }

    #[async_trait]
    impl PasswordWriter for FakeDirectory {
        async fn replace_password(
            &mut self,
            account_dn: &str,
            encoded: &[u8],
        ) -> Result<LdapResult, LdapError> {
            self.written
                .push((account_dn.to_string(), encoded.to_vec()));
            self.write
                .take()
                .expect("the write must be asked for exactly once")
        }

        async fn bind_as_account(
            &mut self,
            account_dn: &str,
            password: &str,
        ) -> Result<(), LdapError> {
            self.binds
                .push((account_dn.to_string(), password.to_string()));
            self.probe
                .take()
                .expect("the probe was issued without a scripted answer")
        }
    }

    #[test]
    fn unicode_pwd_is_quoted_utf16le() {
        let encoded = encode_unicode_pwd("Ab1!");
        assert_eq!(
            encoded.as_slice(),
            &[
                0x22, 0x00, // "
                b'A', 0x00, b'b', 0x00, b'1', 0x00, b'!', 0x00, //
                0x22, 0x00, // "
            ]
        );
    }

    #[test]
    fn unicode_pwd_empty_password_is_two_quotes() {
        let encoded = encode_unicode_pwd("");
        assert_eq!(encoded.as_slice(), &[0x22, 0x00, 0x22, 0x00]);
    }

    #[test]
    fn unicode_pwd_encodes_non_bmp_as_surrogate_pair() {
        // U+1F510 CLOSED LOCK WITH KEY → surrogate pair D83D DD10, little-endian.
        let encoded = encode_unicode_pwd("\u{1F510}");
        assert_eq!(
            encoded.as_slice(),
            &[0x22, 0x00, 0x3D, 0xD8, 0x10, 0xDD, 0x22, 0x00]
        );
    }

    #[test]
    fn unicode_pwd_has_no_byte_order_mark() {
        let encoded = encode_unicode_pwd("pw");
        assert_ne!(&encoded[0..2], &[0xFF, 0xFE]);
        assert_ne!(&encoded[0..2], &[0xFE, 0xFF]);
    }

    #[test]
    fn unicode_pwd_never_contains_the_plain_utf8_password() {
        let encoded = encode_unicode_pwd(SECRET);
        assert!(
            encoded
                .windows(SECRET.len())
                .all(|w| w != SECRET.as_bytes()),
            "password must not appear as plain UTF-8"
        );
    }

    #[test]
    fn a_rebind_that_succeeds_proves_the_rejected_write_had_landed() {
        assert_eq!(effect_from_probe(&Ok(())), TargetEffect::Applied);
    }

    #[test]
    fn a_rebind_answered_with_invalid_credentials_proves_the_write_did_not_land() {
        let probe = Err(LdapError::LdapResult {
            result: ldap_result(49, "invalid credentials"),
        });
        assert_eq!(effect_from_probe(&probe), TargetEffect::NotApplied);
    }

    #[test]
    fn a_rebind_the_directory_declined_to_answer_leaves_the_effect_unknown() {
        for rc in [1, 11, 51, 52, 53] {
            let probe = Err(LdapError::LdapResult {
                result: ldap_result(rc, ""),
            });
            assert_eq!(
                effect_from_probe(&probe),
                TargetEffect::Unknown,
                "rc {rc} says nothing about whether the new password is live"
            );
        }
    }

    #[test]
    fn a_rebind_that_cannot_reach_the_directory_leaves_the_effect_unknown() {
        let probe = Err(LdapError::Io {
            source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        });
        assert_eq!(effect_from_probe(&probe), TargetEffect::Unknown);
    }

    #[tokio::test]
    async fn an_accepted_write_succeeds_and_costs_no_bind() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(0, "")));
        apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect("a write the directory accepted must succeed");
        assert!(
            directory.binds.is_empty(),
            "an accepted write settles itself; probing it would spend a bind for nothing"
        );
    }

    #[tokio::test]
    async fn the_write_sends_the_encoded_password_to_the_located_account() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(0, "")));
        apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect("a write the directory accepted must succeed");

        let (dn, value) = directory.written.first().expect("the write must be sent");
        assert_eq!(dn, ACCOUNT_DN, "the write must target the located account");
        assert_eq!(
            value.as_slice(),
            encode_unicode_pwd(SECRET).as_slice(),
            "the value must be the unicodePwd encoding, not the raw password"
        );
        assert!(
            value.windows(SECRET.len()).all(|w| w != SECRET.as_bytes()),
            "the plain password must not be what goes on the wire"
        );
    }

    #[tokio::test]
    async fn a_rejected_write_is_probed_as_the_rotated_account_with_the_new_password() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(19, "constraint violation")))
            .probed_with(Ok(()));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        assert_eq!(
            directory.binds,
            vec![(ACCOUNT_DN.to_string(), SECRET.to_string())],
            "the probe must rebind once, as the rotated account, with the new password"
        );
        assert_eq!(
            err.effect,
            TargetEffect::Applied,
            "a probe the directory accepted proves the rejected write had landed"
        );
        assert_eq!(err.retry, Retry::Permanent);
        assert_eq!(err.code, RotationFailureCode::TargetRejected);
    }

    #[tokio::test]
    async fn a_rejected_write_whose_probe_is_refused_is_reported_not_applied() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(19, ""))).probed_with(Err(
            LdapError::LdapResult {
                result: ldap_result(RC_INVALID_CREDENTIALS, ""),
            },
        ));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        assert_eq!(directory.binds.len(), 1);
        assert_eq!(err.effect, TargetEffect::NotApplied);
    }

    #[tokio::test]
    async fn a_rejected_write_whose_probe_cannot_reach_the_directory_is_reported_unknown() {
        let mut directory =
            FakeDirectory::answering(Ok(ldap_result(19, ""))).probed_with(Err(LdapError::Io {
                source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            }));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        assert_eq!(directory.binds.len(), 1);
        assert_eq!(err.effect, TargetEffect::Unknown);
    }

    #[tokio::test]
    async fn a_transiently_rejected_write_is_never_probed() {
        // adminLimitExceeded, busy, unavailable.
        for rc in [11, 51, 52] {
            let mut directory = FakeDirectory::answering(Ok(ldap_result(rc, "")));

            let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
                .await
                .expect_err("a rejected write must not be reported as success");

            assert!(
                directory.binds.is_empty(),
                "rc {rc} is retried, so probing it would spend a failed bind against \
                 the managed account on every attempt"
            );
            assert_eq!(err.retry, Retry::Transient, "rc {rc}");
            assert_eq!(err.effect, TargetEffect::Unknown, "rc {rc}");
        }
    }

    #[tokio::test]
    async fn a_write_that_got_no_answer_is_never_probed_and_stays_unknown() {
        let mut directory = FakeDirectory::answering(Err(LdapError::Io {
            source: std::io::Error::from(std::io::ErrorKind::ConnectionReset),
        }));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a write that got no answer must not be reported as success");

        assert!(
            directory.binds.is_empty(),
            "the connection carrying the probe is the one that just failed"
        );
        assert_eq!(err.effect, TargetEffect::Unknown);
        assert_eq!(err.retry, Retry::Transient);
    }

    #[tokio::test]
    async fn a_rejected_write_reports_neither_the_password_nor_directory_text() {
        let mut directory = FakeDirectory::answering(Ok(ldap_result(
            53,
            &format!("will not perform for {SECRET}"),
        )))
        .probed_with(Ok(()));

        let err = apply_password_write(&mut directory, ACCOUNT_DN, SECRET)
            .await
            .expect_err("a rejected write must not be reported as success");

        let rendered = err.to_string();
        assert!(!rendered.contains(SECRET), "password leaked: {rendered}");
        assert!(
            !rendered.contains("OU=Service Accounts"),
            "matched DN leaked: {rendered}"
        );
        assert_eq!(err.detail.as_str(), "LDAP result code 53");
    }
}
