//! `get item`, `get folder`, and the `get username` / `password` / `uri` / `notes` field getters.

use bitwarden_vault::{CipherListView, CipherListViewType, CipherView, CopyableCipherFields};

use crate::{
    client_state::{BwCommand, Unlocked},
    render::{CommandOutput, CommandResult},
    vault::{
        GetFolderArgs, GetItemArgs, GetNotesArgs, GetPasswordArgs, GetUriArgs, GetUsernameArgs,
        resolve_cipher, resolve_folder,
    },
};

impl BwCommand for GetItemArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        // TODO(PM-35687): surface cipher types hidden by the Restricted Item Types policy as
        // NotFound (TS parity). Blocked: the policy client has no state-backed API yet, and
        // `RestrictedItemTypesPolicy` carries no data describing which types are restricted.
        let cipher = resolve_cipher(&user, &self.id, None).await?;
        Ok(CommandOutput::Object(Box::new(cipher)))
    }
}

impl BwCommand for GetFolderArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        let folder = resolve_folder(&user, &self.id).await?;
        Ok(CommandOutput::Object(Box::new(folder)))
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(str::to_owned)
}

/// Resolve the cipher and extract a field, treating a missing/empty field as not found.
async fn get_field(
    user: &bitwarden_pm::PasswordManagerClient,
    id: &str,
    predicate: crate::vault::CipherPredicate<'_>,
    extract: impl Fn(&CipherView) -> Option<String>,
) -> CommandResult {
    let cipher = resolve_cipher(user, id, Some(predicate)).await?;
    let value = extract(&cipher).ok_or(crate::vault::ResolveError::NotFound)?;
    Ok(CommandOutput::Plain(value))
}

fn login_username(c: &CipherView) -> Option<String> {
    non_empty(c.login.as_ref()?.username.as_deref())
}

fn login_password(c: &CipherView) -> Option<String> {
    non_empty(c.login.as_ref()?.password.as_deref())
}

/// Only the first non-empty URI is returned (TS parity).
fn login_first_uri(c: &CipherView) -> Option<String> {
    c.login
        .as_ref()?
        .uris
        .iter()
        .flatten()
        .find_map(|u| non_empty(u.uri.as_deref()))
}

fn has_username(c: &CipherListView) -> bool {
    matches!(&c.r#type, CipherListViewType::Login(l) if l.username.as_deref().is_some_and(|u| !u.is_empty()))
}

// The list view does not carry the password, so rely on the `copyable_fields` hint.
fn has_password(c: &CipherListView) -> bool {
    matches!(c.r#type, CipherListViewType::Login(_))
        && c.copyable_fields
            .contains(&CopyableCipherFields::LoginPassword)
}

fn has_uri(c: &CipherListView) -> bool {
    matches!(&c.r#type, CipherListViewType::Login(l)
        if l.uris.iter().flatten().any(|u| u.uri.as_deref().is_some_and(|u| !u.is_empty())))
}

// Notes are only exposed on the list view for secure notes (via `copyable_fields`); for other
// cipher types they can't be seen here, so those pass and an empty value is reported as not found
// after resolution.
fn may_have_notes(c: &CipherListView) -> bool {
    !matches!(c.r#type, CipherListViewType::SecureNote)
        || c.copyable_fields
            .contains(&CopyableCipherFields::SecureNotes)
}

impl BwCommand for GetUsernameArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        get_field(&user, &self.id, &has_username, login_username).await
    }
}

impl BwCommand for GetPasswordArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        get_field(&user, &self.id, &has_password, login_password).await
    }
}

impl BwCommand for GetUriArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        get_field(&user, &self.id, &has_uri, login_first_uri).await
    }
}

impl BwCommand for GetNotesArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        get_field(&user, &self.id, &may_have_notes, |c| {
            non_empty(c.notes.as_deref())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const ID: &str = "11111111-1111-4111-8111-111111111111";

    fn list_view(r#type: Value, copyable: &[&str]) -> CipherListView {
        serde_json::from_value(json!({
            "id": ID,
            "collectionIds": [],
            "name": "Item",
            "subtitle": "",
            "type": r#type,
            "favorite": false,
            "reprompt": 0,
            "organizationUseTotp": false,
            "edit": true,
            "viewPassword": true,
            "attachments": 0,
            "hasOldAttachments": false,
            "creationDate": "2025-01-01T00:00:00Z",
            "revisionDate": "2025-01-01T00:00:00Z",
            "copyableFields": copyable,
        }))
        .unwrap()
    }

    fn login_list(username: Option<&str>, uris: &[&str], copyable: &[&str]) -> CipherListView {
        list_view(
            json!({ "login": {
                "hasFido2": false,
                "username": username,
                "uris": uris.iter().map(|u| json!({ "uri": u })).collect::<Vec<_>>(),
            }}),
            copyable,
        )
    }

    fn view(login: Option<Value>, notes: Option<&str>) -> CipherView {
        serde_json::from_value(json!({
            "id": ID,
            "collectionIds": [],
            "name": "Item",
            "notes": notes,
            "type": 1,
            "login": login,
            "favorite": false,
            "reprompt": 0,
            "organizationUseTotp": false,
            "edit": true,
            "viewPassword": true,
            "creationDate": "2025-01-01T00:00:00Z",
            "revisionDate": "2025-01-01T00:00:00Z",
        }))
        .unwrap()
    }

    #[test]
    fn username_predicate_requires_non_empty_login_username() {
        assert!(has_username(&login_list(Some("jane"), &[], &[])));
        assert!(!has_username(&login_list(Some(""), &[], &[])));
        assert!(!has_username(&login_list(None, &[], &[])));
        assert!(!has_username(&list_view(json!("secureNote"), &[])));
    }

    #[test]
    fn password_predicate_uses_copyable_hint_and_excludes_non_login() {
        assert!(has_password(&login_list(None, &[], &["LoginPassword"])));
        assert!(!has_password(&login_list(None, &[], &[])));
        assert!(!has_password(&list_view(
            json!("secureNote"),
            &["LoginPassword"]
        )));
    }

    #[test]
    fn uri_predicate_requires_a_non_empty_uri() {
        assert!(has_uri(&login_list(None, &["", "https://a.example"], &[])));
        assert!(!has_uri(&login_list(None, &["", ""], &[])));
        assert!(!has_uri(&login_list(None, &[], &[])));
        assert!(!has_uri(&list_view(json!("secureNote"), &[])));
    }

    #[test]
    fn notes_predicate_excludes_only_secure_notes_without_notes() {
        assert!(!may_have_notes(&list_view(json!("secureNote"), &[])));
        assert!(may_have_notes(&list_view(
            json!("secureNote"),
            &["SecureNotes"]
        )));
        assert!(may_have_notes(&login_list(None, &[], &[])));
    }

    #[test]
    fn extractors_return_non_empty_login_fields() {
        let c = view(
            Some(json!({ "username": "jane", "password": "hunter2" })),
            None,
        );
        assert_eq!(login_username(&c).as_deref(), Some("jane"));
        assert_eq!(login_password(&c).as_deref(), Some("hunter2"));
    }

    #[test]
    fn extractors_treat_empty_or_missing_as_none() {
        let c = view(Some(json!({ "username": "", "password": "" })), None);
        assert_eq!(login_username(&c), None);
        assert_eq!(login_password(&c), None);
        assert_eq!(login_first_uri(&c), None);

        let no_login = view(None, None);
        assert_eq!(login_username(&no_login), None);
        assert_eq!(login_first_uri(&no_login), None);
    }

    #[test]
    fn first_uri_skips_empty_and_returns_only_the_first() {
        let c = view(
            Some(
                json!({ "uris": [{ "uri": "" }, { "uri": "https://a.example" }, { "uri": "https://b.example" }] }),
            ),
            None,
        );
        assert_eq!(login_first_uri(&c).as_deref(), Some("https://a.example"));
    }

    mod commands {
        use super::*;
        use crate::{
            client_state::{BwCommandExt, ClientContext},
            command::GetCommands,
            render::CommandOutput,
            vault::test_vault::TestVault,
        };

        const A: &str = "11111111-1111-4111-8111-111111111111";
        const B: &str = "22222222-2222-4222-8222-222222222222";
        const MISSING: &str = "99999999-9999-4999-8999-999999999999";

        fn plain(result: crate::render::CommandResult) -> String {
            match result.expect("command should succeed") {
                CommandOutput::Plain(s) => s,
                CommandOutput::Object(_) => panic!("expected plain output"),
            }
        }

        fn object(result: crate::render::CommandResult) -> Value {
            match result.expect("command should succeed") {
                CommandOutput::Object(o) => serde_json::to_value(&*o).unwrap(),
                CommandOutput::Plain(_) => panic!("expected object output"),
            }
        }

        fn not_found(result: crate::render::CommandResult) -> bool {
            result.is_err_and(|e| e.to_string() == "Not found.")
        }

        async fn vault_with_login() -> TestVault {
            let v = TestVault::new().await;
            v.add_login(
                A,
                "Example",
                json!({
                    "username": "jane",
                    "password": "hunter2",
                    "uris": [{ "uri": "" }, { "uri": "https://example.com" }],
                }),
            )
            .await;
            v
        }

        #[tokio::test]
        async fn get_item_by_id_and_by_search_term() {
            let v = vault_with_login().await;
            let by_id = object(GetItemArgs { id: A.into() }.run(v.unlocked()).await);
            assert_eq!(by_id["name"], "Example");
            let by_term = object(
                GetItemArgs {
                    id: "example".into(),
                }
                .run(v.unlocked())
                .await,
            );
            assert_eq!(by_term["id"], A);
        }

        #[tokio::test]
        async fn get_item_missing_is_not_found() {
            let v = vault_with_login().await;
            assert!(not_found(
                GetItemArgs { id: MISSING.into() }.run(v.unlocked()).await
            ));
            assert!(not_found(
                GetItemArgs { id: "zzz".into() }.run(v.unlocked()).await
            ));
        }

        #[tokio::test]
        async fn get_item_ambiguous_term_lists_ids() {
            let v = TestVault::new().await;
            v.add_login(A, "Work mail", json!({})).await;
            v.add_login(B, "Work vpn", json!({})).await;
            let err = GetItemArgs { id: "work".into() }
                .run(v.unlocked())
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(err.contains("More than one result"), "{err}");
            assert!(err.contains(A) && err.contains(B), "{err}");
        }

        #[tokio::test]
        async fn trashed_items_are_not_searchable_but_fetchable_by_id() {
            let v = TestVault::new().await;
            v.trash(A, "Old", json!({})).await;
            assert!(not_found(
                GetItemArgs { id: "old".into() }.run(v.unlocked()).await
            ));
            assert_eq!(
                object(GetItemArgs { id: A.into() }.run(v.unlocked()).await)["name"],
                "Old"
            );
        }

        #[tokio::test]
        async fn get_folder_by_id_and_name() {
            let v = TestVault::new().await;
            v.add_folder(A, "Personal").await;
            let by_id = object(GetFolderArgs { id: A.into() }.run(v.unlocked()).await);
            assert_eq!(by_id["name"], "Personal");
            let by_name = object(
                GetFolderArgs {
                    id: "person".into(),
                }
                .run(v.unlocked())
                .await,
            );
            assert_eq!(by_name["id"], A);
            assert!(not_found(
                GetFolderArgs { id: MISSING.into() }.run(v.unlocked()).await
            ));
            assert!(not_found(
                GetFolderArgs { id: "zzz".into() }.run(v.unlocked()).await
            ));
        }

        #[tokio::test]
        async fn login_field_getters_return_plain_values() {
            let v = vault_with_login().await;
            assert_eq!(
                plain(GetUsernameArgs { id: A.into() }.run(v.unlocked()).await),
                "jane"
            );
            assert_eq!(
                plain(GetPasswordArgs { id: A.into() }.run(v.unlocked()).await),
                "hunter2"
            );
            assert_eq!(
                plain(
                    GetUriArgs {
                        id: "example".into()
                    }
                    .run(v.unlocked())
                    .await
                ),
                "https://example.com"
            );
        }

        #[tokio::test]
        async fn missing_or_empty_fields_are_not_found() {
            let v = TestVault::new().await;
            v.add_login(A, "Empty", json!({ "username": "", "password": "" }))
                .await;
            assert!(not_found(
                GetUsernameArgs { id: A.into() }.run(v.unlocked()).await
            ));
            assert!(not_found(
                GetPasswordArgs { id: A.into() }.run(v.unlocked()).await
            ));
            assert!(not_found(
                GetUriArgs { id: A.into() }.run(v.unlocked()).await
            ));
            assert!(not_found(
                GetNotesArgs { id: A.into() }.run(v.unlocked()).await
            ));
        }

        #[tokio::test]
        async fn search_predicate_skips_items_lacking_the_field() {
            let v = TestVault::new().await;
            v.add_login(A, "Shared one", json!({ "username": "", "password": "x" }))
                .await;
            v.add_login(
                B,
                "Shared two",
                json!({ "username": "bob", "password": "y" }),
            )
            .await;
            // Only B has a username, so the ambiguous term resolves uniquely.
            assert_eq!(
                plain(
                    GetUsernameArgs {
                        id: "shared".into()
                    }
                    .run(v.unlocked())
                    .await
                ),
                "bob"
            );
        }

        #[tokio::test]
        async fn notes_getter_returns_notes() {
            let v = TestVault::new().await;
            v.add_cipher(A, "Note", json!({ "notes": "remember", "login": {} }))
                .await;
            assert_eq!(
                plain(GetNotesArgs { id: A.into() }.run(v.unlocked()).await),
                "remember"
            );
        }

        #[tokio::test]
        async fn get_commands_dispatch_to_each_subcommand() {
            let v = TestVault::new().await;
            v.add_cipher(A, "Example", json!({
                "notes": "n",
                "login": { "username": "jane", "password": "pw", "uris": [{ "uri": "https://a.example" }] },
            }))
            .await;
            v.add_folder(B, "Personal").await;

            let run = |c: GetCommands| c.run(v.context());
            assert_eq!(
                object(run(GetCommands::Item(GetItemArgs { id: A.into() })).await)["id"],
                A
            );
            assert_eq!(
                plain(run(GetCommands::Username(GetUsernameArgs { id: A.into() })).await),
                "jane"
            );
            assert_eq!(
                plain(run(GetCommands::Password(GetPasswordArgs { id: A.into() })).await),
                "pw"
            );
            assert_eq!(
                plain(run(GetCommands::Uri(GetUriArgs { id: A.into() })).await),
                "https://a.example"
            );
            assert_eq!(
                plain(run(GetCommands::Notes(GetNotesArgs { id: A.into() })).await),
                "n"
            );
            assert_eq!(
                object(run(GetCommands::Folder(GetFolderArgs { id: B.into() })).await)["name"],
                "Personal"
            );
            assert_eq!(
                object(
                    run(GetCommands::Template {
                        command: crate::vault::TemplateCommands::Folder
                    })
                    .await
                )["name"],
                "Folder name"
            );
        }

        #[tokio::test]
        async fn vaults_are_isolated_from_each_other() {
            let one = vault_with_login().await;
            let two = TestVault::new().await;
            assert!(not_found(
                GetItemArgs { id: A.into() }.run(two.unlocked()).await
            ));
            assert!(
                GetItemArgs { id: A.into() }
                    .run(one.unlocked())
                    .await
                    .is_ok()
            );
        }

        #[tokio::test]
        async fn dispatch_requires_an_unlocked_user() {
            let v = TestVault::new().await;
            let ctx = ClientContext {
                global: v.context().global,
                user: None,
            };
            assert!(GetItemArgs { id: A.into() }.dispatch(ctx).await.is_err());
        }
    }
}
