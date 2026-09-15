# Bitwarden Organization Users

Manages the members of an organization through the API. Exposes `OrganizationUsersClient`, which is
reached from the password manager client via `organization_users()`.

Shared organization types such as `OrganizationUserId` and the membership status and role enums live
in `bitwarden-organizations`.
