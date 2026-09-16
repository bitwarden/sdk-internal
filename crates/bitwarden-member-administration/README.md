# Bitwarden Member Administration

Operations for administering an organization's members, such as inviting staged members and
re-sending invitations. Exposes `OrganizationUsersClient`, reached from the password manager client
via `organization_users()`.

Shared organization types such as `OrganizationUserId` and the membership status and role enums live
in `bitwarden-organizations`.
