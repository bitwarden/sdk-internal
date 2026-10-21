# Bitwarden Member Administration

Operations for administering an organization's members, such as inviting staged members and
re-sending invitations. Exposes `OrganizationUsersManagementClient`, reached from the password
manager client via `organization_users_management()`.

Shared organization types such as `OrganizationUserId` and the membership status and role enums live
in `bitwarden-organizations`.
