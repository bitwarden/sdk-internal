# Bitwarden Member Administration

Operations for administering an organization's members, such as inviting staged members and
re-sending invitations. Exposes `OrganizationUsersManagementClient`, reached from the password
manager client via `organization_users_management()`.

Admins also keep the organization's account recovery keys current: a member who upgrades to a V2
user key leaves behind an account recovery key that no longer opens their vault, and only an admin
can replace it.

Shared organization types such as `OrganizationUserId` and the membership status and role enums live
in `bitwarden-organizations`.
