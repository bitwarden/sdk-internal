# Bitwarden PAM

Commercial crate implementing Privileged Access Management (PAM) functionality against the Bitwarden
server.

PAM lets organizations put privileged Bitwarden collections behind explicit, auditable access
requirements. Rather than a member holding standing access to a sensitive credential, access is
gated by an _access rule_ and granted for a bounded period (a _lease_).

## Access rules

An access rule governs privileged access to a set of collections. Each rule bundles together:

- **Conditions** that must be satisfied before access is granted - for example requiring human
  approval, or restricting access to an allow-list of CIDR ranges.
- **Lease parameters** controlling access once granted: a default and maximum lease duration,
  whether a lease may be extended (and for how long), and whether a cipher may have at most one
  active lease at a time.
- The **collections** the rule governs.

The [`AccessRulesClient`](crate::AccessRulesClient), reached via the
[`PamClient`](crate::PamClient), provides CRUD operations over these rules:

```rust,ignore
use bitwarden_pam::{AccessCondition, AccessRuleAddEditRequest, PamClientExt};

// `client` is a bitwarden_core::Client that has been authenticated.
let access_rules = client.pam().access_rules();

let created = access_rules
    .create(
        organization_id,
        AccessRuleAddEditRequest {
            name: "Production database".to_string(),
            description: Some("Requires approval and an internal IP".to_string()),
            enabled: true,
            conditions: vec![
                AccessCondition::HumanApproval,
                AccessCondition::IpAllowlist {
                    cidrs: vec!["10.0.0.0/8".to_string()],
                },
            ],
            single_active_lease: true,
            default_lease_duration_seconds: Some(3600),
            max_lease_duration_seconds: Some(28_800),
            allows_extensions: true,
            max_extension_duration_seconds: Some(3600),
            collections: vec![collection_id],
        },
    )
    .await?;

let all_rules = access_rules.list(organization_id).await?;
```

Requests are validated locally before being sent, so malformed input fails fast with a typed
[`AccessRuleValidationError`](crate::AccessRuleValidationError) instead of a server round trip.
