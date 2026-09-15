# Bitwarden Policies

Contains policy-related data types and structures used across the SDK, as well as business logic
relating to policy enforcement.

## Introduction to policies

A Bitwarden enterprise policy is a setting (or collection of settings) that changes app behavior for
an organizations' members.

The policy domain is concerned with defining different policies and handling common enforcement
decisions.

"Policy enforcement" is the process of determining whether a policy should affect app behavior for a
specific user. For example:

- is this policy enabled?
- does the organization's plan support policies?
- is the user exempt due to their role or status in the organization?

Policies often relate to other feature domains: for example, the Password Generator Policy affects
how the password generator works. The policy domain cannot unilaterally affect other domains on its
own - feature teams are responsible for consuming policy APIs in order to drive the behavior of
their feature.

The goal of the policy domain is to handle common enforcement logic so that feature teams can
consume the _effective_ policy settings that they actually care about.

## Adding a new policy

1. Add your policy to `policy_type.rs`. This must match the corresponding `PolicyType` enum
   definition on the server. This identifies your policy over the wire.

2. Add your policy definition in a new module under `policies/`, one per policy, alongside its data
   struct (for policies that carry data). This is a strongly typed representation of your policy for
   rust consumers. It must implement the `Policy` trait, which defines enforcement behavior and any
   corresponding configuration data. Make sure to update the `PolicyType.resolve_policy` match arm
   to return this struct.

3. Add your policy to the `PolicyDataType` enum. This is a type-erased representation of your policy
   for FFI consumers. The enum should wrap your configuration data, if any. Make sure to update your
   `Policy.to_erased` implementation to return this enum value.

## Consuming a policy

WARNING: these interfaces are not yet stable and should not be used.

Policy enforcement decisions are represented by `EnforcedPolicy<P: Policy>`. Its relevant properties
are:

- `enforced`: whether the policy should be enforced against the user.
- `data`: the policy configuration data to be enforced, if any.

FFI interfaces return an `EnforcedPolicyErased` instead, which uses the `PolicyDataType` enum for
the combination of policy type + data (as generics are incompatible with the FFI). We recommend
using the native rust interfaces where possible to drive your feature's behavior at the service
level.

The interfaces are:

- `get_enforced` (`get_enforced_erased` for FFI): evaluate a specific `Policy` for a specific
  organization ID. Returns a single `EnforcedPolicy`.
- `get_all_enforced` (`get_all_enforced_erased` for FFI): evaluate the `Policy` type across all
  organizations. Returns a collection of `EnforcedPolicy`s, one for each organization.

Note that no interfaces return None/null: you will always recieve an enforcement decision, even if
the policy should not be enforced.
