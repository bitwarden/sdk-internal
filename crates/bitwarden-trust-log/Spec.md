```
Bitwarden Cryptography Platform                                   B. Schoolmann
Internal Request for Comments: BW-TL-1                                Bitwarden
Category: Internal use                                              August 2026
Obsoletes: none
```

# The Bitwarden Trust Log

## Status of This Memo

This document is a **draft** internal specification. It is published for discussion and review
inside Bitwarden.

## Abstract

This document specifies the **trust log**: a tamper-resistant, append-only, signed log of
security-critical actions, maintained per actor (user, organization, provider, or the server itself)
and served by an untrusted server. Each log entry is a **link** split into a small signed **outer
link** and a **inner message**. The chain of outer links provides completeness — no action can be
inserted, removed, or reordered without detection.

To synchronize these trust logs and to ensure recency, a centralized trust log per-server logs the
latest version of all trust logs.

Together, this provides a cryptographically verifiable and tamper-resistant / tamper-evident system
for establishing keys and other data and policies across the platform.

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1. Requirements Language](#11-requirements-language)
  - [1.2. Notation](#12-notation)
  - [1.3. Terminology](#13-terminology)
  - [1.4. Goals](#14-goals)
- [2. Architecture Overview](#2-architecture-overview)
- [3. Data Structures](#3-data-structures)
  - [3.1. Outer Link](#31-outer-link)
  - [3.2. Inner Message](#32-inner-message)
  - [3.3. Signed Outer Link](#33-signed-outer-link)
  - [3.4. Genesis Link](#34-genesis-link)
- [4. Visibility](#4-visibility)
  - [4.1. Preventing Omission by the Server](#41-preventing-omission-by-the-server)
- [5. Message Types](#5-message-types)
  - [5.1. Bodies](#51-bodies)
  - [5.2. Tracking Organization-Side Changes](#52-tracking-organization-side-changes)
- [6. Log State](#6-log-state)
  - [6.1. Organization and Provider Log State](#61-organization-and-provider-log-state)
  - [6.2. User Log State](#62-user-log-state)
  - [6.3. Log Application Rules](#63-log-application-rules)
- [7. Scaling: Sparse Replay](#7-scaling-sparse-replay)
  - [7.1. Post-Quantum Signature Size Issues](#71-post-quantum-signature-size-issues)
    - [7.1.1. Sparse Replay - Example](#711-sparse-replay---example)
  - [7.2. Sparse Replay](#72-sparse-replay)
  - [7.3. Why Skipping Signatures Is Sound](#73-why-skipping-signatures-is-sound)
  - [7.4. Checkpoints and Incremental Replay](#74-checkpoints-and-incremental-replay)
- [8. Chain Validation](#8-chain-validation)
- [9. The Server Trust Log](#9-the-server-trust-log)
  - [9.1. State Root Links](#91-state-root-links)
  - [9.2. Back-References Prevent Omission of Latest State](#92-back-references-prevent-omission-of-latest-state)
  - [9.3. Global Transparency Tree](#93-global-transparency-tree)
    - [9.3.1. Structure](#931-structure)
    - [9.3.2. Proofs](#932-proofs)
    - [9.3.3. Node hashing](#933-node-hashing)
    - [9.3.4. Inclusion proof](#934-inclusion-proof)
    - [9.3.5. Verifying an inclusion proof](#935-verifying-an-inclusion-proof)
    - [9.3.6. Verifying a non-inclusion proof](#936-verifying-a-non-inclusion-proof)
    - [9.3.7. Proof size](#937-proof-size)
    - [9.3.8. Worked example](#938-worked-example)
  - [9.4. Client Obligations](#94-client-obligations)
  - [9.5. Split-View Attack](#95-split-view-attack)
- [10. Security Considerations](#10-security-considerations)
- [11. References](#11-references)
- [Appendix A. Soundness of Sparse Replay](#appendix-a-soundness-of-sparse-replay)

---

## 1. Introduction

The trust log is a tamper-resistant, append-only data structure that records actions. Each actor — a
user, an organization, a provider, or the server itself (§9) — has one trust log. The goal is to
record actions concerning that actor in a way that provably came from the actor, that can be revoked
(by appending an action stating the revocation), and that the server can neither inject into,
modify, nor omit from.

The trust log is intended to become the central root from which clients determine:

- the currently valid keys of other users, organizations, and providers;
- their own currently valid keys;
- the organizations and providers they agreed to be part of;
- the security-critical permissions an organization holds over a user;
- the devices currently active for a user.

Each entry in the log is a **link**, and every link has two parts:

- an **outer link** — small, always visible to any authorized reader of the log, and **the thing
  that is signed**;
- an **inner message** — the full payload, whose readability is gated by the outer link's declared
  visibility.

The chain of outer links gives _completeness_: the account holder can prove no action was inserted,
removed, or reordered. The **server's own trust log** (§9) — which on a fixed schedule records the
latest state of every other trust log, and which every link back-references — gives _freshness_: it
prevents the server from truncating the tail of a log or showing different readers different
versions of it. A merkle trie over the per-account heads (§9.3) is what makes proving that state
cheap.

### 1.1. Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14
([RFC2119], [RFC8174]) when, and only when, they appear in all capitals.

Text marked "Rationale:" is non-normative and explains why a requirement exists.

### 1.2. Notation

Structures are given in a pseudo-schema:

```
Name = {
  field:   type,     // comment
}
```

with these conventions:

| Notation         | Meaning                                                        |
| ---------------- | -------------------------------------------------------------- |
| `uint`, `uint64` | Unsigned integer; `uint64` is explicitly 64-bit.               |
| `bytes[n]`       | Fixed-length byte string of exactly `n` bytes.                 |
| `bytes`          | Variable-length byte string.                                   |
| `string`         | UTF-8 text.                                                    |
| `uuid`           | 128-bit UUID.                                                  |
| `enum { a, b }`  | One of the listed symbolic values.                             |
| `oneof { ... }`  | Tagged union; exactly one arm is present.                      |
| `map<K, V>`      | Unordered association of keys to values.                       |
| `T \| null`      | Optional field; `null` means absent.                           |
| `HASH(x)`        | The hash function applied to the canonical encoding of x.      |
| `links[i]`       | The link at `sequence_number = i` of the log under discussion. |
| `state(n)`       | Derived log state after applying `links[0..=n]` (§6).          |

`Gn` denotes a goal of §1.4.

### 1.3. Terminology

| Term               | Definition                                                                                                                                                         |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Actor**          | An entity that owns exactly one trust log: a user, an organization, or a provider, or a server                                                                     |
| **Actor kind**     | Which kind an actor is. Constrains the message types its log may contain (§5).                                                                                     |
| **Link**           | One log entry: an outer link, its signature, and its inner message.                                                                                                |
| **Outer link**     | The signed, always-served part of a link (§3.1).                                                                                                                   |
| **Inner message**  | The payload of a link, served subject to visibility (§3.2, §4).                                                                                                    |
| **Log**            | The totally ordered sequence of links of one actor, starting at `sequence_number = 0`.                                                                             |
| **Head**           | The highest-numbered link of a log, and by extension `HASH` of its outer link.                                                                                     |
| **Account holder** | The party controlling the signature keys of a log. For a user, the user; for an organization or provider, this is priviledged users of the organization / provider |
| **Relying party**  | A party verifying an actor's log other than that actor.                                                                                                            |
| **Epoch**          | One `trust_log_state_root` link of the server's trust log, identified by that link's sequence number (§9.1).                                                       |

### 1.4. Goals

| #   | Goal                                                                                                                                                   |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| G1  | An account holder can detect any modification, reordering, or omission of their own history.                                                           |
| G2  | A relying party can determine which keys an account controlled _at a given point in its history_, without trusting the server.                         |
| G3  | The server cannot suppress a security-critical action (key revocation, policy change) by claiming it is confidential.                                  |
| G4  | The server cannot roll back or truncate a log without producing a detectable inconsistency against the server's own trust log.                         |
| G5  | Confidential actions (organization membership, device inventory) stay confidential from unauthorized readers while still being _counted_ in the chain. |

---

## 2. Architecture Overview

Figure 1 shows the logs and how they reference each other.

```
              Figure 1: The logs and the references between them

   +------------------------------------------------------------------------+
   |  SERVER TRUST LOG  (§9)                                                |
   |                                                                        |
   |                      ... <---  S(N-1)    <-------  S(N)  <--- ...      |
   |                               root_{N-1}          root_N               |
   +------------------------------------^-----------------|-----------------+
                                        |                 |
                                        |  (1)            |  (2)
                                        |                 |
                                        |+----------------+
                                        ||
   +------------------------------------||----------------------------------+
   |  Alice's trust log  (§3)           ||                                  |
   |                                    |v                                  |
   |            L0 <- L1 <- L2 <- L3 <- L4   (head)                         |
   |                              |                                         |
   +------------------------------|-----------------------------------------+
                                  |  pin: "at my L3, your log stood at L2, head h"
                                  v      (§6.3)
   +------------------------------------------------------------------------+
   |  Org's trust log:      L0 <- L1 <- L2                                  |
   +------------------------------------------------------------------------+

   (1) L4's global_trust_log names epoch N-1: the newest state root that
       existed when Alice wrote L4.  A link can only name an EARLIER epoch
       than the one that commits to it, so the two never point at each
       other  (§9.2).
   (2) root_N is published afterwards, and commits to L4 as Alice's head
       (§9.3).
```

A link consists of two parts. Figure 2 shows them, and what commits to what:

```
                        Figure 2: Anatomy of a link

                signed by a key valid at this sequence
                                    |
                                    v
   +--------------------------------------------------------------------+
   |                       OuterLink  (~75 bytes)                       |
   |   version | sequence_number | type | visibility                    |
   |                                                                    |
   |   previous_outer_link_hash  --------->  HASH(OuterLink[n-1])       |
   |   current_inner_link_hash   --------->  HASH(InnerMessage[n])      |
   +--------------------------------------------------------------------+
                                    |
                     served only to |  readers entitled by `visibility` (§4)
                                    v
   +--------------------------------------------------------------------+
   |                      InnerMessage  (payload)                       |
   |   version | sequence_number | creation_time                        |
   |   body           (discriminated by outer.type)                     |
   |   client_metadata | global_trust_log                               |
   +--------------------------------------------------------------------+

   The signature covers the OUTER link only. The inner message is authenticated
   transitively, through current_inner_link_hash.
```

And the chain, with one inner message withheld from an unauthorized reader:

```
                     Figure 3: The chain of a user log

  seq        0                1                2                3
       +-----------+    +-----------+    +-----------+    +-----------+
 outer | add_key   |<---| add_key   |<---| join_team |<---| remove_key|
       | (genesis) |    |           |    |           |    |           |
       | public    |    | public    |    | semi_pub  |    | public    |
       +-----+-----+    +-----+-----+    +-----+-----+    +-----+-----+
             |                |                |                |
             v                v                v                v
       +-----------+    +-----------+    +===========+    +-----------+
 inner | AddKeyBody|    | AddKeyBody|    #  WITHHELD  #   | RemoveKey |
       +-----------+    +-----------+    +===========+    +-----------+

  <---   previous_outer_link_hash;  all-zero at genesis
  The outer chain is served WHOLE to every authorized reader, always (§4.1):
  the reader above cannot read link 2's body, but cannot fail to see that it exists.
```

---

## 3. Data Structures

### 3.1. Outer Link

```
OuterLink = {
  version:                  uint,        // structure + algorithm version
  sequence_number:          uint,        // 0 for genesis, strictly +1 thereafter
  previous_outer_link_hash: bytes[32],   // HASH of the previous OuterLink; all-zero for genesis
  current_inner_link_hash:  bytes[32],   // HASH of this link's InnerMessage
  type:                     MessageType, // §5
  visibility:               Visibility,  // public, semi_public or private; §4
}
```

The key signing the outer link MUST be of `type = signature` and MUST be valid at this
`sequence_number` (§8).

Rationale: `type` and `visibility` are inside the signed structure so the server cannot misrepresent
what an action was, nor how confidential it is (§4).

### 3.2. Inner Message

```
InnerMessage = {
  version:                     uint,       // structure + algorithm version
  sequence_number:             uint,       // MUST equal the outer link's sequence_number
  creation_time:               uint64,     // client-asserted, UNIX ms — untrusted
  body:                        Body,       // discriminated by the outer link's `type`
  client_metadata:             ClientMetadata,
  global_trust_log:            GlobalTrustLogRef,  // always present; its fields may be null
}

ClientMetadata = {
  client_type:    enum { web, browser_extension, desktop, mobile, cli, server },
  client_version: string,
  device_id:      bytes[16] | null,
}

GlobalTrustLogRef = {              // all three null, or all three set; never mixed
  merkle_root:  bytes[32] | null,
  epoch:        uint64 | null,     // sequence number of that link in the server's log
  epoch_time:   uint64 | null,     // publication time of that epoch, UNIX ms
}
```

`global_trust_log` names the position of the server's trust log (§9) that the author had observed
when it wrote the link, so that a link is dated against that log (§9.2). The field is **always
present**, but a client that has no epoch to name — because the server's log is not published yet —
MAY leave `merkle_root`, `epoch`, and `epoch_time` all null. This exists solely so per-actor logs
can be deployed before the server's log is.

Three rules make that concession safe, and a verifier MUST enforce all three:

1. **All or nothing.** The three fields are either all null or all set. A `global_trust_log` with
   some fields null and others set MUST be rejected.
2. **Witnessing latches on, per log.** Once any link in a log carries a non-null `global_trust_log`,
   every later link in that log MUST carry one too. A log cannot go back to being unwitnessed, so
   the server cannot induce a client to drop the reference from links it appends later.
3. **A null `global_trust_log` is not a witness.** Links carrying one are protected by the hash
   chain and by pins (§6.3), not by the server's log, and a verifier MUST NOT treat them as
   freshness-witnessed.

### 3.3. Signed Outer Link

```
SignedOuterLink = {
  outer:      OuterLink,
  signature:  bytes,     // over the canonical encoding of `outer`
}
```

### 3.4. Genesis Link

The link at `sequence_number = 0` MUST be `add_key` carrying a key of `type = signature`, MUST be
self-signed by that key, and MUST carry `previous_outer_link_hash` of all zeroes. Because the body
carries the verifying key (§5.1), the genesis self-signature is checkable from the link alone. A
trust log MUST always at least have one valid signing key.

---

## 4. Visibility

```
Visibility = enum { public, semi_public, private }
```

| Value         | Who may read the inner message                                                                                                            |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `public`      | Anyone who may read the outer chain.                                                                                                      |
| `semi_public` | The account holder, and principals sharing the relevant scope (e.g. members/admins of the organization named in the body and the server). |
| `private`     | The account holder only.                                                                                                                  |

Each message type maps statically to one visibility (§5), so a verifier MUST reject any link whose
`outer.visibility` disagrees with that mapping (the _Registry_ check, §8); the server therefore
cannot claim an action is more confidential than it is in order to withhold it (G3).

Private links are not yet specified in this document. If they are implemented, then the body would
be encrypted when stored on the server, so that the server cannot read the body.

### 4.1. Preventing Omission by the Server

The outer chain is served **in full, to every authorized reader, regardless of visibility**.
Visibility gates inner messages only. Since sequence numbers are contiguous and each link commits to
the previous link's hash, a missing link in the interior of the chain is immediately visible (the
_Sequence_ and _Outer chain_ checks, §8). A missing link at the _tail_ is covered by §9.

If the server serves the outer link but refuses an inner message the reader is entitled to — this is
detectable but not preventable by this design. This counts as an attack by the server. It is a
denial of service, and clients MUST treat "outer link present, entitled inner message unavailable"
as a verification failure (the _Entitlement_ check, §8), not as a skippable entry.

---

## 5. Message Types

Every link carries a type from the registry below.

| Type                             | Description                                                                            | Principals                   | Visibility    |
| -------------------------------- | -------------------------------------------------------------------------------------- | ---------------------------- | ------------- |
| `add_key`                        | The actor added a key it controls.                                                     | user, organization, provider | `public`      |
| `remove_key`                     | The actor revoked one of its own keys.                                                 | user, organization, provider | `public`      |
| `join_team`                      | A user joined an organization or a provider, or an organization came under a provider. | user, organization           | `semi_public` |
| `join_team_legacy`               | The author joined a team that has no trust log yet.                                    | user, organization           | `semi_public` |
| `upgrade_team_from_legacy`       | A team that was joined as legacy now has a log, and the author pins it.                | user, organization           | `semi_public` |
| `leave_team`                     | The author ended one of those memberships.                                             | user, organization           | `semi_public` |
| `add_member`                     | A team admitted a user as a member.                                                    | organization, provider       | `semi_public` |
| `add_member_legacy`              | A team admitted a member who has no trust log yet.                                     | organization, provider       | `semi_public` |
| `upgrade_member_from_legacy`     | A member admitted as legacy now has a log, and the team pins it.                       | organization, provider       | `semi_public` |
| `remove_member`                  | A team removed one of its members.                                                     | organization, provider       | `semi_public` |
| `change_organization_permission` | A team changed what a member, group or collection may do.                              | organization, provider       | `semi_public` |
| `change_critical_policy`         | An organization changed a security-critical policy.                                    | organization                 | `public`      |
| `track_organization_change`      | A member recorded an organization-side permission or policy change it observed (§5.2). | user, organization           | `semi_public` |
| `pin_foreign_log`                | The actor witnessed another actor's log at a position.                                 | user, organization, provider | `public`      |
| `trust_log_state_root`           | The server published the latest state of every trust log (§9.1).                       | server                       | `public`      |

`pin_foreign_log` is `public` because its value depends on outside parties being able to read it;
whether that is the right trade against interaction-graph leakage is not settled ⚠️. The `private`
value is declared by no type and is currently headroom — an unused enum value invites misuse, so it
SHOULD either gain a type or be removed.

### 5.1. Bodies

```
AddKeyBody = {
  key_id:                bytes[16],
  type:                  enum { kem, public_key_encryption, signature },
  algorithm:             enum { ml-dsa, rsa },     // parameter sets unspecified
  public_key:            bytes,                    // the public / verifying key itself
  thumbprint:            bytes,                    // over public_key
}

RemoveKeyBody = {
  key_id:      bytes[16],      // MUST refer to a key added earlier in this log
  type:        enum { kem, public_key_encryption, signature },
  reason:      enum { rotation, compromise },
}

TrustLogLink = {               // a reference into ANOTHER actor's log; see §6.3
  sequence:          uint,
  outer_link_hash:   bytes[32],
}

TeamMembershipBody = {         // the author's side of a membership; the team's side is MemberBody
  id:               uuid,
  type:             enum { organization, provider },
  trust_log_link:   TrustLogLink,          // REQUIRED: the team's log as seen when joining
}

LegacyTeamMembershipBody = {   // same, for a team with no trust log to point at
  id:               uuid,
  type:             enum { organization, provider },
}

UpgradeFromLegacyBody = {      // a legacy counterparty now has a log
  subject:          { kind: enum { user, organization, provider }, id: uuid },
  trust_log_link:   TrustLogLink,             // REQUIRED: the whole point of the upgrade
  signed_head:      SignedOuterLink | null,   // strong form, as in PinBody
}

MemberBody = {                 // an action this team took on another account
  organization_id:  uuid,
  subject_user_id:  uuid,
  trust_log_link:   TrustLogLink,          // REQUIRED: the subject's log as seen when adding them
}

LegacyMemberBody = {           // same, for a member with no trust log to point at
  organization_id:  uuid,
  subject_user_id:  uuid,
}

OrganizationPermissionBody = {
  organization_id:  uuid,
  subject:          { kind: enum { member, group, collection }, id: uuid },
  previous:         PermissionSet,
  current:          PermissionSet,
}

TrackOrganizationChangeBody = { // written by a MEMBER, about a change in the team's log (§5.2)
  organization_id:  uuid,
  change:           enum { permission, critical_policy },
  trust_log_link:   TrustLogLink,   // REQUIRED: the position of the change in the team's log
}

CriticalPolicyBody = {
  organization_id:  uuid,
  policy: oneof {
    key_connector    { enabled: bool, url: string },
    data_ownership   { enabled: bool },
    account_recovery { enabled: bool, ... },
  },
  previous:         PolicyValue,
  current:          PolicyValue,
}

PinBody = {                    // this actor witnessed ANOTHER actor's log at a position
  subject:       { kind: enum { user, organization, provider }, id: uuid },
  pinned_head: {
    sequence:          uint,
    outer_link_hash:   bytes[32],
  },
  signed_head:   SignedOuterLink | null,   // the subject's own signed head link, copied verbatim
}

TrustLogStateRootBody = {      // written by the SERVER, in the server's own log (§9.1)
  merkle_root:        bytes[32],   // commitment over every account's head; §9.3
  publication_time:   uint64,      // UNIX ms
}
```

### 5.2. Tracking Organization-Side Changes

A `change_organization_permission` or `change_critical_policy` link lives in the organization's log
and says nothing about which members have seen it. A member MUST therefore append
`track_organization_change` to its **own** log, naming the position of that change in the
organization's log, as soon as it observes the change. Any countdown before the change takes effect
for that member — a notice period, a grace window, a delay before enforcement — starts at the
member's own tracking link, never at the organization's link. The length of the countdown is out of
scope for this document.

Rationale: an organization cannot start a clock against a member who has not seen the change, and a
server that withholds the organization's log can delay the tracking link but never backdate it. The
member's own log is the only place where "I saw this change at this point in my history" is
non-repudiable.

---

## 6. Log State

The log state is the local accumulated state obtained by applying all actions in the log.

```
state(n) = apply links[0], links[1], ..., links[n] in order, starting from InitialState
```

```
                     Figure 4: State

  InitialState --apply(L0)--> state(0) --apply(L1)--> state(1) --...--> state(n)
                     ^                      ^                              |
                     |                      |                              v
              (outer, inner) pair    pure function of                 as_of_sequence = n
                                     (state, outer, inner)            head_hash = HASH(L_n.outer)
```

Every key an actor learns of, its own or a counterparty's, is recorded as a `KeyState`, derived from
the `add_key` / `remove_key` links of whichever log the key was read from:

```
KeyState = {
  key_id:               bytes[16],
  type:                 enum { kem, public_key_encryption, signature },
  algorithm:            enum { ml-dsa, rsa },
  public_key:           bytes,             // as carried by the add_key body
  thumbprint:           bytes,
  added_at_sequence:    uint,              // position in the log this key was read from
  revoked_at_sequence:  uint | null,       // null while valid
  revocation_reason:    enum { rotation, compromise } | null,
}
```

The sequence numbers belong to the log the key came from, so a key in `trust_log_keys` is dated
against this log while a key read from a counterparty is dated against the counterparty's. Which log
a key came from also decides what it may do: only keys from **this** log's own `add_key` /
`remove_key` feed the _Signature_ check (§8). A key read from a counterparty's log MUST NOT,
whatever its `KeyState` looks like — learning a key across logs never grants signing authority in
this one (§7.2 rule 1).

Revoked keys are **retained, not deleted**. Removing them would destroy the ability to check a
signature made before the revocation, which must stay checkable forever.

### 6.1. Organization and Provider Log State

```
OrganizationLogState = {
  as_of_sequence:         uint,
  head_hash:              bytes[32],
  trust_log_keys:         map<key_id, KeyState>,   // the keys this log itself established
  members:                map<user_id, MemberState>,
  providers:              map<provider_id, ProviderRelationshipState>,   // join_team, type = provider
  active_policies:        map<PolicyKind, PolicyValue>,
  requested_permissions:  map<PermissionRequestId, PermissionRequestState>,
}

MembershipPeriod = {                   // one uninterrupted stretch of membership
  joined_at_sequence:   uint,
  left_at_sequence:     uint | null,   // null while the period is still open
}

ProviderRelationshipState = {          // a provider that manages THIS organization
  provider_id:          uuid,
  provider_keys:        map<key_id, KeyState>,   // the provider's own log
  periods:              [MembershipPeriod],             // in ascending sequence order
}

MemberState = {
  user_id:              uuid,
  name:                 string,          // display name / email as recorded by the organization
  permissions:          PermissionSet,
  keys:                 map<key_id, KeyState>,   // empty while legacy; see membership_status
  membership_status:    enum { legacy, modern },
  upgraded_at_sequence: uint | null,     // set by upgrade_member_from_legacy
  periods:              [MembershipPeriod],   // one entry per join; re-joining appends
}

PermissionRequestState = {
  request_id:            uuid,
  permission:            Permission,   // e.g. account recovery enrolment, device approval
  scope:                 { kind: enum { organization, member, group, collection }, id: uuid },
  requested_at_sequence: uint,
  withdrawn_at_sequence: uint | null,
}

ProviderLogState = OrganizationLogState     // plus, if provider-managed organizations are recorded:
                                            //   managed_organizations: map<organization_id, ...>
```

### 6.2. User Log State

```
UserLogState = {
  as_of_sequence:   uint,
  head_hash:        bytes[32],
  trust_log_keys:   map<key_id, KeyState>,       // the keys this log itself established
  organizations:    map<organization_id, OrganizationMembershipState>,
  providers:        map<provider_id, ProviderMembershipState>,   // join_team with type = provider
  known_users:      map<user_id, KnownUserState>,
}

OrganizationMembershipState = {
  organization_id:      uuid,
  name:                 string,
  permissions:          PermissionSet,
  organization_keys:    map<key_id, KeyState>,    // empty while legacy; see membership_status
  active_policies:      map<PolicyKind, PolicyValue>,    // tracked by this user (§5.2)
  requested_policies:   map<PolicyKind, PolicyValue>,    // set by the org, not yet tracked here
  membership_status:    enum { legacy, modern },
  upgraded_at_sequence: uint | null,   // set by upgrade_team_from_legacy
  periods:              [MembershipPeriod],   // one entry per join; re-joining appends
}

ProviderMembershipState = {                        // same shape, provider-scoped
  provider_id:          uuid,
  name:                 string,
  permissions:          PermissionSet,
  provider_keys:        map<key_id, KeyState>,
  periods:              [MembershipPeriod],
}

KnownUserState = {
  user_id:                  uuid,
  name:                     string,
  keys:                     map<key_id, KeyState>,
  first_seen_at_sequence:   uint,
}
```

A client MUST NOT fill `organization_keys`, `active_policies` or `requested_policies` from
server-supplied values: while `membership_status = legacy` there is no counterparty log to derive
them from, and an `upgrade_team_from_legacy` is what makes one available. Only an `active` policy
may be treated as consented to by this user. Once a counterparty appears in `known_users`, a
different key for it MUST be justified by an `add_key` at a later position in that counterparty's
own log, which is what makes a swapped recipient key detectable.

### 6.3. Log Application Rules

| Message type                     | Effect on state                                                                                                                                                                         |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `add_key`                        | Insert into this trust log's key set (`trust_log_keys`). Genesis establishes the first signature key.                                                                                   |
| `remove_key`                     | Set `revoked_at_sequence` + `revocation_reason` on that key of `trust_log_keys`. Never delete.                                                                                          |
| `join_team`                      | Open a new `MembershipPeriod` on `organizations[id]` or `providers[id]` in the author's log, per the body's `type`, with `membership_status = modern`. Advance `pinned_heads[subject]`. |
| `join_team_legacy`               | The same, with `membership_status = legacy` and nothing derived from the counterparty.                                                                                                  |
| `upgrade_team_from_legacy`       | Set `membership_status = modern` + `upgraded_at_sequence` on that membership, and advance `pinned_heads[subject]`. The counterparty's state is derived from here on.                    |
| `leave_team`                     | Close the open period on that entry. Retain it.                                                                                                                                         |
| `add_member` / `remove_member`   | Open / close a `MembershipPeriod` on `members[user_id]` in the team's log, `membership_status = modern`. Advance `pinned_heads[subject]`.                                               |
| `add_member_legacy`              | Insert `members[user_id]` with `membership_status = legacy` and nothing derived from the counterparty.                                                                                  |
| `upgrade_member_from_legacy`     | Set `membership_status = modern` + `upgraded_at_sequence` on that member, and advance `pinned_heads[subject]`.                                                                          |
| `change_organization_permission` | Replace the subject's `PermissionSet`; the body's `previous` MUST equal the derived value.                                                                                              |
| `change_critical_policy`         | Replace `active_policies[kind]` in the organization's own log; likewise checked against `previous`.                                                                                     |
| `track_organization_change`      | In the member's log, move the named permission or policy from `requested_*` to `active_*`, and start any countdown from this sequence (§5.2). Does not advance `pinned_heads[subject]`. |
| `pin_foreign_log`                | Advance `pinned_heads[subject]`. Everything derived from that subject moves with it.                                                                                                    |
| `trust_log_state_root`           | In the server's log, record the published `merkle_root` for this epoch (§9.1).                                                                                                          |

`pin_foreign_log` is the primary type that touches foreign state — a `trust_log_link` on a
membership link does the same, weakly — and it does so indirectly: it advances
`pinned_heads[subject]`, the highest subject sequence this log has witnessed together with the outer
link hash it named, and the subject's state is then recomputed by replaying the subject's log at
least to the new position (§6). One pin can therefore admit a key, revoke another, and bring a
policy into view at once, because all three are the subject's own links newly attested to. It
belongs to both actor shapes, since organizations pin their members just as users pin their
organizations.

---

## 7. Scaling: Sparse Replay

### 7.1. Post-Quantum Signature Size Issues

Post-quantum signatures ([FIPS 204] / ML-DSA) signatures are large, roughly 2-4KiB per signature.
This means that for large sets of operations on a chain, we do not want to bear the cost of
downloading all of the signatures. For example:

| Links     | Outer chain links | Signatures |
| --------- | ----------------- | ---------- |
| 10,000    | ~0.75 MB          | ~20 MB     |
| 100,000   | ~7.5 MB           | ~200 MB    |
| 1,000,000 | ~75 MB            | ~2 GB      |

We want to optimize this to eliminate login latency and network transfer, especially for large
organizations. For this, we introduce sparse replay and checkpoints.

#### 7.1.1. Sparse Replay - Example

A concrete log: an organization with **25,000 current members**, **400 departures** over its
lifetime, and **10 organization key rotations**.

Per-link sizes, ML-DSA-44:

```
outer link          ~75 bytes     (two 32-byte hashes and small integers)
signature         ~2,420 bytes    (FIPS 204, ML-DSA-44)
inner message       ~200 bytes    (chain hash, creation_time, global_trust_log,
                                    client metadata, and a ~70-byte body)
inner message     ~1,500 bytes    for an add_key: the same, carrying a
                                    ~1.3 KiB ML-DSA-44 public key (§5.1)
```

Link inventory:

```
add_member                 25,400     (25,000 current + 400 since departed)
remove_member                 400
add_key / remove_key           22     (2 at genesis + 10 rotations x 2 links)
                           ------
total                      25,822
```

| Reader profile                                              | Outer links | Signatures      | Inner messages | Total       |
| ----------------------------------------------------------- | ----------- | --------------- | -------------- | ----------- |
| **Full replay** — every link, signature, inner message      | ~2.0 MB     | ~62 MB (25,822) | ~5.2 MB        | **~70 MB**  |
| **Sparse, no types requested** — key events only            | ~2.0 MB     | ~53 KB (22)     | ~18 KB (22)    | **~2.1 MB** |
| **Sparse + checkpoint** — one day's activity, ~50 new links | ~3.8 KB     | ~121 KB (50)    | ~10 KB         | **~135 KB** |

### 7.2. Sparse Replay

The key idea of sparse replay is that a reader needs to verify only two things in full: **every
change to the log's key set**, and **the head**. Everything in between is verified implicitly by the
signature on the head (§7.3).

A reader therefore requests the message types it actually cares about, and the server serves:

- the **complete outer chain**, every link, always — §4.1 is unchanged and non-negotiable;
- signatures and inner messages for the requested types, **plus every `add_key` and `remove_key`
  link, whether or not they were requested**.

A request for the outer chain accordingly names the types wanted and whether signatures are wanted.

| Check                 | On a replayed link | On a skipped link            |
| --------------------- | ------------------ | ---------------------------- |
| Version               | MUST               | MUST                         |
| Sequence              | MUST               | **MUST**                     |
| Outer hash chain      | MUST               | **MUST**                     |
| Registry visibility   | MUST               | MUST                         |
| Signature             | MUST               | MAY skip                     |
| Inner binding         | MUST               | MUST, if the inner arrived   |
| Entitlement           | MUST               | relative to the types wanted |
| Global trust log      | MUST               | MUST                         |
| Body validity + state | MUST               | MAY skip                     |
| Principal kind        | MUST               | MUST                         |

1. **`add_key` and `remove_key` are never skippable.** A verifier MUST fully validate every key
   event of the log it is replaying — signature, inner message, and body — whatever else it asked
   for. Skipping a `remove_key` would leave a revoked key in the derived validity set, and every
   signature check is evaluated against that set. This covers the log's **own** key events only;
   keys derived from a foreign log never feed the _Signature_ check (§6). The rule applies again,
   recursively, to any foreign log the reader replays.
2. **Hash and sequence integrity are never skippable.** Contiguous sequence numbers and an unbroken
   outer hash chain MUST be checked over every link, including skipped ones. This is what makes
   skipping signatures sound at all (§7.3).

`pin_foreign_log` deserves a note of its own: its inner message carries a _foreign_ signed head, so
it costs ~2 KiB whether or not the reader validates this log's own signatures. A reader that wants
that evidence MUST ask for the type explicitly; one that does not gets a chain it can still fully
verify, minus the evidence.

_Entitlement_ needs restating under sparse replay: a reader that did not request a type MUST NOT
treat the absent inner message as a failure, but equally MUST NOT later act on state derived from
it. A reader that _did_ request a type and was refused an inner message it is entitled to still
fails, exactly as before.

### 7.3. Why Skipping Signatures Is Sound

```
        Figure 5: One signature authenticates the whole prefix

   +----+     +----+     +----+     +----+     +----+
   | L0 |<----| L1 |<----| L2 |<----| L3 |<----| L4 |
   +----+     +----+     +----+     +----+     +----+
                                                  ^
                                                  | signature verified here
                                                  | (normally the head, which
                                                  |  §9.4 already requires)

   HASH(L3) is committed by L4; HASH(L2) by L3; ... so a single valid
   signature at L4 fixes the content of L0..L3 as well.
```

Each outer link commits to the hash of its predecessor, so a single verified signature authenticates
the **entire prefix** below it, not merely the link it sits on. Appendix A proves this by induction.

In practice this means a reader that

1. checks the unbroken hash chain and contiguous sequence numbers over **every** outer link, and
2. verifies the signature on at least one link at or after the highest sequence it relies on —
   normally the head, which §9.4 already requires,

has authenticated the content of every earlier link, including the ones whose signatures it never
fetched. Note that step 2 is why key events are never skippable: the head's signature counts only if
the key that made it was valid at the head, and that is knowable only from the complete set of key
events (§7.2 rule 1).

### 7.4. Checkpoints and Incremental Replay

A client MAY persist a verified checkpoint and on the next sync replay only the links after it:

```
Checkpoint = {
  version:  uint,
  actor:    { kind: enum { user, organization, provider, server }, id: uuid },
  state:    oneof { UserLogState, OrganizationLogState },   // §6
  server_log_sequence:  uint | null,   // position of the server's log observed then; §9.1
}
```

A checkpoint is trusted state, so it MUST be integrity-protected where it is stored, or discarded
and re-derived. A checkpoint MAY also be synchronized across a user's devices, provided it is held
in an encrypted and authenticated store; a checkpoint that can be tampered with is worse than none,
because it silently suppresses the replay that would have caught the tampering.

---

## 8. Chain Validation

A verifier processing a trust log MUST, in sequence order:

1. **Version.** `outer.version` is implemented. Reject otherwise.
2. **Sequence.** `seq == 0` for the first link; `seq == prev.seq + 1` thereafter.
3. **Outer chain.** `outer.previous_outer_link_hash == HASH(prev.outer)`; all-zero at genesis.
4. **Registry.** `outer.visibility == REGISTRY[outer.type].visibility`.
5. **Signature.** `signature` verifies over `outer` under the key its own envelope identifies, that
   key is of `type = signature` in this log, and it was **valid at this sequence number**.
6. **Inner binding.** If the inner message was received:
   `HASH(inner) == outer.current_inner_link_hash` and
   `inner.sequence_number == outer.sequence_number`.
7. **Entitlement.** If the verifier is entitled to the inner message under `outer.visibility`,
   requested it (§7.2), and did not receive it: **fail**. Do not skip.
8. **Global trust log.** `global_trust_log` has all three fields null or all three set; no link
   after the log's first non-null `global_trust_log` has a null one; and where set, `epoch` is
   non-decreasing across the log and does not exceed the newest epoch the verifier itself has seen
   (§3.2).
9. **Body validity.** The body parses under `outer.type`, and its semantic preconditions hold
   against derived state (§6.3).
10. **Principal kind.** `outer.type` is permitted for the kind of actor whose log this is, per
    `REGISTRY[type].principals` (§5). Reject otherwise.

Failure of any check invalidates the log **from that link onward**. Prefix links already verified
remain valid — this matters, because it means a compromised tail does not erase provable history.

---

## 9. The Server Trust Log

Pins (§6.3) let trust logs witness each other, but they leave the server two paths of attack. It can
truncate a log at its latest pinned position, omitting the newest links; and on a fresh login, the
first time a client interacts with a log, there is nothing to compare against at all — the client
would have to trust the server not to serve it an entirely different log. Both are closed by giving
the server a trust log of its own.

### 9.1. State Root Links

The server is an actor (§1.3) with its own trust log, built from the same structures as §3: an outer
chain of links, each signed, each committing to its predecessor. Its links are of type
`trust_log_state_root`, and each one asserts the latest state of **every** other trust log at the
moment it was written:

```
TrustLogStateRootBody = {
  merkle_root:        bytes[32],   // commitment over every account's head; §9.3
  publication_time:   uint64,      // UNIX ms
}
```

State roots are published on a fixed schedule. An **epoch** is one such link, and it is identified
by that link's `sequence_number` in the server's log — the log's own hash chain is what stops the
server from rewriting an earlier publication after the fact, and the server's own signature is what
makes a tampered publication provable rather than deniable. No separate epoch-head structure or
`previous_epoch_hash` is needed; the server's log already provides both.

Since a state root is a short, signed, public value, it MAY additionally be published to an external
append-only record — a Rekor instance, or a commitment on a blockchain such as Stellar or Bitcoin —
which is one of the mitigations §9.5 needs.

### 9.2. Back-References Prevent Omission of Latest State

Every link of every log carries a `global_trust_log` reference (§3.2) naming the position of the
server's log that its author had observed:

```
        Figure 6: A link dates itself against the server's log

   S(N-1)  <------------  S(N)  <------------  S(N+1)      the server's log (§9.1)
   state root             state root           state root
   signed by the server   signed               signed
                             ^
                             |  global_trust_log = { merkle_root: root_N,
                             |                       epoch: N,
                             |                       epoch_time: ... }
                             |
                 InnerMessage at some sequence n  (§3.2)

   Every link therefore records which state root its author had observed,
   without trusting a clock. The check of §8, item 8 keeps this from going
   backwards.
```

This is what closes omission of latest state. A state root commits to the head of every log, so to
hide the newest links of one log the server must serve a state root that predates them — but the
back-references written into other actors' logs name later state roots, and those links are signed
by actors the server does not control. Withholding the state root does not help either: the
reference latches on per log (§3.2), so once an actor's log has started naming state roots, links
that stop naming them are invalid. The server's options reduce to serving a consistent, current view
or being caught, with the remaining case being the split view of §9.5.

### 9.3. Global Transparency Tree

A state root could in principle enumerate every log's head, but that is unusable at scale: a client
that only cares about its own account and a handful of counterparties would have to fetch the whole
list to check any of it. The **global transparency tree** is the optimized way to make proofs over a
set of trust logs: the state root commits to a merkle trie over all heads, so a single account's
head can be proven — or its absence proven — in ~1 KiB (§9.3.7), independent of how many accounts
exist.

#### 9.3.1. Structure

The server maintains a **sparse Patricia Merkle trie** keyed by `HASH(entity_id)`, whose leaf value
for each account is:

```
MerkleData = {
  version:              uint,
  trust_log_head:       bytes[32],   // HASH of the account's head OuterLink
  trust_log_sequence:   uint,        // that head's sequence_number
}
```

```
            Figure 7: The trie at epoch N

                        root_N   (committed by the server log's link N, §9.1)
                       /      \
                    0 /        \ 1
                     /          \
              +---------+      +---------+
              |   ...   |      |   ...   |     path = bits of HASH(account_id)
              +----+----+      +----+----+
                   |                |
          HASH(account_A)    HASH(account_B)
                   |                |
          +----------------+  +----------------+
          |   MerkleData   |  |   MerkleData   |
          | head: h_A      |  | head: h_B      |
          | sequence: 17   |  | sequence: 4    |
          +----------------+  +----------------+

  Sparse: an absent account is provable (non-inclusion) without enumerating
  the whole tree by including null nodes.
```

#### 9.3.2. Proofs

| Proof                 | Answers                                                                             |
| --------------------- | ----------------------------------------------------------------------------------- |
| **Inclusion**         | "`MerkleData` for account _A_ is in the trie at epoch _N_." Trie path + siblings.   |
| **Non-inclusion**     | "Account _A_ has no entry at epoch _N_." Native to a sparse trie.                   |
| **Epoch consistency** | "Epoch _N_ descends from epoch _M_." The server log's links from _M_ to _N_ (§9.1). |

The Patricia trie gives inclusion and non-inclusion, but **not** an append-only property across
epochs — leaf values legitimately change every epoch. Rollback detection comes from clients and
monitors comparing `trust_log_sequence` between epochs, not from the trie structure itself. This is
worth being precise about: the trie provides _consistent views_, the server's own log provides
_unforgeable history_, and monotonicity checking provides _rollback detection_. All three are
needed.

#### 9.3.3. Node hashing

Inclusion proofs are only well-defined once node hashing is fixed. Leaves and internal nodes MUST be
domain-separated, or an internal node hash can be replayed as a leaf value:

```
EMPTY               = bytes[32]        // the empty-subtree constant; all zeroes
leaf_hash(k, v)     = HASH(0x00 || k || HASH(v))     // k = trie key, v = MerkleData
node_hash(l, r)     = HASH(0x01 || l || r)           // l, r = child hashes
```

`HASH(v)` is over the canonical encoding of `MerkleData`. A trie holding no accounts has root
`EMPTY`.

#### 9.3.4. Inclusion proof

```
InclusionProof = {
  version:   uint,
  epoch:     uint64,          // the epoch this proof is against
  root:      bytes[32],       // convenience copy; NOT trusted, see step 1 below
  key:       bytes[32],       // HASH(entity_id) — the trie path, MSB first
  leaf:      MerkleData,      // the value being proven (§9.1)
  siblings:  [SiblingNode],   // ordered DEEPEST first, ending at the child of the root
}

SiblingNode = oneof {
  empty    { depth: uint8 },                                        // the EMPTY constant
  subtree  { depth: uint8, hash: bytes[32] },                       // an internal subtree
  leaf     { depth: uint8, key: bytes[32], value_hash: bytes[32] },  // a compressed single leaf
}
```

The `leaf` variant exists because the trie is compressed: a subtree containing exactly one account
is stored as that account's leaf rather than expanded to depth 256. Carrying the sibling's own `key`
lets the verifier recompute `leaf_hash` for it — and is what makes non-inclusion provable (§9.3.6).

`NonInclusionProof` is the same structure with `leaf` replaced by what the path terminates in:

```
NonInclusionProof = {
  version:   uint,
  epoch:     uint64,
  root:      bytes[32],
  key:       bytes[32],       // the ABSENT account's key
  terminal:  oneof {
    empty  { },                                       // path ends in an empty subtree
    other  { key: bytes[32], value_hash: bytes[32] },  // path ends at a DIFFERENT account's leaf
  },
  siblings:  [SiblingNode],
}
```

#### 9.3.5. Verifying an inclusion proof

```
        Figure 8: Recomputing the root from a leaf and its siblings

  key = HASH(entity_id) = 1 0 1 1 …        (bits MSB first; depth 0 is the first bit)
  Real keys are 256 bits; four are shown.

  depth 0                       root_N
                             /          \
                         0 /              \ 1     bit0 = 1 -> go RIGHT
                        S3                 *
  depth 1                              /      \
                                   0 /          \ 1   bit1 = 0 -> go LEFT
                                   *             S2
  depth 2                       /     \
                            0 /         \ 1           bit2 = 1 -> go RIGHT
                            S1           *
  depth 3                             /     \
                                  0 /         \ 1     bit3 = 1 -> go RIGHT
                                  S0          LEAF
                                              MerkleData
                                              { head: h_A, sequence: 17 }

  Recompute upwards, deepest sibling first. At each level the path bit says
  which side WE are on, and therefore the argument order:

    x4 = leaf_hash(key, MerkleData)
    x3 = node_hash(S0, x4)      // bit3 = 1: we are the right child
    x2 = node_hash(S1, x3)      // bit2 = 1: right
    x1 = node_hash(x2, S2)      // bit1 = 0: we are the LEFT child
    x0 = node_hash(S3, x1)      // bit0 = 1: right

  ACCEPT iff x0 == the root in a server-log state root the verifier already verified.
```

A verifier MUST, in order:

1. Obtain the `merkle_root` from the server log's `trust_log_state_root` link at `epoch`, having
   verified that link under §8, and use **that** root. `InclusionProof.root` is a convenience field;
   treating it as the root reduces the proof to a self-signed assertion.
2. Recompute `key` as `HASH(entity_id)` from the account identifier it actually cares about. A
   server-supplied `key` proves inclusion of _something_, not of the account the verifier asked
   about.
3. Check the sibling list is well-formed: `depth` values strictly decreasing, no repeats, the
   shallowest equal to 0, and the count equal to the leaf's depth. Without this, a shortened or
   reordered path can be made to collide.
4. Recompute upwards as in Figure 8 and compare against the root from step 1.
5. Only then read the leaf: `trust_log_head` against its own view of the log, and
   `trust_log_sequence` against the highest it has previously observed (§9.4, item 2).

Steps 1–4 establish that the leaf is in the trie. Step 5 is what makes that fact useful; a client
that performs 1–4 and skips 5 has verified a proof and learned nothing.

#### 9.3.6. Verifying a non-inclusion proof

Identical, except that `x_leaf` — the value the recomputation starts from — is:

- `EMPTY`, when `terminal = empty`; or
- `leaf_hash(other.key, other.value_hash)`, when `terminal = other`.

In the second case the verifier MUST additionally check that `other.key != key` and that `other.key`
agrees with `key` on every bit above the terminal depth. That is precisely the statement "walking
_your_ key leads to _someone else's_ leaf, so your key is absent" — and it is why the `leaf` sibling
variant carries a key at all.

Non-inclusion is what a client checks before treating a counterparty as legacy — as having no log at
all (§5): "the server says this organization has no trust log" is otherwise an unfalsifiable claim,
and one the server benefits from making.

#### 9.3.7. Proof size

Path length is `log2` of the number of accounts, not 256, because the trie is compressed: ~24 levels
at 10⁷ accounts. At 33–65 bytes per sibling that is **~1–1.5 KiB per proof** — less than a single
ML-DSA signature (§7.1). Proof verification is therefore affordable on every sync, for the client's
own account and for each counterparty it relies on, which is what makes §9.4 realistic.

#### 9.3.8. Example

```
InclusionProof {
  version:  1,
  epoch:    4711,
  root:     0x9f2c…a7,            // MUST match the server log's state root at sequence 4711
  key:      0xb4e1…09,            // HASH(alice_user_id); bits 1011…
  leaf:     MerkleData { version: 1, trust_log_head: 0x7a1e…c4, trust_log_sequence: 17 },
  siblings: [
    leaf    { depth: 3, key: 0xb0c7…12, value_hash: 0x2c88…f0 },  // Bob, sharing prefix 101
    empty   { depth: 2 },                                         // nothing under 100
    subtree { depth: 1, hash: 0x41d0…9b },                        // everything under 11
    subtree { depth: 0, hash: 0xe903…5d },                        // everything under 0
  ],
}
```

Read bottom-up, this says: everything whose key starts `0` hashes to `0xe903…`; within `1`,
everything starting `11` hashes to `0x41d0…`; within `10`, the `100` subtree is empty; within `101`,
Bob sits at `1010…` and Alice at `1011…`. Combining them reproduces `0x9f2c…a7`, which the server
log's link at sequence 4711 commits to — so at epoch 4711 the server published Alice's log as being
at sequence 17 with head `0x7a1e…c4`. If Alice's client holds a head at sequence 19, the server is
serving an epoch that omits her two newest links; if it holds sequence 17 but a _different_ head,
the server has forked her log.

### 9.4. Client Obligations

A conforming client MUST:

1. Replay the server's trust log from its last-known position to the newest state root on each sync,
   verifying it under §8 as it would any other log, and rejecting gaps in its sequence.
2. Fetch an inclusion proof for **its own account** and check that `trust_log_head` matches its
   local head and that `trust_log_sequence` is `>=` the value it last observed. A decrease is a
   **rollback attack** — hard failure, alert the user, do not silently re-sync.
3. Detect missed publications: if `now - publication_time` exceeds _k_ × the schedule interval,
   warn.
4. Embed the observed `(root, epoch, epoch_time)` as `global_trust_log` in any link it authors.

A relying party verifying _another_ account's log MUST additionally check that the served head is
included in a recent epoch.

### 9.5. Split-View Attack

Everything above assumes all parties see the _same_ server trust log. A server that signs two
different state roots at the same sequence and shows them to disjoint sets of clients (a **split
view**) defeats parts of the construction.

```
              Figure 9: Split view attack

                          +------------------+
                          |      server      |
                          +---+----------+---+
            S(N)              |          |      S'(N)
            root = R          |          |      root = R'      (R != R')
            signature valid   |          |      signature valid
                              v          v
                       +----------+   +----------+
                       |  Alice   |   |   Bob    |
                       +----------+   +----------+

   Both clients run every check in §9.4 and both pass. Neither can tell,
   because neither sees the other's copy of the server's log.
```

This would get detected quickly by the backreferences that user/org trust logs place into their
logs. Outside of this, out-of-band verification is possible. A few mechanisms for this are:
Login-with-device, a public record such as Rekor or a blockchain (stellar/bitcoin).

---

## 10. Security Considerations

This whole document is a security consideration; this section states what the construction defends
against.

| Attack                                                 | Defeated by                                                            |
| ------------------------------------------------------ | ---------------------------------------------------------------------- |
| Insert a forged action                                 | Signature over the outer link (§8)                                     |
| Delete an interior action                              | Contiguous sequence + hash chain (§8)                                  |
| Reorder actions                                        | Hash chain (§8)                                                        |
| Swap an inner payload between links                    | `current_inner_link_hash` + duplicated sequence number (§8)            |
| Hide a key revocation behind confidentiality           | Type→visibility binding (§4, §8)                                       |
| Misrepresent which key signed a link                   | The signature names its own key, checked against the validity set (§8) |
| Substitute key material for a key an actor added       | `add_key` carries the public key itself, inside the signed log (§5.1)  |
| Serve a stale/truncated log to a relying party         | State root inclusion + `trust_log_sequence` monotonicity (§9.3, §9.4)  |
| Omit the latest state of a log                         | `global_trust_log` back-references in other actors' logs (§9.2)        |
| Roll an account back to an earlier head                | Monotonicity check across epochs (§9.4, item 2)                        |
| Silently rewrite a past epoch                          | The server's own log is hash-chained and signed (§9.1)                 |
| Hide a rollback from a reader who trusts another actor | Foreign log pins carrying the subject's signed head (§5.1, §6.3)       |
| Start a policy countdown a member never saw            | The countdown runs from the member's own tracking link (§5.2)          |
| Backdate an action to before a key revocation          | Position-based key validity — timestamps are not consulted (§8)        |

---

## 11. References

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC
  2119, March 1997.
- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC
  8174, May 2017.
- **[FIPS204]** NIST, "Module-Lattice-Based Digital Signature Standard (ML-DSA)", FIPS 204,
  August 2024.
- **[BW-SEC]** Bitwarden, "Security definitions",
  <https://contributing.bitwarden.com/architecture/security/definitions>.
- **[RFC6962]** Laurie, B., Langley, A., Kasper, E., "Certificate Transparency", RFC 6962,
  June 2013.
- **[RFC9162]** Laurie, B., et al., "Certificate Transparency Version 2.0", RFC 9162, December 2021.
  Source of the epoch/consistency-proof model this document adapts.
- **[CONIKS]** Melara, M., et al., "CONIKS: Bringing Key Transparency to End Users", USENIX
  Security 2015. The per-user key-directory model, and the split-view problem of §9.5.
- **[SEEMless]** Chase, M., Deshpande, A., Ghosh, E., Malvai, H., "SEEMless: Secure End-to-End
  Encrypted Messaging with less trust", CCS 2019. Sparse-trie key transparency with privacy.
- **[BW-SDK]** Bitwarden, "SDK architecture",
  <https://contributing.bitwarden.com/architecture/sdk/>.
- **[BW-ORGMEM]** This crate, `OrganizationMembership.md` — worked link sequences for organization
  membership, legacy organizations, and migrating an existing user.

---

## Appendix A. Soundness of Sparse Replay

This appendix proves the claim §7.3 relies on: that one signature authenticates everything below it,
which is what lets a sparse reader skip the signatures in between.

**Claim.** Let `links[0..=n]` have contiguous sequence numbers and an unbroken outer hash chain, and
let the signature on `links[n]` verify under a key valid at `n`. Then the content of every link in
`[0, n]` is authenticated.

Write `P(m)` for the statement: _the value of `outer[m]` fixes the content of `links[0..=m]`_ — the
inner message included, since `outer[m]` commits to `HASH(inner[m])` (§3.1).

**Base case.** `P(0)` holds trivially: `links[0]` is the genesis link (§3.4), so there is nothing
before it, `previous_outer_link_hash` is all-zero, and `outer[0]` commits to its own inner message.
This is the axiom the induction starts from — the first link is always fixed by itself.

**Inductive step.** Assume `P(k-1)`. Now `outer[k]` contains
`previous_outer_link_hash = HASH(outer[k-1])`, and `HASH` is collision-resistant, so the value of
`outer[k]` fixes `outer[k-1]` to exactly one value — the one the reader has checked its copy of
`links[k-1]` against. By `P(k-1)`, that value in turn fixes everything before it. Hence `P(k)`.

**Conclusion.** A signature that verifies over `outer[n]` under a key valid at `n` authenticates
`outer[n]`; `P(n)` extends that authentication to all of `links[0..=n]`. Put in the intuitive form:
if a link is signed, its predecessor must be valid too, and therefore, by induction, so must the
whole prefix.
