# bitwarden-rotation-daemon

Bitwarden PAM credential rotation daemon.

This crate provides the `bw-rotation-daemon` binary, which continuously rotates PAM-managed
credentials according to policies retrieved from the Bitwarden server.

See the plan and authoritative behavior spec for full details:

- Plan: `~/.claude/plans/let-s-explore-implementing-the-spicy-sun.md`
- Spec: `rotation-daemon/rotation-daemon.allium`

Later implementation stages extend this stub.
