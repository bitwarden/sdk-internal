# bw-macro

Proc macro for the `bw` CLI binary. Provides `#[bw_command(...)]`, an attribute applied to args
structs that registers a command into a compile-time inventory.

## Usage

```rust,ignore
#[derive(clap::Args, Clone)]
#[bw_command(
    path = "get exposed",
    state = Unlocked,
    about = "Check if an item password has been exposed in a data breach."
)]
pub struct GetExposedArgs {
    pub id: String,
}

impl GetExposedArgs {
    async fn run(self, Unlocked { client, .. }: Unlocked) -> CommandResult {
        // business logic
    }
}
```

The macro emits:

1. `impl BwCommand for Struct` — delegates to the struct's inherent `run` method via UFCS.
2. `inventory::submit!` — registers a `BwCommandEntry` carrying the path, clap augmentation fn, and
   dispatch fn.

## Attributes

- **`path`** (required): whitespace-separated CLI path. First segment is the group, last segment is
  the leaf subcommand name. Example: `"sync"`, `"get exposed"`, `"list org-members"`.
- **`state`** (required unless `todo`): the `ClientState` the command needs. One of `LoggedOut`,
  `LoggedIn`, `Unlocked`, `AnyState`. Drives `TryFrom<ClientContext>` at dispatch time.
- **`about`**, **`long_about`**, **`after_help`** (optional): forwarded to `clap::Command`.
- **`todo`** (flag, optional): emit a `todo!()` body and skip the UFCS call. Registers the command
  without requiring the user to write a `run` method — useful for stubbing the CLI surface.

## Consumer expectations

The consuming crate must:

- Define `crate::client_state::{BwCommand, ClientContext, LoggedOut, LoggedIn, Unlocked, AnyState}`.
- Define `crate::render::CommandResult`.
- Define `crate::cli_runtime::BwCommandEntry` (signature must match the one this macro emits).
- Depend on `inventory` so `::inventory::submit!` resolves.

The macro hardcodes these `crate::` paths; it is currently only usable from the `bw` crate.

## Debugging

Use `cargo expand -p bw --bin bw <module_path>` to inspect generated output. The three expansions
per annotated struct are:

1. The original struct (unchanged).
2. An `impl BwCommand` block.
3. An `inventory::submit!` with a `BwCommandEntry` literal.

## Not yet supported

- `aliases` for compatibility with legacy flag names.
- Handler attribute (`handler = path::to::fn`) for commands whose dispatch doesn't fit the
  `args → state → run` shape. Such commands currently need to be expressed as args structs with a
  `run` method.
