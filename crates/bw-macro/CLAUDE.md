# bw-macro

Proc macro for the `bw` CLI binary. Provides `#[bw_command(...)]`, an attribute applied to args
structs that registers a command into a compile-time inventory.

## Usage

```rust,ignore
#[derive(clap::Args, Clone)]
#[bw_command(
    path = "get exposed",
    about = "Check if an item password has been exposed in a data breach."
)]
pub struct GetExposedArgs {
    pub id: String,
}

impl BwCommand for GetExposedArgs {
    type Client = Unlocked;
    async fn run(self, Unlocked { client, .. }: Unlocked) -> CommandResult {
        // business logic
    }
}
```

The macro emits an `inventory::submit!` of a `BwCommandEntry` carrying the path, a clap augmentation
closure, and a dispatch closure. The user supplies the `impl BwCommand` by hand; the dispatcher
calls `<Struct as BwCommand>::run(args, ctx.try_into()?)` and Rust infers the client state type from
the trait impl.

## Attributes

- **`path`** (required): whitespace-separated CLI path. First segment is the group, last segment is
  the leaf subcommand name. Example: `"sync"`, `"get exposed"`, `"list org-members"`.
- **`about`**, **`long_about`**, **`after_help`** (optional): forwarded to `clap::Command`.

## Consumer expectations

The consuming crate must:

- Define `crate::client_state::{BwCommand, ClientContext}` plus state types implementing
  `TryFrom<ClientContext>`.
- Define `crate::render::CommandResult`.
- Define `crate::cli_runtime::BwCommandEntry` matching the shape emitted by this macro.
- Depend on `inventory` so `::inventory::submit!` resolves.

The macro hardcodes these `crate::` paths; it is currently only usable from the `bw` crate.

## Debugging

Use `cargo expand -p bw --bin bw <module_path>` to inspect generated output. Each annotated struct
expands to the original struct plus an `inventory::submit!` with a `BwCommandEntry` literal.

## Not yet supported

- `aliases` for compatibility with legacy flag names.
- Handler attribute (`handler = path::to::fn`) for commands whose dispatch doesn't fit the
  `args -> state -> run` shape. No real command has required this so far.
