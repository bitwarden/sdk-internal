//! Runtime glue for the `#[bw_command]` attribute macro.
//!
//! Commands register themselves into a compile-time inventory at link time. At startup,
//! [`assemble_cli`] walks the inventory, groups entries by path prefix, and returns a
//! fully-assembled [`clap::Command`]. [`dispatch`] takes the parsed [`clap::ArgMatches`]
//! plus a [`ClientContext`] and routes to the right entry's handler.

use std::{
    boxed::Box, collections::BTreeMap, future::Future, pin::Pin, string::ToString, vec::Vec,
};

use color_eyre::eyre::eyre;

use crate::{client_state::ClientContext, render::CommandResult};

/// One registered CLI leaf. Produced by the `#[bw_command]` macro and submitted via `inventory`.
pub struct BwCommandEntry {
    /// CLI path split into segments. For example `&["get", "exposed"]` maps to `bw get exposed`.
    pub path: &'static [&'static str],

    /// Attaches this entry's subcommand definition onto the given `clap::Command`.
    pub augment: fn(clap::Command) -> clap::Command,

    /// Parses matched args back into the entry's struct and runs it.
    pub dispatch:
        fn(&clap::ArgMatches, ClientContext) -> Pin<Box<dyn Future<Output = CommandResult>>>,
}

inventory::collect!(BwCommandEntry);

/// Builds the full CLI tree, attaching every registered command under its path to the provided
/// root [`clap::Command`]. The caller supplies the root (carrying top-level globals) via
/// [`clap::CommandFactory`].
pub fn assemble_cli(root: clap::Command) -> clap::Command {
    // Group entries by their first path segment. Top-level commands (single-segment path) attach
    // directly to the root; grouped commands attach to a subcommand named after the group.
    let mut top_level: Vec<&'static BwCommandEntry> = Vec::new();
    let mut grouped: BTreeMap<&'static str, Vec<&'static BwCommandEntry>> = BTreeMap::new();

    for entry in inventory::iter::<BwCommandEntry> {
        match entry.path {
            [_] => top_level.push(entry),
            [group, ..] => grouped.entry(*group).or_default().push(entry),
            [] => panic!("bw_command entry with empty path — macro should prevent this"),
        }
    }

    // Sort entries so help output is deterministic. Inventory iteration order is unspecified.
    top_level.sort_by_key(|e| e.path);
    for entries in grouped.values_mut() {
        entries.sort_by_key(|e| e.path);
    }

    let mut root = top_level
        .into_iter()
        .fold(root, |cmd, entry| (entry.augment)(cmd));

    for (group_name, entries) in grouped {
        let group_about = group_about_text(group_name);
        let group_cmd = clap::Command::new(group_name).about(group_about);
        let group_cmd = entries
            .into_iter()
            .fold(group_cmd, |cmd, entry| (entry.augment)(cmd));
        root = root.subcommand(group_cmd);
    }

    root
}

/// Dispatches a parsed `ArgMatches` to the registered handler.
///
/// Walks `matches` from the root down, descending through each subcommand. At each depth, checks
/// whether the current path matches a registered entry; if so, invokes that entry with the
/// `ArgMatches` at that depth. Subcommands nested inside a handler's own args (e.g., `bw get
/// template folder`, where `folder` is a variant of `TemplateCommands` and not a separately
/// registered entry) are parsed by that handler's `FromArgMatches` impl, not by this walker.
pub async fn dispatch(matches: &clap::ArgMatches, ctx: ClientContext) -> CommandResult {
    let mut path: Vec<String> = Vec::new();
    let mut current = matches;

    while let Some((name, sub)) = current.subcommand() {
        path.push(name.to_string());

        // Check if the current path is a registered entry. If so, dispatch here rather than
        // descending further — any deeper subcommands belong to the handler's own args.
        for entry in inventory::iter::<BwCommandEntry> {
            if entry.path == path.as_slice() {
                return (entry.dispatch)(sub, ctx).await;
            }
        }

        current = sub;
    }

    Err(eyre!(
        "No handler registered for command path: {}",
        path.join(" ")
    ))
}

/// Static descriptions for each command group. Deferred convenience; if the set grows or teams
/// want per-group ownership of this text, revisit.
fn group_about_text(group: &str) -> &'static str {
    match group {
        "get" => "Get an object from the vault.",
        "list" => "List an array of objects from the vault.",
        "create" => "Create an object in the vault.",
        "edit" => "Edit an object from the vault.",
        "delete" => "Delete an object from the vault.",
        "confirm" => "Confirm an object to the organization.",
        "config" => "Configure CLI settings.",
        _ => "",
    }
}
