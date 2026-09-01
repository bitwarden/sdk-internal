//! A read-only walk of a realistic nested structure, printed the way an
//! automated agent would crawl it: describe a node, list its children, descend
//! one path segment at a time.
//!
//! Run with: `cargo run -p bitwarden-introspect --example walk`

use bitwarden_introspect::{Introspect, NodeInfo};

#[derive(Introspect)]
struct Vault {
    accounts: Vec<Account>,
}

#[derive(Introspect)]
struct Account {
    email: String,
    premium: bool,
    ciphers: Vec<Cipher>,
}

#[derive(Introspect)]
struct Cipher {
    name: String,
    username: Option<String>,
    favorite: bool,
}

fn sample() -> Vault {
    Vault {
        accounts: vec![Account {
            email: "alice@example.com".to_string(),
            premium: true,
            ciphers: vec![
                Cipher {
                    name: "GitHub".to_string(),
                    username: Some("alice".to_string()),
                    favorite: true,
                },
                Cipher {
                    name: "Router".to_string(),
                    username: None,
                    favorite: false,
                },
            ],
        }],
    }
}

/// Print a node the way the discovery API surfaces it: the node's own preview,
/// then one line per child edge with its key, type, preview, and writeability.
fn show(path: &[&str], node: &NodeInfo) {
    let where_ = if path.is_empty() {
        "<root>".to_string()
    } else {
        path.join(".")
    };
    println!("\n$ describe {where_}");
    println!("  {} = {}  [{:?}]", node.type_name, node.preview, node.writeability);
    for child in &node.children {
        println!(
            "    .{:<10} {:<8} = {:<20} [{:?}]",
            child.key, child.type_name, child.preview, child.writeability
        );
    }
}

fn main() {
    let vault = sample();

    // 1. Root: what's reachable from the top.
    let root = vault.describe(&[]).expect("root always resolves");
    show(&[], &root);

    // 2. Descend into the first account.
    let path: &[&str] = &["accounts", "0"];
    let account = vault.describe(path).expect("account 0 exists");
    show(path, &account);

    // 3. Into its cipher list, then a single cipher.
    let path: &[&str] = &["accounts", "0", "ciphers", "0"];
    let cipher = vault.describe(path).expect("cipher 0 exists");
    show(path, &cipher);

    // 4. All the way down to a leaf value.
    let path: &[&str] = &["accounts", "0", "ciphers", "0", "name"];
    let leaf = vault.describe(path).expect("cipher name exists");
    show(path, &leaf);

    // 5. A path that doesn't resolve returns None rather than panicking.
    let missing = vault.describe(&["accounts", "0", "nope"]);
    println!("\n$ describe accounts.0.nope\n  {missing:?}");
}
