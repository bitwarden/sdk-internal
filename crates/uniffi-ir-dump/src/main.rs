//! Tool to dump UniFFI Component Interface IR from a compiled cdylib or staticlib into a stable,
//! pretty-printed JSON file.
//!
//! Usage: uniffi-ir-dump <path-to-cdylib-or-staticlib> [out.json]

use std::{env, fs::File, path::PathBuf};

use anyhow::Context;
use serde::Serialize;
use serde_json;
use uniffi_bindgen::{BindgenLoader, cargo_metadata::CrateConfigSupplier};

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let lib_path = PathBuf::from(
        args.next()
            .context("usage: uniffi-ir-dump <path-to-cdylib-or-staticlib> [out.json]")?,
    );
    let out_path = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("uniffi.ir.json"));

    // Use the public BindgenLoader to read metadata and convert to ComponentInterfaces
    // This captures cfg/platform specifics embedded in the compiled library.
    let supplier = CrateConfigSupplier::default();
    let loader = BindgenLoader::new(&supplier);
    let metadata = loader
        .load_metadata(
            camino::Utf8Path::from_path(&lib_path)
                .ok_or_else(|| anyhow::anyhow!("non-utf8 path: {}", lib_path.display()))?,
        )
        .with_context(|| format!("loading metadata from {}", lib_path.display()))?;
    let mut cis = loader
        .load_cis(metadata)
        .context("constructing ComponentInterfaces from metadata")?;

    // Sort by crate name for stable output
    cis.sort_by(|a, b| a.crate_name().cmp(b.crate_name()));

    // Convert to a compact, serializable summary so we can emit JSON
    let crates: Vec<CrateSummary> = cis.into_iter().map(|ci| summarize_ci(&ci)).collect();

    // Write pretty JSON for stable diffing
    let file =
        File::create(&out_path).with_context(|| format!("creating {}", out_path.display()))?;
    serde_json::to_writer_pretty(file, &crates).context("writing JSON IR")?;

    eprintln!("Wrote {}", out_path.display());
    Ok(())
}

#[derive(Debug, Serialize)]
struct CrateSummary {
    crate_name: String,
    namespace: String,
    enums: Vec<String>,
    records: Vec<String>,
    objects: Vec<String>,
    functions: Vec<String>,
    ffi_debug: Vec<String>,
}

fn summarize_ci(ci: &uniffi_bindgen::interface::ComponentInterface) -> CrateSummary {
    // Collect top-level names (sufficient for stable API diffs). The full FFI is captured via
    // Debug.
    let mut enums: Vec<String> = ci
        .enum_definitions()
        .iter()
        .map(|e| e.name().to_string())
        .collect();
    enums.sort();

    let mut records: Vec<String> = ci
        .record_definitions()
        .iter()
        .map(|r| r.name().to_string())
        .collect();
    records.sort();

    let mut objects: Vec<String> = ci
        .object_definitions()
        .iter()
        .map(|o| o.name().to_string())
        .collect();
    objects.sort();

    let mut functions: Vec<String> = ci
        .function_definitions()
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    functions.sort();

    // FFI definitions contain symbol-level info including signatures; include Debug strings for
    // diffing
    let mut ffi_debug: Vec<String> = ci
        .ffi_definitions()
        .map(|def| format!("{:?}", def))
        .collect();
    ffi_debug.sort();

    CrateSummary {
        crate_name: ci.crate_name().to_string(),
        namespace: ci.namespace().to_string(),
        enums,
        records,
        objects,
        functions,
        ffi_debug,
    }
}
