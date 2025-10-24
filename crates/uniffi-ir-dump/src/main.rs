//! Tool to dump UniFFI Component Interface IR from a compiled cdylib or staticlib into a stable,
//! pretty-printed JSON file.
//!
//! Usage: uniffi-ir-dump <path-to-cdylib-or-staticlib> [out.json]

use std::{env, fs::File, path::PathBuf};

use anyhow::Context;
use serde::Serialize;
use serde_json;
use uniffi_bindgen::{BindgenLoader, cargo_metadata::CrateConfigSupplier, interface::AsType};

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

    // Convert to a detailed, serializable IR so we can emit JSON with full signatures
    let crates: Vec<CrateIr> = cis.into_iter().map(|ci| build_crate_ir(&ci)).collect();

    // Write pretty JSON for stable diffing
    let file =
        File::create(&out_path).with_context(|| format!("creating {}", out_path.display()))?;
    serde_json::to_writer_pretty(file, &crates).context("writing JSON IR")?;

    eprintln!("Wrote {}", out_path.display());
    Ok(())
}

#[derive(Debug, Serialize)]
struct CrateIr {
    crate_name: String,
    namespace: String,
    functions: Vec<FunctionIr>,
    objects: Vec<ObjectIr>,
    records: Vec<RecordIr>,
    enums: Vec<EnumIr>,
}

#[derive(Debug, Serialize)]
struct FunctionIr {
    name: String,
    is_async: bool,
    args: Vec<ArgIr>,
    return_type: Option<String>,
    throws: Option<String>,
    ffi_symbol: String,
}

#[derive(Debug, Serialize)]
struct ArgIr {
    name: String,
    r#type: String,
    by_ref: bool,
    optional: bool,
    default: Option<String>,
}

#[derive(Debug, Serialize)]
struct ObjectIr {
    name: String,
    trait_interface: bool,
    constructors: Vec<CallableIr>,
    methods: Vec<CallableIr>,
}

#[derive(Debug, Serialize)]
struct CallableIr {
    name: String,
    is_async: bool,
    args: Vec<ArgIr>,
    return_type: Option<String>,
    throws: Option<String>,
    ffi_symbol: String,
}

#[derive(Debug, Serialize)]
struct RecordIr {
    name: String,
    fields: Vec<FieldIr>,
}

#[derive(Debug, Serialize)]
struct FieldIr {
    name: String,
    r#type: String,
}

#[derive(Debug, Serialize)]
struct EnumIr {
    name: String,
    shape: String,
    variants: Vec<EnumVariantIr>,
}

#[derive(Debug, Serialize)]
struct EnumVariantIr {
    name: String,
    fields: Vec<FieldIr>,
}

fn build_crate_ir(ci: &uniffi_bindgen::interface::ComponentInterface) -> CrateIr {
    // Functions
    let mut functions: Vec<FunctionIr> = ci
        .function_definitions()
        .iter()
        .map(|f| FunctionIr {
            name: f.name().to_string(),
            is_async: f.is_async(),
            args: f
                .arguments()
                .into_iter()
                .map(|a| ArgIr {
                    name: a.name().to_string(),
                    r#type: fmt_type(&a.as_type()),
                    by_ref: a.by_ref(),
                    optional: a.default_value().is_some(),
                    default: a.default_value().map(|d| format!("{:?}", d)),
                })
                .collect(),
            return_type: f.return_type().map(fmt_type),
            throws: f.throws_type().map(fmt_type),
            ffi_symbol: f.ffi_func().name().to_string(),
        })
        .collect();
    functions.sort_by(|a, b| a.name.cmp(&b.name));

    // Objects
    let mut objects: Vec<ObjectIr> = ci
        .object_definitions()
        .iter()
        .map(|o| {
            let mut constructors: Vec<CallableIr> = o
                .constructors()
                .into_iter()
                .map(|c| CallableIr {
                    name: c.name().to_string(),
                    is_async: c.is_async(),
                    args: c
                        .arguments()
                        .into_iter()
                        .map(|a| ArgIr {
                            name: a.name().to_string(),
                            r#type: fmt_type(&a.as_type()),
                            by_ref: a.by_ref(),
                            optional: a.default_value().is_some(),
                            default: a.default_value().map(|d| format!("{:?}", d)),
                        })
                        .collect(),
                    // Constructors return the object; we omit explicit type here.
                    return_type: None,
                    throws: c.throws_type().map(fmt_type),
                    ffi_symbol: c.ffi_func().name().to_string(),
                })
                .collect();
            constructors.sort_by(|a, b| a.name.cmp(&b.name));

            let mut methods: Vec<CallableIr> = o
                .methods()
                .into_iter()
                .map(|m| CallableIr {
                    name: m.name().to_string(),
                    is_async: m.is_async(),
                    args: m
                        .arguments()
                        .into_iter()
                        .map(|a| ArgIr {
                            name: a.name().to_string(),
                            r#type: fmt_type(&a.as_type()),
                            by_ref: a.by_ref(),
                            optional: a.default_value().is_some(),
                            default: a.default_value().map(|d| format!("{:?}", d)),
                        })
                        .collect(),
                    return_type: m.return_type().map(fmt_type),
                    throws: m.throws_type().map(fmt_type),
                    ffi_symbol: m.ffi_func().name().to_string(),
                })
                .collect();
            methods.sort_by(|a, b| a.name.cmp(&b.name));

            ObjectIr {
                name: o.name().to_string(),
                trait_interface: o.is_trait_interface(),
                constructors,
                methods,
            }
        })
        .collect();
    objects.sort_by(|a, b| a.name.cmp(&b.name));

    // Records
    let mut records: Vec<RecordIr> = ci
        .record_definitions()
        .iter()
        .map(|r| {
            let mut fields: Vec<FieldIr> = r
                .fields()
                .iter()
                .map(|f| FieldIr {
                    name: f.name().to_string(),
                    r#type: fmt_type(&f.as_type()),
                })
                .collect();
            fields.sort_by(|a, b| a.name.cmp(&b.name));
            RecordIr {
                name: r.name().to_string(),
                fields,
            }
        })
        .collect();
    records.sort_by(|a, b| a.name.cmp(&b.name));

    // Enums
    let mut enums: Vec<EnumIr> = ci
        .enum_definitions()
        .iter()
        .map(|e| {
            let shape = if ci.is_name_used_as_error(e.name()) {
                if e.is_flat() {
                    "error(flat)"
                } else {
                    "error(rich)"
                }
            } else {
                "enum"
            };
            let mut variants: Vec<EnumVariantIr> = e
                .variants()
                .iter()
                .map(|v| {
                    let mut fields: Vec<FieldIr> = v
                        .fields()
                        .iter()
                        .map(|f| FieldIr {
                            name: f.name().to_string(),
                            r#type: fmt_type(&f.as_type()),
                        })
                        .collect();
                    fields.sort_by(|a, b| a.name.cmp(&b.name));
                    EnumVariantIr {
                        name: v.name().to_string(),
                        fields,
                    }
                })
                .collect();
            variants.sort_by(|a, b| a.name.cmp(&b.name));
            EnumIr {
                name: e.name().to_string(),
                shape: shape.to_string(),
                variants,
            }
        })
        .collect();
    enums.sort_by(|a, b| a.name.cmp(&b.name));

    CrateIr {
        crate_name: ci.crate_name().to_string(),
        namespace: ci.namespace().to_string(),
        functions,
        objects,
        records,
        enums,
    }
}

fn fmt_type(t: &uniffi_bindgen::interface::Type) -> String {
    use uniffi_bindgen::interface::{ObjectImpl, Type};
    match t {
        Type::UInt8 => "u8".into(),
        Type::Int8 => "i8".into(),
        Type::UInt16 => "u16".into(),
        Type::Int16 => "i16".into(),
        Type::UInt32 => "u32".into(),
        Type::Int32 => "i32".into(),
        Type::UInt64 => "u64".into(),
        Type::Int64 => "i64".into(),
        Type::Float32 => "f32".into(),
        Type::Float64 => "f64".into(),
        Type::Boolean => "bool".into(),
        Type::String => "String".into(),
        Type::Duration => "Duration".into(),
        Type::Timestamp => "SystemTime".into(),
        Type::Bytes => "Bytes".into(),
        Type::Record { module_path, name } => format!("record {}::{}", module_path, name),
        Type::Enum { module_path, name } => format!("enum {}::{}", module_path, name),
        Type::Object {
            module_path,
            name,
            imp,
        } => match imp {
            ObjectImpl::Struct => format!("object {}::{}", module_path, name),
            ObjectImpl::Trait => format!("trait {}::{}", module_path, name),
            ObjectImpl::CallbackTrait => format!("callback_trait {}::{}", module_path, name),
        },
        Type::CallbackInterface { module_path, name } => {
            format!("callback {}::{}", module_path, name)
        }
        Type::Custom {
            module_path,
            name,
            builtin,
        } => {
            format!("custom {}::{}({})", module_path, name, fmt_type(builtin))
        }
        Type::Optional { inner_type } => format!("Option<{}>", fmt_type(inner_type)),
        Type::Sequence { inner_type } => format!("Vec<{}>", fmt_type(inner_type)),
        Type::Map {
            key_type,
            value_type,
        } => {
            format!("Map<{}, {}>", fmt_type(key_type), fmt_type(value_type))
        }
    }
}
