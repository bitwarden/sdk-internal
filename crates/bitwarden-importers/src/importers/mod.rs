//! Format-specific importer parsers. Each parser turns its file format into a
//! [`crate::pipeline::ParsedImport`]; the generic pipeline encrypts and submits it.

pub(crate) mod kdbx;
pub mod keeper;
