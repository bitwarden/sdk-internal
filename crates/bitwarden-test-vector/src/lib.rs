#![doc = include_str!("../README.md")]

use std::path::{Path, PathBuf};

mod emergency_access;
mod organization;
mod user;
mod vault;

pub use emergency_access::EmergencyAccessV1Vector;
pub use organization::{OrganizationV1MemberVector, OrganizationV1Vector};
pub use user::{AccountVector, RawCryptographicStateVector, TestVector};
pub use vault::{
    AttachmentKeysVector, AttachmentVersion, CipherKeysVector, CipherVectorItem, VaultVector,
    VectorItem,
};

/// The schema version the current code understands. Bumped whenever the on-disk shape changes in a
/// way that is not backward compatible, which also requires regenerating every vector.
pub const SCHEMA_VERSION: u32 = 1;

/// Errors that can occur while loading or validating a test vector.
#[derive(Debug, thiserror::Error)]
pub enum TestVectorError {
    /// A vector file could not be read.
    #[error("Failed to read test vector at {path}: {source}")]
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying IO error.
        source: std::io::Error,
    },
    /// A vector file could not be parsed.
    #[error("Failed to parse test vector at {path}: {source}")]
    Parse {
        /// The path that could not be parsed.
        path: PathBuf,
        /// The underlying deserialization error.
        source: serde_json::Error,
    },
    /// A vector declares a schema version this code does not understand.
    #[error("Test vector at {path} has schema version {found}, expected {SCHEMA_VERSION}")]
    SchemaVersion {
        /// The path of the offending vector.
        path: PathBuf,
        /// The version the file declares.
        found: u32,
    },
    /// The decrypted state did not match what the vector recorded.
    #[error("Validation failed for {field}: {message}")]
    Validation {
        /// The field that did not match.
        field: &'static str,
        /// What was wrong.
        message: String,
    },
    /// A cryptographic operation failed while validating.
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// The `test-vectors` directory at the repository root.
///
/// Resolved from this crate's own manifest directory at compile time, so it is correct no matter
/// which crate calls it.
pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-vectors")
}

/// Loads every user vector in `test-vectors/users`, sorted by file name so iteration order is
/// stable.
pub fn load_users() -> Result<Vec<TestVector>, TestVectorError> {
    load_dir(&vectors_dir().join("users"))
}

/// Loads every organization vector in `test-vectors/organizations`, sorted by file name.
pub fn load_organizations() -> Result<Vec<OrganizationV1Vector>, TestVectorError> {
    load_dir(&vectors_dir().join("organizations"))
}

/// Loads every emergency access vector in `test-vectors/emergency-access`, sorted by file name.
pub fn load_emergency_access() -> Result<Vec<EmergencyAccessV1Vector>, TestVectorError> {
    load_dir(&vectors_dir().join("emergency-access"))
}

/// Reads and parses a single vector file.
pub fn load_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, TestVectorError> {
    let contents = std::fs::read_to_string(path).map_err(|source| TestVectorError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_str(&contents).map_err(|source| TestVectorError::Parse {
        path: path.to_owned(),
        source,
    })
}

/// Reads every `.json` file in `dir`, in sorted file-name order.
fn load_dir<T: serde::de::DeserializeOwned + SchemaVersioned>(
    dir: &Path,
) -> Result<Vec<T>, TestVectorError> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|source| TestVectorError::Io {
            path: dir.to_owned(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let vector: T = load_file(&path)?;
            if vector.schema_version() != SCHEMA_VERSION {
                return Err(TestVectorError::SchemaVersion {
                    path,
                    found: vector.schema_version(),
                });
            }
            Ok(vector)
        })
        .collect()
}

/// Lets the loaders reject a vector whose schema version they do not understand, before a caller
/// can act on partially-understood data.
pub trait SchemaVersioned {
    /// The schema version this vector declares.
    fn schema_version(&self) -> u32;
}
