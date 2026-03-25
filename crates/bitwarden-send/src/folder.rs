use std::io::{Cursor, Write};

use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zip::{ZipWriter, write::SimpleFileOptions};

use crate::SendFileView;

/// A single file entry within a send folder.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MakeSendFolderEntry {
    /// Relative path of the file within the folder, using forward slashes.
    pub path: String,
    /// Raw file bytes.
    pub contents: Vec<u8>,
}

/// Request to create a zipped send folder.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MakeSendFolderRequest {
    /// Name of the folder (used as the zip file name).
    pub folder_name: String,
    /// Files to include in the zip.
    pub files: Vec<MakeSendFolderEntry>,
}

/// Result of creating a zipped send folder.
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct MakeSendFolderResult {
    /// Metadata for the resulting zip file, suitable for creating a file Send.
    pub file: SendFileView,
    /// Raw zip bytes.
    pub contents: Vec<u8>,
}

/// Errors that can occur when creating a send folder.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum MakeSendFolderError {
    #[error("Folder must contain at least one file")]
    EmptyFolder,
    #[error("File at index {0} has an empty path")]
    EmptyPath(usize),
    #[error("File at index {0} has an invalid path (absolute or contains '..')")]
    InvalidPath(usize),
    #[error("Zip error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub(crate) fn make_send_folder(
    request: MakeSendFolderRequest,
) -> Result<MakeSendFolderResult, MakeSendFolderError> {
    if request.files.is_empty() {
        return Err(MakeSendFolderError::EmptyFolder);
    }

    for (i, entry) in request.files.iter().enumerate() {
        if entry.path.is_empty() {
            return Err(MakeSendFolderError::EmptyPath(i));
        }
        if entry.path.starts_with('/') || entry.path.starts_with('\\') || entry.path.contains("..")
        {
            return Err(MakeSendFolderError::InvalidPath(i));
        }
    }

    let buf = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(buf);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

    for entry in &request.files {
        zip.start_file(&entry.path, options)?;
        zip.write_all(&entry.contents)?;
    }

    let cursor = zip.finish()?;
    let zip_bytes = cursor.into_inner();

    let file_name = format!("{}.zip", request.folder_name);
    let size = zip_bytes.len();

    Ok(MakeSendFolderResult {
        file: SendFileView {
            id: None,
            file_name,
            size: Some(size.to_string()),
            size_name: Some(size_name(size)),
        },
        contents: zip_bytes,
    })
}

fn size_name(size: usize) -> String {
    let units = ["Bytes", "KB", "MB", "GB", "TB"];
    let size = size as f64;
    let unit = (size.ln() / 1024_f64.ln()).floor() as usize;
    let size = size / 1024_f64.powi(unit as i32);

    let size_round = (size * 10.0_f64).round() as usize as f64 / 10.0_f64;
    format!("{} {}", size_round, units[unit])
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn test_make_send_folder() {
        let request = MakeSendFolderRequest {
            folder_name: "test-folder".to_string(),
            files: vec![
                MakeSendFolderEntry {
                    path: "hello.txt".to_string(),
                    contents: b"Hello, world!".to_vec(),
                },
                MakeSendFolderEntry {
                    path: "sub/nested.txt".to_string(),
                    contents: b"Nested file".to_vec(),
                },
            ],
        };

        let result = make_send_folder(request).expect("should succeed");
        assert_eq!(result.file.file_name, "test-folder.zip");
        assert!(result.file.id.is_none());
        assert!(result.file.size.is_some());
        assert!(result.file.size_name.is_some());
        assert!(!result.contents.is_empty());

        // Verify the zip can be read back
        let reader = Cursor::new(&result.contents);
        let mut archive = zip::ZipArchive::new(reader).expect("valid zip");
        assert_eq!(archive.len(), 2);

        let mut file0 = archive.by_index(0).expect("file 0");
        assert_eq!(file0.name(), "hello.txt");
        assert_eq!(file0.compression(), zip::CompressionMethod::Stored);
        let mut buf0 = Vec::new();
        file0.read_to_end(&mut buf0).expect("read file 0");
        assert_eq!(buf0, b"Hello, world!");
        drop(file0);

        let mut file1 = archive.by_index(1).expect("file 1");
        assert_eq!(file1.name(), "sub/nested.txt");
        let mut buf1 = Vec::new();
        file1.read_to_end(&mut buf1).expect("read file 1");
        assert_eq!(buf1, b"Nested file");
    }

    #[test]
    fn test_make_send_folder_empty_folder() {
        let request = MakeSendFolderRequest {
            folder_name: "empty".to_string(),
            files: vec![],
        };
        let err = make_send_folder(request).unwrap_err();
        assert!(matches!(err, MakeSendFolderError::EmptyFolder));
    }

    #[test]
    fn test_make_send_folder_empty_path() {
        let request = MakeSendFolderRequest {
            folder_name: "test".to_string(),
            files: vec![MakeSendFolderEntry {
                path: "".to_string(),
                contents: b"data".to_vec(),
            }],
        };
        let err = make_send_folder(request).unwrap_err();
        assert!(matches!(err, MakeSendFolderError::EmptyPath(0)));
    }

    #[test]
    fn test_make_send_folder_absolute_path() {
        let request = MakeSendFolderRequest {
            folder_name: "test".to_string(),
            files: vec![MakeSendFolderEntry {
                path: "/etc/passwd".to_string(),
                contents: b"data".to_vec(),
            }],
        };
        let err = make_send_folder(request).unwrap_err();
        assert!(matches!(err, MakeSendFolderError::InvalidPath(0)));
    }

    #[test]
    fn test_make_send_folder_relative_path() {
        let request = MakeSendFolderRequest {
            folder_name: "test".to_string(),
            files: vec![MakeSendFolderEntry {
                path: "../secret.txt".to_string(),
                contents: b"data".to_vec(),
            }],
        };
        let err = make_send_folder(request).unwrap_err();
        assert!(matches!(err, MakeSendFolderError::InvalidPath(0)));
    }

    #[test]
    fn test_make_send_folder_size_metadata() {
        let request = MakeSendFolderRequest {
            folder_name: "sized".to_string(),
            files: vec![
                MakeSendFolderEntry {
                    path: "file.bin".to_string(),
                    contents: vec![0u8; 1024],
                },
                MakeSendFolderEntry {
                    path: "other.bin".to_string(),
                    contents: vec![0u8; 546],
                },
            ],
        };
        let result = make_send_folder(request).expect("should succeed");
        let size: usize = result
            .file
            .size
            .as_ref()
            .expect("size")
            .parse()
            .expect("numeric");
        assert_eq!(size, result.contents.len());
        // 1570 bytes of file content + zip headers for 2 entries
        assert_eq!(result.file.size.as_deref(), Some("1778"));
        assert_eq!(result.file.size_name.as_deref(), Some("1.7 KB"));
    }

    #[test]
    fn test_size_name_conversions() {
        assert_eq!(size_name(0), "0 Bytes");
        assert_eq!(size_name(19), "19 Bytes");
        assert_eq!(size_name(1024), "1 KB");
        assert_eq!(size_name(1570), "1.5 KB");
        assert_eq!(size_name(1024 * 1024), "1 MB");
        assert_eq!(size_name(1024 * 1024 * 1024), "1 GB");
    }
}
