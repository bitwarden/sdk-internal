use std::path::PathBuf;

#[derive(Debug)]
/// Configuration for the database used by the SDK.
pub enum DatabaseConfiguration {
    /// SQLite configuration, used on native platforms
    Sqlite {
        /// The name of the SQLite database. Different users should have different database
        /// names to avoid conflicts.
        db_name: String,
        /// The file path to the SQLite database. Databases for different users should be stored in
        /// different files.
        folder_path: PathBuf,
    },

    /// IndexedDB configuration, used on WebAssembly platforms
    IndexedDb {
        /// The name of the IndexedDB database. Different users should have different database
        /// names to avoid conflicts.
        db_name: String,
    },
}
