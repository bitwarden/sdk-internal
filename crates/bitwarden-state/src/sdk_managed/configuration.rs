#[derive(Debug)]
/// Configuration for the database used by the SDK.
pub enum DatabaseConfiguration {
    /// SQLite configuration, used on native platforms
    Sqlite {
        /// The file path to the SQLite database. Databases for different users should be stored in
        /// different files.
        file_path: String,
    },

    /// IndexedDB configuration, used on WebAssembly platforms
    IndexedDb {
        /// The name of the IndexedDB database. Different users should have different database
        /// names to avoid conflicts.
        db_name: String,
    },
}
