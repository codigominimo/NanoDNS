//! SQLite schema for NanoDNS persistence.

/// Schema version stored in the `metadata` table.
pub(crate) const SCHEMA_VERSION: i64 = 1;

/// Pragmas applied to every new database connection.
pub(crate) const PRAGMAS: &str = "
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;
";

/// Tables and indexes created on startup.
pub(crate) const INIT: &str = "
    CREATE TABLE IF NOT EXISTS metadata (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS query_history (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_ms   INTEGER NOT NULL,
        client_id      TEXT,
        client_address TEXT NOT NULL,
        transport      TEXT NOT NULL,
        domain         TEXT NOT NULL,
        query_type     INTEGER NOT NULL,
        query_class    INTEGER NOT NULL,
        decision       TEXT NOT NULL,
        response_code  INTEGER NOT NULL,
        ttl_secs       INTEGER NOT NULL,
        negative       INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_query_history_timestamp
        ON query_history (timestamp_ms);

    CREATE INDEX IF NOT EXISTS idx_query_history_domain
        ON query_history (domain);
";
