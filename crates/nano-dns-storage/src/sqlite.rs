//! SQLite-backed query history with an off-request-path writer thread.

#[cfg(test)]
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

use nano_dns_core::config::StorageConfig;
use nano_dns_core::error::Error as CoreError;
use nano_dns_core::error::Result as CoreResult;
use nano_dns_core::model::{Decision, QueryEvent, Transport};
use nano_dns_core::traits::Storage;
use rusqlite::Connection;
use tracing::warn;

use crate::error::StorageError;
use crate::schema;

/// Maximum number of events waiting to be written.
const MAX_PENDING: usize = 4_096;
/// Number of events committed in one SQLite transaction.
const BATCH_SIZE: usize = 256;

/// Writer command sent through the bounded queue.
enum Command {
    Event(QueryEvent),
    Flush(Sender<CoreResult<()>>),
    Shutdown,
}

/// Optional SQLite persistence for completed DNS queries.
///
/// [`Storage::record`] only enqueues an event. A dedicated thread batches
/// events into transactions so DNS request handlers never wait for disk I/O.
pub struct SqliteStorage {
    history: bool,
    sender: Option<Sender<Command>>,
    pending: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}

impl SqliteStorage {
    /// Open the configured database and start the background writer.
    pub fn open(config: &StorageConfig) -> CoreResult<Self> {
        if !config.enabled {
            return Err(StorageError::Disabled.into());
        }

        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| StorageError::CreateDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let connection = Connection::open(&config.path).map_err(|source| StorageError::Open {
            path: config.path.clone(),
            source,
        })?;
        connection
            .execute_batch(schema::PRAGMAS)
            .map_err(|error| StorageError::Schema(error.to_string()))?;
        connection
            .execute_batch(schema::INIT)
            .map_err(|error| StorageError::Schema(error.to_string()))?;
        connection
            .execute(
                "INSERT INTO metadata (key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![schema::SCHEMA_VERSION],
            )
            .map_err(|error| StorageError::Schema(error.to_string()))?;

        let (sender, receiver) = mpsc::channel();
        let pending = Arc::new(AtomicUsize::new(0));
        let worker_pending = Arc::clone(&pending);
        let worker = thread::Builder::new()
            .name("nano-dns-storage".to_owned())
            .spawn(move || writer_loop(connection, receiver, worker_pending))
            .map_err(StorageError::Spawn)?;

        Ok(Self {
            history: config.history,
            sender: Some(sender),
            pending,
            worker: Some(worker),
        })
    }

    /// Whether full query history is enabled.
    pub fn history_enabled(&self) -> bool {
        self.history
    }

    /// Queue one completed query for persistence.
    pub fn record_event(&self, event: QueryEvent) -> CoreResult<()> {
        if !self.history {
            return Ok(());
        }

        let sender = self.sender.as_ref().ok_or(StorageError::WriterStopped)?;
        self.pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_PENDING).then_some(current + 1)
            })
            .map_err(|_| StorageError::QueueFull)?;

        if sender.send(Command::Event(event)).is_err() {
            self.pending.fetch_sub(1, Ordering::AcqRel);
            return Err(StorageError::WriterStopped.into());
        }
        Ok(())
    }

    /// Wait until all queued events have been committed.
    pub fn flush_events(&self) -> CoreResult<()> {
        if !self.history {
            return Ok(());
        }

        let sender = self.sender.as_ref().ok_or(StorageError::WriterStopped)?;
        let (ack, response) = mpsc::channel();
        sender
            .send(Command::Flush(ack))
            .map_err(|_| StorageError::WriterStopped)?;
        response
            .recv()
            .map_err(|_| CoreError::from(StorageError::WriterStopped))?
    }
}

impl Storage for SqliteStorage {
    fn record(&self, event: QueryEvent) -> CoreResult<()> {
        self.record_event(event)
    }

    fn flush(&self) -> CoreResult<()> {
        self.flush_events()
    }
}

impl Drop for SqliteStorage {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take()
            && sender.send(Command::Shutdown).is_err()
        {
            warn!("SQLite writer already stopped before shutdown");
        }
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            warn!("SQLite writer thread panicked");
        }
    }
}

/// Consume commands on the dedicated writer thread.
fn writer_loop(mut connection: Connection, receiver: Receiver<Command>, pending: Arc<AtomicUsize>) {
    let mut batch = Vec::with_capacity(BATCH_SIZE);

    loop {
        match receiver.recv() {
            Ok(Command::Event(event)) => {
                batch.push(event);
                if batch.len() >= BATCH_SIZE {
                    let result = commit(&mut connection, &mut batch, &pending);
                    if let Err(error) = result {
                        warn!(%error, "cannot persist query history batch");
                    }
                }
            }
            Ok(Command::Flush(ack)) => {
                let result = commit(&mut connection, &mut batch, &pending);
                let _ = ack.send(result);
            }
            Ok(Command::Shutdown) => {
                if let Err(error) = commit(&mut connection, &mut batch, &pending) {
                    warn!(%error, "cannot persist final query history batch");
                }
                break;
            }
            Err(_) => break,
        }
    }
}

/// Write a batch in one transaction and release its queue reservations.
fn commit(
    connection: &mut Connection,
    batch: &mut Vec<QueryEvent>,
    pending: &AtomicUsize,
) -> CoreResult<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let result = write_batch(connection, batch);
    pending.fetch_sub(batch.len(), Ordering::AcqRel);
    batch.clear();
    result
}

/// Insert all events in one SQLite transaction.
fn write_batch(connection: &mut Connection, events: &[QueryEvent]) -> CoreResult<()> {
    let transaction = connection
        .transaction()
        .map_err(|error| StorageError::Write(error.to_string()))?;
    {
        let mut statement = transaction
            .prepare(
                "INSERT INTO query_history (
                    timestamp_ms, client_id, client_address, transport, domain,
                    query_type, query_class, decision, response_code, ttl_secs, negative
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )
            .map_err(|error| StorageError::Write(error.to_string()))?;

        for event in events {
            statement
                .execute(rusqlite::params![
                    i64::try_from(event.timestamp_ms).unwrap_or(i64::MAX),
                    event.client_id,
                    event.client_address.to_string(),
                    transport_name(event.transport),
                    event.name,
                    i64::from(event.query_type),
                    i64::from(event.query_class),
                    decision_name(event.decision),
                    i64::from(event.response_code),
                    i64::from(event.ttl_secs),
                    i64::from(event.negative),
                ])
                .map_err(|error| StorageError::Write(error.to_string()))?;
        }
    }
    transaction
        .commit()
        .map_err(|error| StorageError::Write(error.to_string()).into())
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Dot => "dot",
        Transport::Doh => "doh",
    }
}

fn decision_name(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "allow",
        Decision::Block => "block",
    }
}

/// Open a database path without going through [`SqliteStorage`], for tests.
#[cfg(test)]
fn open_connection(path: &Path) -> Connection {
    Connection::open(path).expect("test database must open")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::AtomicU64;

    use nano_dns_core::model::QueryContext;

    use super::*;

    static NEXT_DB: AtomicU64 = AtomicU64::new(0);

    fn temp_db_path() -> std::path::PathBuf {
        let suffix = NEXT_DB.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "nano-dns-storage-{}-{suffix}.sqlite3",
            std::process::id()
        ))
    }

    fn config(path: &std::path::Path, history: bool) -> StorageConfig {
        StorageConfig {
            enabled: true,
            path: path.to_path_buf(),
            history,
        }
    }

    fn event(name: &str, decision: Decision) -> QueryEvent {
        QueryEvent {
            timestamp_ms: 1_700_000_000_000,
            client_id: Some("phone".to_owned()),
            client_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            transport: QueryContext::new(
                nano_dns_core::model::ClientIdentity::new(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                Transport::Udp,
            )
            .transport,
            name: name.to_owned(),
            query_type: 1,
            query_class: 1,
            decision,
            response_code: 0,
            ttl_secs: 120,
            negative: false,
            cache_hit: false,
        }
    }

    #[test]
    fn disabled_storage_is_rejected() {
        let config = StorageConfig {
            enabled: false,
            path: temp_db_path(),
            history: false,
        };
        assert!(SqliteStorage::open(&config).is_err());
    }

    #[test]
    fn events_are_persisted_after_flush() {
        let path = temp_db_path();
        let storage = SqliteStorage::open(&config(&path, true)).expect("database must open");
        assert!(storage.history_enabled());

        storage
            .record(event("allowed.example.", Decision::Allow))
            .expect("event must be queued");
        storage
            .record(event("blocked.example.", Decision::Block))
            .expect("event must be queued");
        storage.flush().expect("events must be committed");
        drop(storage);

        let connection = open_connection(&path);
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM query_history", [], |row| row.get(0))
            .expect("history table must exist");
        assert_eq!(count, 2);

        let domain: String = connection
            .query_row(
                "SELECT domain FROM query_history WHERE decision = 'block'",
                [],
                |row| row.get(0),
            )
            .expect("blocked event must be stored");
        assert_eq!(domain, "blocked.example.");

        let version: String = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("metadata must exist");
        assert_eq!(version, schema::SCHEMA_VERSION.to_string());
        drop(connection);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn history_disabled_ignores_events() {
        let path = temp_db_path();
        let storage = SqliteStorage::open(&config(&path, false)).expect("database must open");
        assert!(!storage.history_enabled());

        storage
            .record(event("allowed.example.", Decision::Allow))
            .expect("recording is a no-op");
        storage.flush().expect("flush is a no-op");
        drop(storage);

        let connection = open_connection(&path);
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM query_history", [], |row| row.get(0))
            .expect("history table must exist");
        assert_eq!(count, 0);
        drop(connection);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite3-shm"));
    }
}
