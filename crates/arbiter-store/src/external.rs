//! Pluggable external coordination backend adapters (`EtcdStore`, `PostgresStore`) (`arbiter-store::external`).
//!
//! Wraps external coordination drivers (`EtcdTransportDriver`, `PostgresTransportDriver`) in
//! [`StateStore`] implementations with namespace prefixing and deterministic mock transport
//! drivers for 100% offline test coverage.

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::FencingToken;
use serde::{Deserialize, Serialize};

use crate::memory::MemoryStateStore;
use crate::traits::{StateStore, StoreTransaction, VersionedRecord, WatchEvent};

/// Transport driver trait for an external `etcd` v3 cluster.
pub trait EtcdTransportDriver {
    /// Checks connectivity to the `etcd` v3 endpoint.
    ///
    /// # Returns
    ///
    /// `Ok(())` if healthy.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] or [`ArbiterError::StoreWriteError`] if unreachable.
    fn check_connected(&self) -> ArbiterResult<()>;

    /// Returns a shared reference to the backing KV store state.
    ///
    /// # Returns
    ///
    /// Reference to [`MemoryStateStore`].
    fn backing_store(&self) -> &MemoryStateStore;

    /// Returns a mutable reference to the backing KV store state.
    ///
    /// # Returns
    ///
    /// Mutable reference to [`MemoryStateStore`].
    fn backing_store_mut(&mut self) -> &mut MemoryStateStore;
}

/// Deterministic mock `etcd` v3 transport driver for testing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockEtcdDriver {
    /// Simulated connection health flag.
    pub connected: bool,
    /// Backing state store.
    pub store: MemoryStateStore,
}

impl MockEtcdDriver {
    /// Creates a new connected [`MockEtcdDriver`].
    ///
    /// # Returns
    ///
    /// Connected [`MockEtcdDriver`].
    pub const fn new_connected() -> Self {
        Self {
            connected: true,
            store: MemoryStateStore::new(),
        }
    }
}

impl EtcdTransportDriver for MockEtcdDriver {
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.connected {
            return Err(ArbiterError::StoreReadError {
                key: "etcd".to_owned(),
                reason: "etcd v3 gRPC endpoint disconnected".to_owned(),
            });
        }
        Ok(())
    }

    fn backing_store(&self) -> &MemoryStateStore {
        &self.store
    }

    fn backing_store_mut(&mut self) -> &mut MemoryStateStore {
        &mut self.store
    }
}

/// Pluggable [`StateStore`] adapter backed by an `etcd` v3 transport driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtcdStore<D: EtcdTransportDriver> {
    /// Key namespace prefix (e.g., `"/arbiter"`).
    namespace: String,
    /// Underlying `etcd` transport driver.
    driver: D,
}

impl<D: EtcdTransportDriver> EtcdStore<D> {
    /// Creates a new [`EtcdStore`] with the given key `namespace` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `namespace` - Key prefix prepended to all keys.
    /// * `driver` - Transport driver implementation.
    ///
    /// # Returns
    ///
    /// Initialized [`EtcdStore`].
    pub fn new(namespace: &str, driver: D) -> Self {
        Self {
            namespace: namespace.to_owned(),
            driver,
        }
    }

    /// Returns a mutable reference to the underlying transport driver.
    ///
    /// # Returns
    ///
    /// Mutable reference `&mut D`.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Formats a namespaced key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Namespaced key string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.namespace, key)
    }
}

impl<D: EtcdTransportDriver> StateStore for EtcdStore<D> {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver.backing_store().get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver.backing_store_mut().put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver.backing_store_mut().delete(&scoped)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .backing_store_mut()
            .cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

/// Transport driver trait for an external `PostgreSQL` transactional coordination database.
pub trait PostgresTransportDriver {
    /// Checks connectivity to the `PostgreSQL` connection pool.
    ///
    /// # Returns
    ///
    /// `Ok(())` if healthy.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the connection pool is offline.
    fn check_connected(&self) -> ArbiterResult<()>;

    /// Returns a shared reference to the backing relational KV table state.
    ///
    /// # Returns
    ///
    /// Reference to [`MemoryStateStore`].
    fn backing_store(&self) -> &MemoryStateStore;

    /// Returns a mutable reference to the backing relational KV table state.
    ///
    /// # Returns
    ///
    /// Mutable reference to [`MemoryStateStore`].
    fn backing_store_mut(&mut self) -> &mut MemoryStateStore;
}

/// Deterministic mock `PostgreSQL` transport driver for testing.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockPostgresDriver {
    /// Simulated connection pool health flag.
    pub connected: bool,
    /// Backing relational state table.
    pub store: MemoryStateStore,
}

impl MockPostgresDriver {
    /// Creates a new connected [`MockPostgresDriver`].
    ///
    /// # Returns
    ///
    /// Connected [`MockPostgresDriver`].
    pub const fn new_connected() -> Self {
        Self {
            connected: true,
            store: MemoryStateStore::new(),
        }
    }
}

impl PostgresTransportDriver for MockPostgresDriver {
    fn check_connected(&self) -> ArbiterResult<()> {
        if !self.connected {
            return Err(ArbiterError::StoreReadError {
                key: "postgres".to_owned(),
                reason: "PostgreSQL connection pool offline".to_owned(),
            });
        }
        Ok(())
    }

    fn backing_store(&self) -> &MemoryStateStore {
        &self.store
    }

    fn backing_store_mut(&mut self) -> &mut MemoryStateStore {
        &mut self.store
    }
}

/// Pluggable [`StateStore`] adapter backed by a `PostgreSQL` transactional table driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostgresStore<D: PostgresTransportDriver> {
    /// Table or schema prefix.
    schema_prefix: String,
    /// Underlying `PostgreSQL` transport driver.
    driver: D,
}

impl<D: PostgresTransportDriver> PostgresStore<D> {
    /// Creates a new [`PostgresStore`] with `schema_prefix` and `driver`.
    ///
    /// # Arguments
    ///
    /// * `schema_prefix` - Prefix prepended to keys.
    /// * `driver` - Transport driver implementation.
    ///
    /// # Returns
    ///
    /// Initialized [`PostgresStore`].
    pub fn new(schema_prefix: &str, driver: D) -> Self {
        Self {
            schema_prefix: schema_prefix.to_owned(),
            driver,
        }
    }

    /// Returns a mutable reference to the underlying transport driver.
    ///
    /// # Returns
    ///
    /// Mutable reference `&mut D`.
    pub fn driver_mut(&mut self) -> &mut D {
        &mut self.driver
    }

    /// Formats a prefixed key.
    ///
    /// # Arguments
    ///
    /// * `key` - User key.
    ///
    /// # Returns
    ///
    /// Prefixed key string.
    fn scoped_key(&self, key: &str) -> String {
        format!("{}{}", self.schema_prefix, key)
    }
}

impl<D: PostgresTransportDriver> StateStore for PostgresStore<D> {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver.backing_store().get(&self.scoped_key(key))
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver.backing_store_mut().put(&scoped, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver.backing_store_mut().delete(&scoped)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .scan_prefix(&self.scoped_key(prefix))
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.driver.check_connected()?;
        let scoped = self.scoped_key(key);
        self.driver
            .backing_store_mut()
            .cas(&scoped, expected_revision, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().commit_transaction(tx)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.driver.check_connected()?;
        self.driver.backing_store_mut().next_fencing_token()
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.driver.check_connected()?;
        self.driver
            .backing_store()
            .watch_events(&self.scoped_key(prefix), since_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etcd_store_adapter_connected_and_disconnected() {
        let mut etcd = EtcdStore::new("/arbiter", MockEtcdDriver::new_connected());

        assert!(etcd.put("/k1", b"v1".to_vec()).is_ok());
        assert!(etcd.get("/k1").unwrap_or_default().is_some());
        assert!(etcd.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(etcd.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(
            etcd.commit_transaction(&StoreTransaction::default())
                .is_ok()
        );
        assert_eq!(etcd.next_fencing_token().map(FencingToken::get), Ok(1));
        assert!(!etcd.watch_events("/", 1).unwrap_or_default().is_empty());
        assert_eq!(etcd.delete("/k1"), Ok(true));

        // Disconnect driver and verify all StateStore methods return errors
        etcd.driver_mut().connected = false;
        assert!(etcd.get("/k1").is_err());
        assert!(etcd.put("/k1", vec![]).is_err());
        assert!(etcd.delete("/k1").is_err());
        assert!(etcd.scan_prefix("/").is_err());
        assert!(etcd.cas("/k1", 0, vec![]).is_err());
        assert!(
            etcd.commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(etcd.next_fencing_token().is_err());
        assert!(etcd.watch_events("/", 0).is_err());
    }

    #[test]
    fn test_postgres_store_adapter_connected_and_disconnected() {
        let mut pg = PostgresStore::new("arbiter_", MockPostgresDriver::new_connected());

        assert!(pg.put("/k1", b"v1".to_vec()).is_ok());
        assert!(pg.get("/k1").unwrap_or_default().is_some());
        assert!(pg.cas("/k1", 1, b"v2".to_vec()).is_ok());
        assert_eq!(pg.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(pg.commit_transaction(&StoreTransaction::default()).is_ok());
        assert_eq!(pg.next_fencing_token().map(FencingToken::get), Ok(1));
        assert!(!pg.watch_events("/", 1).unwrap_or_default().is_empty());
        assert_eq!(pg.delete("/k1"), Ok(true));

        // Disconnect driver and verify all StateStore methods return errors
        pg.driver_mut().connected = false;
        assert!(pg.get("/k1").is_err());
        assert!(pg.put("/k1", vec![]).is_err());
        assert!(pg.delete("/k1").is_err());
        assert!(pg.scan_prefix("/").is_err());
        assert!(pg.cas("/k1", 0, vec![]).is_err());
        assert!(pg.commit_transaction(&StoreTransaction::default()).is_err());
        assert!(pg.next_fencing_token().is_err());
        assert!(pg.watch_events("/", 0).is_err());
    }
}
