//! Pluggable state store traits, transactional operations, watch events, and lease primitives (`arbiter-store::traits`).
//!
//! Defines the [`StateStore`] interface implemented by [`MemoryStateStore`](crate::memory::MemoryStateStore),
//! `RaftStateStore`, and external coordination adapters (`EtcdStore`, `PostgresStore`).

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::FencingToken;
use serde::{Deserialize, Serialize};

/// Versioned key-value record stored in a [`StateStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedRecord {
    /// Key string.
    pub key: String,
    /// Raw byte payload.
    pub value: Vec<u8>,
    /// Strictly increasing revision number of this key (`>= 1`).
    pub revision: u64,
}

/// Atomic mutation operation within a multi-key ACID [`StoreTransaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionOp {
    /// Unconditional write of `value` to `key`.
    Put {
        /// Target key.
        key: String,
        /// Byte payload to store.
        value: Vec<u8>,
    },
    /// Unconditional deletion of `key`.
    Delete {
        /// Target key to remove.
        key: String,
    },
    /// Conditional Compare-And-Swap requiring `key`'s current revision to equal `expected_revision` (`0` if key must not exist).
    CompareAndSwap {
        /// Target key.
        key: String,
        /// Required current revision (`0` means key must be absent).
        expected_revision: u64,
        /// New byte payload to write.
        new_value: Vec<u8>,
    },
}

/// Multi-key atomic transaction submitted to a [`StateStore`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreTransaction {
    /// Ordered sequence of operations to execute atomically.
    pub operations: Vec<TransactionOp>,
}

/// Reactive state transition event emitted on a [`StateStore`] watch log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WatchEvent {
    /// Key was created or updated to `record`.
    Put(VersionedRecord),
    /// Key was deleted at `revision`.
    Delete {
        /// Deleted key.
        key: String,
        /// Revision of the deletion event.
        revision: u64,
    },
}

/// Pluggable state coordination and consensus storage interface.
pub trait StateStore {
    /// Retrieves the current [`VersionedRecord`] for `key`, or `Ok(None)` if not present.
    ///
    /// # Arguments
    ///
    /// * `key` - Lookup key string slice.
    ///
    /// # Returns
    ///
    /// `Ok(Some(VersionedRecord))` if found, `Ok(None)` if absent.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`](arbiter_core::error::ArbiterError::StoreReadError) on storage failure.
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>>;

    /// Writes `value` to `key`, incrementing and returning the new revision.
    ///
    /// # Arguments
    ///
    /// * `key` - Target key.
    /// * `value` - Byte payload.
    ///
    /// # Returns
    ///
    /// Updated [`VersionedRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`](arbiter_core::error::ArbiterError::StoreWriteError) or
    /// [`ArbiterError::NotLeader`](arbiter_core::error::ArbiterError::NotLeader) on write failure.
    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord>;

    /// Deletes `key` if it exists, returning `true` if a record was removed.
    ///
    /// # Arguments
    ///
    /// * `key` - Target key to delete.
    ///
    /// # Returns
    ///
    /// `true` if the key existed and was removed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`](arbiter_core::error::ArbiterError::StoreWriteError) on failure.
    fn delete(&mut self, key: &str) -> ArbiterResult<bool>;

    /// Scans all records whose key starts with `prefix` in lexicographical key order.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Key prefix filter.
    ///
    /// # Returns
    ///
    /// Sorted vector of matching [`VersionedRecord`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`](arbiter_core::error::ArbiterError::StoreReadError) on failure.
    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>>;

    /// Performs an atomic Compare-And-Swap on `key`.
    ///
    /// # Arguments
    ///
    /// * `key` - Target key.
    /// * `expected_revision` - Expected current revision (`0` if key must not exist yet).
    /// * `new_value` - New payload to store if revision matches.
    ///
    /// # Returns
    ///
    /// Updated [`VersionedRecord`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CasConflict`](arbiter_core::error::ArbiterError::CasConflict) on revision mismatch.
    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord>;

    /// Executes a multi-key ACID [`StoreTransaction`].
    ///
    /// If any operation fails (e.g., a `CompareAndSwap` conflict), no mutations are applied.
    ///
    /// # Arguments
    ///
    /// * `tx` - Transaction specification.
    ///
    /// # Returns
    ///
    /// New global store revision after committing `tx`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CasConflict`](arbiter_core::error::ArbiterError::CasConflict) or
    /// [`ArbiterError::TransactionAborted`](arbiter_core::error::ArbiterError::TransactionAborted) on failure.
    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64>;

    /// Issues the next strictly monotonic [`FencingToken`] from the consensus store.
    ///
    /// # Returns
    ///
    /// Newly incremented [`FencingToken`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`](arbiter_core::error::ArbiterError::StoreWriteError) or
    /// [`ArbiterError::ArithmeticOverflow`](arbiter_core::error::ArbiterError::ArithmeticOverflow).
    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken>;

    /// Returns all [`WatchEvent`]s matching `prefix` that occurred since `since_revision`.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Key prefix filter.
    /// * `since_revision` - Inclusive lower-bound revision number.
    ///
    /// # Returns
    ///
    /// Ordered vector of [`WatchEvent`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`](arbiter_core::error::ArbiterError::StoreReadError) on failure.
    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>>;
}
