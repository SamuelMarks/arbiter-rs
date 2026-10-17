//! Deterministic in-memory state store with fault-injection hooks (`arbiter-store::memory`).
//!
//! Provides a 100% deterministic [`StateStore`] implementation supporting atomic multi-key ACID
//! transactions, prefix scans, reactive watch streams, monotonic [`FencingToken`] generation,
//! and programmable fault injection (simulated I/O read/write errors, CAS conflicts, transaction
//! aborts, and split-brain conditions) for exhaustive unit and chaos simulation testing.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::FencingToken;
use serde::{Deserialize, Serialize};

use crate::traits::{StateStore, StoreTransaction, TransactionOp, VersionedRecord, WatchEvent};

/// Programmable fault-injection mode for [`MemoryStateStore`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryStoreFault {
    /// Fail all read and prefix scan operations.
    FailReads,
    /// Fail all write, delete, CAS, and token operations.
    FailWrites,
    /// Force a synthetic CAS conflict on the next CAS or transaction operation.
    ForceCasConflict,
    /// Force a transaction abort error on `commit_transaction`.
    AbortTransactions,
    /// Simulate split-brain detection on write operations.
    SplitBrain,
}

/// Deterministic in-memory [`StateStore`] implementation.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStateStore {
    /// Key-value records ordered lexicographically by key.
    records: BTreeMap<String, VersionedRecord>,
    /// Monotonic global revision counter.
    global_revision: u64,
    /// Current monotonic fencing token epoch.
    current_fencing_epoch: u64,
    /// Historical watch events paired with their event revision.
    watch_log: Vec<(u64, WatchEvent)>,
    /// Optional active fault injection.
    active_fault: Option<MemoryStoreFault>,
}

impl MemoryStateStore {
    /// Creates a new empty [`MemoryStateStore`].
    ///
    /// # Returns
    ///
    /// Empty [`MemoryStateStore`].
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
            global_revision: 0,
            current_fencing_epoch: 0,
            watch_log: Vec::new(),
            active_fault: None,
        }
    }

    /// Configures or clears a simulated fault mode for deterministic testing.
    ///
    /// # Arguments
    ///
    /// * `fault` - Optional [`MemoryStoreFault`] to inject.
    pub fn set_fault(&mut self, fault: Option<MemoryStoreFault>) {
        self.active_fault = fault;
    }

    /// Checks whether a read fault is currently injected.
    ///
    /// # Arguments
    ///
    /// * `key` - Key or prefix being read.
    ///
    /// # Returns
    ///
    /// `Ok(())` if no read fault is active.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `FailReads` is active.
    fn check_read_fault(&self, key: &str) -> ArbiterResult<()> {
        if matches!(self.active_fault, Some(MemoryStoreFault::FailReads)) {
            return Err(ArbiterError::StoreReadError {
                key: key.to_owned(),
                reason: "injected MemoryStoreFault::FailReads".to_owned(),
            });
        }
        Ok(())
    }

    /// Checks whether a write fault is currently injected.
    ///
    /// # Arguments
    ///
    /// * `key` - Key being mutated.
    ///
    /// # Returns
    ///
    /// `Ok(())` if no write fault is active.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] or [`ArbiterError::SplitBrainDetected`] if injected.
    fn check_write_fault(&self, key: &str) -> ArbiterResult<()> {
        match self.active_fault {
            Some(MemoryStoreFault::FailWrites) => Err(ArbiterError::StoreWriteError {
                key: key.to_owned(),
                reason: "injected MemoryStoreFault::FailWrites".to_owned(),
            }),
            Some(MemoryStoreFault::SplitBrain) => Err(ArbiterError::SplitBrainDetected {
                group_id: key.to_owned(),
                details: "injected MemoryStoreFault::SplitBrain".to_owned(),
            }),
            _ => Ok(()),
        }
    }
}

impl StateStore for MemoryStateStore {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.check_read_fault(key)?;
        Ok(self.records.get(key).cloned())
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.check_write_fault(key)?;
        self.global_revision = self.global_revision.saturating_add(1);
        let record = VersionedRecord {
            key: key.to_owned(),
            value,
            revision: self.global_revision,
        };
        self.records.insert(key.to_owned(), record.clone());
        self.watch_log
            .push((self.global_revision, WatchEvent::Put(record.clone())));
        Ok(record)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.check_write_fault(key)?;
        if self.records.remove(key).is_some() {
            self.global_revision = self.global_revision.saturating_add(1);
            self.watch_log.push((
                self.global_revision,
                WatchEvent::Delete {
                    key: key.to_owned(),
                    revision: self.global_revision,
                },
            ));
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.check_read_fault(prefix)?;
        Ok(self
            .records
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(_, v)| v.clone())
            .collect())
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.check_write_fault(key)?;
        if matches!(self.active_fault, Some(MemoryStoreFault::ForceCasConflict)) {
            return Err(ArbiterError::CasConflict {
                key: key.to_owned(),
                expected_rev: expected_revision,
                actual_rev: u64::MAX,
            });
        }
        let actual_rev = self.records.get(key).map_or(0, |r| r.revision);
        if actual_rev != expected_revision {
            return Err(ArbiterError::CasConflict {
                key: key.to_owned(),
                expected_rev: expected_revision,
                actual_rev,
            });
        }
        self.put(key, new_value)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.check_write_fault("transaction")?;
        if matches!(self.active_fault, Some(MemoryStoreFault::AbortTransactions)) {
            return Err(ArbiterError::TransactionAborted {
                reason: "injected MemoryStoreFault::AbortTransactions".to_owned(),
            });
        }
        if matches!(self.active_fault, Some(MemoryStoreFault::ForceCasConflict)) {
            return Err(ArbiterError::CasConflict {
                key: "transaction".to_owned(),
                expected_rev: 0,
                actual_rev: u64::MAX,
            });
        }

        // Phase 1: Validate all CompareAndSwap preconditions on a cloned snapshot so partial failures roll back cleanly.
        let mut staged_records = self.records.clone();
        let mut staged_rev = self.global_revision;
        let mut staged_events: Vec<(u64, WatchEvent)> = Vec::with_capacity(tx.operations.len());

        for op in &tx.operations {
            match op {
                TransactionOp::Put { key, value } => {
                    staged_rev = staged_rev.saturating_add(1);
                    let rec = VersionedRecord {
                        key: key.clone(),
                        value: value.clone(),
                        revision: staged_rev,
                    };
                    staged_records.insert(key.clone(), rec.clone());
                    staged_events.push((staged_rev, WatchEvent::Put(rec)));
                }
                TransactionOp::Delete { key } => {
                    if staged_records.remove(key).is_some() {
                        staged_rev = staged_rev.saturating_add(1);
                        staged_events.push((
                            staged_rev,
                            WatchEvent::Delete {
                                key: key.clone(),
                                revision: staged_rev,
                            },
                        ));
                    }
                }
                TransactionOp::CompareAndSwap {
                    key,
                    expected_revision,
                    new_value,
                } => {
                    let actual_rev = staged_records.get(key).map_or(0, |r| r.revision);
                    if actual_rev != *expected_revision {
                        return Err(ArbiterError::CasConflict {
                            key: key.clone(),
                            expected_rev: *expected_revision,
                            actual_rev,
                        });
                    }
                    staged_rev = staged_rev.saturating_add(1);
                    let rec = VersionedRecord {
                        key: key.clone(),
                        value: new_value.clone(),
                        revision: staged_rev,
                    };
                    staged_records.insert(key.clone(), rec.clone());
                    staged_events.push((staged_rev, WatchEvent::Put(rec)));
                }
            }
        }

        // Phase 2: Commit staged state atomically.
        self.records = staged_records;
        self.global_revision = staged_rev;
        self.watch_log.extend(staged_events);
        Ok(self.global_revision)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.check_write_fault("fencing_token")?;
        let next_epoch = self.current_fencing_epoch.checked_add(1).ok_or_else(|| {
            ArbiterError::ArithmeticOverflow {
                operation: "MemoryStateStore::next_fencing_token".to_owned(),
            }
        })?;
        self.current_fencing_epoch = next_epoch;
        FencingToken::new(next_epoch)
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.check_read_fault(prefix)?;
        Ok(self
            .watch_log
            .iter()
            .filter_map(|(rev, ev)| {
                if *rev < since_revision {
                    return None;
                }
                let key_matches = match ev {
                    WatchEvent::Put(rec) => rec.key.starts_with(prefix),
                    WatchEvent::Delete { key, .. } => key.starts_with(prefix),
                };
                if key_matches { Some(ev.clone()) } else { None }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_store_crud_cas_scan_and_watch() {
        let mut store = MemoryStateStore::new();
        assert_eq!(store.get("/agents/a1"), Ok(None));

        // CAS creation when expected_revision == 0
        let rec1 = store.cas("/agents/a1", 0, b"v1".to_vec());
        assert!(rec1.is_ok());

        // CAS conflict when expected_revision != 1
        assert!(store.cas("/agents/a1", 0, b"v2".to_vec()).is_err());

        // CAS update with expected_revision == 1
        assert!(store.cas("/agents/a1", 1, b"v2".to_vec()).is_ok());

        // Put another key and non-matching key
        assert!(store.put("/agents/a2", b"v1".to_vec()).is_ok());
        assert!(store.put("/tasks/t1", b"t".to_vec()).is_ok());

        let agents = store.scan_prefix("/agents/").unwrap_or_default();
        assert_eq!(agents.len(), 2);

        // Delete existing and non-existing, plus delete /tasks/t1 to cover non-matching Delete prefix in watch_events
        assert_eq!(store.delete("/agents/a2"), Ok(true));
        assert_eq!(store.delete("/agents/a2"), Ok(false));
        assert_eq!(store.delete("/tasks/t1"), Ok(true));

        // Watch events filtering by revision and prefix
        let all_agent_events = store.watch_events("/agents/", 1).unwrap_or_default();
        assert_eq!(all_agent_events.len(), 4);
        let recent_events = store.watch_events("/agents/", 3).unwrap_or_default();
        assert_eq!(recent_events.len(), 2);

        // Monotonic fencing tokens
        let t1 = store.next_fencing_token();
        let t2 = store.next_fencing_token();
        assert_eq!(t1.map(FencingToken::get), Ok(1));
        assert_eq!(t2.map(FencingToken::get), Ok(2));

        // Overflow fencing token when current_fencing_epoch == u64::MAX
        store.current_fencing_epoch = u64::MAX;
        assert!(store.next_fencing_token().is_err());
    }

    #[test]
    fn test_memory_store_transactions_and_fault_injection() {
        let mut store = MemoryStateStore::new();
        let _ = store.put("/k1", b"init".to_vec());

        // Successful multi-key transaction (Put + Delete + Delete absent + CAS)
        let tx_ok = StoreTransaction {
            operations: vec![
                TransactionOp::CompareAndSwap {
                    key: "/k1".to_owned(),
                    expected_revision: 1,
                    new_value: b"updated".to_vec(),
                },
                TransactionOp::Put {
                    key: "/k2".to_owned(),
                    value: b"val2".to_vec(),
                },
                TransactionOp::Delete {
                    key: "/k2".to_owned(),
                },
                TransactionOp::Delete {
                    key: "/absent".to_owned(),
                },
            ],
        };
        assert!(store.commit_transaction(&tx_ok).is_ok());
        assert_eq!(store.get("/k2"), Ok(None));

        // Failing transaction rolls back earlier Put in the same transaction
        let tx_conflict = StoreTransaction {
            operations: vec![
                TransactionOp::Put {
                    key: "/rolled_back".to_owned(),
                    value: b"dirty".to_vec(),
                },
                TransactionOp::CompareAndSwap {
                    key: "/k1".to_owned(),
                    expected_revision: 999,
                    new_value: b"bad".to_vec(),
                },
            ],
        };
        assert!(store.commit_transaction(&tx_conflict).is_err());
        assert_eq!(store.get("/rolled_back"), Ok(None));

        // Fault injections
        store.set_fault(Some(MemoryStoreFault::FailReads));
        assert!(store.get("/k1").is_err());
        assert!(store.scan_prefix("/").is_err());
        assert!(store.watch_events("/", 0).is_err());

        store.set_fault(Some(MemoryStoreFault::FailWrites));
        assert!(store.put("/k1", vec![]).is_err());
        assert!(store.delete("/k1").is_err());
        assert!(store.cas("/k1", 1, vec![]).is_err());
        assert!(store.commit_transaction(&tx_ok).is_err());
        assert!(store.next_fencing_token().is_err());

        store.set_fault(Some(MemoryStoreFault::SplitBrain));
        assert!(store.put("/k1", vec![]).is_err());

        store.set_fault(Some(MemoryStoreFault::ForceCasConflict));
        assert!(store.cas("/k1", 2, vec![]).is_err());
        assert!(store.commit_transaction(&tx_ok).is_err());

        store.set_fault(Some(MemoryStoreFault::AbortTransactions));
        assert!(store.commit_transaction(&tx_ok).is_err());

        store.set_fault(None);
        assert!(store.get("/k1").is_ok());
    }
}
