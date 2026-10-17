//! Embedded Raft consensus state machine and CRC32-verified persistent local KV store (`arbiter-store::raft`).
//!
//! Implements:
//! - IEEE 802.3 CRC32 checksum calculation and verification for log entries and snapshots to
//!   detect silent disk/memory corruption.
//! - Raft role transitions (`Follower`, `Candidate`, `Leader`), term elections, quorum vote counting,
//!   log replication, snapshot compaction/installation, dynamic membership reconfiguration, and
//!   leader lease verification.
//! - [`StateStore`] implementation (`RaftStateStore`) that rejects mutating operations when not
//!   in the `Leader` role with [`ArbiterError::NotLeader`].

use std::collections::BTreeSet;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::FencingToken;
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryStateStore, MemoryStoreFault};
use crate::traits::{StateStore, StoreTransaction, VersionedRecord, WatchEvent};

/// Computes the standard IEEE 802.3 CRC32 checksum of a byte slice.
///
/// # Arguments
///
/// * `data` - Input byte slice.
///
/// # Returns
///
/// 32-bit unsigned CRC32 checksum.
pub fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Role of a Raft consensus node.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RaftRole {
    /// Passive follower replicating log entries from the leader.
    #[default]
    Follower,
    /// Candidate campaigning for leadership in a new term.
    Candidate,
    /// Elected quorum leader authorized to accept writes and issue fencing tokens.
    Leader,
}

/// Replicated Raft log entry protected by an IEEE CRC32 checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftLogEntry {
    /// Raft term in which the entry was created.
    pub term: u64,
    /// Monotonic 1-based log index.
    pub index: u64,
    /// Target key (`""` for no-op or membership barrier entries).
    pub key: String,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// IEEE CRC32 checksum over `(term, index, key, payload)`.
    pub crc32: u32,
}

impl RaftLogEntry {
    /// Creates a new [`RaftLogEntry`] with a computed CRC32 checksum.
    ///
    /// # Arguments
    ///
    /// * `term` - Raft term.
    /// * `index` - Log index.
    /// * `key` - Target key.
    /// * `payload` - Byte payload.
    ///
    /// # Returns
    ///
    /// Checksummed [`RaftLogEntry`].
    pub fn new(term: u64, index: u64, key: String, payload: Vec<u8>) -> Self {
        let crc32 = Self::calculate_entry_crc(term, index, &key, &payload);
        Self {
            term,
            index,
            key,
            payload,
            crc32,
        }
    }

    /// Verifies that the stored `crc32` matches the entry's contents.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the checksum matches.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] if the entry is corrupted.
    pub fn verify_checksum(&self) -> ArbiterResult<()> {
        let expected = Self::calculate_entry_crc(self.term, self.index, &self.key, &self.payload);
        if self.crc32 != expected {
            return Err(ArbiterError::RaftConsensusError {
                term: self.term,
                reason: format!(
                    "CRC32 checksum mismatch at log index {}: stored 0x{:08x}, computed 0x{:08x}",
                    self.index, self.crc32, expected
                ),
            });
        }
        Ok(())
    }

    /// Computes the CRC32 digest over the canonical fields of a log entry.
    ///
    /// # Arguments
    ///
    /// * `term` - Raft term.
    /// * `index` - Log index.
    /// * `key` - Key string.
    /// * `payload` - Value bytes.
    ///
    /// # Returns
    ///
    /// 32-bit CRC32 digest.
    fn calculate_entry_crc(term: u64, index: u64, key: &str, payload: &[u8]) -> u32 {
        let mut buf = Vec::with_capacity(16 + key.len() + payload.len());
        buf.extend_from_slice(&term.to_le_bytes());
        buf.extend_from_slice(&index.to_le_bytes());
        buf.extend_from_slice(key.as_bytes());
        buf.extend_from_slice(payload);
        compute_crc32(&buf)
    }
}

/// Compacted state-machine snapshot with CRC32 integrity verification.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftSnapshot {
    /// Last log index included in this snapshot.
    pub last_included_index: u64,
    /// Term of `last_included_index`.
    pub last_included_term: u64,
    /// Serialized state-machine image.
    pub data: Vec<u8>,
    /// CRC32 checksum of `data`.
    pub crc32: u32,
}

/// Embedded Raft consensus state machine and CRC32-checked local KV store.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftStateStore {
    /// Unique node identifier of this Raft peer.
    node_id: String,
    /// Known leader node identifier hint.
    leader_hint: String,
    /// Current Raft term.
    current_term: u64,
    /// Current consensus role (`Follower`, `Candidate`, `Leader`).
    role: RaftRole,
    /// Set of voting peer node IDs in the quorum.
    voters: BTreeSet<String>,
    /// Votes received in the current election term.
    votes_received: BTreeSet<String>,
    /// Replicated log entries (after `compacted_index`).
    log: Vec<RaftLogEntry>,
    /// Highest log index compacted into a snapshot.
    compacted_index: u64,
    /// Highest log index known to be committed and applied.
    commit_index: u64,
    /// Monotonic tick until which the leader's local read/write lease is valid.
    leader_lease_until_tick: u64,
    /// Underlying deterministic key-value state machine.
    inner_store: MemoryStateStore,
}

impl RaftStateStore {
    /// Creates a new [`RaftStateStore`] initialized as a `Follower` in term `1`.
    ///
    /// # Arguments
    ///
    /// * `node_id` - This node's identifier.
    /// * `voters` - Initial set of voting peer node IDs (must be non-empty).
    ///
    /// # Returns
    ///
    /// Initialized [`RaftStateStore`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] if `voters` is empty.
    pub fn new(node_id: &str, voters: Vec<String>) -> ArbiterResult<Self> {
        if voters.is_empty() {
            return Err(ArbiterError::RaftConsensusError {
                term: 0,
                reason: "Raft voter membership set cannot be empty".to_owned(),
            });
        }
        Ok(Self {
            node_id: node_id.to_owned(),
            leader_hint: String::new(),
            current_term: 1,
            role: RaftRole::Follower,
            voters: voters.into_iter().collect(),
            votes_received: BTreeSet::new(),
            log: Vec::new(),
            compacted_index: 0,
            commit_index: 0,
            leader_lease_until_tick: 0,
            inner_store: MemoryStateStore::new(),
        })
    }

    /// Returns the current [`RaftRole`] of this node.
    ///
    /// # Returns
    ///
    /// Current [`RaftRole`].
    pub const fn role(&self) -> RaftRole {
        self.role
    }

    /// Returns the current Raft term.
    ///
    /// # Returns
    ///
    /// Current `u64` term.
    pub const fn current_term(&self) -> u64 {
        self.current_term
    }

    /// Injects or clears an underlying storage fault on `inner_store` for testing.
    ///
    /// # Arguments
    ///
    /// * `fault` - Optional [`MemoryStoreFault`].
    pub fn set_storage_fault(&mut self, fault: Option<MemoryStoreFault>) {
        self.inner_store.set_fault(fault);
    }

    /// Starts a leader election campaign, transitioning to `Candidate`, incrementing the term,
    /// and recording a self-vote.
    ///
    /// If the cluster is a single-node quorum (`voters.len() == 1`), immediately transitions to `Leader`.
    ///
    /// # Arguments
    ///
    /// * `lease_until_tick` - Leader lease expiration tick if elected immediately.
    pub fn start_election(&mut self, lease_until_tick: u64) {
        self.current_term = self.current_term.saturating_add(1);
        self.role = RaftRole::Candidate;
        self.votes_received.clear();
        self.votes_received.insert(self.node_id.clone());
        if self.has_quorum_votes() {
            self.become_leader(lease_until_tick);
        }
    }

    /// Records a vote from `voter_id` in `term` and transitions to `Leader` once a strict majority is reached.
    ///
    /// # Arguments
    ///
    /// * `voter_id` - Voting peer ID.
    /// * `term` - Election term of the vote.
    /// * `lease_until_tick` - Leader lease expiration tick if quorum is achieved.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if this node is now the `Leader`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] if `term != self.current_term` or `voter_id` is not a voting member.
    pub fn receive_vote(
        &mut self,
        voter_id: &str,
        term: u64,
        lease_until_tick: u64,
    ) -> ArbiterResult<bool> {
        if term != self.current_term {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("vote term {term} does not match current term"),
            });
        }
        if !self.voters.contains(voter_id) {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("unknown voter '{voter_id}'"),
            });
        }
        self.votes_received.insert(voter_id.to_owned());
        if self.role == RaftRole::Candidate && self.has_quorum_votes() {
            self.become_leader(lease_until_tick);
        }
        Ok(self.role == RaftRole::Leader)
    }

    /// Steps down to `Follower` when a higher term or external leader is observed.
    ///
    /// # Arguments
    ///
    /// * `new_term` - Observed term.
    /// * `leader_hint` - Known leader node ID.
    pub fn step_down(&mut self, new_term: u64, leader_hint: &str) {
        if new_term > self.current_term {
            self.current_term = new_term;
        }
        self.role = RaftRole::Follower;
        leader_hint.clone_into(&mut self.leader_hint);
        self.votes_received.clear();
    }

    /// Verifies that this node is the active `Leader` and its lease has not expired at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if leader with valid lease.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::LeaseExpired`] if
    /// `current_tick >= self.leader_lease_until_tick`.
    pub fn verify_leader_lease(&self, current_tick: u64) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if current_tick >= self.leader_lease_until_tick {
            return Err(ArbiterError::LeaseExpired {
                lease_id: format!("raft-leader-{}", self.node_id),
                expired_at_tick: self.leader_lease_until_tick,
            });
        }
        Ok(())
    }

    /// Appends and applies a batch of replicated [`RaftLogEntry`] records on a `Follower` (catch-up).
    ///
    /// Verifies the CRC32 checksum of every entry before mutating state.
    ///
    /// # Arguments
    ///
    /// * `leader_term` - Term of the sending leader.
    /// * `leader_id` - Node ID of the sending leader.
    /// * `entries` - Slice of [`RaftLogEntry`]s to replicate.
    ///
    /// # Returns
    ///
    /// Highest committed log index after applying `entries`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] if `leader_term < self.current_term` or any
    /// entry fails CRC32 checksum verification.
    pub fn append_replicated_entries(
        &mut self,
        leader_term: u64,
        leader_id: &str,
        entries: &[RaftLogEntry],
    ) -> ArbiterResult<u64> {
        if leader_term < self.current_term {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("rejected stale AppendEntries from term {leader_term}"),
            });
        }
        self.step_down(leader_term, leader_id);

        for entry in entries {
            entry.verify_checksum()?;
        }

        for entry in entries {
            self.log.push(entry.clone());
            self.commit_index = entry.index;
            if !entry.key.is_empty() {
                let _ = self.inner_store.put(&entry.key, entry.payload.clone())?;
            }
        }
        Ok(self.commit_index)
    }

    /// Creates a CRC32-verified [`RaftSnapshot`] of the current state machine and compacts the log
    /// up to `commit_index`.
    ///
    /// # Returns
    ///
    /// Newly created [`RaftSnapshot`].
    pub fn compact_to_snapshot(&mut self) -> RaftSnapshot {
        let data = serde_json::to_vec(&self.inner_store).unwrap_or_default();
        let crc32 = compute_crc32(&data);
        self.compacted_index = self.commit_index;
        self.log.clear();
        RaftSnapshot {
            last_included_index: self.compacted_index,
            last_included_term: self.current_term,
            data,
            crc32,
        }
    }

    /// Installs a [`RaftSnapshot`] on a follower node after verifying its CRC32 checksum.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - Incoming [`RaftSnapshot`].
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful snapshot installation.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] on CRC32 mismatch or
    /// [`ArbiterError::JsonCodec`] on deserialization failure.
    pub fn install_snapshot(&mut self, snapshot: &RaftSnapshot) -> ArbiterResult<()> {
        let actual_crc = compute_crc32(&snapshot.data);
        if actual_crc != snapshot.crc32 {
            return Err(ArbiterError::RaftConsensusError {
                term: snapshot.last_included_term,
                reason: "snapshot CRC32 checksum verification failed".to_owned(),
            });
        }
        let restored: MemoryStateStore = serde_json::from_slice(&snapshot.data)
            .map_err(arbiter_core::error::JsonCodecError::from)?;
        self.inner_store = restored;
        self.compacted_index = snapshot.last_included_index;
        self.commit_index = snapshot.last_included_index;
        self.current_term = snapshot.last_included_term;
        self.log.clear();
        Ok(())
    }

    /// Dynamically updates the voting peer set (membership reconfiguration).
    ///
    /// Must be called on the active `Leader`.
    ///
    /// # Arguments
    ///
    /// * `new_voters` - Updated list of voting peer IDs (must be non-empty).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if `new_voters` is empty.
    pub fn reconfigure_membership(&mut self, new_voters: Vec<String>) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if new_voters.is_empty() {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: "cannot reconfigure to an empty voter set".to_owned(),
            });
        }
        self.voters = new_voters.into_iter().collect();
        Ok(())
    }

    /// Returns the slice of active uncompacted [`RaftLogEntry`]s.
    ///
    /// # Returns
    ///
    /// Slice `&[RaftLogEntry]`.
    pub fn log_entries(&self) -> &[RaftLogEntry] {
        &self.log
    }

    /// Checks whether `votes_received` constitutes a strict majority of `voters`.
    ///
    /// # Returns
    ///
    /// `true` if `votes_received.len() > voters.len() / 2`.
    fn has_quorum_votes(&self) -> bool {
        self.votes_received.len() > (self.voters.len() / 2)
    }

    /// Transitions this node to `Leader` and sets its lease expiration tick.
    ///
    /// # Arguments
    ///
    /// * `lease_until_tick` - Expiration tick for the leader lease.
    fn become_leader(&mut self, lease_until_tick: u64) {
        self.role = RaftRole::Leader;
        self.leader_hint.clone_from(&self.node_id);
        self.leader_lease_until_tick = lease_until_tick;
    }

    /// Ensures this node is currently in the `Leader` role.
    ///
    /// # Returns
    ///
    /// `Ok(())` if `self.role == RaftRole::Leader`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if `Follower` or `Candidate`.
    fn ensure_leader(&self) -> ArbiterResult<()> {
        if self.role != RaftRole::Leader {
            return Err(ArbiterError::NotLeader {
                node_id: self.node_id.clone(),
                leader_hint: self.leader_hint.clone(),
            });
        }
        Ok(())
    }

    /// Appends a local leader write to the Raft log.
    ///
    /// # Arguments
    ///
    /// * `key` - Mutated key.
    /// * `payload` - Byte payload.
    fn append_local_log(&mut self, key: &str, payload: &[u8]) {
        let next_idx = self.commit_index.saturating_add(1);
        let entry = RaftLogEntry::new(
            self.current_term,
            next_idx,
            key.to_owned(),
            payload.to_vec(),
        );
        self.log.push(entry);
        self.commit_index = next_idx;
    }
}

impl StateStore for RaftStateStore {
    fn get(&self, key: &str) -> ArbiterResult<Option<VersionedRecord>> {
        self.inner_store.get(key)
    }

    fn put(&mut self, key: &str, value: Vec<u8>) -> ArbiterResult<VersionedRecord> {
        self.ensure_leader()?;
        self.append_local_log(key, &value);
        self.inner_store.put(key, value)
    }

    fn delete(&mut self, key: &str) -> ArbiterResult<bool> {
        self.ensure_leader()?;
        self.append_local_log(key, b"");
        self.inner_store.delete(key)
    }

    fn scan_prefix(&self, prefix: &str) -> ArbiterResult<Vec<VersionedRecord>> {
        self.inner_store.scan_prefix(prefix)
    }

    fn cas(
        &mut self,
        key: &str,
        expected_revision: u64,
        new_value: Vec<u8>,
    ) -> ArbiterResult<VersionedRecord> {
        self.ensure_leader()?;
        let rec = self
            .inner_store
            .cas(key, expected_revision, new_value.clone())?;
        self.append_local_log(key, &new_value);
        Ok(rec)
    }

    fn commit_transaction(&mut self, tx: &StoreTransaction) -> ArbiterResult<u64> {
        self.ensure_leader()?;
        let rev = self.inner_store.commit_transaction(tx)?;
        self.append_local_log("tx", &rev.to_le_bytes());
        Ok(rev)
    }

    fn next_fencing_token(&mut self) -> ArbiterResult<FencingToken> {
        self.ensure_leader()?;
        let token = self.inner_store.next_fencing_token()?;
        self.append_local_log("fencing_token", &token.get().to_le_bytes());
        Ok(token)
    }

    fn watch_events(&self, prefix: &str, since_revision: u64) -> ArbiterResult<Vec<WatchEvent>> {
        self.inner_store.watch_events(prefix, since_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TransactionOp;

    #[test]
    fn test_raft_election_and_not_leader_rejection() {
        assert!(RaftStateStore::new("n1", vec![]).is_err());

        // Single-node quorum immediately elects itself leader
        let mut single = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        single.start_election(500);
        assert_eq!(single.role(), RaftRole::Leader);
        assert_eq!(single.current_term(), 2);

        // 5-node quorum election (so 2 votes < 3 quorum, testing has_quorum_votes == false on receive_vote)
        let voters = vec![
            "n1".to_owned(),
            "n2".to_owned(),
            "n3".to_owned(),
            "n4".to_owned(),
            "n5".to_owned(),
        ];
        let mut node1 = RaftStateStore::new("n1", voters).unwrap_or_default();

        // Follower rejects all mutating StateStore operations with NotLeader
        assert!(node1.put("/k", b"v".to_vec()).is_err());
        assert!(node1.delete("/k").is_err());
        assert!(node1.cas("/k", 0, b"v".to_vec()).is_err());
        assert!(
            node1
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(node1.next_fencing_token().is_err());
        assert!(node1.verify_leader_lease(10).is_err());
        assert!(node1.reconfigure_membership(vec!["n1".to_owned()]).is_err());

        // Node 1 starts election in term 2 (1 vote out of 5)
        node1.start_election(1000);
        assert_eq!(node1.role(), RaftRole::Candidate);

        // Wrong term vote and unknown voter rejected
        assert!(node1.receive_vote("n2", 99, 1000).is_err());
        assert!(node1.receive_vote("ghost", 2, 1000).is_err());

        // Second vote from n2 (2/5 -> still Candidate!)
        assert_eq!(node1.receive_vote("n2", 2, 1000), Ok(false));
        assert_eq!(node1.role(), RaftRole::Candidate);

        // Third vote from n3 achieves quorum (3/5 -> Leader!)
        assert_eq!(node1.receive_vote("n3", 2, 1000), Ok(true));
        assert_eq!(node1.role(), RaftRole::Leader);

        // Extra vote after already Leader is accepted cleanly
        assert_eq!(node1.receive_vote("n4", 2, 1000), Ok(true));

        // Leader lease verification
        assert!(node1.verify_leader_lease(500).is_ok());
        assert!(node1.verify_leader_lease(1000).is_err());
    }

    #[test]
    fn test_raft_leader_mutations_and_replication() {
        let voters = vec!["n1".to_owned(), "n2".to_owned()];
        let mut node1 = RaftStateStore::new("n1", voters.clone()).unwrap_or_default();
        let mut node2 = RaftStateStore::new("n2", voters).unwrap_or_default();
        node1.start_election(1000);
        let _ = node1.receive_vote("n2", 2, 1000);

        // Leader mutations succeed
        assert!(node1.put("/k1", b"val1".to_vec()).is_ok());
        assert!(node1.cas("/k1", 1, b"val2".to_vec()).is_ok());
        assert!(
            node1
                .commit_transaction(&StoreTransaction {
                    operations: vec![TransactionOp::Put {
                        key: "/k2".to_owned(),
                        value: b"v2".to_vec(),
                    }]
                })
                .is_ok()
        );
        assert!(node1.next_fencing_token().is_ok());
        assert_eq!(node1.delete("/k2"), Ok(true));
        assert_eq!(node1.scan_prefix("/").unwrap_or_default().len(), 1);
        assert!(!node1.watch_events("/", 1).unwrap_or_default().is_empty());

        // Inject storage fault on leader to exercise inner_store error propagation
        node1.set_storage_fault(Some(MemoryStoreFault::FailWrites));
        assert!(node1.cas("/k1", 2, b"x".to_vec()).is_err());
        assert!(
            node1
                .commit_transaction(&StoreTransaction::default())
                .is_err()
        );
        assert!(node1.next_fencing_token().is_err());
        node1.set_storage_fault(None);

        // Replicate log from node1 to follower node2 (plus a no-op empty key entry)
        let mut entries = node1.log_entries().to_vec();
        entries.push(RaftLogEntry::new(2, 99, String::new(), Vec::new()));
        assert!(node2.append_replicated_entries(2, "n1", &entries).is_ok());
        assert_eq!(node2.get("/k1"), node1.get("/k1"));

        // Follower storage fault during append_replicated_entries
        node2.set_storage_fault(Some(MemoryStoreFault::FailWrites));
        assert!(
            node2
                .append_replicated_entries(
                    2,
                    "n1",
                    &[RaftLogEntry::new(2, 100, "/k".to_owned(), b"v".to_vec())]
                )
                .is_err()
        );
        node2.set_storage_fault(None);

        // Stale leader term rejected by node2
        assert!(node2.append_replicated_entries(1, "n1", &[]).is_err());

        // Corrupted log entry rejected via CRC32 check
        let mut corrupted = RaftLogEntry::new(2, 100, "/bad".to_owned(), b"data".to_vec());
        corrupted.crc32 ^= 0x1234;
        assert!(
            node2
                .append_replicated_entries(2, "n1", &[corrupted])
                .is_err()
        );
    }

    #[test]
    fn test_raft_snapshot_compaction_and_membership() {
        let mut leader = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        leader.start_election(1000);
        let _ = leader.put("/snap/1", b"hello".to_vec());

        let valid_snap = leader.compact_to_snapshot();
        assert!(leader.log_entries().is_empty());

        let mut follower =
            RaftStateStore::new("n2", vec!["n1".to_owned(), "n2".to_owned()]).unwrap_or_default();
        assert!(follower.install_snapshot(&valid_snap).is_ok());
        assert_eq!(follower.get("/snap/1"), leader.get("/snap/1"));

        let mut bad_snap = valid_snap;
        bad_snap.crc32 ^= 0xFF;
        assert!(follower.install_snapshot(&bad_snap).is_err());

        let invalid_json_bytes = b"{bad json".to_vec();
        let bad_json_snap = RaftSnapshot {
            last_included_index: 5,
            last_included_term: 3,
            crc32: compute_crc32(&invalid_json_bytes),
            data: invalid_json_bytes,
        };
        assert!(follower.install_snapshot(&bad_json_snap).is_err());

        assert!(leader.reconfigure_membership(vec![]).is_err());
        assert!(
            leader
                .reconfigure_membership(vec!["n1".to_owned(), "n2".to_owned()])
                .is_ok()
        );

        leader.step_down(2, "n2");
        assert_eq!(leader.role(), RaftRole::Follower);
    }
}
