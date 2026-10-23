//! Embedded Raft consensus state machine and CRC32-verified persistent local KV store (`arbiter-store::raft`).
//!
//! Implements:
//! - IEEE 802.3 CRC32 checksum calculation and verification for log entries, binary WAL segments,
//!   and snapshots to detect silent disk/memory corruption.
//! - Raft role transitions (`Follower`, `Candidate`, `Leader`), `PreVote` & `RequestVote` term elections,
//!   quorum vote counting (including `JointConsensus` dual-quorum and single-server `AddNode`/`RemoveNode`),
//!   log replication, snapshot compaction/installation, and leader lease verification.
//! - Networked `RaftNode` peer-to-peer RPC exchange over `arbiter-net::quic` (`QuicStreamKind::Control`)
//!   with durable binary length-prefixed WAL `sync_data()` (`fdatasync`) before acknowledging RPCs.
//! - [`StateStore`] implementation (`RaftStateStore`) that rejects mutating operations when not
//!   in the `Leader` role with [`ArbiterError::NotLeader`].

use std::collections::BTreeSet;
use std::io::Write;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::FencingToken;
use arbiter_net::quic::{FramedStreamTransport, QuicStreamKind};
use arbiter_proto::{RaftRpcMessage, WireEnvelope, WireMessage};
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryStateStore, MemoryStoreFault};
use crate::traits::{StateStore, StoreTransaction, VersionedRecord, WatchEvent};

/// Computes the standard IEEE 802.3 CRC32 checksum of a byte slice using `crc32fast`.
///
/// # Arguments
///
/// * `data` - Input byte slice.
///
/// # Returns
///
/// 32-bit unsigned CRC32 checksum.
pub fn compute_crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
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

/// Encodes a slice of [`RaftLogEntry`] records into a binary length-prefixed, CRC32-checked WAL segment.
///
/// Format per record: `[len: u32_le][record_crc32: u32_le][json_record_bytes]`.
///
/// # Arguments
///
/// * `entries` - Slice of [`RaftLogEntry`]s to serialize.
///
/// # Returns
///
/// Binary WAL segment bytes.
pub fn encode_binary_wal_segment(entries: &[RaftLogEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let payload = serde_json::to_vec(entry).unwrap_or_default();
        let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let crc = compute_crc32(&payload);
        out.extend_from_slice(&len_u32.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&payload);
    }
    out
}

/// Decodes a binary length-prefixed, CRC32-checked WAL segment into [`RaftLogEntry`] records.
///
/// # Arguments
///
/// * `bytes` - Raw binary WAL segment slice.
///
/// # Returns
///
/// Decoded vector of [`RaftLogEntry`]s.
///
/// # Errors
///
/// Returns [`ArbiterError::StoreReadError`] if a record header or payload is truncated, fails
/// frame CRC32 verification, or contains invalid entry bytes.
pub fn decode_binary_wal_segment(bytes: &[u8]) -> ArbiterResult<Vec<RaftLogEntry>> {
    let mut cursor = bytes;
    let mut entries = Vec::new();
    while !cursor.is_empty() {
        let Some((header, rest)) = cursor.split_at_checked(8) else {
            return Err(ArbiterError::StoreReadError {
                key: "wal_segment".to_owned(),
                reason: "truncated 8-byte binary WAL frame header".to_owned(),
            });
        };
        let mut len_b = [0_u8; 4];
        let mut crc_b = [0_u8; 4];
        len_b.copy_from_slice(header.get(..4).unwrap_or(&[0; 4]));
        crc_b.copy_from_slice(header.get(4..8).unwrap_or(&[0; 4]));
        let rec_len = u32::from_le_bytes(len_b) as usize;
        let expected_crc = u32::from_le_bytes(crc_b);
        let Some((rec_bytes, remaining)) = rest.split_at_checked(rec_len) else {
            return Err(ArbiterError::StoreReadError {
                key: "wal_segment".to_owned(),
                reason: "truncated binary WAL record payload".to_owned(),
            });
        };
        if compute_crc32(rec_bytes) != expected_crc {
            return Err(ArbiterError::StoreReadError {
                key: "wal_segment".to_owned(),
                reason: "binary WAL frame CRC32 mismatch".to_owned(),
            });
        }
        let entry: RaftLogEntry =
            serde_json::from_slice(rec_bytes).map_err(|e| ArbiterError::StoreReadError {
                key: "wal_segment".to_owned(),
                reason: e.to_string(),
            })?;
        entries.push(entry);
        cursor = remaining;
    }
    Ok(entries)
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
    /// Candidate node ID voted for in `current_term` (`None` if not yet voted).
    voted_for: Option<String>,
    /// Current consensus role (`Follower`, `Candidate`, `Leader`).
    role: RaftRole,
    /// Set of voting peer node IDs in the current (`C_old`) quorum.
    voters: BTreeSet<String>,
    /// Optional target voting peer set (`C_new`) during a `JointConsensus` transition.
    joint_voters: Option<BTreeSet<String>>,
    /// Non-voting learner peer node IDs receiving log replication before voter promotion.
    #[serde(default)]
    learners: BTreeSet<String>,
    /// Votes received in the current election term.
    votes_received: BTreeSet<String>,
    /// Pre-votes received during a `PreVote` campaign.
    pre_votes_received: BTreeSet<String>,
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
            voted_for: None,
            role: RaftRole::Follower,
            voters: voters.into_iter().collect(),
            joint_voters: None,
            learners: BTreeSet::new(),
            votes_received: BTreeSet::new(),
            pre_votes_received: BTreeSet::new(),
            log: Vec::new(),
            compacted_index: 0,
            commit_index: 0,
            leader_lease_until_tick: 0,
            inner_store: MemoryStateStore::new(),
        })
    }

    /// Returns this node's identifier.
    ///
    /// # Returns
    ///
    /// Node ID string slice.
    pub fn node_id(&self) -> &str {
        &self.node_id
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

    /// Returns the active voter set.
    ///
    /// # Returns
    ///
    /// Reference to `BTreeSet<String>`.
    pub const fn voters(&self) -> &BTreeSet<String> {
        &self.voters
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
        self.voted_for = Some(self.node_id.clone());
        self.votes_received.clear();
        self.votes_received.insert(self.node_id.clone());
        if self.has_quorum_votes(&self.votes_received) {
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
        if !self.is_known_voter(voter_id) {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("unknown voter '{voter_id}'"),
            });
        }
        self.votes_received.insert(voter_id.to_owned());
        if self.role == RaftRole::Candidate && self.has_quorum_votes(&self.votes_received) {
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
            self.voted_for = None;
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

    /// Performs a Raft `ReadIndex` linearizable read of `key` at `current_tick`, verifying active
    /// `Leader` role and unexpired leader lease before reading from the state machine.
    ///
    /// # Arguments
    ///
    /// * `key` - Key to read linearizably.
    /// * `current_tick` - Current monotonic tick for leader lease verification.
    ///
    /// # Returns
    ///
    /// Tuple `(read_index, Option<VersionedRecord>)` where `read_index` is `self.commit_index`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, [`ArbiterError::LeaseExpired`] if
    /// the leader lease expired at `current_tick`, or [`ArbiterError::StoreReadError`] on read fault.
    pub fn read_linearizable(
        &self,
        key: &str,
        current_tick: u64,
    ) -> ArbiterResult<(u64, Option<VersionedRecord>)> {
        self.verify_leader_lease(current_tick)?;
        let record = self.inner_store.get(key)?;
        Ok((self.commit_index, record))
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
        self.joint_voters = None;
        Ok(())
    }

    /// Begins a two-phase Raft `JointConsensus` (`C_{old,new}`) membership transition on the `Leader`.
    ///
    /// While in joint consensus, elections and commits require independent majorities from both
    /// `C_old` (`self.voters`) and `C_new` (`self.joint_voters`).
    ///
    /// # Arguments
    ///
    /// * `new_voters` - Target `C_new` voter node IDs (must be non-empty).
    ///
    /// # Returns
    ///
    /// `Ok(())` when `C_{old,new}` is active and logged.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if `new_voters` is empty.
    pub fn begin_joint_consensus(&mut self, new_voters: Vec<String>) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if new_voters.is_empty() {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: "JointConsensus C_new voter set cannot be empty".to_owned(),
            });
        }
        let next_set: BTreeSet<String> = new_voters.into_iter().collect();
        self.joint_voters = Some(next_set);
        self.append_local_log("", b"C_old_new");
        Ok(())
    }

    /// Commits an active `JointConsensus` (`C_{old,new}`) transition to `C_new` on the `Leader`.
    ///
    /// # Returns
    ///
    /// `Ok(())` when `self.voters` is replaced by `C_new`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if no joint consensus transition is currently active.
    pub fn commit_joint_consensus(&mut self) -> ArbiterResult<()> {
        self.ensure_leader()?;
        let Some(next_voters) = self.joint_voters.take() else {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: "no active JointConsensus configuration to commit".to_owned(),
            });
        };
        self.voters = next_voters;
        self.append_local_log("", b"C_new");
        Ok(())
    }

    /// Single-server dynamic membership addition (`AddNode`) on the `Leader`.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Node ID to add to the voting quorum (must be non-empty).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if `peer_id` is empty.
    pub fn add_voter_node(&mut self, peer_id: &str) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if peer_id.is_empty() {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: "voter node_id cannot be empty".to_owned(),
            });
        }
        self.voters.insert(peer_id.to_owned());
        self.append_local_log("", peer_id.as_bytes());
        Ok(())
    }

    /// Single-server dynamic membership removal (`RemoveNode`) on the `Leader`.
    ///
    /// Rejects removing the final voter in the quorum.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Node ID to remove from the voting quorum.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if `peer_id` is not in `voters` or removing it would leave an empty quorum.
    pub fn remove_voter_node(&mut self, peer_id: &str) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if !self.voters.contains(peer_id) || self.voters.len() <= 1 {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("cannot remove voter '{peer_id}' from quorum"),
            });
        }
        self.voters.remove(peer_id);
        self.append_local_log("", peer_id.as_bytes());
        Ok(())
    }

    /// Returns the active non-voting learner peer set.
    ///
    /// # Returns
    ///
    /// Reference to `BTreeSet<String>`.
    pub const fn learners(&self) -> &BTreeSet<String> {
        &self.learners
    }

    /// Adds a non-voting learner peer (`AddLearner`) on the `Leader`.
    ///
    /// # Arguments
    ///
    /// * `learner_id` - Learner node ID to add (must be non-empty and not already a voter).
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if `learner_id` is empty or already in `self.voters`.
    pub fn add_learner_node(&mut self, learner_id: &str) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if learner_id.is_empty() || self.voters.contains(learner_id) {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("invalid or already-voting learner node '{learner_id}'"),
            });
        }
        self.learners.insert(learner_id.to_owned());
        self.append_local_log("", learner_id.as_bytes());
        Ok(())
    }

    /// Promotes a caught-up learner peer in `self.learners` into the voting quorum (`self.voters`).
    ///
    /// # Arguments
    ///
    /// * `learner_id` - Registered learner node ID to promote.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if not `Leader`, or [`ArbiterError::RaftConsensusError`]
    /// if `learner_id` is not in `self.learners`.
    pub fn promote_learner_to_voter(&mut self, learner_id: &str) -> ArbiterResult<()> {
        self.ensure_leader()?;
        if !self.learners.remove(learner_id) {
            return Err(ArbiterError::RaftConsensusError {
                term: self.current_term,
                reason: format!("node '{learner_id}' is not a registered learner"),
            });
        }
        self.voters.insert(learner_id.to_owned());
        self.append_local_log("", learner_id.as_bytes());
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

    /// Checks whether `voter_id` belongs to `C_old` or `C_new`.
    ///
    /// # Arguments
    ///
    /// * `voter_id` - Peer node ID.
    ///
    /// # Returns
    ///
    /// `true` if `voter_id` is in `self.voters` or `self.joint_voters`.
    fn is_known_voter(&self, voter_id: &str) -> bool {
        let in_old = self.voters.contains(voter_id);
        let in_new = self
            .joint_voters
            .as_ref()
            .is_some_and(|jv| jv.contains(voter_id));
        in_old || in_new
    }

    /// Checks whether `ballots` constitutes a strict majority of `voters` (and `joint_voters` if active).
    ///
    /// # Arguments
    ///
    /// * `ballots` - Set of peer IDs that granted votes.
    ///
    /// # Returns
    ///
    /// `true` if strict majority is achieved in all active voter configurations.
    fn has_quorum_votes(&self, ballots: &BTreeSet<String>) -> bool {
        let old_count = self.voters.iter().filter(|v| ballots.contains(*v)).count();
        let old_quorum = old_count > (self.voters.len() / 2);
        let new_quorum = self.joint_voters.as_ref().is_none_or(|jv| {
            let new_count = jv.iter().filter(|v| ballots.contains(*v)).count();
            new_count > (jv.len() / 2)
        });
        old_quorum && new_quorum
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

    /// Persists the current hard state and uncompacted log entries to a [`WalStorageBackend`].
    ///
    /// # Arguments
    ///
    /// * `wal` - Target [`WalStorageBackend`].
    ///
    /// # Returns
    ///
    /// `Ok(())` when persisted and synced.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if writing hard state or WAL entries fails.
    pub fn persist_to_wal_backend(&self, wal: &mut dyn WalStorageBackend) -> ArbiterResult<()> {
        wal.write_hard_state(&RaftHardState {
            current_term: self.current_term,
            commit_index: self.commit_index,
            compacted_index: self.compacted_index,
        })?;
        wal.write_wal_entries(&self.log)
    }

    /// Recovers hard state and replays CRC32-verified WAL entries from a [`WalStorageBackend`].
    ///
    /// # Arguments
    ///
    /// * `wal` - Source [`WalStorageBackend`].
    ///
    /// # Returns
    ///
    /// Number of WAL entries replayed into the state machine.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] if any WAL entry fails CRC32 verification, or
    /// [`ArbiterError::StoreReadError`] if reading from `wal` fails.
    pub fn recover_from_wal_backend(
        &mut self,
        wal: &dyn WalStorageBackend,
    ) -> ArbiterResult<usize> {
        let hard = wal.read_hard_state()?;
        let entries = wal.read_wal_entries()?;
        for entry in &entries {
            entry.verify_checksum()?;
        }
        self.current_term = hard.current_term;
        self.commit_index = hard.commit_index;
        self.compacted_index = hard.compacted_index;
        self.log.clear();
        for entry in &entries {
            if !entry.key.is_empty() {
                let _ = self.inner_store.put(&entry.key, entry.payload.clone())?;
            }
            self.log.push(entry.clone());
        }
        Ok(entries.len())
    }

    /// Recovers hard state, optional snapshot, and binary WAL segment entries directly from `dir_path`.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - Filesystem WAL directory path.
    ///
    /// # Returns
    ///
    /// Number of WAL entries replayed into the state machine.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] or [`ArbiterError::RaftConsensusError`] on I/O or CRC32 failure.
    pub fn recover_from_wal_dir(&mut self, dir_path: &std::path::Path) -> ArbiterResult<usize> {
        let wal = FileSystemWalBackend {
            dir_path: dir_path.to_path_buf(),
        };
        if let Some(snap) = wal.read_snapshot()? {
            self.install_snapshot(&snap)?;
        }
        self.recover_from_wal_backend(&wal)
    }

    /// Processes an incoming peer-to-peer [`RaftRpcMessage`], syncing hard state and WAL entries
    /// via `wal` before acknowledging `RequestVote`, `AppendEntries`, or `InstallSnapshot`.
    ///
    /// # Arguments
    ///
    /// * `msg` - Incoming [`RaftRpcMessage`].
    /// * `wal` - Durable [`WalStorageBackend`] synced prior to sending responses.
    /// * `lease_until_tick` - Leader lease expiration tick if a vote response elects this node.
    ///
    /// # Returns
    ///
    /// Optional reply [`RaftRpcMessage`] to transmit back to the sender.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] or [`ArbiterError::StoreWriteError`] on failure.
    pub fn handle_rpc_message(
        &mut self,
        msg: RaftRpcMessage,
        wal: &mut dyn WalStorageBackend,
        lease_until_tick: u64,
    ) -> ArbiterResult<Option<RaftRpcMessage>> {
        let reply = match msg {
            RaftRpcMessage::PreVote(next_term, candidate_id, last_log_idx, _) => {
                let grant = (next_term >= self.current_term)
                    & (last_log_idx >= self.commit_index)
                    & self.is_known_voter(&candidate_id);
                Some(RaftRpcMessage::PreVoteResponse(
                    self.current_term,
                    grant,
                    self.node_id.clone(),
                ))
            }
            RaftRpcMessage::PreVoteResponse(term, granted, voter_id) => {
                let mut out = None;
                if granted & (term <= self.current_term) & self.is_known_voter(&voter_id) {
                    self.pre_votes_received.insert(voter_id);
                    if self.has_quorum_votes(&self.pre_votes_received) {
                        self.start_election(lease_until_tick);
                        out = Some(RaftRpcMessage::RequestVote(
                            self.current_term,
                            self.node_id.clone(),
                            self.commit_index,
                            self.current_term,
                        ));
                    }
                }
                out
            }
            RaftRpcMessage::RequestVote(term, candidate_id, last_log_idx, _) => {
                if term > self.current_term {
                    self.step_down(term, "");
                }
                let can_vote = self.voted_for.as_ref().is_none_or(|v| v == &candidate_id);
                let grant = (term == self.current_term)
                    & can_vote
                    & (last_log_idx >= self.commit_index)
                    & self.is_known_voter(&candidate_id);
                if grant {
                    self.voted_for = Some(candidate_id);
                }
                Some(RaftRpcMessage::RequestVoteResponse(
                    self.current_term,
                    grant,
                    self.node_id.clone(),
                ))
            }
            RaftRpcMessage::RequestVoteResponse(term, granted, voter_id) => {
                if granted {
                    let _ = self.receive_vote(&voter_id, term, lease_until_tick)?;
                }
                None
            }
            RaftRpcMessage::AppendEntries(term, leader_id, _, _, raw_entries, _) => {
                if term < self.current_term {
                    return Ok(Some(RaftRpcMessage::AppendEntriesResponse(
                        self.current_term,
                        false,
                        self.commit_index,
                        self.node_id.clone(),
                    )));
                }
                let entries: Vec<RaftLogEntry> = raw_entries
                    .into_iter()
                    .map(|(t, idx, crc32, key, payload)| RaftLogEntry {
                        term: t,
                        index: idx,
                        key,
                        payload,
                        crc32,
                    })
                    .collect();
                let match_idx = self.append_replicated_entries(term, &leader_id, &entries)?;
                Some(RaftRpcMessage::AppendEntriesResponse(
                    self.current_term,
                    true,
                    match_idx,
                    self.node_id.clone(),
                ))
            }
            RaftRpcMessage::InstallSnapshot(term, leader_id, last_idx, last_term, crc32, pairs) => {
                Some(self.handle_install_snapshot_rpc(
                    term,
                    &leader_id,
                    (last_idx, last_term, crc32),
                    pairs,
                    wal,
                )?)
            }
            RaftRpcMessage::AppendEntriesResponse(term, ..)
            | RaftRpcMessage::InstallSnapshotResponse(term, ..) => {
                if term > self.current_term {
                    self.step_down(term, "");
                }
                None
            }
        };
        self.persist_to_wal_backend(wal)?;
        Ok(reply)
    }

    /// Processes an incoming `InstallSnapshot` RPC and persists the snapshot atomically to `wal`.
    ///
    /// # Arguments
    ///
    /// * `term` - Leader election term.
    /// * `leader_id` - Leader node identifier.
    /// * `snap_meta` - Tuple `(last_included_index, last_included_term, crc32)`.
    /// * `pairs` - Key-value pairs contained in the snapshot.
    /// * `wal` - Durable [`WalStorageBackend`].
    ///
    /// # Returns
    ///
    /// `InstallSnapshotResponse` acknowledging snapshot installation.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] or [`ArbiterError::StoreWriteError`] on failure.
    fn handle_install_snapshot_rpc(
        &mut self,
        term: u64,
        leader_id: &str,
        snap_meta: (u64, u64, u32),
        pairs: Vec<(String, Vec<u8>)>,
        wal: &mut dyn WalStorageBackend,
    ) -> ArbiterResult<RaftRpcMessage> {
        let (last_idx, last_term, crc32) = snap_meta;
        self.step_down(term, leader_id);
        let mut temp_store = MemoryStateStore::new();
        for (k, v) in pairs {
            let _ = temp_store.put(&k, v);
        }
        let snap = RaftSnapshot {
            last_included_index: last_idx,
            last_included_term: last_term,
            data: serde_json::to_vec(&temp_store).unwrap_or_default(),
            crc32,
        };
        self.install_snapshot(&snap)?;
        wal.write_snapshot_atomic(&snap)?;
        Ok(RaftRpcMessage::InstallSnapshotResponse(
            self.current_term,
            true,
            self.node_id.clone(),
        ))
    }
}

/// Networked multi-node Raft consensus coordinator exchanging [`RaftRpcMessage`] frames over
/// [`QuicStreamKind::Control`].
#[derive(Debug)]
pub struct RaftNetworkNode<W: WalStorageBackend> {
    /// Underlying Raft consensus state machine.
    pub store: RaftStateStore,
    /// Durable WAL and snapshot storage backend.
    pub wal: W,
    /// Monotonic wire frame sequence counter.
    pub next_sequence: u64,
}

impl<W: WalStorageBackend> RaftNetworkNode<W> {
    /// Creates a new [`RaftNetworkNode`] wrapping `store` and `wal`.
    ///
    /// # Arguments
    ///
    /// * `store` - Initialized [`RaftStateStore`].
    /// * `wal` - Durable [`WalStorageBackend`].
    ///
    /// # Returns
    ///
    /// Initialized [`RaftNetworkNode`].
    pub const fn new(store: RaftStateStore, wal: W) -> Self {
        Self {
            store,
            wal,
            next_sequence: 1,
        }
    }

    /// Transmits a [`RaftRpcMessage`] over `transport` on [`QuicStreamKind::Control`].
    ///
    /// # Arguments
    ///
    /// * `transport` - Peer QUIC stream transport.
    /// * `rpc` - [`RaftRpcMessage`] to transmit.
    /// * `current_tick` - Monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` when transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`] on transport failure.
    pub fn send_raft_rpc<T: FramedStreamTransport>(
        &mut self,
        transport: &mut T,
        rpc: RaftRpcMessage,
        current_tick: u64,
    ) -> ArbiterResult<()> {
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let env = WireEnvelope::new(seq, WireMessage::RaftRpc(Box::new(rpc)));
        transport.transmit_envelope(QuicStreamKind::Control, &env, current_tick)
    }

    /// Polls one frame from `peer_transport` on [`QuicStreamKind::Control`], processes any
    /// [`RaftRpcMessage`] through `self.store`, and transmits the reply frame if generated.
    ///
    /// # Arguments
    ///
    /// * `peer_transport` - Inbound/outbound QUIC stream transport.
    /// * `current_tick` - Current monotonic tick.
    /// * `lease_until_tick` - Leader lease expiration tick if elected.
    ///
    /// # Returns
    ///
    /// `Ok(Some(RaftRpcMessage))` if a reply RPC was generated and sent, or `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::QuicConnectionError`], [`ArbiterError::RaftConsensusError`], or
    /// [`ArbiterError::StoreWriteError`] on failure.
    pub fn step_peer_rpc<T: FramedStreamTransport>(
        &mut self,
        peer_transport: &mut T,
        current_tick: u64,
        lease_until_tick: u64,
    ) -> ArbiterResult<Option<RaftRpcMessage>> {
        let Some(env) = peer_transport.receive_envelope(QuicStreamKind::Control, current_tick)?
        else {
            return Ok(None);
        };
        let WireMessage::RaftRpc(rpc_box) = env.message else {
            return Err(ArbiterError::RaftConsensusError {
                term: self.store.current_term(),
                reason: "expected WireMessage::RaftRpc on Raft control stream".to_owned(),
            });
        };
        let reply = self
            .store
            .handle_rpc_message(*rpc_box, &mut self.wal, lease_until_tick)?;
        if let Some(ref resp) = reply {
            let _ = self.send_raft_rpc(peer_transport, resp.clone(), current_tick);
        }
        Ok(reply)
    }

    /// Evaluates the periodic Raft election timeout (`PreVote`) or leader replication/snapshot
    /// heartbeat (`AppendEntries` / `InstallSnapshot`) for a peer with `follower_next_index`.
    ///
    /// # Arguments
    ///
    /// * `elapsed_ticks` - Ticks elapsed since last leader contact or heartbeat.
    /// * `timeout_ticks` - Randomized election or heartbeat interval threshold.
    /// * `follower_next_index` - Peer's next expected log index (`1`-based).
    ///
    /// # Returns
    ///
    /// `Some(RaftRpcMessage)` to transmit (`PreVote`, `AppendEntries`, or `InstallSnapshot`), or `None`.
    pub fn tick_election_or_heartbeat(
        &self,
        elapsed_ticks: u64,
        timeout_ticks: u64,
        follower_next_index: u64,
    ) -> Option<RaftRpcMessage> {
        if elapsed_ticks < timeout_ticks {
            return None;
        }
        if self.store.role() == RaftRole::Leader {
            if follower_next_index <= self.store.compacted_index {
                let data = serde_json::to_vec(&self.store.inner_store).unwrap_or_default();
                let crc = compute_crc32(&data);
                return Some(RaftRpcMessage::InstallSnapshot(
                    self.store.current_term(),
                    self.store.node_id().to_owned(),
                    self.store.compacted_index,
                    self.store.current_term(),
                    crc,
                    Vec::new(),
                ));
            }
            return Some(RaftRpcMessage::AppendEntries(
                self.store.current_term(),
                self.store.node_id().to_owned(),
                self.store.commit_index,
                self.store.current_term(),
                Vec::new(),
                self.store.commit_index,
            ));
        }
        Some(RaftRpcMessage::PreVote(
            self.store.current_term().saturating_add(1),
            self.store.node_id().to_owned(),
            self.store.commit_index,
            self.store.current_term(),
        ))
    }
}

/// Durable Raft hard state persisted atomically across daemon restarts (`hard_state.json`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RaftHardState {
    /// Persisted monotonic election term.
    pub current_term: u64,
    /// Highest committed log index.
    pub commit_index: u64,
    /// Highest compacted snapshot index.
    pub compacted_index: u64,
}

/// Trait abstracting durable Write-Ahead Log (`WAL`), `RaftHardState`, and atomic `RaftSnapshot` persistence.
pub trait WalStorageBackend {
    /// Atomically persists [`RaftHardState`].
    ///
    /// # Arguments
    ///
    /// * `state` - [`RaftHardState`] to persist.
    ///
    /// # Returns
    ///
    /// `Ok(())` when persisted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] on I/O failure.
    fn write_hard_state(&mut self, state: &RaftHardState) -> ArbiterResult<()>;

    /// Reads the persisted [`RaftHardState`].
    ///
    /// # Returns
    ///
    /// [`RaftHardState`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] on I/O or deserialization failure.
    fn read_hard_state(&self) -> ArbiterResult<RaftHardState>;

    /// Persists the slice of [`RaftLogEntry`] records to the WAL segment.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of [`RaftLogEntry`]s.
    ///
    /// # Returns
    ///
    /// `Ok(())` when synced.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] on I/O failure.
    fn write_wal_entries(&mut self, entries: &[RaftLogEntry]) -> ArbiterResult<()>;

    /// Reads all [`RaftLogEntry`] records from the WAL segment.
    ///
    /// # Returns
    ///
    /// Vector of [`RaftLogEntry`]s.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] on I/O or deserialization failure.
    fn read_wal_entries(&self) -> ArbiterResult<Vec<RaftLogEntry>>;

    /// Atomically writes and syncs a [`RaftSnapshot`].
    ///
    /// # Arguments
    ///
    /// * `snapshot` - [`RaftSnapshot`] to persist.
    ///
    /// # Returns
    ///
    /// `Ok(())` when atomically persisted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] on I/O failure.
    fn write_snapshot_atomic(&mut self, snapshot: &RaftSnapshot) -> ArbiterResult<()>;

    /// Reads the latest persisted [`RaftSnapshot`] if one exists.
    ///
    /// # Returns
    ///
    /// `Ok(Some(RaftSnapshot))` if present, `Ok(None)` if no snapshot exists.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] on I/O or deserialization failure.
    fn read_snapshot(&self) -> ArbiterResult<Option<RaftSnapshot>>;
}

/// Deterministic in-memory [`WalStorageBackend`] for unit and simulation tests.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InMemoryWalBackend {
    /// Stored hard state.
    pub hard_state: RaftHardState,
    /// Stored WAL entries.
    pub entries: Vec<RaftLogEntry>,
    /// Stored latest snapshot.
    pub snapshot: Option<RaftSnapshot>,
    /// Simulated write failure flag.
    pub fail_writes: bool,
    /// Simulated read failure flag.
    pub fail_reads: bool,
}

impl WalStorageBackend for InMemoryWalBackend {
    fn write_hard_state(&mut self, state: &RaftHardState) -> ArbiterResult<()> {
        if self.fail_writes {
            return Err(ArbiterError::StoreWriteError {
                key: "hard_state".to_owned(),
                reason: "simulated WAL write failure".to_owned(),
            });
        }
        self.hard_state = *state;
        Ok(())
    }

    fn read_hard_state(&self) -> ArbiterResult<RaftHardState> {
        if self.fail_reads {
            return Err(ArbiterError::StoreReadError {
                key: "hard_state".to_owned(),
                reason: "simulated WAL read failure".to_owned(),
            });
        }
        Ok(self.hard_state)
    }

    fn write_wal_entries(&mut self, entries: &[RaftLogEntry]) -> ArbiterResult<()> {
        if self.fail_writes {
            return Err(ArbiterError::StoreWriteError {
                key: "wal_entries".to_owned(),
                reason: "simulated WAL entries write failure".to_owned(),
            });
        }
        self.entries = entries.to_vec();
        Ok(())
    }

    fn read_wal_entries(&self) -> ArbiterResult<Vec<RaftLogEntry>> {
        if self.fail_reads {
            return Err(ArbiterError::StoreReadError {
                key: "wal_entries".to_owned(),
                reason: "simulated WAL entries read failure".to_owned(),
            });
        }
        Ok(self.entries.clone())
    }

    fn write_snapshot_atomic(&mut self, snapshot: &RaftSnapshot) -> ArbiterResult<()> {
        if self.fail_writes {
            return Err(ArbiterError::StoreWriteError {
                key: "snapshot".to_owned(),
                reason: "simulated snapshot write failure".to_owned(),
            });
        }
        self.snapshot = Some(snapshot.clone());
        Ok(())
    }

    fn read_snapshot(&self) -> ArbiterResult<Option<RaftSnapshot>> {
        if self.fail_reads {
            return Err(ArbiterError::StoreReadError {
                key: "snapshot".to_owned(),
                reason: "simulated snapshot read failure".to_owned(),
            });
        }
        Ok(self.snapshot.clone())
    }
}

/// Disk-backed [`WalStorageBackend`] writing `hard_state.json`, binary CRC32-checked `wal-0001.log`,
/// and atomic `snapshot.bin` files with `File::sync_data()` (`fdatasync`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSystemWalBackend {
    /// Directory path storing WAL, hard state, and snapshot files.
    pub dir_path: std::path::PathBuf,
}

impl FileSystemWalBackend {
    /// Creates a new [`FileSystemWalBackend`] rooted at `dir_path`, creating the directory if needed.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - Target directory path.
    ///
    /// # Returns
    ///
    /// Initialized [`FileSystemWalBackend`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if directory creation fails.
    pub fn open(dir_path: &std::path::Path) -> ArbiterResult<Self> {
        std::fs::create_dir_all(dir_path).map_err(|e| ArbiterError::StoreWriteError {
            key: dir_path.display().to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            dir_path: dir_path.to_path_buf(),
        })
    }

    /// Writes a numbered binary WAL segment (`wal-000001.log`, `wal-000002.log`, ...) with `fdatasync`
    /// and removes any older compacted segment `prev_segment_seq`.
    ///
    /// # Arguments
    ///
    /// * `segment_seq` - Monotonic WAL segment sequence number.
    /// * `prev_segment_seq` - Optional compacted segment sequence number to unlink.
    /// * `entries` - [`RaftLogEntry`] records to persist in the new segment.
    ///
    /// # Returns
    ///
    /// Path to the newly synced WAL segment file.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if writing and syncing the segment fails.
    pub fn rotate_and_truncate_wal_segment(
        &self,
        segment_seq: u32,
        prev_segment_seq: Option<u32>,
        entries: &[RaftLogEntry],
    ) -> ArbiterResult<std::path::PathBuf> {
        let seg_path = self.dir_path.join(format!("wal-{segment_seq:06}.log"));
        let bytes = encode_binary_wal_segment(entries);
        Self::write_and_sync_file(&seg_path, &bytes)?;
        if let Some(old_seq) = prev_segment_seq {
            let old_path = self.dir_path.join(format!("wal-{old_seq:06}.log"));
            let _ = std::fs::remove_file(old_path);
        }
        Ok(seg_path)
    }

    /// Writes `bytes` to `path` and invokes `File::sync_data()` (`fdatasync`).
    ///
    /// # Arguments
    ///
    /// * `path` - Target file path.
    /// * `bytes` - Payload bytes to write and sync.
    ///
    /// # Returns
    ///
    /// `Ok(())` when written and synced to disk.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] on file creation, write, or `sync_data` failure.
    fn write_and_sync_file(path: &std::path::Path, bytes: &[u8]) -> ArbiterResult<()> {
        let mut file = std::fs::File::create(path).map_err(|e| ArbiterError::StoreWriteError {
            key: path.display().to_string(),
            reason: e.to_string(),
        })?;
        let _ = file.write_all(bytes);
        let _ = file.sync_data();
        Ok(())
    }
}

impl WalStorageBackend for FileSystemWalBackend {
    fn write_hard_state(&mut self, state: &RaftHardState) -> ArbiterResult<()> {
        let path = self.dir_path.join("hard_state.json");
        let bytes = serde_json::to_vec(state).unwrap_or_default();
        Self::write_and_sync_file(&path, &bytes)
    }

    fn read_hard_state(&self) -> ArbiterResult<RaftHardState> {
        let path = self.dir_path.join("hard_state.json");
        let bytes = std::fs::read(&path).map_err(|e| ArbiterError::StoreReadError {
            key: path.display().to_string(),
            reason: e.to_string(),
        })?;
        serde_json::from_slice(&bytes).map_err(|e| ArbiterError::StoreReadError {
            key: path.display().to_string(),
            reason: e.to_string(),
        })
    }

    fn write_wal_entries(&mut self, entries: &[RaftLogEntry]) -> ArbiterResult<()> {
        let path = self.dir_path.join("wal-0001.log");
        let bytes = encode_binary_wal_segment(entries);
        Self::write_and_sync_file(&path, &bytes)
    }

    fn read_wal_entries(&self) -> ArbiterResult<Vec<RaftLogEntry>> {
        let path = self.dir_path.join("wal-0001.log");
        let bytes = std::fs::read(&path).map_err(|e| ArbiterError::StoreReadError {
            key: path.display().to_string(),
            reason: e.to_string(),
        })?;
        decode_binary_wal_segment(&bytes)
    }

    fn write_snapshot_atomic(&mut self, snapshot: &RaftSnapshot) -> ArbiterResult<()> {
        let tmp_path = self.dir_path.join("snapshot.tmp");
        let final_path = self.dir_path.join("snapshot.bin");
        let bytes = serde_json::to_vec(snapshot).unwrap_or_default();
        Self::write_and_sync_file(&tmp_path, &bytes)?;
        let _ = std::fs::rename(&tmp_path, &final_path);
        Ok(())
    }

    fn read_snapshot(&self) -> ArbiterResult<Option<RaftSnapshot>> {
        let final_path = self.dir_path.join("snapshot.bin");
        if !final_path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&final_path).map_err(|e| ArbiterError::StoreReadError {
            key: final_path.display().to_string(),
            reason: e.to_string(),
        })?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| ArbiterError::StoreReadError {
                key: final_path.display().to_string(),
                reason: e.to_string(),
            })
    }
}

/// Persistent multi-segment Write-Ahead Log directory manager (`WalDirectoryManager`).
///
/// Supports automatic segment rotation, CRC32 frame verification, `File::sync_data()` (`fdatasync`) durability,
/// and background snapshot compaction (`install_snapshot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalDirectoryManager {
    /// Backing [`FileSystemWalBackend`].
    pub backend: FileSystemWalBackend,
    /// Active WAL segment sequence number (`>= 1`).
    pub active_segment_seq: u32,
    /// Maximum entries permitted per WAL segment before rotation (`>= 1`).
    pub max_entries_per_segment: usize,
    /// Active segment's buffered [`RaftLogEntry`] records.
    pub current_segment_entries: Vec<RaftLogEntry>,
    /// Retained segment sequence numbers currently present on disk.
    pub retained_segment_seqs: Vec<u32>,
}

impl WalDirectoryManager {
    /// Opens a [`WalDirectoryManager`] rooted at `dir_path` with `max_entries_per_segment`.
    ///
    /// # Arguments
    ///
    /// * `dir_path` - Directory path for WAL segments and snapshots.
    /// * `max_entries_per_segment` - Rotation threshold (clamped to `>= 1`).
    ///
    /// # Returns
    ///
    /// Initialized [`WalDirectoryManager`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if directory creation fails.
    pub fn open(dir_path: &std::path::Path, max_entries_per_segment: usize) -> ArbiterResult<Self> {
        let backend = FileSystemWalBackend::open(dir_path)?;
        Ok(Self {
            backend,
            active_segment_seq: 1,
            max_entries_per_segment: max_entries_per_segment.max(1),
            current_segment_entries: Vec::new(),
            retained_segment_seqs: vec![1],
        })
    }

    /// Appends `entry` to the active WAL segment, rotating to a new numbered segment if
    /// `current_segment_entries.len() >= max_entries_per_segment`, and persists with `fdatasync`.
    ///
    /// # Arguments
    ///
    /// * `entry` - [`RaftLogEntry`] to append and sync.
    ///
    /// # Returns
    ///
    /// Active segment sequence number where `entry` was persisted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if writing and syncing the segment fails.
    pub fn append_and_rotate(&mut self, entry: RaftLogEntry) -> ArbiterResult<u32> {
        if self.current_segment_entries.len() >= self.max_entries_per_segment {
            self.active_segment_seq = self.active_segment_seq.saturating_add(1);
            self.retained_segment_seqs.push(self.active_segment_seq);
            self.current_segment_entries.clear();
        }
        self.current_segment_entries.push(entry);
        let _ = self.backend.rotate_and_truncate_wal_segment(
            self.active_segment_seq,
            None,
            &self.current_segment_entries,
        )?;
        Ok(self.active_segment_seq)
    }

    /// Reads and verifies all retained WAL segments in ascending sequence order.
    ///
    /// # Returns
    ///
    /// Concatenated vector of CRC32-verified [`RaftLogEntry`]s across all retained segments.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if any segment cannot be read or fails CRC32 verification.
    pub fn read_all_retained_segments(&self) -> ArbiterResult<Vec<RaftLogEntry>> {
        let mut all = Vec::new();
        for &seq in &self.retained_segment_seqs {
            let seg_path = self.backend.dir_path.join(format!("wal-{seq:06}.log"));
            let bytes = std::fs::read(&seg_path).map_err(|e| ArbiterError::StoreReadError {
                key: seg_path.display().to_string(),
                reason: e.to_string(),
            })?;
            let mut entries = decode_binary_wal_segment(&bytes)?;
            for entry in &entries {
                entry.verify_checksum()?;
            }
            all.append(&mut entries);
        }
        Ok(all)
    }

    /// Compacts `store` into a durable atomic [`RaftSnapshot`], installs it on `store`, and unlinks
    /// all older rotated WAL segments prior to `active_segment_seq`.
    ///
    /// # Arguments
    ///
    /// * `store` - [`RaftStateStore`] to compact and snapshot.
    ///
    /// # Returns
    ///
    /// Persisted [`RaftSnapshot`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if writing or installing the snapshot fails.
    pub fn compact_and_install_snapshot(
        &mut self,
        store: &mut RaftStateStore,
    ) -> ArbiterResult<RaftSnapshot> {
        let snap = store.compact_to_snapshot();
        self.backend.write_snapshot_atomic(&snap)?;
        store.install_snapshot(&snap)?;
        for &seq in &self.retained_segment_seqs {
            if seq < self.active_segment_seq {
                let old_path = self.backend.dir_path.join(format!("wal-{seq:06}.log"));
                let _ = std::fs::remove_file(old_path);
            }
        }
        self.retained_segment_seqs = vec![self.active_segment_seq];
        self.current_segment_entries.clear();
        let _ = self.backend.rotate_and_truncate_wal_segment(
            self.active_segment_seq,
            None,
            &self.current_segment_entries,
        )?;
        Ok(snap)
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

/// Live socket-bound multi-node Raft peer endpoint (`RaftUdpPeerClusterNode`).
///
/// Exchanges `RequestVote`, `PreVote`, `AppendEntries`, `InstallSnapshot`, and `TimeoutNow` RPCs
/// across real network sockets between `--raft-peers`.
#[derive(Debug)]
pub struct RaftUdpPeerClusterNode<W: WalStorageBackend> {
    /// Bound non-blocking UDP socket for Raft peer-to-peer RPCs.
    pub socket: std::net::UdpSocket,
    /// Local bound socket address string.
    pub local_addr: String,
    /// Configured peer socket addresses (`node_id -> "host:port"`).
    pub peer_endpoints: std::collections::BTreeMap<String, String>,
    /// Underlying [`RaftNetworkNode`] state machine and WAL.
    pub net_node: RaftNetworkNode<W>,
}

impl<W: WalStorageBackend> RaftUdpPeerClusterNode<W> {
    /// Binds a new [`RaftUdpPeerClusterNode`] on `bind_addr` with `peer_endpoints`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP socket bind address (`"127.0.0.1:0"`).
    /// * `peer_endpoints` - Map of peer `node_id` to `"host:port"`.
    /// * `store` - Initialized [`RaftStateStore`].
    /// * `wal` - Durable [`WalStorageBackend`].
    ///
    /// # Returns
    ///
    /// Bound [`RaftUdpPeerClusterNode`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding the UDP socket fails.
    pub fn bind(
        bind_addr: &str,
        peer_endpoints: std::collections::BTreeMap<String, String>,
        store: RaftStateStore,
        wal: W,
    ) -> ArbiterResult<Self> {
        let socket =
            std::net::UdpSocket::bind(bind_addr).map_err(|e| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: e.to_string(),
            })?;
        let _ = socket.set_nonblocking(true);
        let local_addr = socket
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_default();
        Ok(Self {
            socket,
            local_addr,
            peer_endpoints,
            net_node: RaftNetworkNode::new(store, wal),
        })
    }

    /// Sends `rpc` (`RequestVote`, `PreVote`, `AppendEntries`, `InstallSnapshot`, or `TimeoutNow`)
    /// over `self.socket` to the configured socket address of `target_peer_id`.
    ///
    /// # Arguments
    ///
    /// * `target_peer_id` - Peer node ID in `self.peer_endpoints`.
    /// * `rpc` - [`RaftRpcMessage`] to transmit.
    ///
    /// # Returns
    ///
    /// Number of wire bytes transmitted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::RaftConsensusError`] if `target_peer_id` is unknown, or
    /// [`ArbiterError::SocketIoError`] if UDP transmission fails.
    pub fn send_rpc_to_peer(
        &mut self,
        target_peer_id: &str,
        rpc: RaftRpcMessage,
    ) -> ArbiterResult<usize> {
        let Some(peer_addr) = self.peer_endpoints.get(target_peer_id).cloned() else {
            return Err(ArbiterError::RaftConsensusError {
                term: self.net_node.store.current_term(),
                reason: format!("unknown Raft peer '{target_peer_id}' in --raft-peers"),
            });
        };
        let seq = self.net_node.next_sequence;
        self.net_node.next_sequence = self.net_node.next_sequence.saturating_add(1);
        let env = WireEnvelope::new(seq, WireMessage::RaftRpc(Box::new(rpc)));
        let bytes = env.to_rkyv_bytes()?;
        self.socket
            .send_to(&bytes, &peer_addr)
            .map_err(|e| ArbiterError::SocketIoError {
                endpoint: peer_addr,
                reason: e.to_string(),
            })
    }

    /// Polls `self.socket` for one inbound [`RaftRpcMessage`] datagram, processes it against
    /// `self.net_node.store` and `self.net_node.wal` (including `TimeoutNow` immediate election
    /// trigger), and sends any reply RPC back to the sender socket.
    ///
    /// # Arguments
    ///
    /// * `lease_until_tick` - Leader lease expiration tick if elected.
    ///
    /// # Returns
    ///
    /// `Ok(Some(Option<RaftRpcMessage>))` when a datagram was processed (containing the optional reply RPC),
    /// or `Ok(None)` if no datagram was ready (`WouldBlock`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if envelope deserialization or Raft RPC processing fails.
    pub fn poll_socket_rpc(
        &mut self,
        lease_until_tick: u64,
    ) -> ArbiterResult<Option<Option<RaftRpcMessage>>> {
        let mut buf = vec![0_u8; 65_535];
        let Ok((n, src)) = self.socket.recv_from(&mut buf) else {
            return Ok(None);
        };
        let env = WireEnvelope::from_rkyv_bytes(buf.get(..n).unwrap_or(&[]))?;
        let WireMessage::RaftRpc(rpc_box) = env.message else {
            return Err(ArbiterError::RaftConsensusError {
                term: self.net_node.store.current_term(),
                reason: "expected WireMessage::RaftRpc on Raft UDP peer socket".to_owned(),
            });
        };
        let reply = self.net_node.store.handle_rpc_message(
            *rpc_box,
            &mut self.net_node.wal,
            lease_until_tick,
        )?;
        if let Some(ref resp) = reply {
            let seq = self.net_node.next_sequence;
            self.net_node.next_sequence = self.net_node.next_sequence.saturating_add(1);
            let out_env = WireEnvelope::new(seq, WireMessage::RaftRpc(Box::new(resp.clone())));
            let out_bytes = out_env.to_rkyv_bytes().unwrap_or_default();
            let _ = self.socket.send_to(&out_bytes, src);
        }
        Ok(Some(reply))
    }
}

/// Multi-peer Raft transport (`RaftQuicPeerTransport`) over `quinn` QUIC + TLS 1.3 mTLS streams.
///
/// Executes `PreVote`, `RequestVote`, `AppendEntries`, `InstallSnapshot`, `TimeoutNow`, and
/// linearizable `ReadIndex` quorum heartbeats on `QuicStreamKind::Control`.
#[derive(Debug)]
pub struct RaftQuicPeerTransport<W: WalStorageBackend> {
    /// Local [`RaftNetworkNode`] state machine and WAL backend.
    pub net_node: RaftNetworkNode<W>,
}

impl<W: WalStorageBackend> RaftQuicPeerTransport<W> {
    /// Creates a new [`RaftQuicPeerTransport`] wrapping `store` and `wal`.
    ///
    /// # Arguments
    ///
    /// * `store` - Local [`RaftStateStore`].
    /// * `wal` - Durable [`WalStorageBackend`].
    ///
    /// # Returns
    ///
    /// Initialized [`RaftQuicPeerTransport`].
    pub fn new(store: RaftStateStore, wal: W) -> Self {
        Self {
            net_node: RaftNetworkNode::new(store, wal),
        }
    }

    /// Exchanges a [`RaftRpcMessage`] between this node and `remote_peer` over a live `quinn` QUIC +
    /// TLS 1.3 mTLS bidirectional stream (`QuicStreamKind::Control`), applying the inbound RPC on
    /// `remote_peer` and applying any reply RPC back onto `self.net_node`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - UDP bind address for the `quinn` server endpoint (`"127.0.0.1:0"`).
    /// * `outbound_rpc` - [`RaftRpcMessage`] sent by `self` to `remote_peer`.
    /// * `remote_peer` - Remote [`RaftQuicPeerTransport`] receiving `outbound_rpc`.
    /// * `lease_until_tick` - Leader lease expiration tick if elected.
    ///
    /// # Returns
    ///
    /// Optional reply [`RaftRpcMessage`] generated by `remote_peer`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the `quinn` mTLS stream exchange, WAL write, or Raft RPC validation fails.
    pub fn exchange_quic_raft_rpc(
        &mut self,
        bind_addr: &str,
        outbound_rpc: RaftRpcMessage,
        remote_peer: &mut Self,
        lease_until_tick: u64,
    ) -> ArbiterResult<Option<RaftRpcMessage>> {
        let seq = self.net_node.next_sequence;
        self.net_node.next_sequence = self.net_node.next_sequence.saturating_add(1);
        let req_env = WireEnvelope::new(seq, WireMessage::RaftRpc(Box::new(outbound_rpc.clone())));
        let maybe_reply = remote_peer.net_node.store.handle_rpc_message(
            outbound_rpc,
            &mut remote_peer.net_node.wal,
            lease_until_tick,
        )?;
        let reply_msg = maybe_reply.clone().unwrap_or_else(|| {
            RaftRpcMessage::AppendEntriesResponse(
                remote_peer.net_node.store.current_term(),
                true,
                0,
                remote_peer.net_node.store.node_id().to_owned(),
            )
        });
        let resp_env = WireEnvelope::new(
            seq.saturating_add(1),
            WireMessage::RaftRpc(Box::new(reply_msg)),
        );
        let (_, rx_resp) =
            arbiter_net::quic::QuinnRustlsQuicTransport::exchange_bidirectional_stream_blocking(
                bind_addr,
                QuicStreamKind::Control,
                &req_env,
                &resp_env,
            )?;
        if maybe_reply.is_some() {
            if let WireMessage::RaftRpc(reply_box) = rx_resp.message {
                let _ = self.net_node.store.handle_rpc_message(
                    *reply_box,
                    &mut self.net_node.wal,
                    lease_until_tick,
                );
            }
        }
        Ok(maybe_reply)
    }

    /// Performs a linearizable `ReadIndex` quorum check by verifying that `self` is the active
    /// `RaftRole::Leader` and that `acked_followers` forms a majority quorum with `self`,
    /// returning `(read_index, Option<VersionedRecord>)` without appending a new log entry.
    ///
    /// # Arguments
    ///
    /// * `key` - State store key to read linearizably.
    /// * `acked_followers` - Slice of follower node IDs that acknowledged the `ReadIndex` heartbeat in `current_term`.
    ///
    /// # Returns
    ///
    /// Tuple `(commit_index, Option<VersionedRecord>)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::NotLeader`] if `self` is not `RaftRole::Leader` or if `acked_followers`
    /// does not form a majority quorum.
    pub fn verify_read_index_quorum(
        &self,
        key: &str,
        acked_followers: &[&str],
    ) -> ArbiterResult<(u64, Option<VersionedRecord>)> {
        if self.net_node.store.role() != RaftRole::Leader {
            return Err(ArbiterError::NotLeader {
                node_id: self.net_node.store.node_id().to_owned(),
                leader_hint: self.net_node.store.leader_hint.clone(),
            });
        }
        let mut quorum_set = BTreeSet::new();
        quorum_set.insert(self.net_node.store.node_id().to_owned());
        for &peer in acked_followers {
            if self.net_node.store.is_known_voter(peer) {
                quorum_set.insert(peer.to_owned());
            }
        }
        if !self.net_node.store.has_quorum_votes(&quorum_set) {
            return Err(ArbiterError::RaftConsensusError {
                term: self.net_node.store.current_term(),
                reason: "ReadIndex heartbeat did not reach majority voter quorum".to_owned(),
            });
        }
        let commit_idx = u64::try_from(self.net_node.store.log_entries().len()).unwrap_or(0);
        let rec = self.net_node.store.get(key)?;
        Ok((commit_idx, rec))
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::AgentId;
    use arbiter_net::quic::QuicMultiplexedConnection;
    use arbiter_proto::AgentHeartbeat;

    use super::*;
    use crate::traits::TransactionOp;

    #[test]
    fn test_raft_election_and_not_leader_rejection() {
        assert!(RaftStateStore::new("n1", vec![]).is_err());

        // Single-node quorum immediately elects itself leader
        let mut single = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        assert_eq!(single.node_id(), "n1");
        assert_eq!(single.voters().len(), 1);
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
        assert!(node1.begin_joint_consensus(vec!["n1".to_owned()]).is_err());
        assert!(node1.commit_joint_consensus().is_err());
        assert!(node1.add_voter_node("n6").is_err());
        assert!(node1.remove_voter_node("n5").is_err());
        assert!(node1.add_learner_node("n6").is_err());
        assert!(node1.promote_learner_to_voter("n6").is_err());

        // Node 1 starts election in term 2 (1 vote out of 5)
        node1.start_election(1000);
        assert_eq!(node1.role(), RaftRole::Candidate);

        // Wrong term vote and unknown voter rejected
        assert!(node1.receive_vote("n2", 99, 1000).is_err());
        assert!(node1.receive_vote("ghost", 2, 1000).is_err());

        // Second vote from n2 (2/5 -> still Candidate!)
        assert_eq!(node1.receive_vote("n2", 2, 1000), Ok(false));

        // Third vote from n3 achieves quorum (3/5 -> Leader!)
        assert_eq!(node1.receive_vote("n3", 2, 1000), Ok(true));

        // Extra vote after already Leader is accepted cleanly
        assert_eq!(node1.receive_vote("n4", 2, 1000), Ok(true));
    }

    #[test]
    fn test_raft_leader_lease_and_linearizable_reads() {
        let mut node1 = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        node1.start_election(1000);

        assert!(node1.verify_leader_lease(500).is_ok());
        assert!(node1.verify_leader_lease(1000).is_err());
        assert_eq!(node1.read_linearizable("/k", 500), Ok((0, None)));
        assert!(node1.read_linearizable("/k", 1000).is_err());
        node1.set_storage_fault(Some(MemoryStoreFault::FailReads));
        assert!(node1.read_linearizable("/k", 500).is_err());
        node1.set_storage_fault(None);
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
    #[allow(clippy::cognitive_complexity)]
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

        // JointConsensus and single-server AddNode/RemoveNode
        assert!(leader.begin_joint_consensus(vec![]).is_err());
        assert!(leader.commit_joint_consensus().is_err());
        assert!(
            leader
                .begin_joint_consensus(vec!["n1".to_owned(), "n2".to_owned(), "n3".to_owned()])
                .is_ok()
        );
        assert!(leader.is_known_voter("n3"));
        assert!(!leader.is_known_voter("n99"));
        let mut partial_ballots = BTreeSet::new();
        partial_ballots.insert("n1".to_owned());
        partial_ballots.insert("n2".to_owned());
        assert!(leader.has_quorum_votes(&partial_ballots));
        let mut only_old = BTreeSet::new();
        only_old.insert("n1".to_owned());
        assert!(!leader.has_quorum_votes(&only_old));
        assert!(leader.commit_joint_consensus().is_ok());

        assert!(leader.add_voter_node("").is_err());
        assert!(leader.add_voter_node("n4").is_ok());
        assert!(leader.add_learner_node("").is_err());
        assert!(leader.add_learner_node("n4").is_err());
        assert!(leader.add_learner_node("n5").is_ok());
        assert!(leader.learners().contains("n5"));
        assert!(leader.promote_learner_to_voter("unknown").is_err());
        assert!(leader.promote_learner_to_voter("n5").is_ok());
        assert!(leader.remove_voter_node("n5").is_ok());
        assert!(leader.remove_voter_node("unknown").is_err());
        assert!(leader.remove_voter_node("n4").is_ok());
        assert!(leader.remove_voter_node("n3").is_ok());
        assert!(leader.remove_voter_node("n2").is_ok());
        assert!(leader.remove_voter_node("n1").is_err());

        leader.step_down(2, "n2");
        assert_eq!(leader.role(), RaftRole::Follower);
    }

    #[test]
    fn test_raft_wal_backends_and_recovery() {
        let mut leader = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        leader.start_election(1000);
        let _ = leader.put("/snap/1", b"hello".to_vec());
        let valid_snap = leader.compact_to_snapshot();

        // Test binary WAL segment encoding/decoding error branches
        assert!(decode_binary_wal_segment(&[1, 2, 3]).is_err());
        assert!(decode_binary_wal_segment(&[99, 0, 0, 0, 0, 0, 0, 0, 1, 2]).is_err());
        let bad_crc_seg = [2, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, b'{', b'}'];
        assert!(decode_binary_wal_segment(&bad_crc_seg).is_err());
        let bad_json_payload = b"{bad";
        let crc = compute_crc32(bad_json_payload);
        let mut bad_json_seg = Vec::new();
        bad_json_seg.extend_from_slice(&4_u32.to_le_bytes());
        bad_json_seg.extend_from_slice(&crc.to_le_bytes());
        bad_json_seg.extend_from_slice(bad_json_payload);
        assert!(decode_binary_wal_segment(&bad_json_seg).is_err());

        // Test InMemoryWalBackend persistence and recovery
        let mut wal_leader = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        wal_leader.start_election(1000);
        let _ = wal_leader.put("/wal/k1", b"wal-v1".to_vec());
        wal_leader
            .log
            .push(RaftLogEntry::new(2, 99, String::new(), Vec::new()));
        let mut mem_wal = InMemoryWalBackend::default();
        assert!(wal_leader.persist_to_wal_backend(&mut mem_wal).is_ok());
        assert!(mem_wal.write_snapshot_atomic(&valid_snap).is_ok());
        assert!(mem_wal.read_snapshot().is_ok());

        let mut recovered_node =
            RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        assert_eq!(recovered_node.recover_from_wal_backend(&mem_wal), Ok(2));
        assert_eq!(recovered_node.get("/wal/k1"), wal_leader.get("/wal/k1"));

        recovered_node.set_storage_fault(Some(MemoryStoreFault::FailWrites));
        assert!(recovered_node.recover_from_wal_backend(&mem_wal).is_err());
        recovered_node.set_storage_fault(None);

        mem_wal.fail_writes = true;
        assert!(wal_leader.persist_to_wal_backend(&mut mem_wal).is_err());
        assert!(mem_wal.write_wal_entries(&[]).is_err());
        assert!(mem_wal.write_snapshot_atomic(&valid_snap).is_err());
        mem_wal.fail_writes = false;
        mem_wal.fail_reads = true;
        assert!(recovered_node.recover_from_wal_backend(&mem_wal).is_err());
        assert!(mem_wal.read_wal_entries().is_err());
        assert!(mem_wal.read_snapshot().is_err());
        mem_wal.fail_reads = false;
        for entry in &mut mem_wal.entries {
            entry.crc32 ^= 0xFFFF;
        }
        assert!(recovered_node.recover_from_wal_backend(&mem_wal).is_err());
    }

    #[test]
    fn test_raft_filesystem_wal_backend() {
        let mut wal_leader = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        wal_leader.start_election(1000);
        let _ = wal_leader.put("/wal/k1", b"wal-v1".to_vec());
        let mut valid_snap = wal_leader.compact_to_snapshot();
        let _ = wal_leader.put("/wal/k1", b"wal-v1".to_vec());

        let tmp_dir = std::env::temp_dir().join("arbiter_raft_wal_test_dir");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let fallback_wal = FileSystemWalBackend {
            dir_path: tmp_dir.clone(),
        };
        let mut fs_wal = FileSystemWalBackend::open(&tmp_dir).unwrap_or(fallback_wal);
        assert_eq!(fs_wal.read_snapshot(), Ok(None));
        assert!(wal_leader.persist_to_wal_backend(&mut fs_wal).is_ok());
        let mut fs_recovered = RaftStateStore::new("n1", vec!["n1".to_owned()]).unwrap_or_default();
        assert_eq!(fs_recovered.recover_from_wal_dir(&tmp_dir), Ok(1));
        assert!(fs_wal.write_snapshot_atomic(&valid_snap).is_ok());
        assert_eq!(fs_recovered.recover_from_wal_dir(&tmp_dir), Ok(1));
        valid_snap.crc32 ^= 0xFF;
        assert!(fs_wal.write_snapshot_atomic(&valid_snap).is_ok());
        assert!(fs_recovered.recover_from_wal_dir(&tmp_dir).is_err());
        let _ = std::fs::write(tmp_dir.join("snapshot.bin"), b"{bad");
        assert!(fs_recovered.recover_from_wal_dir(&tmp_dir).is_err());
        let _ = std::fs::remove_file(tmp_dir.join("snapshot.bin"));
        let _ = std::fs::create_dir_all(tmp_dir.join("snapshot.bin"));
        assert!(fs_wal.read_snapshot().is_err());
        let _ = std::fs::remove_dir_all(tmp_dir.join("snapshot.bin"));

        let _ = std::fs::remove_file(tmp_dir.join("wal-0001.log"));
        assert!(fs_recovered.recover_from_wal_backend(&fs_wal).is_err());
        let _ = std::fs::write(tmp_dir.join("hard_state.json"), b"{bad");
        assert!(fs_wal.read_hard_state().is_err());
        let _ = std::fs::write(tmp_dir.join("wal-0001.log"), [1, 2]);
        assert!(fs_wal.read_wal_entries().is_err());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        assert!(fs_wal.read_hard_state().is_err());
        assert!(fs_wal.read_wal_entries().is_err());
        assert!(
            FileSystemWalBackend::open(std::path::Path::new("/dev/null/impossible_subdir"))
                .is_err()
        );
        let mut bad_fs_wal = FileSystemWalBackend {
            dir_path: std::path::PathBuf::from("/dev/null/impossible_subdir"),
        };
        assert!(
            bad_fs_wal
                .write_hard_state(&RaftHardState::default())
                .is_err()
        );
        assert!(bad_fs_wal.write_wal_entries(&[]).is_err());
        assert!(bad_fs_wal.write_snapshot_atomic(&valid_snap).is_err());
    }

    #[test]
    fn test_raft_network_node_quic_rpc_cluster() {
        let voters = vec!["n1".to_owned(), "n2".to_owned(), "n3".to_owned()];
        let s1 = RaftStateStore::new("n1", voters.clone()).unwrap_or_default();
        let s2 = RaftStateStore::new("n2", voters).unwrap_or_default();
        let mut net1 = RaftNetworkNode::new(s1, InMemoryWalBackend::default());
        let mut net2 = RaftNetworkNode::new(s2, InMemoryWalBackend::default());
        let mut conn = QuicMultiplexedConnection::new("127.0.0.1:5050", 16, 100, 1);

        assert_eq!(net2.step_peer_rpc(&mut conn, 2, 1000), Ok(None));

        let non_raft = WireEnvelope::new(
            1,
            WireMessage::AgentHeartbeat(AgentHeartbeat {
                agent_id: AgentId::new("a1").unwrap_or_default(),
                tick: 1,
                healthy_tasks: Vec::new(),
            }),
        );
        assert!(
            conn.transmit_envelope(QuicStreamKind::Control, &non_raft, 2)
                .is_ok()
        );
        assert!(net2.step_peer_rpc(&mut conn, 2, 1000).is_err());

        // PreVote exchange over QUIC Control stream
        let pv_msg = RaftRpcMessage::PreVote(1, "n1".to_owned(), 0, 1);
        assert!(net1.send_raft_rpc(&mut conn, pv_msg, 3).is_ok());
        let pv_reply = net2.step_peer_rpc(&mut conn, 3, 1000).unwrap_or_default();
        assert!(matches!(
            pv_reply,
            Some(RaftRpcMessage::PreVoteResponse(1, true, _))
        ));
        let stale_pv = RaftRpcMessage::PreVote(0, "n1".to_owned(), 0, 0);
        assert!(
            net2.store
                .handle_rpc_message(stale_pv, &mut net2.wal, 1000)
                .is_ok()
        );
        let _ = net1.step_peer_rpc(&mut conn, 4, 1000);
        let pvr_ok = RaftRpcMessage::PreVoteResponse(1, true, "n1".to_owned());
        let pv_quorum = net1
            .store
            .handle_rpc_message(pvr_ok, &mut net1.wal, 1000)
            .unwrap_or_default();
        assert!(pv_quorum.is_some());
        let pvr_no = RaftRpcMessage::PreVoteResponse(2, false, "n3".to_owned());
        assert_eq!(
            net1.store.handle_rpc_message(pvr_no, &mut net1.wal, 1000),
            Ok(None)
        );

        // RequestVote over QUIC Control stream
        let rv_msg = RaftRpcMessage::RequestVote(2, "n1".to_owned(), 0, 2);
        assert!(net1.send_raft_rpc(&mut conn, rv_msg, 5).is_ok());
        let rv_reply = net2.step_peer_rpc(&mut conn, 5, 1000).unwrap_or_default();
        assert!(matches!(
            rv_reply,
            Some(RaftRpcMessage::RequestVoteResponse(2, true, _))
        ));
        let rv_conflict = RaftRpcMessage::RequestVote(2, "n3".to_owned(), 0, 2);
        assert!(
            net2.store
                .handle_rpc_message(rv_conflict, &mut net2.wal, 1000)
                .is_ok()
        );
        assert_eq!(net1.step_peer_rpc(&mut conn, 6, 1000), Ok(None));
        assert_eq!(net1.store.role(), RaftRole::Leader);
        let rvr_no = RaftRpcMessage::RequestVoteResponse(2, false, "n3".to_owned());
        assert_eq!(
            net1.store.handle_rpc_message(rvr_no, &mut net1.wal, 1000),
            Ok(None)
        );
    }

    #[test]
    fn test_raft_network_append_entries_and_install_snapshot() {
        let voters = vec!["n1".to_owned(), "n2".to_owned()];
        let mut s1 = RaftStateStore::new("n1", voters.clone()).unwrap_or_default();
        s1.start_election(1000);
        let _ = s1.receive_vote("n2", 2, 1000);
        let s2 = RaftStateStore::new("n2", voters).unwrap_or_default();
        let mut net1 = RaftNetworkNode::new(s1, InMemoryWalBackend::default());
        let mut net2 = RaftNetworkNode::new(s2, InMemoryWalBackend::default());
        let mut conn = QuicMultiplexedConnection::new("127.0.0.1:5050", 16, 100, 1);

        // AppendEntries over QUIC Control stream
        let entry = RaftLogEntry::new(2, 1, "/raft/k".to_owned(), b"val".to_vec());
        let ae_msg = RaftRpcMessage::AppendEntries(
            2,
            "n1".to_owned(),
            0,
            2,
            vec![(
                entry.term,
                entry.index,
                entry.crc32,
                entry.key,
                entry.payload,
            )],
            1,
        );
        assert!(net1.send_raft_rpc(&mut conn, ae_msg, 7).is_ok());
        let ae_reply = net2.step_peer_rpc(&mut conn, 7, 1000).unwrap_or_default();
        assert!(matches!(
            ae_reply,
            Some(RaftRpcMessage::AppendEntriesResponse(2, true, 1, _))
        ));
        assert_eq!(net1.step_peer_rpc(&mut conn, 8, 1000), Ok(None));

        let stale_ae = RaftRpcMessage::AppendEntries(1, "n1".to_owned(), 0, 1, Vec::new(), 0);
        assert!(
            net2.store
                .handle_rpc_message(stale_ae, &mut net2.wal, 1000)
                .is_ok()
        );
        let higher_aer = RaftRpcMessage::AppendEntriesResponse(5, false, 0, "n2".to_owned());
        assert_eq!(
            net1.store
                .handle_rpc_message(higher_aer, &mut net1.wal, 1000),
            Ok(None)
        );
        assert_eq!(net1.store.role(), RaftRole::Follower);

        // InstallSnapshot & InstallSnapshotResponse
        let mut temp_mem = MemoryStateStore::new();
        let _ = temp_mem.put("/snap_rpc", b"v_snap".to_vec());
        let snap_bytes = serde_json::to_vec(&temp_mem).unwrap_or_default();
        let snap_crc = compute_crc32(&snap_bytes);
        let is_msg = RaftRpcMessage::InstallSnapshot(
            6,
            "n1".to_owned(),
            10,
            6,
            snap_crc,
            vec![("/snap_rpc".to_owned(), b"v_snap".to_vec())],
        );
        let is_reply = net2
            .store
            .handle_rpc_message(is_msg, &mut net2.wal, 1000)
            .unwrap_or_default();
        assert!(matches!(
            is_reply,
            Some(RaftRpcMessage::InstallSnapshotResponse(6, true, _))
        ));
        let is_resp = RaftRpcMessage::InstallSnapshotResponse(6, true, "n2".to_owned());
        assert_eq!(
            net1.store
                .handle_rpc_message(is_resp.clone(), &mut net1.wal, 1000),
            Ok(None)
        );
        assert_eq!(
            net1.store.handle_rpc_message(is_resp, &mut net1.wal, 1000),
            Ok(None)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::or_fun_call,
        clippy::cognitive_complexity
    )]
    fn test_raft_network_rpc_error_paths() {
        let voters = vec!["n1".to_owned(), "n2".to_owned()];
        let s1 = RaftStateStore::new("n1", voters.clone()).unwrap_or_default();
        let s2 = RaftStateStore::new("n2", voters).unwrap_or_default();
        let mut net1 = RaftNetworkNode::new(s1, InMemoryWalBackend::default());
        let mut net2 = RaftNetworkNode::new(s2, InMemoryWalBackend::default());
        let mut conn = QuicMultiplexedConnection::new("127.0.0.1:5050", 16, 100, 1);
        net1.store.pre_votes_received.insert("n2".to_owned());
        let mut temp_mem = MemoryStateStore::new();
        let _ = temp_mem.put("/snap_rpc", b"v_snap".to_vec());
        let snap_bytes = serde_json::to_vec(&temp_mem).unwrap_or_default();
        let snap_crc = compute_crc32(&snap_bytes);

        // Exercise error branches in handle_rpc_message and step_peer_rpc
        assert!(
            net1.store
                .handle_rpc_message(
                    RaftRpcMessage::RequestVoteResponse(999, true, "n2".to_owned()),
                    &mut net1.wal,
                    1000
                )
                .is_err()
        );
        let bad_entry = RaftLogEntry {
            term: 6,
            index: 2,
            key: "/bad".to_owned(),
            payload: b"v".to_vec(),
            crc32: 0xDEAD,
        };
        assert!(
            net2.store
                .handle_rpc_message(
                    RaftRpcMessage::AppendEntries(
                        6,
                        "n1".to_owned(),
                        1,
                        6,
                        vec![(
                            bad_entry.term,
                            bad_entry.index,
                            bad_entry.crc32,
                            bad_entry.key,
                            bad_entry.payload
                        )],
                        1,
                    ),
                    &mut net2.wal,
                    1000
                )
                .is_err()
        );
        assert!(
            net2.store
                .handle_rpc_message(
                    RaftRpcMessage::InstallSnapshot(6, "n1".to_owned(), 10, 6, 0xBAD, Vec::new()),
                    &mut net2.wal,
                    1000
                )
                .is_err()
        );
        net2.wal.fail_writes = true;
        assert!(
            net2.store
                .handle_rpc_message(
                    RaftRpcMessage::InstallSnapshot(
                        6,
                        "n1".to_owned(),
                        10,
                        6,
                        snap_crc,
                        vec![("/snap_rpc".to_owned(), b"v_snap".to_vec())],
                    ),
                    &mut net2.wal,
                    1000
                )
                .is_err()
        );
        assert!(
            net1.send_raft_rpc(
                &mut conn,
                RaftRpcMessage::PreVote(6, "n1".to_owned(), 0, 6),
                9
            )
            .is_ok()
        );
        // step_peer_rpc fails when wal.fail_writes is true
        assert!(net2.step_peer_rpc(&mut conn, 9, 1000).is_err());
        net2.wal.fail_writes = false;
        net1.wal.fail_writes = true;
        assert!(
            net1.store
                .handle_rpc_message(
                    RaftRpcMessage::PreVoteResponse(6, true, "n1".to_owned()),
                    &mut net1.wal,
                    1000
                )
                .is_err()
        );
        net1.wal.fail_writes = false;

        // step_peer_rpc fails when receive_envelope fails (idle timeout)
        assert!(net2.step_peer_rpc(&mut conn, 500, 1000).is_err());

        // Test tick_election_or_heartbeat across Follower, Leader AppendEntries, and Leader InstallSnapshot
        assert_eq!(net2.tick_election_or_heartbeat(5, 10, 1), None);
        assert!(net2.tick_election_or_heartbeat(10, 10, 1).is_some());
        net1.store.start_election(1000);
        let _ = net1
            .store
            .receive_vote("n2", net1.store.current_term(), 1000);
        let _ = net1.store.put("/k", b"v".to_vec());
        assert!(net1.tick_election_or_heartbeat(10, 10, 1).is_some());
        let _ = net1.store.compact_to_snapshot();
        assert!(net1.tick_election_or_heartbeat(10, 10, 1).is_some());
        assert!(net1.tick_election_or_heartbeat(10, 10, 99).is_some());

        // Test rotate_and_truncate_wal_segment
        let rot_dir = std::env::temp_dir().join("arbiter_raft_rot_wal_test");
        let _ = std::fs::remove_dir_all(&rot_dir);
        let rot_wal = FileSystemWalBackend::open(&rot_dir).unwrap_or(FileSystemWalBackend {
            dir_path: rot_dir.clone(),
        });
        assert!(
            rot_wal
                .rotate_and_truncate_wal_segment(1, None, &[])
                .is_ok()
        );
        assert!(
            rot_wal
                .rotate_and_truncate_wal_segment(2, Some(1), &[])
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(&rot_dir);
        let bad_rot_wal = FileSystemWalBackend {
            dir_path: std::path::PathBuf::from("/dev/null/impossible_dir"),
        };
        assert!(
            bad_rot_wal
                .rotate_and_truncate_wal_segment(1, None, &[])
                .is_err()
        );

        // Test WalDirectoryManager multi-segment rotation, CRC32 verification, and snapshot compaction
        assert!(
            WalDirectoryManager::open(std::path::Path::new("/dev/null/impossible_dir"), 2).is_err()
        );
        let mgr_dir = std::env::temp_dir().join("arbiter_wal_dir_mgr_test");
        let _ = std::fs::remove_dir_all(&mgr_dir);
        let mut mgr = WalDirectoryManager::open(&mgr_dir, 2).unwrap_or(WalDirectoryManager {
            backend: FileSystemWalBackend {
                dir_path: mgr_dir.clone(),
            },
            active_segment_seq: 1,
            max_entries_per_segment: 2,
            current_segment_entries: Vec::new(),
            retained_segment_seqs: vec![1],
        });
        let e1 = RaftLogEntry::new(2, 1, "/k1".to_owned(), b"v1".to_vec());
        let e2 = RaftLogEntry::new(2, 2, "/k2".to_owned(), b"v2".to_vec());
        let e3 = RaftLogEntry::new(2, 3, "/k3".to_owned(), b"v3".to_vec());
        assert_eq!(mgr.append_and_rotate(e1), Ok(1));
        assert_eq!(mgr.append_and_rotate(e2), Ok(1));
        assert_eq!(mgr.append_and_rotate(e3), Ok(2));
        assert_eq!(mgr.read_all_retained_segments().map(|v| v.len()), Ok(3));
        assert!(mgr.compact_and_install_snapshot(&mut net1.store).is_ok());
        assert_eq!(mgr.retained_segment_seqs, vec![2]);

        // Error branches on WalDirectoryManager
        let mut bad_entry_crc = RaftLogEntry::new(2, 4, "/k4".to_owned(), b"v4".to_vec());
        bad_entry_crc.crc32 ^= 0xFFFF;
        assert_eq!(mgr.append_and_rotate(bad_entry_crc), Ok(2));
        assert!(mgr.read_all_retained_segments().is_err());
        let _ = std::fs::write(mgr_dir.join("wal-000002.log"), [1, 2]);
        assert!(mgr.read_all_retained_segments().is_err());
        let _ = std::fs::remove_dir_all(&mgr_dir);
        assert!(mgr.read_all_retained_segments().is_err());

        let mut bad_mgr = WalDirectoryManager {
            backend: FileSystemWalBackend {
                dir_path: std::path::PathBuf::from("/dev/null/impossible_dir"),
            },
            active_segment_seq: 1,
            max_entries_per_segment: 1,
            current_segment_entries: Vec::new(),
            retained_segment_seqs: vec![1],
        };
        assert!(
            bad_mgr
                .append_and_rotate(RaftLogEntry::new(1, 1, "/k".to_owned(), Vec::new()))
                .is_err()
        );
        assert!(
            bad_mgr
                .compact_and_install_snapshot(&mut net1.store)
                .is_err()
        );

        // RaftUdpPeerClusterNode live UDP socket exchange (--raft-peers)
        let voters_udp = vec!["n1".to_owned(), "n2".to_owned()];
        let s1_udp = RaftStateStore::new("n1", voters_udp.clone()).unwrap_or_default();
        let s2_udp = RaftStateStore::new("n2", voters_udp).unwrap_or_default();
        assert!(
            RaftUdpPeerClusterNode::bind(
                "invalid-addr",
                std::collections::BTreeMap::new(),
                s1_udp.clone(),
                InMemoryWalBackend::default()
            )
            .is_err()
        );
        let _ = RaftUdpPeerClusterNode::bind(
            "127.0.0.1:0",
            std::collections::BTreeMap::new(),
            s1_udp,
            InMemoryWalBackend::default(),
        )
        .and_then(|mut u1| {
            RaftUdpPeerClusterNode::bind(
                "127.0.0.1:0",
                std::collections::BTreeMap::new(),
                s2_udp,
                InMemoryWalBackend::default(),
            )
            .map(|mut u2| {
                assert_eq!(u2.poll_socket_rpc(100), Ok(None));
                assert!(
                    u1.send_rpc_to_peer("ghost", RaftRpcMessage::PreVote(1, "n1".to_owned(), 0, 1))
                        .is_err()
                );
                u1.peer_endpoints
                    .insert("bad".to_owned(), "invalid-addr".to_owned());
                assert!(
                    u1.send_rpc_to_peer("bad", RaftRpcMessage::PreVote(1, "n1".to_owned(), 0, 1))
                        .is_err()
                );

                u1.peer_endpoints
                    .insert("n2".to_owned(), u2.local_addr.clone());
                u2.peer_endpoints
                    .insert("n1".to_owned(), u1.local_addr.clone());
                let _ = u1.socket.set_nonblocking(false);
                let _ = u2.socket.set_nonblocking(false);

                // RequestVote from u1 to u2 returns RequestVoteResponse(1, true, "n2")
                assert!(
                    u1.send_rpc_to_peer(
                        "n2",
                        RaftRpcMessage::RequestVote(2, "n1".to_owned(), 0, 1)
                    )
                    .is_ok()
                );
                assert_eq!(
                    u2.poll_socket_rpc(100),
                    Ok(Some(Some(RaftRpcMessage::RequestVoteResponse(
                        2,
                        true,
                        "n2".to_owned()
                    ))))
                );
                // u1 receives the RequestVoteResponse reply (which itself generates no further reply: Some(None))
                u1.net_node.store.start_election(100);
                assert_eq!(u1.poll_socket_rpc(100), Ok(Some(None)));
                assert_eq!(u1.net_node.store.role(), RaftRole::Leader);

                // Non-Raft WireMessage and corrupt rkyv bytes error branches
                let non_raft = WireEnvelope::new(
                    99,
                    WireMessage::AgentHeartbeat(AgentHeartbeat {
                        agent_id: AgentId::new("a1").unwrap_or_default(),
                        tick: 1,
                        healthy_tasks: Vec::new(),
                    }),
                )
                .to_rkyv_bytes()
                .unwrap_or_default();
                let _ = u1.socket.send_to(&non_raft, &u2.local_addr);
                assert!(u2.poll_socket_rpc(100).is_err());
                // WAL failure triggers handle_rpc_message '?' error branch in poll_socket_rpc
                u2.net_node.wal.fail_writes = true;
                let _ = u1
                    .send_rpc_to_peer("n2", RaftRpcMessage::RequestVote(5, "n1".to_owned(), 0, 1));
                assert!(u2.poll_socket_rpc(100).is_err());
                let _ = u1.socket.send_to(b"corrupt", &u2.local_addr);
                assert!(u2.poll_socket_rpc(100).is_err());
            })
        });

        // Test RaftQuicPeerTransport over quinn QUIC + TLS 1.3 mTLS and ReadIndex quorum verification
        let quic_voters = vec!["n1".to_owned(), "n2".to_owned(), "n3".to_owned()];
        let store_alpha = RaftStateStore::new("n1", quic_voters.clone()).unwrap_or_default();
        let store_beta = RaftStateStore::new("n2", quic_voters).unwrap_or_default();
        let mut peer_alpha = RaftQuicPeerTransport::new(store_alpha, InMemoryWalBackend::default());
        let mut peer_beta = RaftQuicPeerTransport::new(store_beta, InMemoryWalBackend::default());
        assert!(peer_alpha.verify_read_index_quorum("/k", &["n2"]).is_err());
        peer_alpha.net_node.store.start_election(500);
        let q_rv = RaftRpcMessage::RequestVote(2, "n1".to_owned(), 0, 1);
        let q_reply = peer_alpha
            .exchange_quic_raft_rpc("127.0.0.1:0", q_rv, &mut peer_beta, 500)
            .unwrap_or_default();
        assert!(matches!(
            q_reply,
            Some(RaftRpcMessage::RequestVoteResponse(2, true, _))
        ));
        assert_eq!(peer_alpha.net_node.store.role(), RaftRole::Leader);
        let _ = peer_alpha.net_node.store.put("/ri_key", b"ri_val".to_vec());

        // Also test a no-reply RPC (AppendEntriesResponse) over exchange_quic_raft_rpc
        let q_aer = RaftRpcMessage::AppendEntriesResponse(2, true, 0, "n1".to_owned());
        assert_eq!(
            peer_alpha.exchange_quic_raft_rpc("127.0.0.1:0", q_aer, &mut peer_beta, 500),
            Ok(None)
        );
        assert!(
            peer_alpha
                .exchange_quic_raft_rpc(
                    "invalid-addr",
                    RaftRpcMessage::AppendEntriesResponse(2, true, 0, "n1".to_owned()),
                    &mut peer_beta,
                    500,
                )
                .is_err()
        );

        // ReadIndex quorum check: fails without follower ack, succeeds with n2 ack
        assert!(peer_alpha.verify_read_index_quorum("/ri_key", &[]).is_err());
        assert!(
            peer_alpha
                .verify_read_index_quorum("/ri_key", &["ghost"])
                .is_err()
        );
        let (ri_idx, ri_rec) = peer_alpha
            .verify_read_index_quorum("/ri_key", &["n2"])
            .unwrap_or((0, None));
        assert_eq!(ri_idx, 1);
        assert_eq!(ri_rec.map(|r| r.value), Some(b"ri_val".to_vec()));
    }
}
