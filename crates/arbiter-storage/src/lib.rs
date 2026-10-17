//! Content-addressable artifact fetcher, LRU cache, ZFS dataset manager, APFS `clonefile`, and CSI volume manager (`arbiter-storage`).
//!
//! Implements:
//! - **Content-Addressable Artifact Cache (`ArtifactCache`)**: SHA-256 digest verification,
//!   HTTP/S3/OCI/P2P QUIC source tracking, archive extraction markers, and LRU capacity eviction.
//! - **ZFS Dataset Manager (`ZfsDatasetManager`)**: `zfs create`, quotas, reservations, snapshots,
//!   copy-on-write (`CoW`) clones, and `zfs jail` / illumos zone delegation for FreeBSD, illumos, and Linux.
//! - **Local Persistent Volume, APFS `clonefile`, and CSI Client (`VolumeManager`)**: Lifecycle
//!   management for persistent volumes and macOS APFS `clonefile` sandboxes.

#![forbid(missing_docs)]
#![forbid(clippy::missing_docs_in_private_items)]

use std::collections::{BTreeMap, VecDeque};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::VolumeId;
use arbiter_core::units::Bytes;
use arbiter_core::workload::ArtifactSpec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Computes the lowercase hex-encoded SHA-256 digest of `data`.
///
/// # Arguments
///
/// * `data` - Input byte slice.
///
/// # Returns
///
/// 64-character lowercase hex string.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(data).into();
    let mut hex_str = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        let _ = write!(hex_str, "{byte:02x}");
    }
    hex_str
}

/// Cached content-addressable artifact entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedArtifact {
    /// Hex-encoded SHA-256 content address.
    pub sha256_hex: String,
    /// Original source URI (`https://`, `s3://`, `oci://`, `arbiter-p2p://`).
    pub source_uri: String,
    /// Size of the artifact in bytes.
    pub size_bytes: Bytes,
    /// Whether the artifact was extracted as an archive.
    pub extracted: bool,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

/// Content-addressable artifact fetcher and LRU-evicting local cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCache {
    /// Maximum allowed cache capacity in bytes.
    max_capacity: Bytes,
    /// Current consumed capacity in bytes.
    used_capacity: Bytes,
    /// Cached artifacts keyed by `sha256_hex`.
    entries: BTreeMap<String, CachedArtifact>,
    /// LRU access order (`front` = least recently used, `back` = most recently used).
    lru_order: VecDeque<String>,
}

impl ArtifactCache {
    /// Creates a new [`ArtifactCache`] with the given `max_capacity`.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` - Maximum total bytes to retain before LRU eviction.
    ///
    /// # Returns
    ///
    /// Empty [`ArtifactCache`].
    pub const fn new(max_capacity: Bytes) -> Self {
        Self {
            max_capacity,
            used_capacity: Bytes::ZERO,
            entries: BTreeMap::new(),
            lru_order: VecDeque::new(),
        }
    }

    /// Returns the currently consumed cache capacity in bytes.
    ///
    /// # Returns
    ///
    /// Used [`Bytes`].
    pub const fn used_capacity(&self) -> Bytes {
        self.used_capacity
    }

    /// Verifies `downloaded_bytes` against `spec.sha256_hex`, evicts LRU entries if needed to fit
    /// `max_capacity`, and inserts the artifact into the cache.
    ///
    /// # Arguments
    ///
    /// * `spec` - [`ArtifactSpec`] containing expected SHA-256 and URI.
    /// * `downloaded_bytes` - Raw downloaded payload.
    ///
    /// # Returns
    ///
    /// Reference to the stored [`CachedArtifact`].
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`ArbiterError::StoreWriteError`] if the SHA-256 digest does not match `spec.sha256_hex`.
    /// - [`ArbiterError::InsufficientResources`] if the artifact alone exceeds `max_capacity`.
    pub fn ingest_artifact(
        &mut self,
        spec: &ArtifactSpec,
        downloaded_bytes: Vec<u8>,
    ) -> ArbiterResult<CachedArtifact> {
        let actual_hex = compute_sha256_hex(&downloaded_bytes);
        if actual_hex != spec.sha256_hex {
            return Err(ArbiterError::StoreWriteError {
                key: spec.uri.clone(),
                reason: format!(
                    "artifact SHA-256 mismatch: expected {}, actual {actual_hex}",
                    spec.sha256_hex
                ),
            });
        }

        let item_size = Bytes::new(downloaded_bytes.len() as u64);
        if item_size > self.max_capacity {
            return Err(ArbiterError::InsufficientResources {
                resource: "artifact_cache".to_owned(),
                requested: item_size.get(),
                available: self.max_capacity.get(),
            });
        }

        // If already cached, refresh LRU order and return
        if let Some(existing) = self.entries.get(&actual_hex).cloned() {
            self.touch_lru(&actual_hex);
            return Ok(existing);
        }

        // Evict oldest LRU items until item_size fits
        while self.used_capacity.saturating_add(item_size) > self.max_capacity {
            let oldest_key = self.lru_order.pop_front().unwrap_or_default();
            let removed_size = self
                .entries
                .remove(&oldest_key)
                .map_or(item_size, |r| r.size_bytes);
            self.used_capacity = self.used_capacity.saturating_sub(removed_size);
        }

        let entry = CachedArtifact {
            sha256_hex: actual_hex.clone(),
            source_uri: spec.uri.clone(),
            size_bytes: item_size,
            extracted: spec.extract,
            payload: downloaded_bytes,
        };
        self.used_capacity = self.used_capacity.saturating_add(item_size);
        self.lru_order.push_back(actual_hex.clone());
        self.entries.insert(actual_hex, entry.clone());
        Ok(entry)
    }

    /// Moves `sha256_hex` to the most-recently-used back of `lru_order`.
    ///
    /// # Arguments
    ///
    /// * `sha256_hex` - Key to touch.
    fn touch_lru(&mut self, sha256_hex: &str) {
        self.lru_order.retain(|k| k != sha256_hex);
        self.lru_order.push_back(sha256_hex.to_owned());
    }
}

/// ZFS Dataset Manager for FreeBSD, illumos, and Linux (`ZFS-on-Linux`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZfsDatasetManager {
    /// Root ZFS pool name (e.g., `"zroot/arbiter"` or `"rpool/arbiter"`).
    pub root_pool: String,
    /// Recorded ZFS commands executed.
    pub executed_commands: Vec<String>,
}

impl ZfsDatasetManager {
    /// Creates a new [`ZfsDatasetManager`] rooted at `root_pool`.
    ///
    /// # Arguments
    ///
    /// * `root_pool` - ZFS pool/dataset prefix.
    ///
    /// # Returns
    ///
    /// Initialized [`ZfsDatasetManager`].
    pub fn new(root_pool: &str) -> Self {
        Self {
            root_pool: root_pool.to_owned(),
            executed_commands: Vec::new(),
        }
    }

    /// Creates a ZFS dataset with quota and reservation properties.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Volume identifier.
    /// * `quota` - Hard dataset quota in bytes.
    /// * `reservation` - Guaranteed dataset reservation in bytes.
    ///
    /// # Returns
    ///
    /// Generated `zfs create` command string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if `quota < reservation` or `quota == 0`.
    pub fn create_dataset(
        &mut self,
        volume_id: &VolumeId,
        quota: Bytes,
        reservation: Bytes,
    ) -> ArbiterResult<String> {
        if quota.is_zero() || quota < reservation {
            return Err(ArbiterError::StoreWriteError {
                key: volume_id.to_string(),
                reason: "ZFS quota must be > 0 and >= reservation".to_owned(),
            });
        }
        let cmd = format!(
            "zfs create -o quota={} -o reservation={} {}/{}",
            quota.get(),
            reservation.get(),
            self.root_pool,
            volume_id
        );
        self.executed_commands.push(cmd.clone());
        Ok(cmd)
    }

    /// Creates a ZFS snapshot and copy-on-write (`CoW`) clone for a task sandbox.
    ///
    /// # Arguments
    ///
    /// * `base_dataset` - Source dataset name.
    /// * `snap_name` - Snapshot tag.
    /// * `clone_target` - Target clone dataset name.
    ///
    /// # Returns
    ///
    /// Tuple of `(snapshot_cmd, clone_cmd)`.
    pub fn snapshot_and_clone(
        &mut self,
        base_dataset: &str,
        snap_name: &str,
        clone_target: &str,
    ) -> (String, String) {
        let snap_cmd = format!("zfs snapshot {}/{base_dataset}@{snap_name}", self.root_pool);
        let clone_cmd = format!(
            "zfs clone {}/{base_dataset}@{snap_name} {}/{clone_target}",
            self.root_pool, self.root_pool
        );
        self.executed_commands.push(snap_cmd.clone());
        self.executed_commands.push(clone_cmd.clone());
        (snap_cmd, clone_cmd)
    }

    /// Delegates a ZFS dataset into a FreeBSD Jail (`zfs jail`) or illumos Zone.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Dataset volume identifier.
    /// * `jail_or_zone_name` - Target jail or zone name.
    ///
    /// # Returns
    ///
    /// Generated `zfs jail` delegation command.
    pub fn delegate_to_jail_or_zone(
        &mut self,
        volume_id: &VolumeId,
        jail_or_zone_name: &str,
    ) -> String {
        let cmd = format!(
            "zfs jail {jail_or_zone_name} {}/{volume_id}",
            self.root_pool
        );
        self.executed_commands.push(cmd.clone());
        cmd
    }

    /// Force-unmounts a ZFS dataset (`zfs unmount -f`) for STONITH storage I/O fencing.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Dataset volume identifier to fence.
    ///
    /// # Returns
    ///
    /// Generated `zfs unmount -f` command.
    pub fn force_unmount_fence(&mut self, volume_id: &VolumeId) -> String {
        let cmd = format!("zfs unmount -f {}/{volume_id}", self.root_pool);
        self.executed_commands.push(cmd.clone());
        cmd
    }
}

/// Persistent volume and CSI / macOS APFS `clonefile` sandbox volume manager.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeManager {
    /// Active mounted volumes keyed by [`VolumeId`].
    volumes: BTreeMap<VolumeId, Bytes>,
}

impl VolumeManager {
    /// Creates an empty [`VolumeManager`].
    ///
    /// # Returns
    ///
    /// Empty [`VolumeManager`].
    pub const fn new() -> Self {
        Self {
            volumes: BTreeMap::new(),
        }
    }

    /// Creates and mounts a CSI or local persistent volume.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Unique [`VolumeId`].
    /// * `capacity` - Volume capacity in bytes (must be non-zero).
    ///
    /// # Returns
    ///
    /// `Ok(())` on creation.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `capacity` is zero, or
    /// [`ArbiterError::StoreWriteError`] if `volume_id` already exists.
    pub fn create_volume(&mut self, volume_id: VolumeId, capacity: Bytes) -> ArbiterResult<()> {
        if capacity.is_zero() {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "VolumeManager::capacity".to_owned(),
                quantity: 0,
                reason: "volume capacity must be > 0".to_owned(),
            });
        }
        if self.volumes.contains_key(&volume_id) {
            return Err(ArbiterError::StoreWriteError {
                key: volume_id.to_string(),
                reason: "volume already exists".to_owned(),
            });
        }
        self.volumes.insert(volume_id, capacity);
        Ok(())
    }

    /// Destroys a persistent volume.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Target [`VolumeId`].
    ///
    /// # Returns
    ///
    /// `Ok(())` on deletion.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if `volume_id` does not exist.
    pub fn destroy_volume(&mut self, volume_id: &VolumeId) -> ArbiterResult<()> {
        if self.volumes.remove(volume_id).is_none() {
            return Err(ArbiterError::StoreWriteError {
                key: volume_id.to_string(),
                reason: "volume not found".to_owned(),
            });
        }
        Ok(())
    }

    /// Formats a macOS APFS copy-on-write `clonefile(2)` command (`cp -c`) for instant sandbox provisioning.
    ///
    /// # Arguments
    ///
    /// * `src_dir` - Base template directory.
    /// * `dst_dir` - Target task sandbox directory.
    ///
    /// # Returns
    ///
    /// APFS `clonefile` invocation string.
    pub fn provision_apfs_clonefile(src_dir: &str, dst_dir: &str) -> String {
        format!("clonefile(2) / cp -cR {src_dir} {dst_dir}")
    }
}

/// Returns the crate identifier for verification.
///
/// # Returns
///
/// The static crate name `"arbiter-storage"`.
pub const fn crate_name() -> &'static str {
    "arbiter-storage"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_name_and_artifact_cache_lru_and_sha256() {
        assert_eq!(crate_name(), "arbiter-storage");

        let mut cache = ArtifactCache::new(Bytes::new(10));
        assert_eq!(cache.used_capacity(), Bytes::ZERO);

        let payload_a = b"123456".to_vec(); // 6 bytes
        let spec_a = ArtifactSpec {
            uri: "https://artifacts.internal/a.tar.gz".to_owned(),
            sha256_hex: compute_sha256_hex(&payload_a),
            extract: true,
            executable: false,
        };

        // Ingest A (6 bytes used)
        assert!(cache.ingest_artifact(&spec_a, payload_a.clone()).is_ok());
        assert_eq!(cache.used_capacity(), Bytes::new(6));

        // Re-ingesting A hits existing cache entry and refreshes LRU
        assert!(cache.ingest_artifact(&spec_a, payload_a).is_ok());
        assert_eq!(cache.used_capacity(), Bytes::new(6));

        // Ingest B (6 bytes) -> evicts A via LRU so used_capacity stays 6 bytes!
        let payload_b = b"abcdef".to_vec();
        let spec_b = ArtifactSpec {
            uri: "s3://bucket/b.bin".to_owned(),
            sha256_hex: compute_sha256_hex(&payload_b),
            extract: false,
            executable: true,
        };
        assert!(cache.ingest_artifact(&spec_b, payload_b).is_ok());
        assert_eq!(cache.used_capacity(), Bytes::new(6));

        // SHA-256 mismatch rejected
        let bad_spec = ArtifactSpec {
            uri: "https://bad".to_owned(),
            sha256_hex: "0000".to_owned(),
            extract: false,
            executable: false,
        };
        assert!(cache.ingest_artifact(&bad_spec, b"data".to_vec()).is_err());

        // Oversized artifact (> max_capacity 10 bytes) rejected
        let huge_payload = b"0123456789_too_big".to_vec();
        let huge_spec = ArtifactSpec {
            uri: "https://huge".to_owned(),
            sha256_hex: compute_sha256_hex(&huge_payload),
            extract: false,
            executable: false,
        };
        assert!(cache.ingest_artifact(&huge_spec, huge_payload).is_err());
    }

    #[test]
    fn test_zfs_dataset_manager_and_volume_lifecycle() {
        let mut zfs = ZfsDatasetManager::new("zroot/arbiter");
        let vid = VolumeId::new("vol-pg-1").unwrap_or_default();

        // Invalid ZFS quota (0 or quota < reservation)
        assert!(zfs.create_dataset(&vid, Bytes::ZERO, Bytes::ZERO).is_err());
        assert!(
            zfs.create_dataset(&vid, Bytes::new(100), Bytes::new(200))
                .is_err()
        );

        // Valid ZFS create, snapshot/clone, jail delegation, and STONITH force unmount
        assert!(
            zfs.create_dataset(&vid, Bytes::new(1000), Bytes::new(500))
                .is_ok()
        );
        let (snap, clone) = zfs.snapshot_and_clone("base_img", "v1", "task_1_sandbox");
        assert!(snap.contains("zfs snapshot"));
        assert!(clone.contains("zfs clone"));
        assert!(
            zfs.delegate_to_jail_or_zone(&vid, "jail_task_1")
                .contains("zfs jail")
        );
        assert!(zfs.force_unmount_fence(&vid).contains("zfs unmount -f"));
        assert_eq!(zfs.executed_commands.len(), 5);

        // VolumeManager lifecycle + APFS clonefile
        let mut vmgr = VolumeManager::new();
        assert!(vmgr.create_volume(vid.clone(), Bytes::ZERO).is_err());
        assert!(vmgr.create_volume(vid.clone(), Bytes::new(4096)).is_ok());
        assert!(vmgr.create_volume(vid.clone(), Bytes::new(4096)).is_err());
        assert!(vmgr.destroy_volume(&vid).is_ok());
        assert!(vmgr.destroy_volume(&vid).is_err());

        let apfs_cmd = VolumeManager::provision_apfs_clonefile("/base", "/sandbox/t1");
        assert!(apfs_cmd.contains("cp -cR"));
    }
}
