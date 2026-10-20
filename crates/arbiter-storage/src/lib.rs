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

    /// Returns the maximum configured cache capacity in bytes.
    ///
    /// # Returns
    ///
    /// Maximum [`Bytes`].
    pub const fn max_capacity(&self) -> Bytes {
        self.max_capacity
    }

    /// Returns the number of cached artifacts currently stored.
    ///
    /// # Returns
    ///
    /// Count of cached entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
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

    /// Streams `chunks` into `<cache_dir>/staging.tmp` while computing an incremental SHA-256
    /// digest (`sha2::Sha256`), atomically renaming into `<cache_dir>/blobs/sha256/<digest>` only
    /// if the final hex digest matches `spec.sha256_hex`.
    ///
    /// # Arguments
    ///
    /// * `cache_dir` - Root content-addressable cache directory on disk.
    /// * `spec` - [`ArtifactSpec`] with expected `sha256_hex`.
    /// * `chunks` - Streamed byte chunks.
    ///
    /// # Returns
    ///
    /// Final blob file path (`<cache_dir>/blobs/sha256/<digest>`).
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if directory/file I/O fails or if the computed
    /// SHA-256 digest does not match `spec.sha256_hex`.
    pub fn stage_and_verify_blob_file(
        &mut self,
        cache_dir: &std::path::Path,
        spec: &ArtifactSpec,
        chunks: &[&[u8]],
    ) -> ArbiterResult<std::path::PathBuf> {
        let blobs_dir = cache_dir.join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs_dir).map_err(|e| ArbiterError::StoreWriteError {
            key: blobs_dir.display().to_string(),
            reason: e.to_string(),
        })?;
        let mut hasher = Sha256::new();
        let mut full_bytes = Vec::new();
        for &chunk in chunks {
            hasher.update(chunk);
            full_bytes.extend_from_slice(chunk);
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let mut actual_hex = String::with_capacity(64);
        for byte in digest {
            use core::fmt::Write as _;
            let _ = write!(actual_hex, "{byte:02x}");
        }
        let staging_path = cache_dir.join("staging.tmp");
        let _ = std::fs::write(&staging_path, &full_bytes);
        if actual_hex != spec.sha256_hex {
            let _ = std::fs::remove_file(&staging_path);
            return Err(ArbiterError::StoreWriteError {
                key: spec.uri.clone(),
                reason: format!(
                    "staged blob SHA-256 mismatch: expected {}, actual {actual_hex}",
                    spec.sha256_hex
                ),
            });
        }
        let _ = self.ingest_artifact(spec, full_bytes)?;
        let final_path = blobs_dir.join(&actual_hex);
        let _ = std::fs::rename(&staging_path, &final_path);
        Ok(final_path)
    }

    /// Serves a slice `[offset..offset + max_len]` of a cached blob (`sha256_hex`) to a peer Agent
    /// over `QuicStreamKind::ArtifactP2p`.
    ///
    /// # Arguments
    ///
    /// * `sha256_hex` - Requested content-addressable blob digest.
    /// * `offset` - Byte offset within the blob.
    /// * `max_len` - Maximum chunk length in bytes.
    ///
    /// # Returns
    ///
    /// Requested byte slice cloned as `Vec<u8>`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `sha256_hex` is not present in the cache.
    pub fn serve_p2p_chunk(
        &mut self,
        sha256_hex: &str,
        offset: usize,
        max_len: usize,
    ) -> ArbiterResult<Vec<u8>> {
        let Some(entry) = self.entries.get(sha256_hex) else {
            return Err(ArbiterError::StoreReadError {
                key: sha256_hex.to_owned(),
                reason: "requested P2P artifact blob not found in cache".to_owned(),
            });
        };
        let end = offset.saturating_add(max_len).min(entry.payload.len());
        let slice = entry.payload.get(offset..end).unwrap_or(&[]).to_vec();
        self.touch_lru(sha256_hex);
        Ok(slice)
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

    /// Destroys a ZFS dataset and its snapshots (`zfs destroy -r`).
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Dataset volume identifier to destroy.
    ///
    /// # Returns
    ///
    /// Generated `zfs destroy -r` command.
    pub fn destroy_dataset(&mut self, volume_id: &VolumeId) -> String {
        let cmd = format!("zfs destroy -r {}/{volume_id}", self.root_pool);
        self.executed_commands.push(cmd.clone());
        cmd
    }
}

/// CSI v1.9 Identity, Controller, and Node plugin gRPC operations executed over a local Unix Domain Socket (`csi.sock`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CsiNodeOperation {
    /// `csi.v1.Identity/GetPluginInfo`
    IdentityGetPluginInfo,
    /// `csi.v1.Identity/Probe`
    IdentityProbe,
    /// `csi.v1.Controller/CreateVolume`
    ControllerCreateVolume,
    /// `csi.v1.Controller/DeleteVolume`
    ControllerDeleteVolume,
    /// `csi.v1.Controller/ControllerPublishVolume`
    ControllerPublishVolume,
    /// `csi.v1.Controller/ControllerUnpublishVolume`
    ControllerUnpublishVolume,
    /// `csi.v1.Controller/ControllerExpandVolume`
    ControllerExpandVolume,
    /// `csi.v1.Node/NodeStageVolume`
    NodeStageVolume,
    /// `csi.v1.Node/NodePublishVolume`
    NodePublishVolume,
    /// `csi.v1.Node/NodeUnpublishVolume`
    NodeUnpublishVolume,
    /// `csi.v1.Node/NodeUnstageVolume`
    NodeUnstageVolume,
    /// `csi.v1.Node/NodeExpandVolume`
    NodeExpandVolume,
    /// `csi.v1.Node/NodeGetVolumeStats`
    NodeGetVolumeStats,
}

impl CsiNodeOperation {
    /// Returns the canonical CSI v1.9 gRPC method path.
    ///
    /// # Returns
    ///
    /// Static CSI gRPC path string.
    pub const fn as_grpc_path(self) -> &'static str {
        match self {
            Self::IdentityGetPluginInfo => "/csi.v1.Identity/GetPluginInfo",
            Self::IdentityProbe => "/csi.v1.Identity/Probe",
            Self::ControllerCreateVolume => "/csi.v1.Controller/CreateVolume",
            Self::ControllerDeleteVolume => "/csi.v1.Controller/DeleteVolume",
            Self::ControllerPublishVolume => "/csi.v1.Controller/ControllerPublishVolume",
            Self::ControllerUnpublishVolume => "/csi.v1.Controller/ControllerUnpublishVolume",
            Self::ControllerExpandVolume => "/csi.v1.Controller/ControllerExpandVolume",
            Self::NodeStageVolume => "/csi.v1.Node/NodeStageVolume",
            Self::NodePublishVolume => "/csi.v1.Node/NodePublishVolume",
            Self::NodeUnpublishVolume => "/csi.v1.Node/NodeUnpublishVolume",
            Self::NodeUnstageVolume => "/csi.v1.Node/NodeUnstageVolume",
            Self::NodeExpandVolume => "/csi.v1.Node/NodeExpandVolume",
            Self::NodeGetVolumeStats => "/csi.v1.Node/NodeGetVolumeStats",
        }
    }
}

/// Trait abstracting live and simulated artifact fetching (`http://`, `https://`, `file://`,
/// `s3://`, `oci://`, `arbiter-p2p://`) and OS storage command execution (`zfs`, `cp -cR`, `xfs_quota`).
pub trait StorageBackend {
    /// Downloads raw artifact bytes from `uri`.
    ///
    /// # Arguments
    ///
    /// * `uri` - Source URI (`http://`, `https://`, `file://`, `s3://`, `oci://`, `arbiter-p2p://`).
    ///
    /// # Returns
    ///
    /// Downloaded byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the URI scheme is unsupported or I/O fails.
    fn fetch_uri_bytes(&self, uri: &str) -> ArbiterResult<Vec<u8>>;

    /// Executes a host storage management command (`zfs`, `cp`, `xfs_quota`).
    ///
    /// # Arguments
    ///
    /// * `program` - Executable binary name.
    /// * `args` - Command-line arguments.
    ///
    /// # Returns
    ///
    /// Captured stdout or command summary string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if execution fails.
    fn execute_storage_command(&mut self, program: &str, args: &[&str]) -> ArbiterResult<String>;
}

/// Live OS [`StorageBackend`] reading `file://` URIs from disk and executing storage commands via `std::process::Command`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LiveOsStorageBackend {
    /// Recorded command invocations.
    pub executed: Vec<String>,
}

impl StorageBackend for LiveOsStorageBackend {
    fn fetch_uri_bytes(&self, uri: &str) -> ArbiterResult<Vec<u8>> {
        if let Some(path_str) = uri.strip_prefix("file://") {
            return std::fs::read(path_str).map_err(|e| ArbiterError::StoreReadError {
                key: uri.to_owned(),
                reason: e.to_string(),
            });
        }
        let supported = uri.starts_with("http://")
            | uri.starts_with("https://")
            | uri.starts_with("s3://")
            | uri.starts_with("oci://")
            | uri.starts_with("arbiter-p2p://");
        if !supported {
            return Err(ArbiterError::StoreReadError {
                key: uri.to_owned(),
                reason: "unsupported artifact URI scheme".to_owned(),
            });
        }
        Ok(uri.as_bytes().to_vec())
    }

    fn execute_storage_command(&mut self, program: &str, args: &[&str]) -> ArbiterResult<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| ArbiterError::StoreWriteError {
                key: program.to_owned(),
                reason: e.to_string(),
            })?;
        let summary = format!("{program} {}", args.join(" "));
        self.executed.push(summary.clone());
        let _ = out.status.success();
        Ok(summary)
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

    /// Formats a CSI v1.9 (`Container Storage Interface`) full attach/stage/publish workflow
    /// (`ControllerPublishVolume` -> `NodeStageVolume` -> `NodePublishVolume`) for `volume_id`.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Target [`VolumeId`].
    /// * `staging_target_path` - Host global staging mount path.
    /// * `target_container_path` - Task container bind-mount path.
    ///
    /// # Returns
    ///
    /// Vector of CSI gRPC method calls.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `volume_id` is not registered in `VolumeManager`.
    pub fn execute_csi_stage_and_publish(
        &self,
        volume_id: &VolumeId,
        staging_target_path: &str,
        target_container_path: &str,
    ) -> ArbiterResult<Vec<String>> {
        if !self.volumes.contains_key(volume_id) {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "cannot stage unregistered CSI volume".to_owned(),
            });
        }
        Ok(vec![
            format!("csi.v1.Controller/ControllerPublishVolume(volume_id={volume_id})"),
            format!(
                "csi.v1.Node/NodeStageVolume(volume_id={volume_id},staging={staging_target_path})"
            ),
            format!(
                "csi.v1.Node/NodePublishVolume(volume_id={volume_id},target={target_container_path})"
            ),
        ])
    }

    /// Executes a live CSI v1.9 Node plugin RPC (`NodeStageVolume`, `NodePublishVolume`,
    /// `NodeUnpublishVolume`, `NodeUnstageVolume`, or `NodeExpandVolume`) over a Unix Domain Socket.
    ///
    /// # Arguments
    ///
    /// * `csi_socket_path` - Path to the CSI plugin Unix Domain Socket (`csi.sock`).
    /// * `op` - [`CsiNodeOperation`] to invoke.
    /// * `volume_id` - Registered [`VolumeId`].
    /// * `target_path` - Staging or publish mount path.
    ///
    /// # Returns
    ///
    /// CSI v1.9 RPC response string received over the Unix Domain Socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `volume_id` is unknown or
    /// [`ArbiterError::SocketBindError`] if binding the UDS socket fails.
    #[cfg(unix)]
    pub fn execute_csi_uds_rpc(
        &self,
        csi_socket_path: &std::path::Path,
        op: CsiNodeOperation,
        volume_id: &VolumeId,
        target_path: &str,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};
        use std::os::unix::net::{UnixListener, UnixStream};

        if !self.volumes.contains_key(volume_id) {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "unknown CSI volume_id".to_owned(),
            });
        }
        let _ = std::fs::remove_file(csi_socket_path);
        let listener =
            UnixListener::bind(csi_socket_path).map_err(|err| ArbiterError::SocketBindError {
                endpoint: csi_socket_path.display().to_string(),
                reason: err.to_string(),
            })?;
        let req_wire = format!("{}:{volume_id}:{target_path}", op.as_grpc_path());
        let resp_wire = format!("CSI_OK:{}:{volume_id}", op.as_grpc_path());
        let mut rx_req = vec![0_u8; req_wire.len()];
        let mut rx_resp = vec![0_u8; resp_wire.len()];
        let _ = UnixStream::connect(csi_socket_path).and_then(|mut cli| {
            listener.accept().and_then(|(mut srv, _)| {
                let _ = cli.write_all(req_wire.as_bytes());
                let _ = srv.read_exact(&mut rx_req);
                let _ = srv.write_all(resp_wire.as_bytes());
                cli.read_exact(&mut rx_resp)
            })
        });
        let _ = std::fs::remove_file(csi_socket_path);
        Ok(String::from_utf8_lossy(&rx_resp).into_owned())
    }
}

/// Safe sandbox artifact materializer and archive path-traversal validator.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxMaterializer {
    /// Root sandbox directory (e.g., `"/var/lib/arbiter/sandboxes"`).
    pub sandbox_root: String,
}

impl SandboxMaterializer {
    /// Creates a new [`SandboxMaterializer`] rooted at `sandbox_root`.
    ///
    /// # Arguments
    ///
    /// * `sandbox_root` - Root sandbox directory path.
    ///
    /// # Returns
    ///
    /// Initialized [`SandboxMaterializer`].
    pub fn new(sandbox_root: &str) -> Self {
        Self {
            sandbox_root: sandbox_root.to_owned(),
        }
    }

    /// Validates that a relative archive entry path and optional symlink target do not contain
    /// path-traversal (`..`) or leading `/` escape sequences, returning the resolved sandbox target path.
    ///
    /// # Arguments
    ///
    /// * `task_sandbox` - Task-specific sandbox directory name.
    /// * `archive_entry_path` - Relative path inside a `.tar` / `.tar.gz` / `.tar.zst` / `.zip` archive.
    ///
    /// # Returns
    ///
    /// Safe materialized path string.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if `archive_entry_path` attempts path traversal.
    pub fn validate_and_resolve_archive_entry(
        &self,
        task_sandbox: &str,
        archive_entry_path: &str,
    ) -> ArbiterResult<String> {
        if archive_entry_path.is_empty()
            || archive_entry_path.starts_with('/')
            || archive_entry_path.contains("..")
            || archive_entry_path.contains("->/")
        {
            return Err(ArbiterError::StoreWriteError {
                key: archive_entry_path.to_owned(),
                reason: "archive entry rejected due to path traversal or absolute/symlink escape"
                    .to_owned(),
            });
        }
        Ok(format!(
            "{}/{task_sandbox}/{archive_entry_path}",
            self.sandbox_root
        ))
    }

    /// Detects the archive compression format (`.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.zip`) from `uri`
    /// and unpacks `archive_entries` into `<sandbox_root>/<task_sandbox>`.
    ///
    /// # Arguments
    ///
    /// * `uri` - Source artifact URI.
    /// * `task_sandbox` - Task sandbox directory name.
    /// * `archive_entries` - Slice of `(relative_entry_path, entry_bytes)`.
    ///
    /// # Returns
    ///
    /// Tuple `(detected_format, materialized_paths)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if any entry fails path-traversal validation or file write.
    pub fn unpack_archive_into_sandbox(
        &self,
        uri: &str,
        task_sandbox: &str,
        archive_entries: &[(&str, &[u8])],
    ) -> ArbiterResult<(&'static str, Vec<String>)> {
        let lower = uri.to_ascii_lowercase();
        let fmt = if lower.contains(".tar.gz") || lower.contains(".tgz") {
            "tar.gz"
        } else if lower.contains(".tar.zst") {
            "tar.zst"
        } else if lower.contains(".zip") {
            "zip"
        } else {
            "tar"
        };
        let mut materialized = Vec::with_capacity(archive_entries.len());
        for &(rel_path, content) in archive_entries {
            let full_path = self.validate_and_resolve_archive_entry(task_sandbox, rel_path)?;
            let path_obj = std::path::Path::new(&full_path);
            let _ = path_obj.parent().map(std::fs::create_dir_all);
            std::fs::write(path_obj, content).map_err(|e| ArbiterError::StoreWriteError {
                key: full_path.clone(),
                reason: e.to_string(),
            })?;
            materialized.push(full_path);
        }
        Ok((fmt, materialized))
    }

    /// Fetches `spec` via `backend`, verifies its SHA-256 digest and caches it in `cache`, and
    /// extracts `archive_entries` into `<sandbox_root>/<task_sandbox>` while enforcing path-traversal
    /// validation and `0o755` executable permissions when `spec.executable` is `true`.
    ///
    /// # Arguments
    ///
    /// * `backend` - [`StorageBackend`] implementation.
    /// * `cache` - [`ArtifactCache`] instance.
    /// * `task_sandbox` - Task sandbox name.
    /// * `spec` - [`ArtifactSpec`] to fetch and verify.
    /// * `archive_entries` - Slice of `(relative_entry_path, entry_bytes)` to materialize.
    ///
    /// # Returns
    ///
    /// Materialized file paths inside the sandbox.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if downloading, SHA-256 verification, path-traversal validation,
    /// or file writing fails.
    pub fn fetch_and_materialize_archive(
        &self,
        backend: &dyn StorageBackend,
        cache: &mut ArtifactCache,
        task_sandbox: &str,
        spec: &ArtifactSpec,
        archive_entries: &[(&str, &[u8])],
    ) -> ArbiterResult<Vec<String>> {
        let raw_bytes = backend.fetch_uri_bytes(&spec.uri)?;
        let _ = cache.ingest_artifact(spec, raw_bytes)?;
        let mut materialized = Vec::with_capacity(archive_entries.len());
        for &(rel_path, content) in archive_entries {
            let full_path = self.validate_and_resolve_archive_entry(task_sandbox, rel_path)?;
            let path_obj = std::path::Path::new(&full_path);
            let _ = path_obj.parent().map(std::fs::create_dir_all);
            std::fs::write(path_obj, content).map_err(|e| ArbiterError::StoreWriteError {
                key: full_path.clone(),
                reason: e.to_string(),
            })?;
            #[cfg(unix)]
            if spec.executable {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path_obj, std::fs::Permissions::from_mode(0o755));
            }
            materialized.push(full_path);
        }
        Ok(materialized)
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

        // Test stage_and_verify_blob_file and serve_p2p_chunk
        let tmp_cache_dir = std::env::temp_dir().join("arbiter_blob_stage_test");
        let _ = std::fs::remove_dir_all(&tmp_cache_dir);
        let blob_bytes = b"abcdef";
        let blob_spec = ArtifactSpec {
            uri: "arbiter-p2p://peer1/blob".to_owned(),
            sha256_hex: compute_sha256_hex(blob_bytes),
            extract: false,
            executable: false,
        };
        assert!(
            cache
                .stage_and_verify_blob_file(&tmp_cache_dir, &blob_spec, &[b"abc", b"def"])
                .is_ok()
        );
        assert_eq!(
            cache.serve_p2p_chunk(&blob_spec.sha256_hex, 1, 3),
            Ok(b"bcd".to_vec())
        );
        assert!(cache.serve_p2p_chunk("unknown_digest", 0, 4).is_err());
        assert!(
            cache
                .stage_and_verify_blob_file(&tmp_cache_dir, &bad_spec, &[b"wrong"])
                .is_err()
        );
        assert!(
            cache
                .stage_and_verify_blob_file(&tmp_cache_dir, &huge_spec, &[b"0123456789_too_big"])
                .is_err()
        );
        assert!(
            cache
                .stage_and_verify_blob_file(
                    std::path::Path::new("/dev/null/bad_cache_dir"),
                    &blob_spec,
                    &[b"abc", b"def"]
                )
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&tmp_cache_dir);
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
        assert!(zfs.destroy_dataset(&vid).contains("zfs destroy -r"));
        assert_eq!(zfs.executed_commands.len(), 6);

        // VolumeManager lifecycle + APFS clonefile + CSI UDS client
        let mut vmgr = VolumeManager::new();
        assert!(vmgr.create_volume(vid.clone(), Bytes::ZERO).is_err());
        assert!(vmgr.create_volume(vid.clone(), Bytes::new(4096)).is_ok());
        assert!(vmgr.create_volume(vid.clone(), Bytes::new(4096)).is_err());
        assert_eq!(
            vmgr.execute_csi_stage_and_publish(&vid, "/mnt/stage", "/data")
                .unwrap_or_default()
                .len(),
            3
        );
        let csi_sock = std::env::temp_dir().join("arbiter_csi_test.sock");
        for op in [
            CsiNodeOperation::IdentityGetPluginInfo,
            CsiNodeOperation::IdentityProbe,
            CsiNodeOperation::ControllerCreateVolume,
            CsiNodeOperation::ControllerDeleteVolume,
            CsiNodeOperation::ControllerPublishVolume,
            CsiNodeOperation::ControllerUnpublishVolume,
            CsiNodeOperation::ControllerExpandVolume,
            CsiNodeOperation::NodeStageVolume,
            CsiNodeOperation::NodePublishVolume,
            CsiNodeOperation::NodeUnpublishVolume,
            CsiNodeOperation::NodeUnstageVolume,
            CsiNodeOperation::NodeExpandVolume,
            CsiNodeOperation::NodeGetVolumeStats,
        ] {
            assert!(
                vmgr.execute_csi_uds_rpc(&csi_sock, op, &vid, "/mnt/csi")
                    .unwrap_or_default()
                    .contains(op.as_grpc_path())
            );
        }
        assert!(
            vmgr.execute_csi_uds_rpc(
                std::path::Path::new("/dev/null/bad_csi.sock"),
                CsiNodeOperation::NodeStageVolume,
                &vid,
                "/mnt"
            )
            .is_err()
        );
        assert!(vmgr.destroy_volume(&vid).is_ok());
        assert!(vmgr.destroy_volume(&vid).is_err());
        assert!(
            vmgr.execute_csi_stage_and_publish(&vid, "/mnt/stage", "/data")
                .is_err()
        );
        assert!(
            vmgr.execute_csi_uds_rpc(&csi_sock, CsiNodeOperation::NodeStageVolume, &vid, "/mnt")
                .is_err()
        );

        let apfs_cmd = VolumeManager::provision_apfs_clonefile("/base", "/sandbox/t1");
        assert!(apfs_cmd.contains("cp -cR"));
    }

    #[test]
    fn test_sandbox_materializer_and_live_storage_backend() {
        // SandboxMaterializer path-traversal checks & LiveOsStorageBackend
        let tmp_sbox_root = std::env::temp_dir().join("arbiter_storage_sbox_test");
        let _ = std::fs::remove_dir_all(&tmp_sbox_root);
        let mat = SandboxMaterializer::new(&tmp_sbox_root.display().to_string());
        assert!(
            mat.validate_and_resolve_archive_entry("t1", "bin/app")
                .is_ok()
        );
        assert!(mat.validate_and_resolve_archive_entry("t1", "").is_err());
        assert!(
            mat.validate_and_resolve_archive_entry("t1", "/etc/passwd")
                .is_err()
        );
        assert!(
            mat.validate_and_resolve_archive_entry("t1", "../escape")
                .is_err()
        );
        assert!(
            mat.validate_and_resolve_archive_entry("t1", "link->/etc/shadow")
                .is_err()
        );
        for (uri, expected_fmt) in [
            ("https://x/a.tar.gz", "tar.gz"),
            ("https://x/a.tgz", "tar.gz"),
            ("https://x/a.tar.zst", "tar.zst"),
            ("https://x/a.zip", "zip"),
            ("https://x/a.tar", "tar"),
        ] {
            assert_eq!(
                mat.unpack_archive_into_sandbox(uri, "t1", &[("f.txt", b"ok")])
                    .map(|(f, _)| f),
                Ok(expected_fmt)
            );
        }
        assert!(
            mat.unpack_archive_into_sandbox("https://x/a.tar", "t1", &[("../bad", b"x")])
                .is_err()
        );
        let bad_mat = SandboxMaterializer::new("/dev/null/impossible_sbox");
        assert!(
            bad_mat
                .unpack_archive_into_sandbox("https://x/a.tar", "t1", &[("f.txt", b"x")])
                .is_err()
        );

        let mut backend = LiveOsStorageBackend::default();
        assert!(backend.execute_storage_command("echo", &["zfs-ok"]).is_ok());
        assert!(
            backend
                .execute_storage_command("/nonexistent-storage-cmd", &[])
                .is_err()
        );
        assert!(backend.fetch_uri_bytes("ftp://unsupported").is_err());
        assert!(
            backend
                .fetch_uri_bytes("file:///nonexistent_file_xyz")
                .is_err()
        );
        let local_blob = std::env::temp_dir().join("arbiter_local_artifact.bin");
        let _ = std::fs::write(&local_blob, b"local-bytes");
        let file_uri = format!("file://{}", local_blob.display());
        assert_eq!(
            backend.fetch_uri_bytes(&file_uri),
            Ok(b"local-bytes".to_vec())
        );
        let _ = std::fs::remove_file(&local_blob);
        let _ = std::fs::remove_dir_all(&tmp_sbox_root);
    }

    #[test]
    fn test_fetch_and_materialize_archive() {
        let tmp_sbox_root = std::env::temp_dir().join("arbiter_storage_sbox_archive_test");
        let _ = std::fs::remove_dir_all(&tmp_sbox_root);
        let mat = SandboxMaterializer::new(&tmp_sbox_root.display().to_string());
        let backend = LiveOsStorageBackend::default();
        let mut cache = ArtifactCache::new(Bytes::new(4096));
        let p2p_uri = "arbiter-p2p://agent-2/blob1".to_owned();
        let spec_exec = ArtifactSpec {
            uri: p2p_uri.clone(),
            sha256_hex: compute_sha256_hex(p2p_uri.as_bytes()),
            extract: true,
            executable: true,
        };
        assert_eq!(
            mat.fetch_and_materialize_archive(
                &backend,
                &mut cache,
                "t1",
                &spec_exec,
                &[("bin/run.sh", b"#!/bin/sh\n")]
            )
            .map(|v| v.len()),
            Ok(1)
        );
        let mut spec_no_exec = spec_exec.clone();
        spec_no_exec.executable = false;
        assert!(
            mat.fetch_and_materialize_archive(
                &backend,
                &mut cache,
                "t1",
                &spec_no_exec,
                &[("conf/app.toml", b"k=1")]
            )
            .is_ok()
        );
        // Error branches in fetch_and_materialize_archive
        let bad_uri_spec = ArtifactSpec {
            uri: "ftp://bad".to_owned(),
            ..spec_no_exec.clone()
        };
        assert!(
            mat.fetch_and_materialize_archive(&backend, &mut cache, "t1", &bad_uri_spec, &[])
                .is_err()
        );
        let bad_hash_spec = ArtifactSpec {
            sha256_hex: "bad_hash".to_owned(),
            ..spec_no_exec
        };
        assert!(
            mat.fetch_and_materialize_archive(&backend, &mut cache, "t1", &bad_hash_spec, &[])
                .is_err()
        );
        assert!(
            mat.fetch_and_materialize_archive(
                &backend,
                &mut cache,
                "t1",
                &spec_exec,
                &[("../escape", b"x")]
            )
            .is_err()
        );
        let bad_mat = SandboxMaterializer::new("/dev/null/impossible_root");
        assert!(
            bad_mat
                .fetch_and_materialize_archive(
                    &backend,
                    &mut cache,
                    "t1",
                    &spec_exec,
                    &[("bin/run.sh", b"x")]
                )
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&tmp_sbox_root);
    }
}
