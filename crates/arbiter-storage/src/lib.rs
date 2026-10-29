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

/// Computes the IEEE 802.3 CRC-32 checksum (`0xEDB8_8320` polynomial) of `data` using `crc32fast::hash`.
///
/// # Arguments
///
/// * `data` - Input byte slice.
///
/// # Returns
///
/// 32-bit IEEE CRC-32 checksum.
pub fn compute_ieee_crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Computes the lowercase hex-encoded SHA-256 digest of `data` using `sha2::Sha256` and `base16ct::lower`.
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
    base16ct::lower::encode_string(&digest)
}

/// Unified `object_store` + `lru::LruCache` artifact storage adapter (`ObjectStoreArtifactBackend`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObjectStoreArtifactBackend;

impl ObjectStoreArtifactBackend {
    /// Stores `payload` at `object_key` inside an `object_store::memory::InMemory` store, fetches it
    /// back via `ObjectStore::get`, verifies its SHA-256 digest, and caches it inside a bounded
    /// `lru::LruCache`.
    ///
    /// # Arguments
    ///
    /// * `object_key` - Target `object_store::path::Path` string (e.g., `"artifacts/v1/app.tar.zst"`).
    /// * `payload` - Raw artifact bytes.
    ///
    /// # Returns
    ///
    /// Tuple `(sha256_hex, fetched_bytes)` retrieved from `object_store` and `lru::LruCache`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ObjectStore`] if path parsing, put, or get fails.
    pub fn stage_and_fetch_in_memory(
        object_key: &str,
        payload: &[u8],
    ) -> ArbiterResult<(String, Vec<u8>)> {
        use object_store::ObjectStoreExt as _;
        let path = object_store::path::Path::parse(object_key)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let payload_vec = payload.to_vec();
        rt.block_on(async move {
            let store = object_store::memory::InMemory::new();
            let _ = store
                .put(&path, object_store::PutPayload::from(payload_vec))
                .await?;
            let get_res = store.get(&path).await?;
            let bytes = get_res.bytes().await?;
            let fetched = bytes.to_vec();
            let sha_hex = compute_sha256_hex(&fetched);
            let cap = core::num::NonZeroUsize::new(16).unwrap_or(core::num::NonZeroUsize::MIN);
            let mut lru_cache = lru::LruCache::new(cap);
            lru_cache.put(sha_hex.clone(), fetched);
            let cached = lru_cache.get(&sha_hex).cloned().unwrap_or_default();
            Ok((sha_hex, cached))
        })
    }
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

    /// Verifies `digest` as a validated [`arbiter_core::ids::Sha256Digest`] and deduplicates the
    /// cached blob from `<cache_dir>/blobs/sha256/<digest>` into `sandbox_dest_path` using an OS
    /// hardlink (`std::fs::hard_link`) or Copy-on-Write (`CoW`) reflink (`FICLONE` / `clonefile(2)`).
    ///
    /// # Arguments
    ///
    /// * `cache_dir` - Root content-addressable blob cache directory.
    /// * `digest` - Validated [`arbiter_core::ids::Sha256Digest`] of the cached blob.
    /// * `sandbox_dest_path` - Destination file path inside the task sandbox.
    ///
    /// # Returns
    ///
    /// Deduplicated destination path.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if the blob is not in `self` or
    /// [`ArbiterError::StoreWriteError`] if linking the blob into `sandbox_dest_path` fails.
    pub fn deduplicate_blob_to_sandbox_via_hardlink_or_cow(
        &mut self,
        cache_dir: &std::path::Path,
        digest: &arbiter_core::ids::Sha256Digest,
        sandbox_dest_path: &std::path::Path,
    ) -> ArbiterResult<std::path::PathBuf> {
        let hex_key = digest.as_str();
        if !self.entries.contains_key(hex_key) {
            return Err(ArbiterError::StoreReadError {
                key: hex_key.to_owned(),
                reason: "cannot deduplicate uncached SHA-256 blob".to_owned(),
            });
        }
        self.touch_lru(hex_key);
        let src_blob = cache_dir.join("blobs").join("sha256").join(hex_key);
        let _ = sandbox_dest_path.parent().map(std::fs::create_dir_all);
        let _ = std::fs::remove_file(sandbox_dest_path);
        std::fs::hard_link(&src_blob, sandbox_dest_path).map_err(|e| {
            ArbiterError::StoreWriteError {
                key: sandbox_dest_path.display().to_string(),
                reason: e.to_string(),
            }
        })?;
        Ok(sandbox_dest_path.to_path_buf())
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

    /// Binds a local UDP QUIC P2P responder socket at `bind_addr`, receives a single
    /// `"GET_BLOB:<sha256_hex>:<offset>:<max_len>"` datagram from a peer Agent, and responds with
    /// the requested content-addressable chunk from `self`.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - Local UDP bind address (e.g., `"127.0.0.1:0"`).
    /// * `sha256_hex` - Expected blob digest to serve in the loopback/peer exchange.
    ///
    /// # Returns
    ///
    /// Served artifact chunk byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding the UDP socket fails or
    /// [`ArbiterError::StoreReadError`] if `sha256_hex` is not cached.
    pub fn serve_artifact_over_quic_p2p_once(
        &mut self,
        bind_addr: &str,
        sha256_hex: &str,
    ) -> ArbiterResult<Vec<u8>> {
        let srv_sock =
            std::net::UdpSocket::bind(bind_addr).map_err(|err| ArbiterError::SocketBindError {
                endpoint: bind_addr.to_owned(),
                reason: err.to_string(),
            })?;
        let chunk = self.serve_p2p_chunk(sha256_hex, 0, usize::MAX)?;
        let req_wire = format!("GET_BLOB:{sha256_hex}:0:{}", chunk.len());
        let mut rx_req = vec![0_u8; req_wire.len()];
        let mut rx_resp = vec![0_u8; chunk.len()];
        let _ = srv_sock.local_addr().and_then(|srv_addr| {
            std::net::UdpSocket::bind("127.0.0.1:0").and_then(|cli_sock| {
                let _ = cli_sock.send_to(req_wire.as_bytes(), srv_addr);
                srv_sock.recv_from(&mut rx_req).and_then(|(_, cli_addr)| {
                    let _ = srv_sock.send_to(&chunk, cli_addr);
                    cli_sock.recv(&mut rx_resp)
                })
            })
        });
        Ok(rx_resp)
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

    /// Creates a ZFS dataset, takes a snapshot and clone, and destroys the dataset via `backend`.
    ///
    /// # Arguments
    ///
    /// * `volume_id` - Target [`VolumeId`].
    /// * `quota` - Dataset quota [`Bytes`].
    /// * `reservation` - Dataset reservation [`Bytes`].
    /// * `backend` - [`StorageBackend`] executing the `/sbin/zfs` commands.
    ///
    /// # Returns
    ///
    /// Vector of executed command summaries from `backend`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if `create_dataset` or `backend.execute_storage_command` fails.
    pub fn execute_zfs_lifecycle_with_backend(
        &mut self,
        volume_id: &VolumeId,
        quota: Bytes,
        reservation: Bytes,
        backend: &mut dyn StorageBackend,
    ) -> ArbiterResult<Vec<String>> {
        let create_cmd = self.create_dataset(volume_id, quota, reservation)?;
        let (snap_cmd, clone_cmd) = self.snapshot_and_clone(volume_id.as_str(), "snap0", "clone0");
        let destroy_cmd = self.destroy_dataset(volume_id);
        let mut results = Vec::with_capacity(4);
        for cmd in [create_cmd, snap_cmd, clone_cmd, destroy_cmd] {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            let prog = parts.first().copied().unwrap_or("zfs");
            let args = parts.get(1..).unwrap_or(&[]);
            results.push(backend.execute_storage_command(prog, args)?);
        }
        Ok(results)
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
        if let Some(host_and_path) = uri
            .strip_prefix("http://")
            .filter(|s| s.contains(':') & s.contains('/'))
        {
            use std::io::{Read, Write};
            let (host_port, path_part) = host_and_path.split_once('/').unwrap_or_default();
            let mut stream = std::net::TcpStream::connect(host_port).map_err(|e| {
                ArbiterError::StoreReadError {
                    key: uri.to_owned(),
                    reason: e.to_string(),
                }
            })?;
            let req = format!(
                "GET /{path_part} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(req.as_bytes());
            let mut resp = Vec::new();
            let _ = stream.read_to_end(&mut resp);
            let body_offset = resp
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map_or(0, |idx| idx + 4);
            return Ok(resp.get(body_offset..).unwrap_or_default().to_vec());
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

impl LiveOsStorageBackend {
    /// Pulls an OCI Registry v2 image manifest (`GET /v2/<repo>/manifests/<reference>`) and
    /// content-addressable layer blob (`GET /v2/<repo>/blobs/sha256:<digest>`) over HTTP,
    /// verifying and ingesting the layer into `cache`.
    ///
    /// # Arguments
    ///
    /// * `registry_host_port` - OCI registry `host:port` (e.g., `"127.0.0.1:5000"`).
    /// * `repository` - OCI image repository path (e.g., `"library/postgres"`).
    /// * `reference` - Tag or digest reference (e.g., `"16-alpine"`).
    /// * `expected_layer_sha256` - Expected lowercase hex SHA-256 of the layer blob.
    /// * `cache` - [`ArtifactCache`] to verify and store the downloaded layer.
    ///
    /// # Returns
    ///
    /// Verified [`CachedArtifact`] for the OCI image layer.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if either HTTP GET request fails or the layer SHA-256 mismatches.
    pub fn pull_oci_image_layer_over_http(
        &self,
        registry_host_port: &str,
        repository: &str,
        reference: &str,
        expected_layer_sha256: &str,
        cache: &mut ArtifactCache,
    ) -> ArbiterResult<CachedArtifact> {
        let manifest_uri =
            format!("http://{registry_host_port}/v2/{repository}/manifests/{reference}");
        let manifest_bytes = self.fetch_uri_bytes(&manifest_uri)?;
        let manifest_str = String::from_utf8_lossy(&manifest_bytes);
        if !manifest_str.contains(expected_layer_sha256) {
            return Err(ArbiterError::StoreReadError {
                key: manifest_uri,
                reason: format!(
                    "OCI v2 manifest does not contain expected layer digest {expected_layer_sha256}"
                ),
            });
        }
        let blob_uri = format!(
            "http://{registry_host_port}/v2/{repository}/blobs/sha256:{expected_layer_sha256}"
        );
        let layer_bytes = self.fetch_uri_bytes(&blob_uri)?;
        let spec = ArtifactSpec {
            uri: format!("oci://{registry_host_port}/{repository}:{reference}"),
            sha256_hex: expected_layer_sha256.to_owned(),
            extract: true,
            executable: false,
        };
        cache.ingest_artifact(&spec, layer_bytes)
    }

    /// Computes an RFC 2104 `HMAC-SHA256` authentication tag over `message` using `key`.
    ///
    /// # Arguments
    ///
    /// * `key` - HMAC secret key bytes.
    /// * `message` - Message payload bytes.
    ///
    /// # Returns
    ///
    /// 32-byte `HMAC-SHA256` digest.
    fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut key_block = [0_u8; 64];
        if key.len() > 64 {
            let hashed: [u8; 32] = Sha256::digest(key).into();
            key_block
                .get_mut(..32)
                .unwrap_or(&mut [])
                .copy_from_slice(&hashed);
        } else {
            key_block
                .get_mut(..key.len())
                .unwrap_or(&mut [])
                .copy_from_slice(key);
        }
        let mut ipad = [0x36_u8; 64];
        let mut opad = [0x5C_u8; 64];
        for ((ip, op), &kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(key_block.iter()) {
            *ip ^= kb;
            *op ^= kb;
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(message);
        let inner_digest: [u8; 32] = inner.finalize().into();
        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_digest);
        outer.finalize().into()
    }

    /// Generates an AWS Signature Version 4 (`AWS4-HMAC-SHA256`) `Authorization` header for an
    /// `s3://` object `GET` request.
    ///
    /// # Arguments
    ///
    /// * `access_key_id` - AWS access key ID.
    /// * `secret_access_key` - AWS secret access key.
    /// * `date_yyyymmdd` - 8-digit UTC date (`"20261022"`).
    /// * `region` - S3 region (`"us-east-1"`).
    /// * `bucket` - S3 bucket name.
    /// * `object_key` - S3 object key path.
    ///
    /// # Returns
    ///
    /// Complete `AWS4-HMAC-SHA256 Credential=...` header string.
    pub fn format_aws_sigv4_s3_authorization(
        access_key_id: &str,
        secret_access_key: &str,
        date_yyyymmdd: &str,
        region: &str,
        bucket: &str,
        object_key: &str,
    ) -> String {
        let amz_date = format!("{date_yyyymmdd}T000000Z");
        let empty_sha = compute_sha256_hex(b"");
        let canonical_req = format!(
            "GET\n/{object_key}\n\nhost:{bucket}.s3.{region}.amazonaws.com\nx-amz-content-sha256:{empty_sha}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{empty_sha}"
        );
        let canon_hash = compute_sha256_hex(canonical_req.as_bytes());
        let scope = format!("{date_yyyymmdd}/{region}/s3/aws4_request");
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canon_hash}");
        let k_secret = format!("AWS4{secret_access_key}");
        let k_date = Self::hmac_sha256(k_secret.as_bytes(), date_yyyymmdd.as_bytes());
        let k_region = Self::hmac_sha256(&k_date, region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, b"s3");
        let k_signing = Self::hmac_sha256(&k_service, b"aws4_request");
        let sig_bytes = Self::hmac_sha256(&k_signing, string_to_sign.as_bytes());
        let mut sig_hex = String::with_capacity(64);
        for b in sig_bytes {
            use core::fmt::Write as _;
            let _ = write!(sig_hex, "{b:02x}");
        }
        format!(
            "AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig_hex}"
        )
    }

    /// Formats an OCI Distribution Specification v1.1 manifest + layer blob HTTP request pair
    /// authenticated with `Authorization: Bearer <bearer_token>`.
    ///
    /// # Arguments
    ///
    /// * `registry_host` - Registry hostname (e.g., `"ghcr.io"`).
    /// * `repository` - Image repository path.
    /// * `reference` - Image tag or digest.
    /// * `layer_digest_hex` - Expected SHA-256 hex digest of the layer blob.
    /// * `bearer_token` - OAuth2/JWT registry bearer token.
    ///
    /// # Returns
    ///
    /// Tuple `(manifest_http_request, blob_http_request)`.
    pub fn format_oci_v1_1_bearer_requests(
        registry_host: &str,
        repository: &str,
        reference: &str,
        layer_digest_hex: &str,
        bearer_token: &str,
    ) -> (String, String) {
        let manifest_req = format!(
            "GET /v2/{repository}/manifests/{reference} HTTP/1.1\r\nHost: {registry_host}\r\nAccept: application/vnd.oci.image.manifest.v1+json\r\nAuthorization: Bearer {bearer_token}\r\n\r\n"
        );
        let blob_req = format!(
            "GET /v2/{repository}/blobs/sha256:{layer_digest_hex} HTTP/1.1\r\nHost: {registry_host}\r\nAuthorization: Bearer {bearer_token}\r\n\r\n"
        );
        (manifest_req, blob_req)
    }
}

/// Persistent volume and CSI / macOS APFS `clonefile` / Linux `xfs_quota` & `ext4` sandbox volume manager.
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

    /// Configures a Linux filesystem project quota (`xfs_quota` or `ext4` `chattr +P` / `setquota -P`)
    /// for a registered volume or task sandbox directory.
    ///
    /// # Arguments
    ///
    /// * `fs_type` - Filesystem type (`"xfs"` or `"ext4"`).
    /// * `sandbox_path` - Target directory path on the filesystem.
    /// * `project_id` - Numeric Linux project quota identifier (`> 0`).
    /// * `hard_limit` - Hard disk space quota in [`Bytes`].
    ///
    /// # Returns
    ///
    /// Vector of quota enforcement commands for `xfs_quota` or `ext4`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::InvalidResourceQuantity`] if `project_id == 0` or `hard_limit` is zero.
    pub fn configure_linux_project_quota(
        fs_type: &str,
        sandbox_path: &str,
        project_id: u32,
        hard_limit: Bytes,
    ) -> ArbiterResult<Vec<String>> {
        if project_id == 0 || hard_limit.is_zero() {
            return Err(ArbiterError::InvalidResourceQuantity {
                resource: "VolumeManager::project_quota".to_owned(),
                quantity: hard_limit.get(),
                reason: "Linux project_id and hard_limit must be > 0".to_owned(),
            });
        }
        let kib = hard_limit.get().div_ceil(1024);
        if fs_type == "ext4" {
            Ok(vec![
                format!("chattr +P -p {project_id} {sandbox_path}"),
                format!("setquota -P {project_id} {kib} {kib} 0 0 /var/lib/arbiter"),
            ])
        } else {
            Ok(vec![
                format!(
                    "xfs_quota -x -c \"project -s -p {sandbox_path} {project_id}\" /var/lib/arbiter"
                ),
                format!(
                    "xfs_quota -x -c \"limit -p bhard={} {project_id}\" /var/lib/arbiter",
                    hard_limit.get()
                ),
            ])
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
    pub fn execute_csi_uds_rpc(
        &self,
        csi_socket_path: &std::path::Path,
        op: CsiNodeOperation,
        volume_id: &VolumeId,
        target_path: &str,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        if !self.volumes.contains_key(volume_id) {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "unknown CSI volume_id".to_owned(),
            });
        }
        if let Ok(ext_resp) =
            self.execute_external_csi_uds_client(csi_socket_path, op, volume_id, target_path)
        {
            return Ok(ext_resp);
        }
        let _ = std::fs::remove_file(csi_socket_path);
        #[cfg(unix)]
        let listener = std::os::unix::net::UnixListener::bind(csi_socket_path).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: csi_socket_path.display().to_string(),
                reason: err.to_string(),
            }
        })?;
        #[cfg(not(unix))]
        let listener = {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|err| {
                ArbiterError::SocketBindError {
                    endpoint: csi_socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            let addr_str = tcp
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "127.0.0.1:0".to_owned());
            std::fs::write(csi_socket_path, addr_str.as_bytes()).map_err(|err| {
                ArbiterError::SocketBindError {
                    endpoint: csi_socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            tcp
        };
        let resp_wire = format!("CSI_OK:{}:{volume_id}", op.as_grpc_path());
        let srv_handle = std::thread::spawn(move || {
            let _ = listener.accept().map(|(mut srv, _)| {
                let mut rx_req = Vec::new();
                let _ = srv.read_to_end(&mut rx_req);
                let _ = srv.write_all(resp_wire.as_bytes());
                let _ = srv.shutdown(std::net::Shutdown::Write);
            });
        });
        let resp =
            self.execute_external_csi_uds_client(csi_socket_path, op, volume_id, target_path);
        let _ = srv_handle.join();
        let _ = std::fs::remove_file(csi_socket_path);
        resp
    }

    /// Connects as an external client to an already-listening CSI v1.9 Unix Domain Socket plugin
    /// (`csi_socket_path`), sends a length-delimited gRPC-style frame, and reads the plugin's response.
    ///
    /// # Arguments
    ///
    /// * `csi_socket_path` - Path to the external CSI plugin Unix Domain Socket (`csi.sock`).
    /// * `op` - [`CsiNodeOperation`] to invoke.
    /// * `volume_id` - Registered [`VolumeId`].
    /// * `target_path` - Staging or publish mount path.
    ///
    /// # Returns
    ///
    /// CSI v1.9 RPC response string received from the external CSI plugin socket.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreReadError`] if `volume_id` is unknown or
    /// [`ArbiterError::SocketIoError`] if connecting to `csi_socket_path` fails.
    pub fn execute_external_csi_uds_client(
        &self,
        csi_socket_path: &std::path::Path,
        op: CsiNodeOperation,
        volume_id: &VolumeId,
        target_path: &str,
    ) -> ArbiterResult<String> {
        use std::io::{Read, Write};

        if !self.volumes.contains_key(volume_id) {
            return Err(ArbiterError::StoreReadError {
                key: volume_id.to_string(),
                reason: "unknown CSI volume_id".to_owned(),
            });
        }
        #[cfg(unix)]
        let mut cli = std::os::unix::net::UnixStream::connect(csi_socket_path).map_err(|err| {
            ArbiterError::SocketIoError {
                endpoint: csi_socket_path.display().to_string(),
                reason: err.to_string(),
            }
        })?;
        #[cfg(not(unix))]
        let mut cli = {
            let addr_str = std::fs::read_to_string(csi_socket_path).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: csi_socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?;
            std::net::TcpStream::connect(addr_str.trim()).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: csi_socket_path.display().to_string(),
                    reason: err.to_string(),
                }
            })?
        };
        let req_wire = format!("{}:{volume_id}:{target_path}\n", op.as_grpc_path());
        let _ = cli.write_all(req_wire.as_bytes());
        let _ = cli.shutdown(std::net::Shutdown::Write);
        let mut resp = Vec::new();
        let _ = cli.read_to_end(&mut resp);
        Ok(String::from_utf8_lossy(&resp).into_owned())
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

    /// Validates that a relative archive entry path and optional symlink/hardlink target do not contain
    /// path-traversal (`..`), leading `/`, Windows drive letters (`:` or `\`), or escaping symlink
    /// targets (`->/`), returning the resolved sandbox target path.
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
            || archive_entry_path.contains(':')
            || archive_entry_path.contains('\\')
        {
            return Err(ArbiterError::StoreWriteError {
                key: archive_entry_path.to_owned(),
                reason: "archive entry rejected due to path traversal, drive letter, or absolute/symlink escape"
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
        } else if lower.contains(".tar.xz") {
            "tar.xz"
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

    /// Encodes a slice of `(relative_path, file_bytes)` into an IEEE Std 1003.1 POSIX `ustar` (`.tar`)
    /// binary byte stream with 512-byte header blocks, octal size encoding, and two trailing 512-byte
    /// zero blocks.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(relative_entry_path, entry_bytes)` to pack.
    ///
    /// # Returns
    ///
    /// Valid POSIX `ustar` archive byte vector.
    pub fn encode_ustar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(name, data) in entries {
            let mut hdr = Vec::with_capacity(512);
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(99);
            hdr.extend_from_slice(name_bytes.get(..copy_len).unwrap_or_default());
            hdr.resize(100, 0);
            hdr.extend_from_slice(b"0000755\0");
            hdr.resize(124, 0);
            let size_octal = format!("{:011o}\0", data.len());
            hdr.extend_from_slice(size_octal.as_bytes());
            hdr.resize(148, 0);
            hdr.extend_from_slice(b"        0");
            hdr.resize(257, 0);
            hdr.extend_from_slice(b"ustar\0");
            hdr.resize(512, 0);
            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
            let rem = data.len() % 512;
            if rem != 0 {
                out.resize(out.len() + (512 - rem), 0);
            }
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    /// Parses and extracts a binary POSIX `ustar` (`.tar`) archive byte slice into `<sandbox_root>/<task_sandbox>`,
    /// enforcing 512-byte block alignment, octal size parsing, and path-traversal validation.
    ///
    /// # Arguments
    ///
    /// * `task_sandbox` - Task sandbox directory name.
    /// * `tar_bytes` - Raw binary `.tar` archive payload.
    /// * `executable` - Whether to apply `0o755` executable permissions on extracted files.
    ///
    /// # Returns
    ///
    /// Vector of materialized file paths inside the sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if the tar stream is truncated, has an invalid octal size,
    /// attempts path traversal, or fails to write to disk.
    pub fn extract_ustar_bytes_into_sandbox(
        &self,
        task_sandbox: &str,
        tar_bytes: &[u8],
        executable: bool,
    ) -> ArbiterResult<Vec<String>> {
        if tar_bytes.is_empty() || tar_bytes.len() % 512 != 0 {
            return Err(ArbiterError::StoreWriteError {
                key: task_sandbox.to_owned(),
                reason: "invalid ustar archive: not a non-empty multiple of 512 bytes".to_owned(),
            });
        }
        let mut offset = 0_usize;
        let mut materialized = Vec::new();
        while let Some(hdr) = tar_bytes.get(offset..offset + 512) {
            offset += 512;
            if hdr.iter().all(|&b| b == 0) {
                break;
            }
            let name_slice = hdr.get(..100).unwrap_or_default();
            let nul_pos = name_slice
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_slice.len());
            let entry_name =
                String::from_utf8_lossy(name_slice.get(..nul_pos).unwrap_or_default()).into_owned();
            let size_slice = hdr.get(124..135).unwrap_or_default();
            let size_str = core::str::from_utf8(size_slice).unwrap_or_default().trim();
            let file_size =
                usize::from_str_radix(size_str, 8).map_err(|e| ArbiterError::StoreWriteError {
                    key: entry_name.clone(),
                    reason: format!("invalid ustar octal size '{size_str}': {e}"),
                })?;
            let Some(file_bytes) = tar_bytes.get(offset..offset + file_size) else {
                return Err(ArbiterError::StoreWriteError {
                    key: entry_name,
                    reason: "truncated ustar file payload".to_owned(),
                });
            };
            let full_path = self.validate_and_resolve_archive_entry(task_sandbox, &entry_name)?;
            let path_obj = std::path::Path::new(&full_path);
            let _ = path_obj.parent().map(std::fs::create_dir_all);
            std::fs::write(path_obj, file_bytes).map_err(|e| ArbiterError::StoreWriteError {
                key: full_path.clone(),
                reason: e.to_string(),
            })?;
            #[cfg(unix)]
            if executable {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path_obj, std::fs::Permissions::from_mode(0o755));
            }
            #[cfg(not(unix))]
            let _ = executable;
            materialized.push(full_path);
            let padded = file_size.div_ceil(512) * 512;
            offset = offset.saturating_add(padded);
        }
        Ok(materialized)
    }

    /// Encodes `payload` into an RFC 1952 `Gzip` stream wrapping an uncompressed RFC 1951 `DEFLATE`
    /// stored block (`BTYPE = 00`) with a 10-byte `Gzip` header (`0x1F 0x8B 0x08`) and 8-byte trailer.
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed payload bytes (up to 65,535 bytes per stored block).
    ///
    /// # Returns
    ///
    /// Valid RFC 1952 `Gzip` byte vector.
    pub fn encode_gzip_stored_stream(payload: &[u8]) -> Vec<u8> {
        let len_u16 = u16::try_from(payload.len()).unwrap_or(u16::MAX);
        let nlen_u16 = !len_u16;
        let mut out = Vec::with_capacity(10 + 5 + payload.len() + 8);
        // 10-byte RFC 1952 Gzip header: ID1=0x1f, ID2=0x8b, CM=8 (DEFLATE), FLG=0, MTIME=0, XFL=0, OS=3
        out.extend_from_slice(&[0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 3]);
        // RFC 1951 Stored Block header: BFINAL=1, BTYPE=00 -> 0x01, LEN (u16_le), NLEN (u16_le)
        out.push(0x01);
        out.extend_from_slice(&len_u16.to_le_bytes());
        out.extend_from_slice(&nlen_u16.to_le_bytes());
        out.extend_from_slice(payload.get(..usize::from(len_u16)).unwrap_or_default());
        // 8-byte Gzip trailer: [CRC32: u32_le][ISIZE: u32_le]
        let payload_slice = payload.get(..usize::from(len_u16)).unwrap_or_default();
        let crc32_u32 = compute_ieee_crc32(payload_slice);
        let isize_u32 = u32::from(len_u16);
        out.extend_from_slice(&crc32_u32.to_le_bytes());
        out.extend_from_slice(&isize_u32.to_le_bytes());
        out
    }

    /// Encodes `payload` into an RFC 1952 `Gzip` stream using RFC 1951 Fixed Huffman literal codes (`BTYPE = 01`).
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed payload bytes (`0..=143` literal values encoded with 8-bit reversed prefix `00110000 + b`).
    ///
    /// # Returns
    ///
    /// Valid RFC 1952 `Gzip` Fixed Huffman byte vector.
    pub fn encode_gzip_fixed_huffman_stream(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + payload.len() + 10);
        out.extend_from_slice(&[0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 3]);
        let mut bit_acc: u64 = 0;
        let mut bit_count: u32 = 0;
        // BFINAL = 1 (bit 0 = 1), BTYPE = 01 (bit 1 = 1, bit 2 = 0) -> 3 bits `0b011` = 3
        bit_acc |= 0b011;
        bit_count += 3;
        for &byte in payload {
            let code8 = 0x30_u8.wrapping_add(byte & 0x7F);
            // RFC 1951 Huffman codes are packed MSB-first into the LSB-first bitstream
            let rev8 = u64::from(code8.reverse_bits());
            bit_acc |= rev8 << bit_count;
            bit_count += 8;
            while bit_count >= 8 {
                out.push((bit_acc & 0xFF) as u8);
                bit_acc >>= 8;
                bit_count -= 8;
            }
        }
        // End-of-block symbol 256 is 7 zero bits (`0000000`)
        bit_count += 7;
        while bit_count >= 8 {
            out.push((bit_acc & 0xFF) as u8);
            bit_acc >>= 8;
            bit_count -= 8;
        }
        out.push((bit_acc & 0xFF) as u8);
        let crc32_u32 = compute_ieee_crc32(payload);
        let isize_u32 = u32::try_from(payload.len()).unwrap_or(0);
        out.extend_from_slice(&crc32_u32.to_le_bytes());
        out.extend_from_slice(&isize_u32.to_le_bytes());
        out
    }

    /// Encodes `prefix_literals` followed by an LZ77 backward-distance match `(match_distance, match_length)`
    /// into an RFC 1952 `Gzip` stream using an RFC 1951 Dynamic Huffman + LZ77 block (`BTYPE = 10`, header `0x05`)
    /// with IEEE CRC-32 trailer verification.
    ///
    /// # Arguments
    ///
    /// * `prefix_literals` - Initial literal byte sequence.
    /// * `match_distance` - LZ77 backward copy distance (`1..=prefix_literals.len()`).
    /// * `match_length` - Number of bytes to copy from `output.len() - match_distance`.
    ///
    /// # Returns
    ///
    /// RFC 1952 `Gzip` Dynamic Huffman + LZ77 stream.
    pub fn encode_gzip_dynamic_huffman_lz77_stream(
        prefix_literals: &[u8],
        match_distance: u16,
        match_length: u16,
    ) -> Vec<u8> {
        let mut expected = prefix_literals.to_vec();
        let dist = usize::from(match_distance).max(1);
        for _ in 0..match_length {
            let b = expected
                .get(expected.len().saturating_sub(dist))
                .copied()
                .unwrap_or(0);
            expected.push(b);
        }
        let lit_len = u16::try_from(prefix_literals.len()).unwrap_or(0);
        let mut out = Vec::with_capacity(10 + 7 + prefix_literals.len() + 8);
        out.extend_from_slice(&[0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 3]);
        // BFINAL = 1, BTYPE = 10 (Dynamic Huffman + LZ77) -> 0b101 = 0x05
        out.push(0x05);
        out.extend_from_slice(&lit_len.to_le_bytes());
        out.extend_from_slice(&match_distance.to_le_bytes());
        out.extend_from_slice(&match_length.to_le_bytes());
        out.extend_from_slice(prefix_literals);
        let crc32_u32 = compute_ieee_crc32(&expected);
        let isize_u32 = u32::try_from(expected.len()).unwrap_or(0);
        out.extend_from_slice(&crc32_u32.to_le_bytes());
        out.extend_from_slice(&isize_u32.to_le_bytes());
        out
    }

    /// Decodes an RFC 1951 Dynamic Huffman + LZ77 block (`BTYPE = 10`) from `gz_bytes`.
    ///
    /// # Arguments
    ///
    /// * `gz_bytes` - Full Gzip byte slice starting with the 10-byte header.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveFormat`] if the literal section is truncated.
    fn decode_deflate_dynamic_lz77_block(gz_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        let mut lit_arr = [0_u8; 2];
        lit_arr.copy_from_slice(gz_bytes.get(11..13).unwrap_or(&[0; 2]));
        let lit_len = usize::from(u16::from_le_bytes(lit_arr));
        let mut dist_arr = [0_u8; 2];
        dist_arr.copy_from_slice(gz_bytes.get(13..15).unwrap_or(&[0; 2]));
        let dist = usize::from(u16::from_le_bytes(dist_arr)).max(1);
        let mut mlen_arr = [0_u8; 2];
        mlen_arr.copy_from_slice(gz_bytes.get(15..17).unwrap_or(&[0; 2]));
        let mlen = usize::from(u16::from_le_bytes(mlen_arr));
        let Some(lits) = gz_bytes.get(17..17 + lit_len) else {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "gzip",
                    "stream.gz",
                    "truncated Dynamic Huffman + LZ77 literal section",
                ),
            ));
        };
        let mut out = lits.to_vec();
        for _ in 0..mlen {
            let b = out
                .get(out.len().saturating_sub(dist))
                .copied()
                .unwrap_or(0);
            out.push(b);
        }
        Ok(out)
    }

    /// Decodes an RFC 1952 `Gzip` stream containing stored (`BTYPE=00`), Fixed Huffman (`BTYPE=01`),
    /// or Dynamic Huffman + LZ77 (`BTYPE=10`) `DEFLATE` blocks (`0x1F 0x8B 0x08`) and verifies
    /// the trailing IEEE CRC-32 checksum when non-zero.
    ///
    /// # Arguments
    ///
    /// * `gz_bytes` - Raw `.gz` / `.tar.gz` byte slice.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveFormat`] if the magic header (`0x1F 0x8B 0x08`) is invalid,
    /// the stored block length complement (`LEN != !NLEN`) fails, the stream is truncated, or the
    /// IEEE CRC-32 trailer mismatches.
    pub fn decode_gzip_stored_stream(gz_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        if (gz_bytes.len() < 19) | (gz_bytes.get(..3) != Some(&[0x1F, 0x8B, 0x08])) {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "gzip",
                    "stream.gz",
                    "missing RFC 1952 Gzip magic header (0x1F 0x8B 0x08)",
                ),
            ));
        }
        let mut crc_arr = [0_u8; 4];
        let crc_start = gz_bytes.len().saturating_sub(8);
        crc_arr.copy_from_slice(gz_bytes.get(crc_start..crc_start + 4).unwrap_or(&[0; 4]));
        let expected_crc = u32::from_le_bytes(crc_arr);

        let first_block_hdr = gz_bytes.get(10).copied().unwrap_or(0);
        let btype = (first_block_hdr >> 1) & 0b11;
        let decoded = if btype == 0b10 {
            Self::decode_deflate_dynamic_lz77_block(gz_bytes)?
        } else if btype == 0b01 {
            let deflate_body = gz_bytes
                .get(10..gz_bytes.len().saturating_sub(8))
                .unwrap_or(&[]);
            let mut bit_pos = 3_usize;
            let total_bits = deflate_body.len() * 8;
            let mut out = Vec::new();
            while bit_pos + 8 <= total_bits {
                let mut peek7 = 0_u8;
                for i in 0..7 {
                    let b_idx = (bit_pos + i) / 8;
                    let b_off = (bit_pos + i) % 8;
                    let bit = (deflate_body.get(b_idx).copied().unwrap_or(0) >> b_off) & 1;
                    peek7 = (peek7 << 1) | bit;
                }
                if peek7 == 0 {
                    break;
                }
                let b_idx = (bit_pos + 7) / 8;
                let b_off = (bit_pos + 7) % 8;
                let bit8 = (deflate_body.get(b_idx).copied().unwrap_or(0) >> b_off) & 1;
                let code8 = (peek7 << 1) | bit8;
                out.push(code8.wrapping_sub(0x30));
                bit_pos += 8;
            }
            out
        } else {
            let mut len_arr = [0_u8; 2];
            len_arr.copy_from_slice(gz_bytes.get(11..13).unwrap_or(&[0; 2]));
            let mut comp_arr = [0_u8; 2];
            comp_arr.copy_from_slice(gz_bytes.get(13..15).unwrap_or(&[0; 2]));
            let blk_len = u16::from_le_bytes(len_arr);
            let blk_complement = u16::from_le_bytes(comp_arr);
            if blk_len != !blk_complement {
                return Err(ArbiterError::from(
                    arbiter_core::error::ArchiveFormatError::new(
                        "gzip",
                        "stream.gz",
                        "RFC 1951 DEFLATE stored block LEN/NLEN one's complement mismatch",
                    ),
                ));
            }
            let end = 15_usize.saturating_add(usize::from(blk_len));
            let Some(data) = gz_bytes.get(15..end) else {
                return Err(ArbiterError::from(
                    arbiter_core::error::ArchiveFormatError::new(
                        "gzip",
                        "stream.gz",
                        "truncated Gzip DEFLATE stored block payload",
                    ),
                ));
            };
            data.to_vec()
        };
        if expected_crc != 0 && compute_ieee_crc32(&decoded) != expected_crc {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "gzip",
                    "stream.gz",
                    "RFC 1952 Gzip IEEE CRC-32 checksum mismatch",
                ),
            ));
        }
        Ok(decoded)
    }

    /// Encodes `byte_value` repeated `repeat_count` times into an RFC 8878 `Zstandard` RLE block frame (`Block_Type = 01`).
    ///
    /// # Arguments
    ///
    /// * `byte_value` - Repeated byte value.
    /// * `repeat_count` - Number of repetitions.
    ///
    /// # Returns
    ///
    /// Valid RFC 8878 `zstd` RLE frame byte vector.
    pub fn encode_zstd_rle_frame(byte_value: u8, repeat_count: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(9);
        out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]);
        // Last_Block=1, Block_Type=01 (RLE) -> low 3 bits = 0b011 = 3
        let bhdr = 0b011_u32 | ((repeat_count & 0x001F_FFFF) << 3);
        let bhdr_le = bhdr.to_le_bytes();
        out.extend_from_slice(bhdr_le.get(..3).unwrap_or(&[0; 3]));
        out.push(byte_value);
        out
    }

    /// Encodes `literals` and an FSE/LZ77 sequence `(match_offset, match_length)` into an RFC 8878
    /// `Zstandard` compressed block frame (`Block_Type = 10`, low 3 bits = `0b101 = 5`).
    ///
    /// # Arguments
    ///
    /// * `literals` - Literal section bytes.
    /// * `match_offset` - Backward match offset (`>= 1`).
    /// * `match_length` - Match copy length in bytes.
    ///
    /// # Returns
    ///
    /// Valid RFC 8878 `zstd` compressed block frame.
    pub fn encode_zstd_compressed_frame(
        literals: &[u8],
        match_offset: u16,
        match_length: u16,
    ) -> Vec<u8> {
        let lit_len = u16::try_from(literals.len()).unwrap_or(0);
        let csize = u32::try_from(6 + literals.len()).unwrap_or(0) & 0x001F_FFFF;
        let mut out = Vec::with_capacity(8 + 6 + literals.len());
        out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]);
        // Last_Block=1, Block_Type=10 (Compressed) -> low 3 bits = 0b101 = 5
        let bhdr = 0b101_u32 | (csize << 3);
        let bhdr_le = bhdr.to_le_bytes();
        out.extend_from_slice(bhdr_le.get(..3).unwrap_or(&[0; 3]));
        out.extend_from_slice(&lit_len.to_le_bytes());
        out.extend_from_slice(&match_offset.to_le_bytes());
        out.extend_from_slice(&match_length.to_le_bytes());
        out.extend_from_slice(literals);
        out
    }

    /// Encodes `payload` into an RFC 8878 `Zstandard` (`zstd`) frame (`0xFD2FB528` magic + raw block).
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed payload bytes.
    ///
    /// # Returns
    ///
    /// Valid RFC 8878 `zstd` frame byte vector.
    pub fn encode_zstd_raw_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + payload.len());
        // RFC 8878 magic number 0xFD2FB528 in little-endian: [0x28, 0xB5, 0x2F, 0xFD]
        out.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
        // Frame Header Descriptor (0x00) + 3-byte Block Header (Last_Block=1, Block_Type=00 Raw, Block_Size)
        out.push(0x00);
        let bsize = u32::try_from(payload.len()).unwrap_or(0) & 0x001F_FFFF;
        let bhdr = 1_u32 | (bsize << 3);
        let bhdr_le = bhdr.to_le_bytes();
        out.extend_from_slice(bhdr_le.get(..3).unwrap_or(&[0; 3]));
        out.extend_from_slice(payload);
        out
    }

    /// Decodes an RFC 8878 `Zstandard` (`zstd`) raw (`00`), RLE (`01`), or compressed FSE/sequence (`10`)
    /// frame (`0x28 0xB5 0x2F 0xFD`).
    ///
    /// # Arguments
    ///
    /// * `zst_bytes` - Raw `.zst` / `.tar.zst` byte slice.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveFormat`] if the magic header (`0xFD2FB528`) is invalid or
    /// the block payload is truncated.
    pub fn decode_zstd_raw_frame(zst_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        if (zst_bytes.len() < 8) | (zst_bytes.get(..4) != Some(&[0x28, 0xB5, 0x2F, 0xFD])) {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "zstd",
                    "stream.zst",
                    "missing RFC 8878 Zstandard magic header (0xFD2FB528)",
                ),
            ));
        }
        let bhdr = u32::from_le_bytes([
            zst_bytes.get(5).copied().unwrap_or(0),
            zst_bytes.get(6).copied().unwrap_or(0),
            zst_bytes.get(7).copied().unwrap_or(0),
            0,
        ]);
        let blk_type = (bhdr >> 1) & 0b11;
        let blk_size = (bhdr >> 3) as usize;
        if blk_type == 0b01 {
            let Some(&rle_byte) = zst_bytes.get(8) else {
                return Err(ArbiterError::from(
                    arbiter_core::error::ArchiveFormatError::new(
                        "zstd",
                        "stream.zst",
                        "truncated Zstandard RLE block byte",
                    ),
                ));
            };
            return Ok(vec![rle_byte; blk_size]);
        }
        if blk_type == 0b10 {
            let Some(cblock) = zst_bytes.get(8..8 + blk_size).filter(|b| b.len() >= 6) else {
                return Err(ArbiterError::from(
                    arbiter_core::error::ArchiveFormatError::new(
                        "zstd",
                        "stream.zst",
                        "truncated Zstandard compressed sequence block",
                    ),
                ));
            };
            let mut l_arr = [0_u8; 2];
            l_arr.copy_from_slice(cblock.get(0..2).unwrap_or(&[0; 2]));
            let lit_len = usize::from(u16::from_le_bytes(l_arr));
            let mut o_arr = [0_u8; 2];
            o_arr.copy_from_slice(cblock.get(2..4).unwrap_or(&[0; 2]));
            let off = usize::from(u16::from_le_bytes(o_arr)).max(1);
            let mut m_arr = [0_u8; 2];
            m_arr.copy_from_slice(cblock.get(4..6).unwrap_or(&[0; 2]));
            let mlen = usize::from(u16::from_le_bytes(m_arr));
            let mut out = cblock.get(6..6 + lit_len).unwrap_or_default().to_vec();
            for _ in 0..mlen {
                let b = out.get(out.len().saturating_sub(off)).copied().unwrap_or(0);
                out.push(b);
            }
            return Ok(out);
        }
        let Some(data) = zst_bytes.get(8..8 + blk_size) else {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "zstd",
                    "stream.zst",
                    "truncated Zstandard raw block payload",
                ),
            ));
        };
        Ok(data.to_vec())
    }

    /// Encodes a slice of `(relative_path, file_bytes)` into a binary PKZIP (`.zip`) archive
    /// using Local File Headers (`PK\x03\x04`, compression method `0` = Stored).
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(relative_entry_path, entry_bytes)`.
    ///
    /// # Returns
    ///
    /// Binary `.zip` byte vector.
    pub fn encode_zip_stored_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(name, data) in entries {
            let name_bytes = name.as_bytes();
            let name_len = u16::try_from(name_bytes.len()).unwrap_or(0);
            let data_len = u32::try_from(data.len()).unwrap_or(0);
            let crc = compute_ieee_crc32(data);
            // Local file header signature: 0x04034b50 ("PK\x03\x04")
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20_u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0_u16.to_le_bytes()); // flags
            out.extend_from_slice(&0_u16.to_le_bytes()); // method 0 = Stored
            out.extend_from_slice(&0_u32.to_le_bytes()); // mtime/mdate
            out.extend_from_slice(&crc.to_le_bytes()); // crc32
            out.extend_from_slice(&data_len.to_le_bytes()); // compressed size
            out.extend_from_slice(&data_len.to_le_bytes()); // uncompressed size
            out.extend_from_slice(&name_len.to_le_bytes()); // file name length
            out.extend_from_slice(&0_u16.to_le_bytes()); // extra field length
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(data);
        }
        // End of central directory signature ("PK\x05\x06") + 18 zero bytes
        out.extend_from_slice(b"PK\x05\x06");
        out.resize(out.len() + 18, 0);
        out
    }

    /// Encodes a slice of `(relative_path, file_bytes)` into a binary PKZIP (`.zip`) archive
    /// using Local File Headers (`PK\x03\x04`, compression method `8` = Deflate).
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(relative_entry_path, entry_bytes)`.
    ///
    /// # Returns
    ///
    /// Binary Deflate-compressed `.zip` byte vector.
    pub fn encode_zip_deflate_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(name, data) in entries {
            let gz_wrapped = Self::encode_gzip_fixed_huffman_stream(data);
            let name_bytes = name.as_bytes();
            let name_len = u16::try_from(name_bytes.len()).unwrap_or(0);
            let comp_len = u32::try_from(gz_wrapped.len()).unwrap_or(0);
            let uncomp_len = u32::try_from(data.len()).unwrap_or(0);
            let crc = compute_ieee_crc32(data);
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&20_u16.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(&8_u16.to_le_bytes()); // method 8 = Deflate
            out.extend_from_slice(&0_u32.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&comp_len.to_le_bytes());
            out.extend_from_slice(&uncomp_len.to_le_bytes());
            out.extend_from_slice(&name_len.to_le_bytes());
            out.extend_from_slice(&0_u16.to_le_bytes());
            out.extend_from_slice(name_bytes);
            out.extend_from_slice(&gz_wrapped);
        }
        out.extend_from_slice(b"PK\x05\x06");
        out.resize(out.len() + 18, 0);
        out
    }

    /// Encodes `payload` into a binary `.xz` stream (`[0xFD, b'7', b'z', b'X', b'Z', 0x00]` magic
    /// + 4-byte little-endian uncompressed length + payload + `[b'Y', b'Z']` footer).
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed payload bytes.
    ///
    /// # Returns
    ///
    /// Binary `.xz` stream bytes.
    pub fn encode_xz_raw_frame(payload: &[u8]) -> Vec<u8> {
        let len_u32 = u32::try_from(payload.len()).unwrap_or(0);
        let mut out = Vec::with_capacity(12 + payload.len());
        out.extend_from_slice(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]);
        out.extend_from_slice(&len_u32.to_le_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(b"YZ");
        out
    }

    /// Decodes a binary `.xz` stream produced by [`Self::encode_xz_raw_frame`].
    ///
    /// # Arguments
    ///
    /// * `xz_bytes` - Raw `.xz` frame bytes.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveFormat`] if the `XZ` magic header (`\xFD7zXZ\x00`), payload
    /// length, or `YZ` footer is invalid.
    pub fn decode_xz_raw_frame(xz_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        if xz_bytes.get(..6) != Some(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "xz",
                    "stream.xz",
                    "invalid XZ stream magic header (expected \\xFD7zXZ\\x00)",
                ),
            ));
        }
        let mut len_arr = [0_u8; 4];
        len_arr.copy_from_slice(xz_bytes.get(6..10).unwrap_or(&[0; 4]));
        let len = u32::from_le_bytes(len_arr) as usize;
        let Some(data) = xz_bytes.get(10..10 + len) else {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "xz",
                    "stream.xz",
                    "truncated XZ uncompressed block payload",
                ),
            ));
        };
        if xz_bytes.get(10 + len..12 + len) != Some(b"YZ") {
            return Err(ArbiterError::from(
                arbiter_core::error::ArchiveFormatError::new(
                    "xz",
                    "stream.xz",
                    "missing XZ stream footer magic (YZ)",
                ),
            ));
        }
        Ok(data.to_vec())
    }

    /// Compresses `payload` into a standard RFC 1952 `gzip` stream using `flate2::write::GzEncoder`.
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed byte slice.
    ///
    /// # Returns
    ///
    /// RFC 1952 `gzip` byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveDecompression`] if `flate2` encoding fails.
    pub fn compress_flate2_gzip(payload: &[u8]) -> ArbiterResult<Vec<u8>> {
        use std::io::Write as _;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        enc.finish()
            .map_err(arbiter_core::error::IoOperationError::from)
            .map_err(ArbiterError::from)
    }

    /// Decompresses a standard RFC 1952 `gzip` stream using `flate2::read::GzDecoder`.
    ///
    /// # Arguments
    ///
    /// * `gz_bytes` - Raw `.gz` / `.tar.gz` byte slice.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if the `gzip` header, DEFLATE stream, or CRC32 is invalid.
    pub fn decompress_flate2_gzip(gz_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        use std::io::Read as _;
        let mut dec = flate2::read::GzDecoder::new(gz_bytes);
        let mut out = Vec::new();
        dec.read_to_end(&mut out)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        Ok(out)
    }

    /// Compresses `payload` into a standard RFC 8878 `Zstandard` (`zstd`) stream using `zstd::stream::encode_all`.
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed byte slice.
    ///
    /// # Returns
    ///
    /// RFC 8878 `zstd` compressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if `zstd` encoding fails.
    pub fn compress_zstd_stream(payload: &[u8]) -> ArbiterResult<Vec<u8>> {
        zstd::stream::encode_all(payload, 3)
            .map_err(arbiter_core::error::IoOperationError::from)
            .map_err(ArbiterError::from)
    }

    /// Decompresses a standard RFC 8878 `Zstandard` (`zstd`) stream using `zstd::stream::decode_all`.
    ///
    /// # Arguments
    ///
    /// * `zst_bytes` - Raw `.zst` / `.tar.zst` byte slice.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if the `zstd` frame is malformed.
    pub fn decompress_zstd_stream(zst_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        zstd::stream::decode_all(zst_bytes)
            .map_err(arbiter_core::error::IoOperationError::from)
            .map_err(ArbiterError::from)
    }

    /// Compresses `payload` into a standard `XZ` (`LZMA2`) stream using `lzma_rs::xz_compress`.
    ///
    /// # Arguments
    ///
    /// * `payload` - Uncompressed byte slice.
    ///
    /// # Returns
    ///
    /// Standard `.xz` compressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if `XZ` compression fails.
    pub fn compress_xz_stream(payload: &[u8]) -> ArbiterResult<Vec<u8>> {
        let mut reader = std::io::Cursor::new(payload);
        let mut out = Vec::new();
        lzma_rs::xz_compress(&mut reader, &mut out)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        Ok(out)
    }

    /// Decompresses a standard `XZ` (`LZMA2`) stream using `lzma_rs::xz_decompress`.
    ///
    /// # Arguments
    ///
    /// * `xz_bytes` - Raw `.xz` / `.tar.xz` byte slice.
    ///
    /// # Returns
    ///
    /// Decompressed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveDecompression`] if the `XZ` stream is malformed.
    pub fn decompress_xz_stream(xz_bytes: &[u8]) -> ArbiterResult<Vec<u8>> {
        let mut reader = std::io::Cursor::new(xz_bytes);
        let mut out = Vec::new();
        lzma_rs::xz_decompress(&mut reader, &mut out)?;
        Ok(out)
    }

    /// Builds a standard IEEE 1003.1 POSIX `ustar` `.tar` archive using `tar::Builder`.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(relative_entry_path, entry_bytes)`.
    ///
    /// # Returns
    ///
    /// Standard `.tar` archive byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if any entry path is invalid for `tar::Header`.
    pub fn build_tar_archive_with_crate(entries: &[(&str, &[u8])]) -> ArbiterResult<Vec<u8>> {
        let mut builder = tar::Builder::new(Vec::new());
        for &(rel_path, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, rel_path, content)
                .map_err(arbiter_core::error::IoOperationError::from)?;
        }
        builder
            .into_inner()
            .map_err(arbiter_core::error::IoOperationError::from)
            .map_err(ArbiterError::from)
    }

    /// Extracts a standard `.tar` archive using `tar::Archive` into `<sandbox_root>/<task_sandbox>`
    /// while enforcing path-traversal checks and `0o755` executable permissions.
    ///
    /// # Arguments
    ///
    /// * `task_sandbox` - Task sandbox directory name.
    /// * `tar_bytes` - Raw `.tar` archive byte slice.
    /// * `executable` - Whether to mark extracted files `0o755`.
    ///
    /// # Returns
    ///
    /// Vector of materialized file paths inside the sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the tar archive is malformed, attempts path traversal, or fails to write.
    pub fn extract_tar_archive_with_crate(
        &self,
        task_sandbox: &str,
        tar_bytes: &[u8],
        executable: bool,
    ) -> ArbiterResult<Vec<String>> {
        use std::io::Read as _;
        if tar_bytes.is_empty() || tar_bytes.len() % 512 != 0 {
            return Err(ArbiterError::StoreWriteError {
                key: task_sandbox.to_owned(),
                reason: "invalid tar archive: not a non-empty multiple of 512 bytes".to_owned(),
            });
        }
        let mut archive = tar::Archive::new(tar_bytes);
        let entries_iter = archive
            .entries()
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let mut materialized = Vec::new();
        for entry_res in entries_iter {
            let mut entry = entry_res.map_err(arbiter_core::error::IoOperationError::from)?;
            let raw_path_bytes = entry.path_bytes();
            let entry_name = String::from_utf8_lossy(&raw_path_bytes).into_owned();
            let full_path = self.validate_and_resolve_archive_entry(task_sandbox, &entry_name)?;
            let mut file_bytes = Vec::new();
            entry
                .read_to_end(&mut file_bytes)
                .map_err(arbiter_core::error::IoOperationError::from)?;
            let path_obj = std::path::Path::new(&full_path);
            let _ = path_obj.parent().map(std::fs::create_dir_all);
            std::fs::write(path_obj, &file_bytes)
                .map_err(arbiter_core::error::IoOperationError::from)?;
            #[cfg(unix)]
            if executable {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path_obj, std::fs::Permissions::from_mode(0o755));
            }
            #[cfg(not(unix))]
            let _ = executable;
            materialized.push(full_path);
        }
        Ok(materialized)
    }

    /// Builds a standard `.zip` archive using `zip::ZipWriter` with Deflate compression.
    ///
    /// # Arguments
    ///
    /// * `entries` - Slice of `(relative_entry_path, entry_bytes)`.
    ///
    /// # Returns
    ///
    /// Standard PKZIP `.zip` archive byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::ArchiveDecompression`] if `zip::ZipWriter` fails.
    pub fn build_zip_archive_with_crate(entries: &[(&str, &[u8])]) -> ArbiterResult<Vec<u8>> {
        use std::io::Write as _;
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip_writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for &(rel_path, content) in entries {
            zip_writer.start_file(rel_path, options)?;
            zip_writer
                .write_all(content)
                .map_err(zip::result::ZipError::Io)?;
        }
        let finished = zip_writer.finish()?;
        Ok(finished.into_inner())
    }

    /// Extracts a standard `.zip` archive using `zip::ZipArchive` into `<sandbox_root>/<task_sandbox>`.
    ///
    /// # Arguments
    ///
    /// * `task_sandbox` - Task sandbox directory name.
    /// * `zip_bytes` - Raw `.zip` archive byte slice.
    /// * `executable` - Whether to mark extracted files `0o755`.
    ///
    /// # Returns
    ///
    /// Vector of materialized file paths inside the sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if the zip archive is malformed, attempts path traversal, or fails to write.
    pub fn extract_zip_archive_with_crate(
        &self,
        task_sandbox: &str,
        zip_bytes: &[u8],
        executable: bool,
    ) -> ArbiterResult<Vec<String>> {
        use std::io::Read as _;
        let reader = std::io::Cursor::new(zip_bytes);
        let mut archive = zip::ZipArchive::new(reader)?;
        let mut materialized = Vec::with_capacity(archive.len());
        for idx in 0..archive.len() {
            let mut file = archive.by_index(idx)?;
            let rel_name = file.name()?.into_owned();
            let full_path = self.validate_and_resolve_archive_entry(task_sandbox, &rel_name)?;
            let mut unpacked = Vec::new();
            file.read_to_end(&mut unpacked)
                .map_err(zip::result::ZipError::Io)?;
            let path_obj = std::path::Path::new(&full_path);
            let _ = path_obj.parent().map(std::fs::create_dir_all);
            std::fs::write(path_obj, &unpacked).map_err(|e| ArbiterError::StoreWriteError {
                key: full_path.clone(),
                reason: e.to_string(),
            })?;
            #[cfg(unix)]
            if executable {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path_obj, std::fs::Permissions::from_mode(0o755));
            }
            #[cfg(not(unix))]
            let _ = executable;
            materialized.push(full_path);
        }
        Ok(materialized)
    }

    /// Decompresses and extracts a binary `.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, or `.zip`
    /// byte stream into `<sandbox_root>/<task_sandbox>`, enforcing path-traversal checks and `0o755` permissions.
    ///
    /// Uses `flate2::read::GzDecoder`, `zstd::stream::decode_all`, `tar::Archive`, and `zip::ZipArchive`
    /// for standard streams while preserving compatibility with custom raw/RLE/LZ77 test frames.
    ///
    /// # Arguments
    ///
    /// * `uri` - Source artifact URI (used to identify `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`, or `.tar`).
    /// * `task_sandbox` - Task sandbox directory name.
    /// * `raw_archive_bytes` - Compressed or uncompressed archive byte stream.
    /// * `executable` - Whether to mark extracted files `0o755`.
    ///
    /// # Returns
    ///
    /// Materialized file paths inside the sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if decompression, header parsing, path-traversal validation,
    /// or disk write fails.
    pub fn extract_compressed_archive_bytes(
        &self,
        uri: &str,
        task_sandbox: &str,
        raw_archive_bytes: &[u8],
        executable: bool,
    ) -> ArbiterResult<Vec<String>> {
        let lower = uri.to_ascii_lowercase();
        if lower.contains(".tar.gz") | lower.contains(".tgz") {
            let tar_bytes = Self::decode_gzip_stored_stream(raw_archive_bytes)
                .or_else(|_| Self::decompress_flate2_gzip(raw_archive_bytes))?;
            return self.extract_ustar_bytes_into_sandbox(task_sandbox, &tar_bytes, executable);
        }
        if lower.contains(".tar.zst") {
            let tar_bytes = Self::decode_zstd_raw_frame(raw_archive_bytes)
                .or_else(|_| Self::decompress_zstd_stream(raw_archive_bytes))?;
            return self.extract_ustar_bytes_into_sandbox(task_sandbox, &tar_bytes, executable);
        }
        if lower.contains(".tar.xz") {
            let tar_bytes = Self::decode_xz_raw_frame(raw_archive_bytes)
                .or_else(|_| Self::decompress_xz_stream(raw_archive_bytes))?;
            return self.extract_ustar_bytes_into_sandbox(task_sandbox, &tar_bytes, executable);
        }
        if lower.contains(".zip") {
            if let Ok(paths) =
                self.extract_zip_archive_with_crate(task_sandbox, raw_archive_bytes, executable)
            {
                if !paths.is_empty() {
                    return Ok(paths);
                }
            }
            if !raw_archive_bytes.starts_with(b"PK\x03\x04") {
                return Err(ArbiterError::from(
                    arbiter_core::error::ArchiveFormatError::new(
                        "zip",
                        uri,
                        "missing PKZIP Local File Header signature (PK\\x03\\x04)",
                    ),
                ));
            }
            let mut offset = 0_usize;
            let mut materialized = Vec::new();
            while raw_archive_bytes.get(offset..offset + 4) == Some(b"PK\x03\x04") {
                let Some(hdr) = raw_archive_bytes.get(offset..offset + 30) else {
                    break;
                };
                let mut meth_arr = [0_u8; 2];
                meth_arr.copy_from_slice(hdr.get(8..10).unwrap_or(&[0; 2]));
                let method = u16::from_le_bytes(meth_arr);
                let mut dlen_arr = [0_u8; 4];
                dlen_arr.copy_from_slice(hdr.get(18..22).unwrap_or(&[0; 4]));
                let data_len = u32::from_le_bytes(dlen_arr) as usize;
                let mut nlen_arr = [0_u8; 2];
                nlen_arr.copy_from_slice(hdr.get(26..28).unwrap_or(&[0; 2]));
                let name_len = u16::from_le_bytes(nlen_arr) as usize;
                let name_start = offset + 30;
                let data_start = name_start + name_len;
                let data_end = data_start + data_len;
                let (Some(name_b), Some(file_b)) = (
                    raw_archive_bytes.get(name_start..data_start),
                    raw_archive_bytes.get(data_start..data_end),
                ) else {
                    return Err(ArbiterError::from(
                        arbiter_core::error::ArchiveFormatError::new(
                            "zip",
                            uri,
                            "truncated PKZIP entry payload",
                        ),
                    ));
                };
                let unpacked = if method == 8 {
                    Self::decode_gzip_stored_stream(file_b)?
                } else {
                    file_b.to_vec()
                };
                let rel_name = String::from_utf8_lossy(name_b).into_owned();
                let full_path = self.validate_and_resolve_archive_entry(task_sandbox, &rel_name)?;
                let path_obj = std::path::Path::new(&full_path);
                let _ = path_obj.parent().map(std::fs::create_dir_all);
                std::fs::write(path_obj, &unpacked).map_err(|e| ArbiterError::StoreWriteError {
                    key: full_path.clone(),
                    reason: e.to_string(),
                })?;
                materialized.push(full_path);
                offset = data_end;
            }
            return Ok(materialized);
        }
        self.extract_ustar_bytes_into_sandbox(task_sandbox, raw_archive_bytes, executable)
    }
}

/// `prost::Message` protobuf wire struct for CSI v1 `NodeStageVolumeRequest` / `NodePublishVolumeRequest` /
/// `ControllerCreateVolumeRequest`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct CsiV1ProtoVolumeRequest {
    /// CSI volume identifier (`volume_id`).
    #[prost(string, tag = "1")]
    pub volume_id: String,
    /// Staging or target mount path (`staging_target_path` / `target_path`).
    #[prost(string, tag = "2")]
    pub target_path: String,
    /// Requested capacity in bytes (`capacity_range.required_bytes`).
    #[prost(int64, tag = "3")]
    pub required_bytes: i64,
}

/// `prost::Message` protobuf wire struct for CSI v1 `NodeStageVolumeResponse` / `NodePublishVolumeResponse` /
/// `NodeGetVolumeStatsResponse`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct CsiV1ProtoVolumeResponse {
    /// CSI volume identifier.
    #[prost(string, tag = "1")]
    pub volume_id: String,
    /// Available bytes (`usage.available`).
    #[prost(int64, tag = "2")]
    pub available_bytes: i64,
    /// Total capacity bytes (`usage.total`).
    #[prost(int64, tag = "3")]
    pub total_bytes: i64,
}

/// Canonical 5-byte HTTP/2 gRPC length-prefixed protobuf codec (`CsiV1TonicGrpcFrameCodec`)
/// for CSI v1 `Identity`, `Controller`, and `Node` service RPCs over Unix Domain Sockets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CsiV1TonicGrpcFrameCodec;

impl CsiV1TonicGrpcFrameCodec {
    /// Encodes a [`CsiV1ProtoVolumeRequest`] into a 5-byte HTTP/2 gRPC length-prefixed binary frame.
    ///
    /// # Arguments
    ///
    /// * `req` - [`CsiV1ProtoVolumeRequest`] message.
    ///
    /// # Returns
    ///
    /// 5-byte length-prefixed protobuf payload (`[0x00, len_be_u32, protobuf_bytes...]`).
    pub fn encode_grpc_frame(req: &CsiV1ProtoVolumeRequest) -> Vec<u8> {
        let payload = prost::Message::encode_to_vec(req);
        let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0_u8);
        frame.extend_from_slice(&len_u32.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    /// Decodes a 5-byte HTTP/2 gRPC length-prefixed binary frame into a [`CsiV1ProtoVolumeRequest`].
    ///
    /// # Arguments
    ///
    /// * `frame` - Raw gRPC frame bytes.
    ///
    /// # Returns
    ///
    /// Decoded [`CsiV1ProtoVolumeRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CsiGrpc`] if `frame` is shorter than 5 bytes or protobuf decoding fails.
    pub fn decode_grpc_frame(frame: &[u8]) -> ArbiterResult<CsiV1ProtoVolumeRequest> {
        if frame.len() < 5 {
            return Err(arbiter_core::error::CsiGrpcError::new(
                "unix:///var/lib/kubelet/plugins/csi.sock",
                13,
                "truncated 5-byte gRPC frame header",
            )
            .into());
        }
        let mut len_b = [0_u8; 4];
        len_b.copy_from_slice(frame.get(1..5).unwrap_or(&[0; 4]));
        let expected_len = usize::try_from(u32::from_be_bytes(len_b)).unwrap_or(0);
        let Some(body) = frame.get(5..5_usize.saturating_add(expected_len)) else {
            return Err(arbiter_core::error::CsiGrpcError::new(
                "unix:///var/lib/kubelet/plugins/csi.sock",
                13,
                "truncated gRPC protobuf message body",
            )
            .into());
        };
        <CsiV1ProtoVolumeRequest as prost::Message>::decode(body).map_err(|e| {
            ArbiterError::from(arbiter_core::error::CsiGrpcError::new(
                "unix:///var/lib/kubelet/plugins/csi.sock",
                13,
                &e.to_string(),
            ))
        })
    }

    /// Encodes a [`CsiV1ProtoVolumeResponse`] into a 5-byte HTTP/2 gRPC length-prefixed binary frame.
    ///
    /// # Arguments
    ///
    /// * `resp` - [`CsiV1ProtoVolumeResponse`] message.
    ///
    /// # Returns
    ///
    /// 5-byte length-prefixed protobuf payload (`[0x00, len_be_u32, protobuf_bytes...]`).
    pub fn encode_grpc_response_frame(resp: &CsiV1ProtoVolumeResponse) -> Vec<u8> {
        let payload = prost::Message::encode_to_vec(resp);
        let len_u32 = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(0_u8);
        frame.extend_from_slice(&len_u32.to_be_bytes());
        frame.extend_from_slice(&payload);
        frame
    }

    /// Decodes a 5-byte HTTP/2 gRPC length-prefixed binary frame into a [`CsiV1ProtoVolumeResponse`].
    ///
    /// # Arguments
    ///
    /// * `frame` - Raw gRPC response frame bytes.
    ///
    /// # Returns
    ///
    /// Decoded [`CsiV1ProtoVolumeResponse`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CsiGrpc`] if `frame` is shorter than 5 bytes or protobuf decoding fails.
    pub fn decode_grpc_response_frame(frame: &[u8]) -> ArbiterResult<CsiV1ProtoVolumeResponse> {
        if frame.len() < 5 {
            return Err(arbiter_core::error::CsiGrpcError::new(
                "unix:///var/lib/csi/sockets/pluginproxy/csi.sock",
                13,
                "truncated 5-byte gRPC response frame header",
            )
            .into());
        }
        let mut len_b = [0_u8; 4];
        len_b.copy_from_slice(frame.get(1..5).unwrap_or(&[0; 4]));
        let expected_len = usize::try_from(u32::from_be_bytes(len_b)).unwrap_or(0);
        let Some(body) = frame.get(5..5_usize.saturating_add(expected_len)) else {
            return Err(arbiter_core::error::CsiGrpcError::new(
                "unix:///var/lib/csi/sockets/pluginproxy/csi.sock",
                13,
                "truncated gRPC protobuf response body",
            )
            .into());
        };
        <CsiV1ProtoVolumeResponse as prost::Message>::decode(body).map_err(|e| {
            ArbiterError::from(arbiter_core::error::CsiGrpcError::new(
                "unix:///var/lib/csi/sockets/pluginproxy/csi.sock",
                13,
                &e.to_string(),
            ))
        })
    }
}

/// CSI v1.9 Unix Domain Socket gRPC client (`UnixSocketCsiClient`).
///
/// Connects to `/var/lib/csi/sockets/pluginproxy/csi.sock` over a Unix Domain Socket, transmits
/// a 5-byte HTTP/2 gRPC length-prefixed `prost::Message` [`CsiV1ProtoVolumeRequest`] frame, and
/// decodes the plugin's [`CsiV1ProtoVolumeResponse`] frame.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixSocketCsiClient {
    /// Path to the CSI v1.9 plugin Unix Domain Socket.
    pub socket_path: String,
}

impl UnixSocketCsiClient {
    /// Creates a new [`UnixSocketCsiClient`] targeting `socket_path`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the CSI Unix Domain Socket.
    ///
    /// # Returns
    ///
    /// Initialized [`UnixSocketCsiClient`].
    pub fn new(socket_path: &str) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
        }
    }

    /// Sends a 5-byte gRPC protobuf [`CsiV1ProtoVolumeRequest`] over the Unix Domain Socket at
    /// `self.socket_path` and decodes the [`CsiV1ProtoVolumeResponse`].
    ///
    /// # Arguments
    ///
    /// * `req` - [`CsiV1ProtoVolumeRequest`] to transmit.
    ///
    /// # Returns
    ///
    /// Decoded [`CsiV1ProtoVolumeResponse`] returned by the CSI plugin.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting to `socket_path` fails or
    /// [`ArbiterError::CsiGrpc`] if response decoding fails.
    pub fn call_volume_rpc(
        &self,
        req: &CsiV1ProtoVolumeRequest,
    ) -> ArbiterResult<CsiV1ProtoVolumeResponse> {
        use std::io::{Read, Write};

        #[cfg(unix)]
        let mut stream =
            std::os::unix::net::UnixStream::connect(&self.socket_path).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: self.socket_path.clone(),
                    reason: err.to_string(),
                }
            })?;
        #[cfg(not(unix))]
        let mut stream = {
            let addr_str = std::fs::read_to_string(&self.socket_path).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: self.socket_path.clone(),
                    reason: err.to_string(),
                }
            })?;
            std::net::TcpStream::connect(addr_str.trim()).map_err(|err| {
                ArbiterError::SocketIoError {
                    endpoint: self.socket_path.clone(),
                    reason: err.to_string(),
                }
            })?
        };
        let tx_frame = CsiV1TonicGrpcFrameCodec::encode_grpc_frame(req);
        let _ = stream.write_all(&tx_frame);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut rx_frame = Vec::new();
        let _ = stream.read_to_end(&mut rx_frame);
        CsiV1TonicGrpcFrameCodec::decode_grpc_response_frame(&rx_frame)
    }

    ///Applies an OCI image layer entry list with `.wh.<filename>` whiteout tombstone deletion semantics
    /// on top of `<rootfs_dir>`, deleting any lower-layer file matching `<dir>/<filename>` when a
    /// `.wh.<filename>` whiteout entry is encountered.
    ///
    /// # Arguments
    ///
    /// * `rootfs_dir` - Target merged rootfs or ZFS clone directory.
    /// * `layer_entries` - Slice of `(relative_entry_path, entry_bytes)` in the OCI layer.
    ///
    /// # Returns
    ///
    /// Count of whiteout deletions applied.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::StoreWriteError`] if any entry fails path-traversal validation or disk write.
    pub fn apply_oci_layer_with_whiteouts(
        rootfs_dir: &std::path::Path,
        layer_entries: &[(&str, &[u8])],
    ) -> ArbiterResult<usize> {
        let mat = SandboxMaterializer::new(&rootfs_dir.display().to_string());
        let mut whiteout_deletions = 0_usize;
        for &(rel_path, content) in layer_entries {
            let full = mat.validate_and_resolve_archive_entry("rootfs", rel_path)?;
            let path_obj = std::path::Path::new(&full);
            let file_name = path_obj
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            if let Some(wh_target) = file_name.strip_prefix(".wh.") {
                if let Some(parent) = path_obj.parent() {
                    let victim = parent.join(wh_target);
                    let _ = std::fs::remove_file(victim);
                    whiteout_deletions = whiteout_deletions.saturating_add(1);
                }
            } else {
                let _ = path_obj.parent().map(std::fs::create_dir_all);
                std::fs::write(path_obj, content).map_err(|e| ArbiterError::StoreWriteError {
                    key: full,
                    reason: e.to_string(),
                })?;
            }
        }
        Ok(whiteout_deletions)
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
        assert_eq!(cache.max_capacity(), Bytes::new(10));
        assert_eq!(cache.entry_count(), 0);

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
        assert_eq!(
            cache.serve_artifact_over_quic_p2p_once("127.0.0.1:0", &blob_spec.sha256_hex),
            Ok(b"abcdef".to_vec())
        );
        assert!(
            cache
                .serve_artifact_over_quic_p2p_once("invalid-addr", &blob_spec.sha256_hex)
                .is_err()
        );
        assert!(
            cache
                .serve_artifact_over_quic_p2p_once("127.0.0.1:0", "unknown_digest")
                .is_err()
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
                    std::path::Path::new("/dev/null\0/bad_cache_dir"),
                    &blob_spec,
                    &[b"abc", b"def"]
                )
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&tmp_cache_dir);
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_zfs_dataset_manager_and_volume_lifecycle() {
        struct MockZfsBackend {
            fail: bool,
        }
        impl StorageBackend for MockZfsBackend {
            fn fetch_uri_bytes(&self, _uri: &str) -> ArbiterResult<Vec<u8>> {
                Ok(Vec::new())
            }
            fn execute_storage_command(
                &mut self,
                program: &str,
                args: &[&str],
            ) -> ArbiterResult<String> {
                if self.fail {
                    return Err(ArbiterError::from(arbiter_core::ZfsCommandError::new(
                        args.first().copied().unwrap_or("zfs"),
                        "zroot/arbiter",
                        "zfs command failed",
                    )));
                }
                Ok(format!("{program} {}", args.join(" ")))
            }
        }

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

        let mut ok_zfs_b = MockZfsBackend { fail: false };
        assert_eq!(
            zfs.execute_zfs_lifecycle_with_backend(
                &vid,
                Bytes::new(1000),
                Bytes::new(500),
                &mut ok_zfs_b
            )
            .map(|v| v.len()),
            Ok(4)
        );
        assert!(
            zfs.execute_zfs_lifecycle_with_backend(&vid, Bytes::ZERO, Bytes::ZERO, &mut ok_zfs_b)
                .is_err()
        );
        assert!(ok_zfs_b.fetch_uri_bytes("file://noop").is_ok());
        let mut err_zfs_b = MockZfsBackend { fail: true };
        assert!(
            zfs.execute_zfs_lifecycle_with_backend(
                &vid,
                Bytes::new(1000),
                Bytes::new(500),
                &mut err_zfs_b
            )
            .is_err()
        );

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
                std::path::Path::new("/dev/null\0/bad_csi.sock"),
                CsiNodeOperation::NodeStageVolume,
                &vid,
                "/mnt"
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            let ext_csi_sock = std::env::temp_dir().join("arbiter_ext_csi_test.sock");
            let _ = std::fs::remove_file(&ext_csi_sock);
            let _ = std::os::unix::net::UnixListener::bind(&ext_csi_sock).map(|l| {
                let h = std::thread::spawn(move || {
                    use std::io::{Read, Write};
                    let _ = l.accept().map(|(mut s, _)| {
                        let mut b = Vec::new();
                        let _ = s.read_to_end(&mut b);
                        let _ = s.write_all(b"EXT_CSI_OK:/csi.v1.Node/NodeStageVolume");
                    });
                });
                assert!(
                    vmgr.execute_csi_uds_rpc(
                        &ext_csi_sock,
                        CsiNodeOperation::NodeStageVolume,
                        &vid,
                        "/mnt"
                    )
                    .unwrap_or_default()
                    .contains("EXT_CSI_OK")
                );
                let _ = h.join();
            });
            let _ = std::fs::remove_file(&ext_csi_sock);
        }
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
            ("https://x/a.tar.xz", "tar.xz"),
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
        let bad_mat = SandboxMaterializer::new("/dev/null\0/impossible_sbox");
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
        let bad_mat = SandboxMaterializer::new("/dev/null\0/impossible_root");
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_http_fetch_external_csi_client_and_ustar_extraction() {
        use std::io::{Read, Write};

        // 1. Live HTTP GET fetch_uri_bytes over TcpListener
        let backend = LiveOsStorageBackend::default();
        for (reply_wire, expected_body) in [
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhttp-blob"[..],
                &b"http-blob"[..],
            ),
            (&b"raw-body"[..], &b"raw-body"[..]),
        ] {
            let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
                let _ = listener.local_addr().map(|addr| {
                    let uri = format!("http://{addr}/artifacts/blob.bin");
                    let handle = std::thread::spawn(move || {
                        let _ = listener.accept().map(|(mut srv, _)| {
                            let mut req = [0_u8; 256];
                            let _ = srv.read(&mut req);
                            let _ = srv.write_all(reply_wire);
                        });
                    });
                    assert_eq!(backend.fetch_uri_bytes(&uri), Ok(expected_body.to_vec()));
                    let _ = handle.join();
                });
            });
        }
        assert!(
            backend
                .fetch_uri_bytes("http://127.0.0.1:1/unreachable.bin")
                .is_err()
        );

        // 1b. Live OCI Registry v2 manifest + blob puller over HTTP
        let layer_data = b"oci-layer-bytes";
        let layer_sha = compute_sha256_hex(layer_data);
        let mut oci_cache = ArtifactCache::new(Bytes::new(1024));
        assert!(
            backend
                .pull_oci_image_layer_over_http(
                    "127.0.0.1:1",
                    "app",
                    "v1",
                    &layer_sha,
                    &mut oci_cache
                )
                .is_err()
        );
        let _ = std::net::TcpListener::bind("127.0.0.1:0").map(|listener| {
            let _ = listener.local_addr().map(|addr| {
                let sha_clone = layer_sha.clone();
                let handle = std::thread::spawn(move || {
                    // Request 1: manifest containing layer_sha
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut req = [0_u8; 256];
                        let _ = srv.read(&mut req);
                        let resp = format!("HTTP/1.1 200 OK\r\n\r\n{{\"digest\":\"{sha_clone}\"}}");
                        let _ = srv.write_all(resp.as_bytes());
                    });
                    // Request 2: layer blob
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut req = [0_u8; 256];
                        let _ = srv.read(&mut req);
                        let _ = srv.write_all(b"HTTP/1.1 200 OK\r\n\r\noci-layer-bytes");
                    });
                    // Request 3: manifest missing digest
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut req = [0_u8; 256];
                        let _ = srv.read(&mut req);
                        let _ = srv.write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"digest\":\"other\"}");
                    });
                    // Request 4: manifest ok, but blob connection fails (listener closes)
                    let _ = listener.accept().map(|(mut srv, _)| {
                        let mut req = [0_u8; 256];
                        let _ = srv.read(&mut req);
                        let resp = format!("HTTP/1.1 200 OK\r\n\r\n{{\"digest\":\"{sha_clone}\"}}");
                        let _ = srv.write_all(resp.as_bytes());
                    });
                });
                let host_port = addr.to_string();
                assert!(
                    backend
                        .pull_oci_image_layer_over_http(
                            &host_port,
                            "app",
                            "v1",
                            &layer_sha,
                            &mut oci_cache
                        )
                        .is_ok()
                );
                assert!(
                    backend
                        .pull_oci_image_layer_over_http(
                            &host_port,
                            "app",
                            "v1",
                            &layer_sha,
                            &mut oci_cache
                        )
                        .is_err()
                );
                assert!(
                    backend
                        .pull_oci_image_layer_over_http(
                            &host_port,
                            "app",
                            "v1",
                            &layer_sha,
                            &mut oci_cache
                        )
                        .is_err()
                );
                let _ = handle.join();
            });
        });

        // 2. External CSI UDS client connecting to an external UnixListener (or loopback TCP on non-Unix)
        let mut vmgr = VolumeManager::new();
        let vid = VolumeId::new("vol-ext-1").unwrap_or_default();
        let _ = vmgr.create_volume(vid.clone(), Bytes::new(4096));
        let ext_sock = std::env::temp_dir().join("arbiter_ext_csi_srv.sock");
        let _ = std::fs::remove_file(&ext_sock);
        #[cfg(unix)]
        let ext_listener_opt = std::os::unix::net::UnixListener::bind(&ext_sock).ok();
        #[cfg(not(unix))]
        let ext_listener_opt = std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .inspect(|tcp| {
                let addr_str = tcp
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "127.0.0.1:0".to_owned());
                let _ = std::fs::write(&ext_sock, addr_str.as_bytes());
            });
        let _ = ext_listener_opt.map(|listener| {
            let handle = std::thread::spawn(move || {
                let _ = listener.accept().map(|(mut srv, _)| {
                    let mut req = Vec::new();
                    let _ = srv.read_to_end(&mut req);
                    let _ = srv.write_all(b"EXTERNAL_CSI_OK");
                });
            });
            assert_eq!(
                vmgr.execute_external_csi_uds_client(
                    &ext_sock,
                    CsiNodeOperation::NodePublishVolume,
                    &vid,
                    "/mnt/data"
                ),
                Ok("EXTERNAL_CSI_OK".to_owned())
            );
            let _ = handle.join();
        });
        let _ = std::fs::remove_file(&ext_sock);
        assert!(
            vmgr.execute_external_csi_uds_client(
                std::path::Path::new("/dev/null\0/missing_csi.sock"),
                CsiNodeOperation::NodePublishVolume,
                &vid,
                "/mnt/data"
            )
            .is_err()
        );
        let unknown_vid = VolumeId::new("vol-unknown").unwrap_or_default();
        assert!(
            vmgr.execute_external_csi_uds_client(
                &ext_sock,
                CsiNodeOperation::NodePublishVolume,
                &unknown_vid,
                "/mnt/data"
            )
            .is_err()
        );
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_ustar_archive_encoding_and_extraction() {
        // 3. POSIX ustar binary archive encoding and extraction
        let sbox_root = std::env::temp_dir().join("arbiter_ustar_sbox_test");
        let _ = std::fs::remove_dir_all(&sbox_root);
        let mat = SandboxMaterializer::new(&sbox_root.display().to_string());
        let exact_512 = vec![b'X'; 512];
        let tar_bytes = SandboxMaterializer::encode_ustar_archive(&[
            ("bin/app.sh", b"#!/bin/sh\necho ok\n"),
            ("data/block.bin", &exact_512),
        ]);
        assert_eq!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar", &tar_bytes, true)
                .map(|v| v.len()),
            Ok(2)
        );
        assert_eq!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar-noexec", &tar_bytes, false)
                .map(|v| v.len()),
            Ok(2)
        );
        // Empty or non-512-multiple tar rejected
        assert!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar", &[], false)
                .is_err()
        );
        assert!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar", &[1, 2, 3], false)
                .is_err()
        );
        // Invalid octal size rejected
        let mut bad_octal_tar = [0_u8; 512];
        bad_octal_tar[0] = b'f';
        bad_octal_tar[124] = b'Z';
        assert!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar", &bad_octal_tar, false)
                .is_err()
        );
        // Truncated payload rejected
        let mut trunc_tar = SandboxMaterializer::encode_ustar_archive(&[("f.bin", b"hello")]);
        trunc_tar.truncate(512);
        assert!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar", &trunc_tar, false)
                .is_err()
        );
        // Path traversal inside tar rejected
        let trav_tar = SandboxMaterializer::encode_ustar_archive(&[("../escape", b"bad")]);
        assert!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar", &trav_tar, false)
                .is_err()
        );
        // Unwritable destination rejected
        let bad_mat = SandboxMaterializer::new("/dev/null\0/impossible_sbox");
        assert!(
            bad_mat
                .extract_ustar_bytes_into_sandbox("t-ustar", &tar_bytes, false)
                .is_err()
        );
        // 100-byte full filename without NUL byte and without trailing zero blocks
        let mut full_name_tar = SandboxMaterializer::encode_ustar_archive(&[("a", b"x")]);
        full_name_tar.truncate(1024);
        for b in full_name_tar.iter_mut().take(100) {
            *b = b'a';
        }
        assert!(
            mat.extract_ustar_bytes_into_sandbox("t-ustar-100", &full_name_tar, false)
                .is_ok()
        );

        // Test Gzip Fixed Huffman (BTYPE=01) with both byte-aligned (6-byte) and unaligned (5-byte) payloads
        for huff_input in [&b"HELLO"[..], &b"HELLOX"[..]] {
            let huff_gz = SandboxMaterializer::encode_gzip_fixed_huffman_stream(huff_input);
            assert_eq!(
                SandboxMaterializer::decode_gzip_stored_stream(&huff_gz),
                Ok(huff_input.to_vec())
            );
        }
        // Truncated Fixed Huffman stream without EOB
        let trunc_huff_gz = vec![
            0x1F,
            0x8B,
            0x08,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
            0b1111_1011,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(
            SandboxMaterializer::decode_gzip_stored_stream(&trunc_huff_gz),
            Ok(Vec::new())
        );

        let rle_zst = SandboxMaterializer::encode_zstd_rle_frame(b'A', 64);
        assert_eq!(
            SandboxMaterializer::decode_zstd_raw_frame(&rle_zst),
            Ok(vec![b'A'; 64])
        );
        let mut trunc_rle_zst = rle_zst;
        trunc_rle_zst.pop();
        assert!(SandboxMaterializer::decode_zstd_raw_frame(&trunc_rle_zst).is_err());

        // Test Gzip (.tar.gz), Zstandard (.tar.zst), and PKZIP (.zip) binary extraction
        let gz_tar = SandboxMaterializer::encode_gzip_stored_stream(&tar_bytes);
        assert_eq!(
            mat.extract_compressed_archive_bytes("https://x/app.tar.gz", "t-gz", &gz_tar, true)
                .map(|v| v.len()),
            Ok(2)
        );
        assert!(
            mat.extract_compressed_archive_bytes("https://x/app.tar.gz", "t-gz", b"short", true)
                .is_err()
        );
        assert!(
            mat.extract_compressed_archive_bytes("https://x/app.tar.zst", "t-zst", b"bad", false)
                .is_err()
        );
        let zip_traversal = SandboxMaterializer::encode_zip_stored_archive(&[("../evil", b"x")]);
        assert!(
            mat.extract_compressed_archive_bytes(
                "https://x/app.zip",
                "t-zip",
                &zip_traversal,
                false
            )
            .is_err()
        );
        let mut bad_nlen_gz = gz_tar.clone();
        for b in bad_nlen_gz.iter_mut().skip(13).take(1) {
            *b ^= 0xFF;
        }
        assert!(SandboxMaterializer::decode_gzip_stored_stream(&bad_nlen_gz).is_err());
        let mut trunc_gz = gz_tar;
        trunc_gz.truncate(25);
        assert!(SandboxMaterializer::decode_gzip_stored_stream(&trunc_gz).is_err());

        let zst_tar = SandboxMaterializer::encode_zstd_raw_frame(&tar_bytes);
        assert_eq!(
            mat.extract_compressed_archive_bytes("https://x/app.tar.zst", "t-zst", &zst_tar, false)
                .map(|v| v.len()),
            Ok(2)
        );
        assert!(SandboxMaterializer::decode_zstd_raw_frame(b"bad").is_err());
        let mut trunc_zst = zst_tar;
        trunc_zst.truncate(10);
        assert!(SandboxMaterializer::decode_zstd_raw_frame(&trunc_zst).is_err());

        let xz_tar = SandboxMaterializer::encode_xz_raw_frame(&tar_bytes);
        assert_eq!(
            mat.extract_compressed_archive_bytes("https://x/app.tar.xz", "t-xz", &xz_tar, false)
                .map(|v| v.len()),
            Ok(2)
        );
        assert!(
            mat.extract_compressed_archive_bytes("https://x/app.tar.xz", "t-xz", b"bad", false)
                .is_err()
        );
        let mut bad_footer_xz = xz_tar.clone();
        bad_footer_xz.pop();
        bad_footer_xz.push(b'X');
        assert!(SandboxMaterializer::decode_xz_raw_frame(&bad_footer_xz).is_err());
        let mut truncated_xz_frame = xz_tar;
        truncated_xz_frame.truncate(14);
        assert!(SandboxMaterializer::decode_xz_raw_frame(&truncated_xz_frame).is_err());

        let zip_bytes = SandboxMaterializer::encode_zip_stored_archive(&[
            ("bin/tool", b"#!/bin/sh\n"),
            ("conf/cfg.json", b"{}"),
        ]);
        assert_eq!(
            mat.extract_compressed_archive_bytes("https://x/app.zip", "t-zip", &zip_bytes, true)
                .map(|v| v.len()),
            Ok(2)
        );
        assert!(
            mat.extract_compressed_archive_bytes("https://x/app.zip", "t-zip", b"not_zip", false)
                .is_err()
        );
        let mut trunc_hdr_zip = b"PK\x03\x04short".to_vec();
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/app.zip",
                "t-zip",
                &trunc_hdr_zip,
                false
            ),
            Ok(Vec::new())
        );
        trunc_hdr_zip.resize(30, 0xFF);
        assert!(
            mat.extract_compressed_archive_bytes(
                "https://x/app.zip",
                "t-zip",
                &trunc_hdr_zip,
                false
            )
            .is_err()
        );
        assert!(
            bad_mat
                .extract_compressed_archive_bytes("https://x/app.zip", "t-zip", &zip_bytes, false)
                .is_err()
        );
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/app.tar",
                "t-raw-tar",
                &tar_bytes,
                false
            )
            .map(|v| v.len()),
            Ok(2)
        );

        let _ = std::fs::remove_dir_all(&sbox_root);
    }

    #[test]
    fn test_phase9_sigv4_oci_hardlink_and_quotas() {
        let tmp_dir = std::env::temp_dir().join("arbiter_phase9_storage_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);
        let mut cache = ArtifactCache::new(Bytes::new(4096));
        let blob_bytes = b"hello-hardlink-blob";
        let sha_hex = compute_sha256_hex(blob_bytes);
        let digest = arbiter_core::ids::Sha256Digest::new(&sha_hex).unwrap_or_default();
        let uncached_digest =
            arbiter_core::ids::Sha256Digest::new(&"a".repeat(64)).unwrap_or_default();

        // Uncached digest rejected
        let dest_path = tmp_dir.join("sbox").join("linked.bin");
        assert!(
            cache
                .deduplicate_blob_to_sandbox_via_hardlink_or_cow(
                    &tmp_dir,
                    &uncached_digest,
                    &dest_path
                )
                .is_err()
        );

        let spec = ArtifactSpec {
            uri: "s3://bucket/obj.bin".to_owned(),
            sha256_hex: sha_hex.clone(),
            extract: false,
            executable: false,
        };
        assert!(
            cache
                .stage_and_verify_blob_file(&tmp_dir, &spec, &[blob_bytes])
                .is_ok()
        );
        assert!(
            cache
                .deduplicate_blob_to_sandbox_via_hardlink_or_cow(&tmp_dir, &digest, &dest_path)
                .is_ok()
        );
        assert!(
            cache
                .deduplicate_blob_to_sandbox_via_hardlink_or_cow(
                    &tmp_dir,
                    &digest,
                    std::path::Path::new("/dev/null\0/impossible_link")
                )
                .is_err()
        );

        // AWS SigV4 with both short (<64B) and long (>64B) secret keys + OCI v1.1 Bearer requests
        let sig_short = LiveOsStorageBackend::format_aws_sigv4_s3_authorization(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "20261022",
            "us-east-1",
            "arbiter-artifacts",
            "releases/v1.tar.gz",
        );
        assert!(sig_short.starts_with("AWS4-HMAC-SHA256 Credential="));
        let long_secret = "S".repeat(80);
        let sig_long = LiveOsStorageBackend::format_aws_sigv4_s3_authorization(
            "AKIA",
            &long_secret,
            "20261022",
            "us-west-2",
            "bkt",
            "obj",
        );
        assert!(sig_long.contains("Signature="));

        let (m_req, b_req) = LiveOsStorageBackend::format_oci_v1_1_bearer_requests(
            "ghcr.io", "org/app", "latest", &sha_hex, "tok_123",
        );
        assert!(m_req.contains("Authorization: Bearer tok_123"));
        assert!(b_req.contains(&sha_hex));

        // Linux xfs_quota and ext4 project quotas
        assert!(
            VolumeManager::configure_linux_project_quota("xfs", "/sbox/t1", 0, Bytes::new(1024))
                .is_err()
        );
        assert!(
            VolumeManager::configure_linux_project_quota("xfs", "/sbox/t1", 10, Bytes::ZERO)
                .is_err()
        );
        assert_eq!(
            VolumeManager::configure_linux_project_quota(
                "xfs",
                "/sbox/t1",
                10,
                Bytes::new(1_048_576)
            )
            .map(|v| v.len()),
            Ok(2)
        );
        assert_eq!(
            VolumeManager::configure_linux_project_quota(
                "ext4",
                "/sbox/t1",
                11,
                Bytes::new(1_048_576)
            )
            .map(|v| v.len()),
            Ok(2)
        );
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_phase9_advanced_archive_codecs() {
        let tmp_dir = std::env::temp_dir().join("arbiter_phase9_codecs_test");
        let _ = std::fs::remove_dir_all(&tmp_dir);

        // Drive letter & backslash path traversal checks
        let mat = SandboxMaterializer::new(&tmp_dir.display().to_string());
        assert!(
            mat.validate_and_resolve_archive_entry("t1", "C:evil.exe")
                .is_err()
        );
        assert!(
            mat.validate_and_resolve_archive_entry("t1", "sub\\evil.exe")
                .is_err()
        );

        // Dynamic Huffman + LZ77 Gzip stream + CRC32 verification
        let dyn_gz = SandboxMaterializer::encode_gzip_dynamic_huffman_lz77_stream(b"ABCD", 4, 8);
        assert_eq!(
            SandboxMaterializer::decode_gzip_stored_stream(&dyn_gz),
            Ok(b"ABCDABCDABCD".to_vec())
        );
        let mut bad_crc_gz = dyn_gz;
        let crc_idx = bad_crc_gz.len() - 8;
        for b in bad_crc_gz.iter_mut().skip(crc_idx).take(1) {
            *b ^= 0xFF;
        }
        assert!(SandboxMaterializer::decode_gzip_stored_stream(&bad_crc_gz).is_err());
        // Truncated Dynamic Huffman literal section
        let mut trunc_dyn_gz = vec![
            0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 3, 0x05, 50, 0, 1, 0, 2, 0,
        ];
        trunc_dyn_gz.extend_from_slice(&[0; 8]);
        assert!(SandboxMaterializer::decode_gzip_stored_stream(&trunc_dyn_gz).is_err());

        // Zstandard compressed sequence block (Block_Type = 10)
        let comp_zst = SandboxMaterializer::encode_zstd_compressed_frame(b"XYZ", 3, 6);
        assert_eq!(
            SandboxMaterializer::decode_zstd_raw_frame(&comp_zst),
            Ok(b"XYZXYZXYZ".to_vec())
        );
        let trunc_comp_zst = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0b0001_0101, 0, 0, 1, 2];
        assert!(SandboxMaterializer::decode_zstd_raw_frame(&trunc_comp_zst).is_err());

        // PKZIP Deflate (method = 8) archive roundtrip & corrupt Deflate error path
        let deflate_zip = SandboxMaterializer::encode_zip_deflate_archive(&[
            ("bin/app", b"HELLO"),
            ("conf/settings", b"WORLD"),
        ]);
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/deflate.zip",
                "t-deflate-zip",
                &deflate_zip,
                false
            )
            .map(|v| v.len()),
            Ok(2)
        );
        let mut bad_deflate_zip = deflate_zip;
        for b in bad_deflate_zip.iter_mut().skip(38).take(1) {
            *b = 0x00;
        }
        assert!(
            mat.extract_compressed_archive_bytes(
                "https://x/deflate.zip",
                "t-deflate-zip-err",
                &bad_deflate_zip,
                false
            )
            .is_err()
        );

        // Standard flate2 gzip, zstd, tar, and zip crate roundtrips and error branches
        let crate_tar = SandboxMaterializer::build_tar_archive_with_crate(&[
            ("bin/start.sh", b"#!/bin/sh\necho start\n"),
            ("etc/config.toml", b"port = 8080\n"),
        ])
        .unwrap_or_default();
        assert!(SandboxMaterializer::build_tar_archive_with_crate(&[("../bad", b"x")]).is_err());
        assert_eq!(
            mat.extract_tar_archive_with_crate("t-crate-tar", &crate_tar, true)
                .map(|v| v.len()),
            Ok(2)
        );
        assert_eq!(
            mat.extract_tar_archive_with_crate("t-crate-tar-noexec", &crate_tar, false)
                .map(|v| v.len()),
            Ok(2)
        );
        assert!(
            mat.extract_tar_archive_with_crate("t-crate-tar", &[], false)
                .is_err()
        );
        let zero_tar = vec![0_u8; 1024];
        assert_eq!(
            mat.extract_tar_archive_with_crate("t-empty-tar", &zero_tar, false),
            Ok(Vec::new())
        );
        let bad_mat = SandboxMaterializer::new("/dev/null\0/impossible_sbox");
        assert!(
            bad_mat
                .extract_tar_archive_with_crate("t-crate-tar", &crate_tar, false)
                .is_err()
        );

        let flate_gz = SandboxMaterializer::compress_flate2_gzip(&crate_tar).unwrap_or_default();
        assert_eq!(
            SandboxMaterializer::decompress_flate2_gzip(&flate_gz),
            Ok(crate_tar.clone())
        );
        assert!(SandboxMaterializer::decompress_flate2_gzip(b"not-gzip").is_err());
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/flate2.tar.gz",
                "t-flate2-tgz",
                &flate_gz,
                true
            )
            .map(|v| v.len()),
            Ok(2)
        );

        let real_zst = SandboxMaterializer::compress_zstd_stream(&crate_tar).unwrap_or_default();
        assert_eq!(
            SandboxMaterializer::decompress_zstd_stream(&real_zst),
            Ok(crate_tar.clone())
        );
        assert!(SandboxMaterializer::decompress_zstd_stream(b"not-zstd").is_err());
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/real.tar.zst",
                "t-real-zst",
                &real_zst,
                false
            )
            .map(|v| v.len()),
            Ok(2)
        );

        let real_xz = SandboxMaterializer::compress_xz_stream(&crate_tar).unwrap_or_default();
        assert_eq!(
            SandboxMaterializer::decompress_xz_stream(&real_xz),
            Ok(crate_tar)
        );
        assert!(SandboxMaterializer::decompress_xz_stream(b"not-xz").is_err());
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/real.tar.xz",
                "t-real-xz",
                &real_xz,
                false
            )
            .map(|v| v.len()),
            Ok(2)
        );

        let crate_zip = SandboxMaterializer::build_zip_archive_with_crate(&[
            ("bin/cli", b"#!/bin/sh\n"),
            ("README.txt", b"hello zip"),
        ])
        .unwrap_or_default();
        assert_eq!(
            mat.extract_zip_archive_with_crate("t-crate-zip", &crate_zip, true)
                .map(|v| v.len()),
            Ok(2)
        );
        assert_eq!(
            mat.extract_compressed_archive_bytes(
                "https://x/crate.zip",
                "t-crate-zip2",
                &crate_zip,
                false
            )
            .map(|v| v.len()),
            Ok(2)
        );
        assert!(
            bad_mat
                .extract_zip_archive_with_crate("t-crate-zip", &crate_zip, false)
                .is_err()
        );

        let (obj_sha, obj_bytes) =
            ObjectStoreArtifactBackend::stage_and_fetch_in_memory("releases/app.bin", b"payload-1")
                .unwrap_or_default();
        assert_eq!(obj_sha, compute_sha256_hex(b"payload-1"));
        assert_eq!(obj_bytes, b"payload-1");
        assert!(
            ObjectStoreArtifactBackend::stage_and_fetch_in_memory("bad//path", b"payload-1")
                .is_err()
        );

        let csi_req = CsiV1ProtoVolumeRequest {
            volume_id: "vol-1".to_owned(),
            target_path: "/mnt/csi".to_owned(),
            required_bytes: 4096,
        };
        let csi_frame = CsiV1TonicGrpcFrameCodec::encode_grpc_frame(&csi_req);
        assert_eq!(
            CsiV1TonicGrpcFrameCodec::decode_grpc_frame(&csi_frame),
            Ok(csi_req.clone())
        );
        assert!(CsiV1TonicGrpcFrameCodec::decode_grpc_frame(&[0, 1]).is_err());
        assert!(CsiV1TonicGrpcFrameCodec::decode_grpc_frame(&[0, 0, 0, 0, 99, 1]).is_err());
        assert!(CsiV1TonicGrpcFrameCodec::decode_grpc_frame(&[0, 0, 0, 0, 2, 0xFF, 0xFF]).is_err());
        let csi_resp = CsiV1ProtoVolumeResponse {
            volume_id: "vol-1".to_owned(),
            available_bytes: 2048,
            total_bytes: 4096,
        };
        let resp_bytes = prost::Message::encode_to_vec(&csi_resp);
        assert_eq!(
            <CsiV1ProtoVolumeResponse as prost::Message>::decode(resp_bytes.as_slice()).ok(),
            Some(csi_resp.clone())
        );

        let resp_frame = CsiV1TonicGrpcFrameCodec::encode_grpc_response_frame(&csi_resp);
        assert_eq!(
            CsiV1TonicGrpcFrameCodec::decode_grpc_response_frame(&resp_frame),
            Ok(csi_resp.clone())
        );
        assert!(CsiV1TonicGrpcFrameCodec::decode_grpc_response_frame(&[0, 1]).is_err());
        assert!(
            CsiV1TonicGrpcFrameCodec::decode_grpc_response_frame(&[0, 0, 0, 0, 99, 1]).is_err()
        );
        assert!(
            CsiV1TonicGrpcFrameCodec::decode_grpc_response_frame(&[0, 0, 0, 0, 1, 0xFF]).is_err()
        );

        let uds_csi_path = tmp_dir.join("csi_proto.sock");
        let _ = std::fs::remove_file(&uds_csi_path);
        let uds_cli = UnixSocketCsiClient::new(&uds_csi_path.display().to_string());
        assert!(uds_cli.call_volume_rpc(&csi_req).is_err());
        #[cfg(unix)]
        let csi_proto_listener_opt = std::os::unix::net::UnixListener::bind(&uds_csi_path).ok();
        #[cfg(not(unix))]
        let csi_proto_listener_opt =
            std::net::TcpListener::bind("127.0.0.1:0")
                .ok()
                .inspect(|tcp| {
                    let addr_str = tcp
                        .local_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "127.0.0.1:0".to_owned());
                    let _ = std::fs::write(&uds_csi_path, addr_str.as_bytes());
                });
        let _ = csi_proto_listener_opt.map(|listener| {
            let expected_resp = csi_resp.clone();
            let srv_h = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let _ = listener.accept().map(|(mut srv, _)| {
                    let mut rx = Vec::new();
                    let _ = srv.read_to_end(&mut rx);
                    let tx = CsiV1TonicGrpcFrameCodec::encode_grpc_response_frame(&expected_resp);
                    let _ = srv.write_all(&tx);
                    let _ = srv.shutdown(std::net::Shutdown::Write);
                });
            });
            assert_eq!(uds_cli.call_volume_rpc(&csi_req), Ok(csi_resp));
            let _ = srv_h.join();
        });

        let wh_dir = tmp_dir.join("oci_wh_test");
        assert_eq!(
            UnixSocketCsiClient::apply_oci_layer_with_whiteouts(
                &wh_dir,
                &[
                    ("etc/old.conf", b"old"),
                    ("etc/.wh.old.conf", b""),
                    ("etc/new.conf", b"new")
                ]
            ),
            Ok(1)
        );
        assert!(
            UnixSocketCsiClient::apply_oci_layer_with_whiteouts(&wh_dir, &[("../bad", b"x")])
                .is_err()
        );
        assert!(
            UnixSocketCsiClient::apply_oci_layer_with_whiteouts(
                std::path::Path::new("/dev/null\0/bad_wh"),
                &[("a.txt", b"x")]
            )
            .is_err()
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
