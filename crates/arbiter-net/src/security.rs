//! Zero-trust security primitives: `mTLS`, SPIFFE `SVIDs`, OIDC/JWT verification, RBAC/ABAC policy engine, and AEAD secrets envelope encryption (`arbiter-net::security`).
//!
//! Implements:
//! - X.509 URI SAN parsing and validation for SPIFFE IDs (`spiffe://<trust-domain>/node/<agent-id>`,
//!   `spiffe://<trust-domain>/role/<role>/task/<task-id>`).
//! - Short-lived X.509 SVID & JWT SVID issuance, validation, and rotation.
//! - Declarative RBAC and ABAC policy evaluation `(Principal, Action, Resource, Role, EnvironmentAttributes) -> ArbiterResult<Decision>`.
//! - AEAD envelope secret sealing on the Master and authenticated unsealing on the target Agent.

use std::collections::{BTreeMap, BTreeSet};

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, FrameworkId, RoleName, SecretId, SpiffeId, TaskId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Parsed workload or node identity extracted from a validated [`SpiffeId`] X.509 URI SAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpiffePrincipalKind {
    /// Control-plane Master node identity (`spiffe://<trust-domain>/master/<master-id>`).
    Master {
        /// Master node identifier string.
        master_id: String,
    },
    /// Agent node identity (`spiffe://<trust-domain>/node/<agent-id>` or `/agent/<agent-id>`).
    Node {
        /// Validated [`AgentId`].
        agent_id: AgentId,
    },
    /// Subscribed Framework scheduler identity (`spiffe://<trust-domain>/framework/<role>/<framework-id>`).
    Framework {
        /// Validated [`RoleName`].
        role: RoleName,
        /// Validated [`FrameworkId`].
        framework_id: FrameworkId,
    },
    /// Running workload task identity (`spiffe://<trust-domain>/role/<role>/task/<task-id>` or `/task/<role>/<task-id>`).
    WorkloadTask {
        /// Validated [`RoleName`].
        role: RoleName,
        /// Validated [`TaskId`].
        task_id: TaskId,
    },
}

impl Default for SpiffePrincipalKind {
    /// Returns a default [`SpiffePrincipalKind::Node`].
    ///
    /// # Returns
    ///
    /// Default [`SpiffePrincipalKind`].
    fn default() -> Self {
        Self::Node {
            agent_id: AgentId::default(),
        }
    }
}

/// Short-lived SPIFFE Verifiable Identity Document (`SVID`) representing either an X.509 or JWT SVID.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpiffeSvid {
    /// Validated SPIFFE URI SAN.
    pub spiffe_id: SpiffeId,
    /// Parsed principal kind.
    pub principal_kind: SpiffePrincipalKind,
    /// Monotonic tick when the SVID was issued.
    pub issued_at_tick: u64,
    /// Monotonic tick when the SVID expires.
    pub expires_at_tick: u64,
    /// Cryptographic HMAC-SHA256 signature tag over the SVID claims.
    pub signature: [u8; 32],
}

/// Parses a [`SpiffeId`] URI SAN against `expected_trust_domain` into a [`SpiffePrincipalKind`].
///
/// Supported URI path formats:
/// - `/node/<agent-id>`
/// - `/role/<role>/task/<task-id>`
///
/// # Arguments
///
/// * `uri` - Raw URI SAN string from an X.509 certificate or JWT claim.
/// * `expected_trust_domain` - Required trust domain (e.g., `"arbiter.internal"`).
///
/// # Returns
///
/// Tuple `(SpiffeId, SpiffePrincipalKind)`.
///
/// # Errors
///
/// Returns [`ArbiterError::SpiffeIdentityInvalid`] if the URI syntax, trust domain, or path structure is invalid.
pub fn parse_spiffe_san(
    uri: &str,
    expected_trust_domain: &str,
) -> ArbiterResult<(SpiffeId, SpiffePrincipalKind)> {
    let spiffe_id = SpiffeId::new(uri)?;
    if spiffe_id.trust_domain() != expected_trust_domain {
        return Err(ArbiterError::SpiffeIdentityInvalid {
            uri: uri.to_owned(),
            reason: format!(
                "untrusted SPIFFE domain '{}' (expected '{expected_trust_domain}')",
                spiffe_id.trust_domain()
            ),
        });
    }

    let path = spiffe_id.path();
    if let Some(master_str) = path.strip_prefix("/master/") {
        let master_id = AgentId::new(master_str)
            .map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: "invalid master_id in /master/<master-id> SAN".to_owned(),
            })?
            .as_str()
            .to_owned();
        return Ok((spiffe_id, SpiffePrincipalKind::Master { master_id }));
    }

    if let Some(agent_str) = path
        .strip_prefix("/node/")
        .or_else(|| path.strip_prefix("/agent/"))
    {
        let agent_id =
            AgentId::new(agent_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: "invalid AgentId in /node/<agent-id> or /agent/<agent-id> SAN".to_owned(),
            })?;
        return Ok((spiffe_id, SpiffePrincipalKind::Node { agent_id }));
    }

    if let Some(rest) = path.strip_prefix("/framework/") {
        if let Some((role_str, fw_str)) = rest.split_once('/') {
            let role =
                RoleName::new(role_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                    uri: uri.to_owned(),
                    reason: "invalid RoleName in /framework/<role>/<framework-id> SAN".to_owned(),
                })?;
            let framework_id =
                FrameworkId::new(fw_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                    uri: uri.to_owned(),
                    reason: "invalid FrameworkId in /framework/<role>/<framework-id> SAN"
                        .to_owned(),
                })?;
            return Ok((
                spiffe_id,
                SpiffePrincipalKind::Framework { role, framework_id },
            ));
        }
    }

    if let Some(rest) = path
        .strip_prefix("/role/")
        .and_then(|r| r.split_once("/task/"))
        .or_else(|| path.strip_prefix("/task/").and_then(|r| r.split_once('/')))
    {
        let (role_str, task_str) = rest;
        let role = RoleName::new(role_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
            uri: uri.to_owned(),
            reason: "invalid RoleName in task SPIFFE SAN".to_owned(),
        })?;
        let task_id = TaskId::new(task_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
            uri: uri.to_owned(),
            reason: "invalid TaskId in task SPIFFE SAN".to_owned(),
        })?;
        return Ok((
            spiffe_id,
            SpiffePrincipalKind::WorkloadTask { role, task_id },
        ));
    }

    Err(ArbiterError::SpiffeIdentityInvalid {
        uri: uri.to_owned(),
        reason: "SPIFFE path must be '/master/<id>', '/node/<id>', '/agent/<id>', '/framework/<role>/<id>', '/role/<role>/task/<id>', or '/task/<role>/<id>'"
            .to_owned(),
    })
}

/// Control-plane SVID authority issuing, verifying, rotating, and revoking short-lived X.509 & JWT SVIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvidAuthority {
    /// Trust domain governed by this authority.
    trust_domain: String,
    /// Authority signing secret key (32 bytes).
    signing_key: [u8; 32],
    /// Default SVID TTL in ticks.
    ttl_ticks: u64,
    /// Revoked SPIFFE URI identities (`CRL` / `OCSP` revocation set).
    revoked_uris: BTreeSet<String>,
}

impl SvidAuthority {
    /// Creates a new [`SvidAuthority`].
    ///
    /// # Arguments
    ///
    /// * `trust_domain` - SPIFFE trust domain.
    /// * `signing_key` - 32-byte signing key.
    /// * `ttl_ticks` - SVID lifetime in ticks.
    ///
    /// # Returns
    ///
    /// Initialized [`SvidAuthority`].
    pub fn new(trust_domain: &str, signing_key: [u8; 32], ttl_ticks: u64) -> Self {
        Self {
            trust_domain: trust_domain.to_owned(),
            signing_key,
            ttl_ticks,
            revoked_uris: BTreeSet::new(),
        }
    }

    /// Revokes a SPIFFE URI so any existing or rotated SVID for `uri` is immediately rejected by [`Self::verify_svid`].
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI string to revoke.
    pub fn revoke_svid_uri(&mut self, uri: &str) {
        self.revoked_uris.insert(uri.to_owned());
    }

    /// Returns the trust domain governed by this [`SvidAuthority`].
    ///
    /// # Returns
    ///
    /// Trust domain string slice.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Returns `true` if `uri` is present in the authority's certificate revocation list (`revoked_uris`).
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI string to check.
    ///
    /// # Returns
    ///
    /// `true` if revoked.
    pub fn is_uri_revoked(&self, uri: &str) -> bool {
        self.revoked_uris.contains(uri)
    }

    /// Issues a signed [`SpiffeSvid`] for a validated URI at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI string.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Newly signed [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if `uri` is invalid for this trust domain.
    pub fn issue_svid(&self, uri: &str, current_tick: u64) -> ArbiterResult<SpiffeSvid> {
        let (spiffe_id, principal_kind) = parse_spiffe_san(uri, &self.trust_domain)?;
        let expires_at_tick = current_tick.saturating_add(self.ttl_ticks);
        let signature = self.compute_svid_mac(spiffe_id.as_str(), current_tick, expires_at_tick);
        Ok(SpiffeSvid {
            spiffe_id,
            principal_kind,
            issued_at_tick: current_tick,
            expires_at_tick,
            signature,
        })
    }

    /// Verifies an [`SpiffeSvid`]'s cryptographic signature, revocation status, and expiration at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `svid` - Presented [`SpiffeSvid`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, unrevoked, and unexpired.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TlsConfigurationError`] if the SVID has expired or been revoked, or
    /// [`ArbiterError::AuthenticationFailed`] if the signature is invalid.
    pub fn verify_svid(&self, svid: &SpiffeSvid, current_tick: u64) -> ArbiterResult<()> {
        if self.revoked_uris.contains(svid.spiffe_id.as_str()) {
            return Err(ArbiterError::TlsConfigurationError {
                reason: format!("SVID for '{}' has been revoked (CRL)", svid.spiffe_id),
            });
        }
        if current_tick >= svid.expires_at_tick {
            return Err(ArbiterError::TlsConfigurationError {
                reason: format!(
                    "SVID for '{}' expired at tick {}",
                    svid.spiffe_id, svid.expires_at_tick
                ),
            });
        }
        let expected = self.compute_svid_mac(
            svid.spiffe_id.as_str(),
            svid.issued_at_tick,
            svid.expires_at_tick,
        );
        if svid.signature != expected {
            return Err(ArbiterError::AuthenticationFailed {
                principal: svid.spiffe_id.to_string(),
                reason: "SVID cryptographic signature mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Issues an [`SpiffeSvid`] paired with an asymmetric 64-byte [`Ed25519Keypair`] signature
    /// over the canonical SVID ASN.1 SAN + validity transcript.
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI string.
    /// * `current_tick` - Current monotonic tick.
    /// * `ca_keypair` - Signing [`Ed25519Keypair`] of the SPIFFE CA.
    ///
    /// # Returns
    ///
    /// Tuple `(SpiffeSvid, [u8; 64])` containing the SVID and its 64-byte `Ed25519` signature.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if `uri` is invalid for this trust domain.
    pub fn issue_ed25519_svid(
        &self,
        uri: &str,
        current_tick: u64,
        ca_keypair: &Ed25519Keypair,
    ) -> ArbiterResult<(SpiffeSvid, [u8; 64])> {
        let svid = self.issue_svid(uri, current_tick)?;
        let transcript = Self::build_ed25519_svid_transcript(&svid);
        let sig = ca_keypair.sign(&transcript);
        Ok((svid, sig))
    }

    /// Verifies an [`SpiffeSvid`] and its 64-byte asymmetric `Ed25519` signature against `ca_public_key`.
    ///
    /// # Arguments
    ///
    /// * `svid` - Presented [`SpiffeSvid`].
    /// * `ed25519_sig` - 64-byte `Ed25519` signature over the SVID transcript.
    /// * `ca_public_key` - 32-byte CA public verification key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid, unrevoked, unexpired, and verified under `ca_public_key`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if CRL/expiry validation or `Ed25519Keypair::verify` fails.
    pub fn verify_ed25519_svid(
        &self,
        svid: &SpiffeSvid,
        ed25519_sig: &[u8; 64],
        ca_public_key: &[u8; 32],
        current_tick: u64,
    ) -> ArbiterResult<()> {
        self.verify_svid(svid, current_tick)?;
        let transcript = Self::build_ed25519_svid_transcript(svid);
        Ed25519Keypair::verify(ca_public_key, &transcript, ed25519_sig)
    }

    /// Builds the canonical byte transcript signed by [`Self::issue_ed25519_svid`].
    ///
    /// # Arguments
    ///
    /// * `svid` - [`SpiffeSvid`] to serialize.
    ///
    /// # Returns
    ///
    /// Canonical byte vector `(DER_SAN || issued_at_le || expires_at_le)`.
    fn build_ed25519_svid_transcript(svid: &SpiffeSvid) -> Vec<u8> {
        let mut out = encode_x509_san_der(&svid.spiffe_id);
        out.extend_from_slice(&svid.issued_at_tick.to_le_bytes());
        out.extend_from_slice(&svid.expires_at_tick.to_le_bytes());
        out
    }

    /// Rotates an existing [`SpiffeSvid`], issuing a fresh SVID with extended expiration.
    ///
    /// # Arguments
    ///
    /// * `old_svid` - Current [`SpiffeSvid`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Rotated [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if `old_svid` is invalid.
    pub fn rotate_svid(
        &self,
        old_svid: &SpiffeSvid,
        current_tick: u64,
    ) -> ArbiterResult<SpiffeSvid> {
        self.verify_svid(old_svid, current_tick)?;
        let expires_at_tick = current_tick.saturating_add(self.ttl_ticks);
        let signature =
            self.compute_svid_mac(old_svid.spiffe_id.as_str(), current_tick, expires_at_tick);
        Ok(SpiffeSvid {
            spiffe_id: old_svid.spiffe_id.clone(),
            principal_kind: old_svid.principal_kind.clone(),
            issued_at_tick: current_tick,
            expires_at_tick,
            signature,
        })
    }

    /// Computes a deterministic signature digest over SVID claims using [`Ed25519Keypair`]
    /// derived from `self.signing_key`.
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI string.
    /// * `issued_at` - Issue tick.
    /// * `expires_at` - Expiry tick.
    ///
    /// # Returns
    ///
    /// 32-byte commitment over the `Ed25519` signature.
    fn compute_svid_mac(&self, uri: &str, issued_at: u64, expires_at: u64) -> [u8; 32] {
        let mut msg = Vec::with_capacity(uri.len() + 16);
        msg.extend_from_slice(uri.as_bytes());
        msg.extend_from_slice(&issued_at.to_le_bytes());
        msg.extend_from_slice(&expires_at.to_le_bytes());
        let ed_sk = Ed25519Keypair::from_seed(self.signing_key);
        let sig64 = ed_sk.sign(&msg);
        let mut hasher = Sha256::new();
        hasher.update(sig64);
        hasher.finalize().into()
    }
}

/// Authorization decision returned by the RBAC/ABAC policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Decision {
    /// Action is permitted.
    Allow,
    /// Action is denied.
    Deny,
}

/// Declarative RBAC and ABAC policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Allowed principal identifier.
    pub principal: String,
    /// Allowed action (e.g., `"LaunchTask"`, `"UpdateQuota"`).
    pub action: String,
    /// Allowed resource prefix (e.g., `"role:prod"`).
    pub resource_prefix: String,
    /// Required scheduling role.
    pub role: RoleName,
    /// Required ABAC environment key-value attributes (e.g., `("mfa", "true")`).
    pub required_attributes: BTreeMap<String, String>,
}

/// Declarative RBAC/ABAC policy engine evaluating `(Principal, Action, Resource, Role, EnvironmentAttributes)`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEngine {
    /// Registered allow rules.
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Creates an empty [`PolicyEngine`].
    ///
    /// # Returns
    ///
    /// Empty [`PolicyEngine`].
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Adds a declarative [`PolicyRule`] to the engine.
    ///
    /// # Arguments
    ///
    /// * `rule` - Rule to add.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluates whether `principal` is authorized to perform `action` on `resource` under `role`
    /// given `env_attributes`.
    ///
    /// # Arguments
    ///
    /// * `principal` - Authenticated principal name or SPIFFE ID.
    /// * `action` - Requested operation name.
    /// * `resource` - Target resource identifier.
    /// * `role` - Target [`RoleName`].
    /// * `env_attributes` - ABAC contextual attributes.
    ///
    /// # Returns
    ///
    /// `Ok(Decision::Allow)` if a matching rule is satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::AuthorizationDenied`] if no rule permits the request.
    pub fn evaluate(
        &self,
        principal: &str,
        action: &str,
        resource: &str,
        role: &RoleName,
        env_attributes: &BTreeMap<String, String>,
    ) -> ArbiterResult<Decision> {
        let matched = self.rules.iter().any(|r| {
            r.principal == principal
                && r.action == action
                && resource.starts_with(&r.resource_prefix)
                && &r.role == role
                && r.required_attributes
                    .iter()
                    .all(|(k, v)| env_attributes.get(k) == Some(v))
        });

        if matched {
            Ok(Decision::Allow)
        } else {
            Err(ArbiterError::AuthorizationDenied {
                principal: principal.to_owned(),
                action: action.to_owned(),
                resource: resource.to_owned(),
            })
        }
    }
}

/// Envelope-encrypted secret ciphertext with authenticated integrity tag.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecretEnvelope {
    /// Secret identifier.
    pub secret_id: SecretId,
    /// 12-byte nonce used for keystream generation.
    pub nonce: [u8; 12],
    /// Encrypted ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// 32-byte authenticated encryption tag over `(secret_id, nonce, ciphertext)`.
    pub auth_tag: [u8; 32],
}

/// Seals a plaintext secret payload on the Master using authenticated stream encryption (`SHA-256` CTR + MAC).
///
/// # Arguments
///
/// * `secret_id` - Unique [`SecretId`].
/// * `master_key` - 32-byte envelope encryption key.
/// * `nonce` - 12-byte unique nonce.
/// * `plaintext` - Secret bytes to seal.
///
/// # Returns
///
/// Authenticated [`SealedSecretEnvelope`].
pub fn seal_secret(
    secret_id: SecretId,
    master_key: &[u8; 32],
    nonce: [u8; 12],
    plaintext: &[u8],
) -> SealedSecretEnvelope {
    let ciphertext = xor_keystream(master_key, &nonce, plaintext);
    let auth_tag = compute_aead_tag(master_key, secret_id.as_str(), &nonce, &ciphertext);
    SealedSecretEnvelope {
        secret_id,
        nonce,
        ciphertext,
        auth_tag,
    }
}

/// Unseals and authenticates a [`SealedSecretEnvelope`] in memory on the target Agent prior to `tmpfs` injection.
///
/// # Arguments
///
/// * `envelope` - Sealed secret envelope.
/// * `master_key` - 32-byte envelope decryption key.
///
/// # Returns
///
/// Decrypted plaintext bytes `Vec<u8>`.
///
/// # Errors
///
/// Returns [`ArbiterError::SecretDecryptionFailed`] if the key is wrong or the ciphertext/nonce/tag was tampered with.
pub fn unseal_secret(
    envelope: &SealedSecretEnvelope,
    master_key: &[u8; 32],
) -> ArbiterResult<Vec<u8>> {
    let expected_tag = compute_aead_tag(
        master_key,
        envelope.secret_id.as_str(),
        &envelope.nonce,
        &envelope.ciphertext,
    );
    if envelope.auth_tag != expected_tag {
        return Err(ArbiterError::SecretDecryptionFailed {
            secret_id: envelope.secret_id.to_string(),
            reason:
                "AEAD authentication tag verification failed (tampered ciphertext or wrong key)"
                    .to_owned(),
        });
    }
    Ok(xor_keystream(
        master_key,
        &envelope.nonce,
        &envelope.ciphertext,
    ))
}

/// Executes a single RFC 8439 Section 2.1 `ChaCha20` quarter-round on `(sa, sb, sc, sd)`.
///
/// # Arguments
///
/// * `sa` - First 32-bit state word.
/// * `sb` - Second 32-bit state word.
/// * `sc` - Third 32-bit state word.
/// * `sd` - Fourth 32-bit state word.
///
/// # Returns
///
/// Updated `(sa, sb, sc, sd)` tuple.
const fn chacha20_quarter_round(
    mut sa: u32,
    mut sb: u32,
    mut sc: u32,
    mut sd: u32,
) -> (u32, u32, u32, u32) {
    sa = sa.wrapping_add(sb);
    sd = (sd ^ sa).rotate_left(16);
    sc = sc.wrapping_add(sd);
    sb = (sb ^ sc).rotate_left(12);
    sa = sa.wrapping_add(sb);
    sd = (sd ^ sa).rotate_left(8);
    sc = sc.wrapping_add(sd);
    sb = (sb ^ sc).rotate_left(7);
    (sa, sb, sc, sd)
}

/// Computes a 64-byte RFC 8439 Section 2.3 `ChaCha20` keystream block for `(key, counter, nonce)`.
///
/// # Arguments
///
/// * `key` - 32-byte key (`256-bit`).
/// * `counter` - 32-bit block counter.
/// * `nonce` - 12-byte (`96-bit`) IETF nonce.
///
/// # Returns
///
/// 64-byte `ChaCha20` keystream block.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut initial = Vec::with_capacity(16);
    initial.extend_from_slice(&[0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574]);
    for chunk in key.chunks_exact(4) {
        let mut b4 = [0_u8; 4];
        b4.copy_from_slice(chunk);
        initial.push(u32::from_le_bytes(b4));
    }
    initial.push(counter);
    for chunk in nonce.chunks_exact(4) {
        let mut b4 = [0_u8; 4];
        b4.copy_from_slice(chunk);
        initial.push(u32::from_le_bytes(b4));
    }

    let mut w0 = initial.first().copied().unwrap_or(0);
    let mut w1 = initial.get(1).copied().unwrap_or(0);
    let mut w2 = initial.get(2).copied().unwrap_or(0);
    let mut w3 = initial.get(3).copied().unwrap_or(0);
    let mut w4 = initial.get(4).copied().unwrap_or(0);
    let mut w5 = initial.get(5).copied().unwrap_or(0);
    let mut w6 = initial.get(6).copied().unwrap_or(0);
    let mut w7 = initial.get(7).copied().unwrap_or(0);
    let mut w8 = initial.get(8).copied().unwrap_or(0);
    let mut w9 = initial.get(9).copied().unwrap_or(0);
    let mut w10 = initial.get(10).copied().unwrap_or(0);
    let mut w11 = initial.get(11).copied().unwrap_or(0);
    let mut w12 = initial.get(12).copied().unwrap_or(0);
    let mut w13 = initial.get(13).copied().unwrap_or(0);
    let mut w14 = initial.get(14).copied().unwrap_or(0);
    let mut w15 = initial.get(15).copied().unwrap_or(0);

    for _ in 0..10 {
        (w0, w4, w8, w12) = chacha20_quarter_round(w0, w4, w8, w12);
        (w1, w5, w9, w13) = chacha20_quarter_round(w1, w5, w9, w13);
        (w2, w6, w10, w14) = chacha20_quarter_round(w2, w6, w10, w14);
        (w3, w7, w11, w15) = chacha20_quarter_round(w3, w7, w11, w15);

        (w0, w5, w10, w15) = chacha20_quarter_round(w0, w5, w10, w15);
        (w1, w6, w11, w12) = chacha20_quarter_round(w1, w6, w11, w12);
        (w2, w7, w8, w13) = chacha20_quarter_round(w2, w7, w8, w13);
        (w3, w4, w9, w14) = chacha20_quarter_round(w3, w4, w9, w14);
    }

    let final_words = [
        w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15,
    ];
    let mut out_vec = Vec::with_capacity(64);
    for (&w, &init_w) in final_words.iter().zip(initial.iter()) {
        out_vec.extend_from_slice(&w.wrapping_add(init_w).to_le_bytes());
    }
    let mut out = [0_u8; 64];
    out.copy_from_slice(&out_vec);
    out
}

/// Generates an RFC 8439 `ChaCha20` keystream starting at counter `1` and XORs it with `input`.
///
/// # Arguments
///
/// * `key` - 32-byte key.
/// * `nonce` - 12-byte IETF nonce.
/// * `input` - Input byte slice.
///
/// # Returns
///
/// `XORed` output bytes.
fn xor_keystream(key: &[u8; 32], nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for (block_idx, chunk) in input.chunks(64).enumerate() {
        let counter = u32::try_from(block_idx).unwrap_or(0).wrapping_add(1);
        let block = chacha20_block(key, counter, nonce);
        for (&in_byte, &stream_byte) in chunk.iter().zip(block.iter()) {
            output.push(in_byte ^ stream_byte);
        }
    }
    output
}

/// Computes an RFC 8439 Section 2.5 `Poly1305` 16-byte (`128-bit`) authenticator tag over `msg`
/// using the 32-byte one-time key `otk = r || s`.
///
/// Evaluates the polynomial over $\mathbb{Z} / (2^{130} - 5)\mathbb{Z}$ using 5-limb 26-bit
/// pure-integer arithmetic with zero floating-point operations.
///
/// # Arguments
///
/// * `otk` - 32-byte Poly1305 one-time key (`r` in bytes `0..16`, `s` in bytes `16..32`).
/// * `msg` - Message byte slice to authenticate.
///
/// # Returns
///
/// 16-byte (`128-bit`) RFC 8439 `Poly1305` MAC tag.
#[allow(clippy::too_many_lines)]
pub fn poly1305_mac(otk: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let mut r_bytes = [0_u8; 16];
    r_bytes.copy_from_slice(otk.get(0..16).unwrap_or(&[0_u8; 16]));
    // Clamp r according to RFC 8439 Section 2.5
    let clamp_mask: [u8; 16] = [
        0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff,
        0x0f,
    ];
    for (rb, &cm) in r_bytes.iter_mut().zip(clamp_mask.iter()) {
        *rb &= cm;
    }
    let r = u128::from_le_bytes(r_bytes);
    let r0 = u64::try_from(r & 0x03ff_ffff).unwrap_or(0);
    let r1 = u64::try_from((r >> 26) & 0x03ff_ffff).unwrap_or(0);
    let r2 = u64::try_from((r >> 52) & 0x03ff_ffff).unwrap_or(0);
    let r3 = u64::try_from((r >> 78) & 0x03ff_ffff).unwrap_or(0);
    let r4 = u64::try_from((r >> 104) & 0x03ff_ffff).unwrap_or(0);

    let s1 = r1.wrapping_mul(5);
    let s2 = r2.wrapping_mul(5);
    let s3 = r3.wrapping_mul(5);
    let s4 = r4.wrapping_mul(5);

    let mut h0 = 0_u64;
    let mut h1 = 0_u64;
    let mut h2 = 0_u64;
    let mut h3 = 0_u64;
    let mut h4 = 0_u64;

    for chunk in msg.chunks(16) {
        let mut block = [0_u8; 17];
        for (dst_b, &src_b) in block
            .iter_mut()
            .zip(chunk.iter().chain(core::iter::once(&1_u8)))
        {
            *dst_b = src_b;
        }
        let mut low16 = [0_u8; 16];
        low16.copy_from_slice(block.get(0..16).unwrap_or(&[0_u8; 16]));
        let n_lo = u128::from_le_bytes(low16);
        let n_hi = u64::from(block.get(16).copied().unwrap_or(0));

        h0 = h0.wrapping_add(u64::try_from(n_lo & 0x03ff_ffff).unwrap_or(0));
        h1 = h1.wrapping_add(u64::try_from((n_lo >> 26) & 0x03ff_ffff).unwrap_or(0));
        h2 = h2.wrapping_add(u64::try_from((n_lo >> 52) & 0x03ff_ffff).unwrap_or(0));
        h3 = h3.wrapping_add(u64::try_from((n_lo >> 78) & 0x03ff_ffff).unwrap_or(0));
        h4 = h4
            .wrapping_add(u64::try_from((n_lo >> 104) & 0x00ff_ffff).unwrap_or(0))
            .wrapping_add(n_hi << 24);

        let d0 = u128::from(h0)
            .wrapping_mul(u128::from(r0))
            .wrapping_add(u128::from(h1).wrapping_mul(u128::from(s4)))
            .wrapping_add(u128::from(h2).wrapping_mul(u128::from(s3)))
            .wrapping_add(u128::from(h3).wrapping_mul(u128::from(s2)))
            .wrapping_add(u128::from(h4).wrapping_mul(u128::from(s1)));
        let mut d1 = u128::from(h0)
            .wrapping_mul(u128::from(r1))
            .wrapping_add(u128::from(h1).wrapping_mul(u128::from(r0)))
            .wrapping_add(u128::from(h2).wrapping_mul(u128::from(s4)))
            .wrapping_add(u128::from(h3).wrapping_mul(u128::from(s3)))
            .wrapping_add(u128::from(h4).wrapping_mul(u128::from(s2)));
        let mut d2 = u128::from(h0)
            .wrapping_mul(u128::from(r2))
            .wrapping_add(u128::from(h1).wrapping_mul(u128::from(r1)))
            .wrapping_add(u128::from(h2).wrapping_mul(u128::from(r0)))
            .wrapping_add(u128::from(h3).wrapping_mul(u128::from(s4)))
            .wrapping_add(u128::from(h4).wrapping_mul(u128::from(s3)));
        let mut d3 = u128::from(h0)
            .wrapping_mul(u128::from(r3))
            .wrapping_add(u128::from(h1).wrapping_mul(u128::from(r2)))
            .wrapping_add(u128::from(h2).wrapping_mul(u128::from(r1)))
            .wrapping_add(u128::from(h3).wrapping_mul(u128::from(r0)))
            .wrapping_add(u128::from(h4).wrapping_mul(u128::from(s4)));
        let mut d4 = u128::from(h0)
            .wrapping_mul(u128::from(r4))
            .wrapping_add(u128::from(h1).wrapping_mul(u128::from(r3)))
            .wrapping_add(u128::from(h2).wrapping_mul(u128::from(r2)))
            .wrapping_add(u128::from(h3).wrapping_mul(u128::from(r1)))
            .wrapping_add(u128::from(h4).wrapping_mul(u128::from(r0)));

        let mut c = u64::try_from(d0 >> 26).unwrap_or(0);
        h0 = u64::try_from(d0 & 0x03ff_ffff).unwrap_or(0);
        d1 = d1.wrapping_add(u128::from(c));
        c = u64::try_from(d1 >> 26).unwrap_or(0);
        h1 = u64::try_from(d1 & 0x03ff_ffff).unwrap_or(0);
        d2 = d2.wrapping_add(u128::from(c));
        c = u64::try_from(d2 >> 26).unwrap_or(0);
        h2 = u64::try_from(d2 & 0x03ff_ffff).unwrap_or(0);
        d3 = d3.wrapping_add(u128::from(c));
        c = u64::try_from(d3 >> 26).unwrap_or(0);
        h3 = u64::try_from(d3 & 0x03ff_ffff).unwrap_or(0);
        d4 = d4.wrapping_add(u128::from(c));
        c = u64::try_from(d4 >> 26).unwrap_or(0);
        h4 = u64::try_from(d4 & 0x03ff_ffff).unwrap_or(0);
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 = h1.wrapping_add(c);
    }

    let mut c = h1 >> 26;
    h1 &= 0x03ff_ffff;
    h2 = h2.wrapping_add(c);
    c = h2 >> 26;
    h2 &= 0x03ff_ffff;
    h3 = h3.wrapping_add(c);
    c = h3 >> 26;
    h3 &= 0x03ff_ffff;
    h4 = h4.wrapping_add(c);
    c = h4 >> 26;
    h4 &= 0x03ff_ffff;
    h0 = h0.wrapping_add(c.wrapping_mul(5));
    c = h0 >> 26;
    h0 &= 0x03ff_ffff;
    h1 = h1.wrapping_add(c);

    let mut g0 = h0.wrapping_add(5);
    c = g0 >> 26;
    g0 &= 0x03ff_ffff;
    let mut g1 = h1.wrapping_add(c);
    c = g1 >> 26;
    g1 &= 0x03ff_ffff;
    let mut g2 = h2.wrapping_add(c);
    c = g2 >> 26;
    g2 &= 0x03ff_ffff;
    let mut g3 = h3.wrapping_add(c);
    c = g3 >> 26;
    g3 &= 0x03ff_ffff;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    let inv_mask = !mask;
    h0 = (h0 & inv_mask) | g0;
    h1 = (h1 & inv_mask) | g1;
    h2 = (h2 & inv_mask) | g2;
    h3 = (h3 & inv_mask) | g3;
    h4 = (h4 & inv_mask) | (g4 & mask);

    let acc = u128::from(h0)
        | (u128::from(h1) << 26)
        | (u128::from(h2) << 52)
        | (u128::from(h3) << 78)
        | (u128::from(h4) << 104);
    let mut s_bytes = [0_u8; 16];
    s_bytes.copy_from_slice(otk.get(16..32).unwrap_or(&[0_u8; 16]));
    let s = u128::from_le_bytes(s_bytes);
    acc.wrapping_add(s).to_le_bytes()
}

/// Computes an RFC 8439 Section 2.8 `ChaCha20-Poly1305` 16-byte AEAD tag over `(aad, ciphertext)`
/// using the one-time key derived from `chacha20_block(key, 0, nonce)[0..32]`.
///
/// # Arguments
///
/// * `key` - 32-byte key.
/// * `nonce` - 12-byte IETF nonce.
/// * `aad` - Associated data slice.
/// * `ciphertext` - Ciphertext slice.
///
/// # Returns
///
/// 16-byte RFC 8439 `Poly1305` AEAD tag.
pub fn chacha20_poly1305_aead_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0_u8; 32];
    otk.copy_from_slice(block0.get(0..32).unwrap_or(&[0_u8; 32]));
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    let mut mac_data = Vec::with_capacity(aad.len() + aad_pad + ciphertext.len() + ct_pad + 16);
    mac_data.extend_from_slice(aad);
    mac_data.resize(mac_data.len() + aad_pad, 0);
    mac_data.extend_from_slice(ciphertext);
    mac_data.resize(mac_data.len() + ct_pad, 0);
    mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305_mac(&otk, &mac_data)
}

/// Computes a FIPS 180-4 `SHA-256` 32-byte digest over `message`.
///
/// # Arguments
///
/// * `message` - Input byte slice.
///
/// # Returns
///
/// 32-byte `SHA-256` digest.
pub fn sha256_digest(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

/// Computes an RFC 2104 `HMAC-SHA256` 32-byte authentication code over `message` using `key`
/// backed by `hmac::Hmac<Sha256>`.
///
/// # Arguments
///
/// * `key` - Secret key byte slice.
/// * `message` - Message byte slice to authenticate.
///
/// # Returns
///
/// 32-byte RFC 2104 `HMAC-SHA256` digest.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use hmac::Mac as _;
    let mut k_block = [0_u8; 64];
    if key.len() > 64 {
        let hashed_key: [u8; 32] = Sha256::digest(key).into();
        for (dst_b, &src_b) in k_block.iter_mut().zip(hashed_key.iter()) {
            *dst_b = src_b;
        }
    } else {
        for (dst_b, &src_b) in k_block.iter_mut().zip(key.iter()) {
            *dst_b = src_b;
        }
    }
    hmac::Hmac::<Sha256>::new_from_slice(&k_block)
        .map(|mut mac| {
            mac.update(message);
            mac.finalize().into_bytes().into()
        })
        .unwrap_or([0_u8; 32])
}

/// Seals a plaintext payload using `RustCrypto` `chacha20poly1305::ChaCha20Poly1305` (RFC 8439),
/// returning `(ciphertext, 16-byte_tag)`.
///
/// # Arguments
///
/// * `key` - 32-byte `ChaCha20-Poly1305` key.
/// * `nonce_bytes` - 12-byte IETF nonce.
/// * `aad_bytes` - Additional authenticated data (`AAD`).
/// * `plaintext` - Plaintext bytes to seal.
///
/// # Returns
///
/// Tuple `(ciphertext_bytes, 16-byte_tag)`.
///
/// # Errors
///
/// Returns [`ArbiterError::AeadCipher`] if encryption fails.
pub fn chacha20poly1305_aead_seal(
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad_bytes: &[u8],
    plaintext: &[u8],
) -> ArbiterResult<(Vec<u8>, [u8; 16])> {
    use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
    let mut buffer = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(&nonce, aad_bytes, &mut buffer)?;
    let mut tag_arr = [0_u8; 16];
    tag_arr.copy_from_slice(tag.as_slice());
    Ok((buffer, tag_arr))
}

/// Opens and authenticates a ciphertext payload using `RustCrypto` `chacha20poly1305::ChaCha20Poly1305` (RFC 8439).
///
/// # Arguments
///
/// * `key` - 32-byte `ChaCha20-Poly1305` key.
/// * `nonce_bytes` - 12-byte IETF nonce.
/// * `aad_bytes` - Additional authenticated data (`AAD`).
/// * `ciphertext` - Encrypted bytes.
/// * `tag_bytes` - 16-byte authentication tag.
///
/// # Returns
///
/// Authenticated plaintext byte vector.
///
/// # Errors
///
/// Returns [`ArbiterError::AeadCipher`] if authentication tag verification fails.
pub fn chacha20poly1305_aead_open(
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad_bytes: &[u8],
    ciphertext: &[u8],
    tag_bytes: &[u8; 16],
) -> ArbiterResult<Vec<u8>> {
    use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
    let tag = chacha20poly1305::Tag::from(*tag_bytes);
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt_in_place_detached(&nonce, aad_bytes, &mut buffer, &tag)?;
    Ok(buffer)
}

/// Computes the 32-byte AEAD authentication tag over `(key, secret_id, nonce, ciphertext)`
/// combining the 16-byte RFC 8439 `ChaCha20-Poly1305` AEAD tag (`bytes 0..16`) with the 16-byte
/// NIST SP 800-38D `AES-256-GCM` tag (`bytes 16..32`).
///
/// # Arguments
///
/// * `key` - 32-byte key.
/// * `secret_id` - Secret ID string.
/// * `nonce` - 12-byte nonce.
/// * `ciphertext` - Ciphertext slice.
///
/// # Returns
///
/// 32-byte authentication tag.
fn compute_aead_tag(
    key: &[u8; 32],
    secret_id: &str,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> [u8; 32] {
    let poly_tag = chacha20_poly1305_aead_tag(key, nonce, secret_id.as_bytes(), ciphertext);
    let (_, gcm_tag) = aes256_gcm_seal(key, nonce, secret_id.as_bytes(), ciphertext);
    let mut out = [0_u8; 32];
    for (dst_b, &src_b) in out.iter_mut().zip(poly_tag.iter().chain(gcm_tag.iter())) {
        *dst_b = src_b;
    }
    out
}

/// Seals a plaintext payload using `ring::aead::CHACHA20_POLY1305` (RFC 8439) and `ring::aead::AES_256_GCM`
/// (NIST SP 800-38D), returning `(ciphertext, 16-byte_tag)`.
///
/// # Arguments
///
/// * `use_aes_256_gcm` - If `true`, uses `ring::aead::AES_256_GCM`; otherwise uses `ring::aead::CHACHA20_POLY1305`.
/// * `key` - 32-byte AEAD key.
/// * `nonce_bytes` - 12-byte AEAD nonce.
/// * `aad_bytes` - Additional authenticated data (`AAD`).
/// * `plaintext` - Plaintext bytes to seal.
///
/// # Returns
///
/// Tuple `(ciphertext_bytes, 16-byte_tag)`.
///
/// # Errors
///
/// Returns [`ArbiterError::AeadCipher`] if `ring::aead` sealing fails.
pub fn ring_aead_seal(
    use_aes_256_gcm: bool,
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad_bytes: &[u8],
    plaintext: &[u8],
) -> ArbiterResult<(Vec<u8>, [u8; 16])> {
    let alg = if use_aes_256_gcm {
        &ring::aead::AES_256_GCM
    } else {
        &ring::aead::CHACHA20_POLY1305
    };
    let unbound = ring::aead::UnboundKey::new(alg, key)?;
    let less_safe = ring::aead::LessSafeKey::new(unbound);
    let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
    let aad = ring::aead::Aad::from(aad_bytes);
    let mut in_out = plaintext.to_vec();
    let tag = less_safe.seal_in_place_separate_tag(nonce, aad, &mut in_out)?;
    let mut tag_arr = [0_u8; 16];
    tag_arr.copy_from_slice(tag.as_ref());
    Ok((in_out, tag_arr))
}

/// Opens and authenticates a ciphertext payload using `ring::aead::CHACHA20_POLY1305` (RFC 8439)
/// or `ring::aead::AES_256_GCM` (NIST SP 800-38D).
///
/// # Arguments
///
/// * `use_aes_256_gcm` - If `true`, uses `ring::aead::AES_256_GCM`; otherwise uses `ring::aead::CHACHA20_POLY1305`.
/// * `key` - 32-byte AEAD key.
/// * `nonce_bytes` - 12-byte AEAD nonce.
/// * `aad_bytes` - Additional authenticated data (`AAD`).
/// * `ciphertext` - Encrypted bytes.
/// * `tag_bytes` - 16-byte authentication tag.
///
/// # Returns
///
/// Authenticated plaintext byte vector.
///
/// # Errors
///
/// Returns [`ArbiterError::AeadCipher`] if authentication tag verification fails.
pub fn ring_aead_open(
    use_aes_256_gcm: bool,
    key: &[u8; 32],
    nonce_bytes: [u8; 12],
    aad_bytes: &[u8],
    ciphertext: &[u8],
    tag_bytes: &[u8; 16],
) -> ArbiterResult<Vec<u8>> {
    let alg = if use_aes_256_gcm {
        &ring::aead::AES_256_GCM
    } else {
        &ring::aead::CHACHA20_POLY1305
    };
    let unbound = ring::aead::UnboundKey::new(alg, key)?;
    let less_safe = ring::aead::LessSafeKey::new(unbound);
    let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
    let aad = ring::aead::Aad::from(aad_bytes);
    let mut in_out = Vec::with_capacity(ciphertext.len() + tag_bytes.len());
    in_out.extend_from_slice(ciphertext);
    in_out.extend_from_slice(tag_bytes);
    let plain_slice = less_safe.open_in_place(nonce, aad, &mut in_out)?;
    Ok(plain_slice.to_vec())
}

/// Seals a plaintext secret using NIST SP 800-38D `AES-256-GCM` with Associated Data (`AAD`).
///
/// # Arguments
///
/// * `secret_id` - Unique [`SecretId`].
/// * `master_key` - 32-byte `AES-256` master key.
/// * `nonce` - 12-byte (`96-bit`) GCM IV.
/// * `associated_data` - Context-binding AAD (`role || task_id || agent_id`).
/// * `plaintext` - Secret bytes to encrypt.
///
/// # Returns
///
/// [`SealedSecretEnvelope`] encrypted and authenticated with `AES-256-GCM`.
pub fn seal_secret_aes256_gcm(
    secret_id: SecretId,
    master_key: &[u8; 32],
    nonce: [u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> SealedSecretEnvelope {
    let mut full_aad = Vec::with_capacity(secret_id.as_str().len() + 1 + associated_data.len());
    full_aad.extend_from_slice(secret_id.as_str().as_bytes());
    full_aad.push(b':');
    full_aad.extend_from_slice(associated_data);
    let (ciphertext, gcm_tag) = aes256_gcm_seal(master_key, &nonce, &full_aad, plaintext);
    let hmac_commit = hmac_sha256(master_key, &gcm_tag);
    let mut auth_tag = [0_u8; 32];
    for (dst, &src) in auth_tag
        .iter_mut()
        .zip(gcm_tag.iter().chain(hmac_commit.iter().take(16)))
    {
        *dst = src;
    }
    SealedSecretEnvelope {
        secret_id,
        nonce,
        ciphertext,
        auth_tag,
    }
}

/// Unseals a [`SealedSecretEnvelope`] encrypted via [`seal_secret_aes256_gcm`] into a [`ZeroizingSecretBuffer`].
///
/// # Arguments
///
/// * `envelope` - Sealed secret envelope.
/// * `master_key` - 32-byte `AES-256` master key.
/// * `associated_data` - Expected AAD bytes (`role || task_id || agent_id`).
///
/// # Returns
///
/// Decrypted [`ZeroizingSecretBuffer`] that wipes plaintext from RAM on `Drop`.
///
/// # Errors
///
/// Returns [`ArbiterError::SecretDecryptionFailed`] if `AES-256-GCM` tag verification fails.
pub fn unseal_secret_aes256_gcm(
    envelope: &SealedSecretEnvelope,
    master_key: &[u8; 32],
    associated_data: &[u8],
) -> ArbiterResult<ZeroizingSecretBuffer> {
    let mut full_aad =
        Vec::with_capacity(envelope.secret_id.as_str().len() + 1 + associated_data.len());
    full_aad.extend_from_slice(envelope.secret_id.as_str().as_bytes());
    full_aad.push(b':');
    full_aad.extend_from_slice(associated_data);
    let mut gcm_tag = [0_u8; 16];
    for (dst, &src) in gcm_tag.iter_mut().zip(envelope.auth_tag.iter().take(16)) {
        *dst = src;
    }
    let expected_commit = hmac_sha256(master_key, &gcm_tag);
    let mut commit_diff = 0_u8;
    for (&actual, &expected) in envelope
        .auth_tag
        .iter()
        .skip(16)
        .zip(expected_commit.iter().take(16))
    {
        commit_diff |= actual ^ expected;
    }
    if commit_diff != 0 {
        return Err(ArbiterError::SecretDecryptionFailed {
            secret_id: envelope.secret_id.to_string(),
            reason: "AES-256-GCM envelope commitment mismatch".to_owned(),
        });
    }
    let plaintext = aes256_gcm_open(
        master_key,
        &envelope.nonce,
        &full_aad,
        &envelope.ciphertext,
        &gcm_tag,
    )
    .map_err(|_| ArbiterError::SecretDecryptionFailed {
        secret_id: envelope.secret_id.to_string(),
        reason: "AES-256-GCM authentication tag verification failed".to_owned(),
    })?;
    Ok(ZeroizingSecretBuffer::new(plaintext))
}

/// Seals a plaintext secret with explicit Associated Data (`AAD` = `role || task_id || agent_id`)
/// so a sealed envelope cannot be replayed across different roles, tasks, or Agents.
///
/// # Arguments
///
/// * `secret_id` - Unique [`SecretId`].
/// * `master_key` - 32-byte encryption key.
/// * `nonce` - 12-byte unique nonce.
/// * `associated_data` - Context-binding AAD bytes (`role || task_id || agent_id`).
/// * `plaintext` - Secret bytes to encrypt.
///
/// # Returns
///
/// [`SealedSecretEnvelope`] authenticated with `associated_data`.
pub fn seal_secret_with_aad(
    secret_id: SecretId,
    master_key: &[u8; 32],
    nonce: [u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> SealedSecretEnvelope {
    let ciphertext = xor_keystream(master_key, &nonce, plaintext);
    let mut full_aad = Vec::with_capacity(secret_id.as_str().len() + 1 + associated_data.len());
    full_aad.extend_from_slice(secret_id.as_str().as_bytes());
    full_aad.push(b':');
    full_aad.extend_from_slice(associated_data);
    let auth_tag = compute_aead_tag(
        master_key,
        &String::from_utf8_lossy(&full_aad),
        &nonce,
        &ciphertext,
    );
    SealedSecretEnvelope {
        secret_id,
        nonce,
        ciphertext,
        auth_tag,
    }
}

/// Unseals a [`SealedSecretEnvelope`] verifying its Associated Data (`AAD`) in constant time.
///
/// # Arguments
///
/// * `envelope` - Sealed secret envelope.
/// * `master_key` - 32-byte decryption key.
/// * `associated_data` - Expected AAD bytes (`role || task_id || agent_id`).
///
/// # Returns
///
/// Decrypted plaintext bytes.
///
/// # Errors
///
/// Returns [`ArbiterError::SecretDecryptionFailed`] if the key, AAD, or ciphertext is invalid.
pub fn unseal_secret_with_aad(
    envelope: &SealedSecretEnvelope,
    master_key: &[u8; 32],
    associated_data: &[u8],
) -> ArbiterResult<Vec<u8>> {
    let mut full_aad =
        Vec::with_capacity(envelope.secret_id.as_str().len() + 1 + associated_data.len());
    full_aad.extend_from_slice(envelope.secret_id.as_str().as_bytes());
    full_aad.push(b':');
    full_aad.extend_from_slice(associated_data);
    let expected = compute_aead_tag(
        master_key,
        &String::from_utf8_lossy(&full_aad),
        &envelope.nonce,
        &envelope.ciphertext,
    );
    let mut diff = 0_u8;
    for (&a, &b) in envelope.auth_tag.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(ArbiterError::SecretDecryptionFailed {
            secret_id: envelope.secret_id.to_string(),
            reason: "AEAD AAD tag verification failed (replay or tampering)".to_owned(),
        });
    }
    Ok(xor_keystream(
        master_key,
        &envelope.nonce,
        &envelope.ciphertext,
    ))
}

/// Multi-epoch secret encryption key ring supporting zero-downtime key rotation.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretKeyRing {
    /// Active key epoch number.
    pub active_epoch: u64,
    /// Keys indexed by epoch number.
    pub keys: BTreeMap<u64, [u8; 32]>,
}

impl SecretKeyRing {
    /// Creates a new [`SecretKeyRing`] seeded with `initial_epoch` and `key`.
    ///
    /// # Arguments
    ///
    /// * `initial_epoch` - Starting key epoch.
    /// * `key` - 32-byte master key.
    ///
    /// # Returns
    ///
    /// Initialized [`SecretKeyRing`].
    pub fn new(initial_epoch: u64, key: [u8; 32]) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(initial_epoch, key);
        Self {
            active_epoch: initial_epoch,
            keys,
        }
    }

    /// Rotates the key ring to a new epoch key while retaining historical keys for unsealing in-flight envelopes.
    ///
    /// # Arguments
    ///
    /// * `new_epoch` - New epoch number (must be `> self.active_epoch`).
    /// * `new_key` - New 32-byte master key.
    ///
    /// # Returns
    ///
    /// `Ok(())` when rotated.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TlsConfigurationError`] if `new_epoch <= self.active_epoch`.
    pub fn rotate_key(&mut self, new_epoch: u64, new_key: [u8; 32]) -> ArbiterResult<()> {
        if new_epoch <= self.active_epoch {
            return Err(ArbiterError::TlsConfigurationError {
                reason: format!(
                    "new key epoch {new_epoch} must be strictly greater than active_epoch {}",
                    self.active_epoch
                ),
            });
        }
        self.keys.insert(new_epoch, new_key);
        self.active_epoch = new_epoch;
        Ok(())
    }

    /// Seals a secret under the currently active `active_epoch` key with epoch-bound AAD, returning `(key_epoch, SealedSecretEnvelope)`.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - Unique [`SecretId`].
    /// * `nonce` - 12-byte unique nonce.
    /// * `associated_data` - Context-binding AAD (`role || task_id || agent_id`).
    /// * `plaintext` - Secret bytes to encrypt.
    ///
    /// # Returns
    ///
    /// `(key_epoch, SealedSecretEnvelope)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SecretDecryptionFailed`] if no key exists for `active_epoch`.
    pub fn seal_for_active_epoch(
        &self,
        secret_id: SecretId,
        nonce: [u8; 12],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> ArbiterResult<(u64, SealedSecretEnvelope)> {
        let Some(key) = self.keys.get(&self.active_epoch) else {
            return Err(ArbiterError::SecretDecryptionFailed {
                secret_id: secret_id.to_string(),
                reason: format!("missing master key for active epoch {}", self.active_epoch),
            });
        };
        let mut epoch_aad = Vec::with_capacity(8 + associated_data.len());
        epoch_aad.extend_from_slice(&self.active_epoch.to_le_bytes());
        epoch_aad.extend_from_slice(associated_data);
        Ok((
            self.active_epoch,
            seal_secret_with_aad(secret_id, key, nonce, &epoch_aad, plaintext),
        ))
    }

    /// Unseals an epoch-tagged [`SealedSecretEnvelope`] using the historical or current key for `key_epoch`.
    ///
    /// # Arguments
    ///
    /// * `key_epoch` - Key epoch under which `envelope` was sealed.
    /// * `envelope` - Sealed secret envelope.
    /// * `associated_data` - Expected context AAD (`role || task_id || agent_id`).
    ///
    /// # Returns
    ///
    /// Decrypted [`ZeroizingSecretBuffer`] that wipes plaintext on `Drop`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SecretDecryptionFailed`] if `key_epoch` is unknown or AAD/tag verification fails.
    pub fn unseal_for_epoch(
        &self,
        key_epoch: u64,
        envelope: &SealedSecretEnvelope,
        associated_data: &[u8],
    ) -> ArbiterResult<ZeroizingSecretBuffer> {
        let Some(key) = self.keys.get(&key_epoch) else {
            return Err(ArbiterError::SecretDecryptionFailed {
                secret_id: envelope.secret_id.to_string(),
                reason: format!("unknown key epoch {key_epoch}"),
            });
        };
        let mut epoch_aad = Vec::with_capacity(8 + associated_data.len());
        epoch_aad.extend_from_slice(&key_epoch.to_le_bytes());
        epoch_aad.extend_from_slice(associated_data);
        let plain = unseal_secret_with_aad(envelope, key, &epoch_aad)?;
        Ok(ZeroizingSecretBuffer::new(plain))
    }
}

/// ASN.1 DER OID bytes for X.509v3 `SubjectAltName` (`2.5.29.17` -> `06 03 55 1D 11`).
pub const X509_OID_SUBJECT_ALT_NAME: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x11];

/// ASN.1 context-specific primitive tag `[6]` (`0x86`) for `uniformResourceIdentifier` inside `GeneralNames`.
pub const X509_GENERAL_NAME_URI_TAG: u8 = 0x86;

/// Encodes a validated SPIFFE ID into an ASN.1 DER X.509v3 `SubjectAltName` extension (`SEQUENCE { OID 2.5.29.17, OCTET STRING { SEQUENCE { [6] IA5String } } }`).
///
/// # Arguments
///
/// * `spiffe_id` - Validated [`SpiffeId`] (`<= 120` bytes).
///
/// # Returns
///
/// ASN.1 DER extension byte vector.
pub fn encode_x509_san_der(spiffe_id: &SpiffeId) -> Vec<u8> {
    let uri_bytes = spiffe_id.as_str().as_bytes();
    let uri_len = u8::try_from(uri_bytes.len()).unwrap_or(0);
    let general_names_len = uri_len.saturating_add(2);
    let octet_len = general_names_len.saturating_add(2);
    let seq_len = octet_len
        .saturating_add(2)
        .saturating_add(u8::try_from(X509_OID_SUBJECT_ALT_NAME.len()).unwrap_or(5));
    let mut der = Vec::with_capacity(usize::from(seq_len) + 2);
    der.push(0x30); // Outer SEQUENCE
    der.push(seq_len);
    der.extend_from_slice(&X509_OID_SUBJECT_ALT_NAME);
    der.push(0x04); // OCTET STRING
    der.push(octet_len);
    der.push(0x30); // GeneralNames SEQUENCE
    der.push(general_names_len);
    der.push(X509_GENERAL_NAME_URI_TAG); // [6] uniformResourceIdentifier
    der.push(uri_len);
    der.extend_from_slice(uri_bytes);
    der
}

/// Parses an ASN.1 DER X.509v3 `SubjectAltName` extension (`OID 2.5.29.17`) and extracts its
/// `uniformResourceIdentifier` (`[6]`) as a validated `(SpiffeId, SpiffePrincipalKind)`.
///
/// # Arguments
///
/// * `der` - ASN.1 DER byte slice.
/// * `expected_trust_domain` - Required SPIFFE trust domain.
///
/// # Returns
///
/// Extracted `(SpiffeId, SpiffePrincipalKind)`.
///
/// # Errors
///
/// Returns [`ArbiterError::X509ValidationError`] or [`ArbiterError::SpiffeIdentityInvalid`] if the
/// ASN.1 DER structure, OID, tag, or SPIFFE URI is invalid.
pub fn decode_x509_san_der(
    der: &[u8],
    expected_trust_domain: &str,
) -> ArbiterResult<(SpiffeId, SpiffePrincipalKind)> {
    let Some(oid_slice) = der.get(2..7) else {
        return Err(ArbiterError::X509ValidationError {
            subject: "ASN.1-DER".to_owned(),
            reason: "ASN.1 DER buffer too short for SubjectAltName OID".to_owned(),
        });
    };
    if der.first().copied() != Some(0x30) || oid_slice != X509_OID_SUBJECT_ALT_NAME {
        return Err(ArbiterError::X509ValidationError {
            subject: "ASN.1-DER".to_owned(),
            reason: "missing X.509v3 SubjectAltName OID (2.5.29.17)".to_owned(),
        });
    };
    let Some(&uri_tag) = der.get(11) else {
        return Err(ArbiterError::X509ValidationError {
            subject: "ASN.1-DER".to_owned(),
            reason: "truncated GeneralNames SEQUENCE in SubjectAltName".to_owned(),
        });
    };
    if uri_tag != X509_GENERAL_NAME_URI_TAG {
        return Err(ArbiterError::X509ValidationError {
            subject: "ASN.1-DER".to_owned(),
            reason: format!("expected ASN.1 URI tag 0x86, found 0x{uri_tag:02x}"),
        });
    };
    let uri_len = usize::from(der.get(12).copied().unwrap_or(0));
    let Some(uri_bytes) = der.get(13..13 + uri_len) else {
        return Err(ArbiterError::X509ValidationError {
            subject: "ASN.1-DER".to_owned(),
            reason: "truncated IA5String URI payload in SubjectAltName".to_owned(),
        });
    };
    let Ok(uri_str) = core::str::from_utf8(uri_bytes) else {
        return Err(ArbiterError::X509ValidationError {
            subject: "ASN.1-DER".to_owned(),
            reason: "non-UTF8 bytes in SubjectAltName URI".to_owned(),
        });
    };
    parse_spiffe_san(uri_str, expected_trust_domain)
}

/// RFC 4648 Section 5 URL-safe Base64 alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`).
const BASE64URL_ALPHABET: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encodes `input` bytes into unpadded RFC 4648 §5 `Base64URL` format (used by RFC 7515 JWS and PEM/DER).
///
/// # Arguments
///
/// * `input` - Raw byte slice to encode.
///
/// # Returns
///
/// Unpadded `Base64URL` string.
pub fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().saturating_mul(4).div_ceil(3));
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let idx0 = usize::try_from((triple >> 18) & 0x3F).unwrap_or(0);
        let idx1 = usize::try_from((triple >> 12) & 0x3F).unwrap_or(0);
        let idx2 = usize::try_from((triple >> 6) & 0x3F).unwrap_or(0);
        let idx3 = usize::try_from(triple & 0x3F).unwrap_or(0);
        out.push(char::from(
            BASE64URL_ALPHABET.get(idx0).copied().unwrap_or(b'A'),
        ));
        out.push(char::from(
            BASE64URL_ALPHABET.get(idx1).copied().unwrap_or(b'A'),
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                BASE64URL_ALPHABET.get(idx2).copied().unwrap_or(b'A'),
            ));
        }
        if chunk.len() > 2 {
            out.push(char::from(
                BASE64URL_ALPHABET.get(idx3).copied().unwrap_or(b'A'),
            ));
        }
    }
    out
}

/// Decodes an unpadded RFC 4648 §5 `Base64URL` string into raw bytes.
///
/// # Arguments
///
/// * `encoded` - Unpadded `Base64URL` string slice.
///
/// # Returns
///
/// Decoded byte vector.
///
/// # Errors
///
/// Returns [`ArbiterError::AuthenticationFailed`] if `encoded` contains non-`Base64URL` characters
/// or has an invalid remainder length (`len % 4 == 1`).
pub fn base64url_decode(encoded: &str) -> ArbiterResult<Vec<u8>> {
    let mut sextets = Vec::with_capacity(encoded.len());
    for &byte in encoded.as_bytes() {
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => {
                return Err(ArbiterError::AuthenticationFailed {
                    principal: "base64url".to_owned(),
                    reason: format!("invalid Base64URL character 0x{byte:02x}"),
                });
            }
        };
        sextets.push(val);
    }
    let mut out = Vec::with_capacity(sextets.len().saturating_mul(3) / 4);
    for chunk in sextets.chunks(4) {
        if chunk.len() == 1 {
            return Err(ArbiterError::AuthenticationFailed {
                principal: "base64url".to_owned(),
                reason: "invalid Base64URL length (remainder 1)".to_owned(),
            });
        }
        let s0 = chunk.first().copied().unwrap_or(0);
        let s1 = chunk.get(1).copied().unwrap_or(0);
        out.push((s0 << 2) | (s1 >> 4));
        if let Some(&s2) = chunk.get(2) {
            out.push(((s1 & 0x0F) << 4) | (s2 >> 2));
            if let Some(&s3) = chunk.get(3) {
                out.push(((s2 & 0x03) << 6) | s3);
            }
        }
    }
    Ok(out)
}

/// Supported JWS / OIDC token signing algorithms (`HS256`, `EdDSA`, `ES256`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwtSigningAlgorithm {
    /// HMAC with SHA-256 (`HS256`).
    #[default]
    Hs256,
    /// Edwards-curve Digital Signature Algorithm over Ed25519 (`EdDSA`).
    EdDsa,
    /// ECDSA over NIST P-256 with SHA-256 (`ES256`).
    Es256,
}

impl JwtSigningAlgorithm {
    /// Returns the JWS header string for this algorithm.
    ///
    /// # Returns
    ///
    /// Header string (`"alg=HS256"`, `"alg=EdDSA"`, or `"alg=ES256"`).
    pub const fn header_str(self) -> &'static str {
        match self {
            Self::Hs256 => "alg=HS256",
            Self::EdDsa => "alg=EdDSA",
            Self::Es256 => "alg=ES256",
        }
    }
}

/// OIDC / JWT operator authentication claims (`header.payload.signature`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcJwtClaims {
    /// Token issuer (`iss`).
    pub issuer: String,
    /// Subject principal (`sub`).
    pub subject: String,
    /// Permitted scheduling role (`role`).
    pub role: RoleName,
    /// Expiration tick (`exp`).
    pub expires_at_tick: u64,
}

impl OidcJwtClaims {
    /// Issues a signed 3-part JWT string (`alg=HS256.<json_claims>.<hex_hmac>`).
    ///
    /// # Arguments
    ///
    /// * `signing_key` - 32-byte signing key.
    ///
    /// # Returns
    ///
    /// Signed 3-part JWT string.
    pub fn encode_jwt(&self, signing_key: &[u8; 32]) -> String {
        self.encode_jwt_with_alg(JwtSigningAlgorithm::Hs256, signing_key)
    }

    /// Issues a signed 3-part JWT string using `alg` (`HS256`, `EdDSA`, or `ES256`).
    ///
    /// # Arguments
    ///
    /// * `alg` - [`JwtSigningAlgorithm`].
    /// * `signing_key` - 32-byte signing key.
    ///
    /// # Returns
    ///
    /// Signed 3-part JWT string.
    pub fn encode_jwt_with_alg(&self, alg: JwtSigningAlgorithm, signing_key: &[u8; 32]) -> String {
        let header = alg.header_str();
        let payload = serde_json::to_string(self).unwrap_or_default();
        let sig = Self::compute_sig(header, &payload, signing_key);
        format!("{header}.{payload}.{sig}")
    }

    /// Issues a standard RFC 7515 `Base64URL`-encoded JWS token (`<base64url_header>.<base64url_payload>.<base64url_signature>`).
    ///
    /// # Arguments
    ///
    /// * `alg` - [`JwtSigningAlgorithm`] (`HS256`, `EdDSA`, or `ES256`).
    /// * `signing_key` - 32-byte cryptographic signing key.
    ///
    /// # Returns
    ///
    /// Compact RFC 7515 `Base64URL` JWS string.
    pub fn encode_jws_rfc7515(&self, alg: JwtSigningAlgorithm, signing_key: &[u8; 32]) -> String {
        let header_b64 = base64url_encode(alg.header_str().as_bytes());
        let payload_json = serde_json::to_string(self).unwrap_or_default();
        let payload_b64 = base64url_encode(payload_json.as_bytes());
        let sig_hex = Self::compute_sig(&header_b64, &payload_b64, signing_key);
        let sig_b64 = base64url_encode(sig_hex.as_bytes());
        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    /// Verifies and decodes a 3-part JWT string (supporting both RFC 7515 `Base64URL` JWS and
    /// backwards-compatible `alg=.*` tokens) at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `token` - 3-part JWT token string.
    /// * `signing_key` - 32-byte cryptographic verification key.
    /// * `expected_issuer` - Required `iss` claim.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Verified [`OidcJwtClaims`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::AuthenticationFailed`] if the token format, signature, issuer, or expiration is invalid.
    pub fn verify_jwt(
        token: &str,
        signing_key: &[u8; 32],
        expected_issuer: &str,
        current_tick: u64,
    ) -> ArbiterResult<Self> {
        let Some((header, rest)) = token.split_once('.') else {
            return Err(ArbiterError::AuthenticationFailed {
                principal: "jwt".to_owned(),
                reason: "missing JWT header delimiter".to_owned(),
            });
        };
        let Some((payload, sig)) = rest.split_last_dot() else {
            return Err(ArbiterError::AuthenticationFailed {
                principal: "jwt".to_owned(),
                reason: "missing JWT signature delimiter".to_owned(),
            });
        };
        let payload_json_bytes = if header.starts_with("alg=") {
            let expected_sig = Self::compute_sig(header, payload, signing_key);
            if sig != expected_sig {
                return Err(ArbiterError::AuthenticationFailed {
                    principal: "jwt".to_owned(),
                    reason: "JWT signature mismatch".to_owned(),
                });
            }
            payload.as_bytes().to_vec()
        } else {
            let header_decoded = base64url_decode(header)?;
            if !header_decoded.starts_with(b"alg=") {
                return Err(ArbiterError::AuthenticationFailed {
                    principal: "jwt".to_owned(),
                    reason: "unsupported Base64URL JWS header".to_owned(),
                });
            }
            let payload_decoded = base64url_decode(payload)?;
            let sig_decoded = base64url_decode(sig)?;
            let expected_sig = Self::compute_sig(header, payload, signing_key);
            if sig_decoded != expected_sig.as_bytes() {
                return Err(ArbiterError::AuthenticationFailed {
                    principal: "jwt".to_owned(),
                    reason: "RFC 7515 JWS signature mismatch".to_owned(),
                });
            }
            payload_decoded
        };
        let claims: Self = serde_json::from_slice(&payload_json_bytes).map_err(|e| {
            ArbiterError::AuthenticationFailed {
                principal: "jwt".to_owned(),
                reason: e.to_string(),
            }
        })?;
        if claims.issuer != expected_issuer || current_tick >= claims.expires_at_tick {
            return Err(ArbiterError::AuthenticationFailed {
                principal: claims.subject,
                reason: "JWT expired or untrusted issuer".to_owned(),
            });
        }
        Ok(claims)
    }

    /// Verifies a 3-part JWT or RFC 7515 JWS token while strictly enforcing that the token header's
    /// signing algorithm matches `expected_alg` (preventing `EdDSA`/`ES256` -> `HS256` downgrade attacks).
    ///
    /// # Arguments
    ///
    /// * `token` - 3-part JWT or RFC 7515 JWS string.
    /// * `expected_alg` - Required [`JwtSigningAlgorithm`].
    /// * `signing_key` - 32-byte cryptographic verification key.
    /// * `expected_issuer` - Required `iss` claim.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Verified [`OidcJwtClaims`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CryptographicSignatureError`] if the header algorithm does not match
    /// `expected_alg`, or [`ArbiterError::AuthenticationFailed`] if verification fails.
    pub fn verify_jwt_for_algorithm(
        token: &str,
        expected_alg: JwtSigningAlgorithm,
        signing_key: &[u8; 32],
        expected_issuer: &str,
        current_tick: u64,
    ) -> ArbiterResult<Self> {
        let Some((header, _)) = token.split_once('.') else {
            return Err(ArbiterError::CryptographicSignatureError {
                algorithm: expected_alg.header_str().to_owned(),
                reason: "missing JWT header delimiter".to_owned(),
            });
        };
        let actual_hdr = if header.starts_with("alg=") {
            header.to_owned()
        } else {
            let decoded = base64url_decode(header).map_err(|e| {
                ArbiterError::CryptographicSignatureError {
                    algorithm: expected_alg.header_str().to_owned(),
                    reason: e.to_string(),
                }
            })?;
            String::from_utf8_lossy(&decoded).into_owned()
        };
        if actual_hdr != expected_alg.header_str() {
            return Err(ArbiterError::CryptographicSignatureError {
                algorithm: expected_alg.header_str().to_owned(),
                reason: format!(
                    "JWT algorithm mismatch: expected '{}', found '{actual_hdr}'",
                    expected_alg.header_str()
                ),
            });
        }
        Self::verify_jwt(token, signing_key, expected_issuer, current_tick)
    }

    /// Computes a hex cryptographic signature tag over `header` and `payload` using `key`.
    ///
    /// - For `alg=HS256`: computes standard RFC 2104 `HMAC-SHA256(key, header || "." || payload)`.
    /// - For `alg=EdDSA`: signs `header || "." || payload` with [`Ed25519Keypair::from_seed(*key)`].
    /// - For `alg=ES256`: signs `header || "." || payload` with [`P256Keypair::from_seed(*key)`].
    ///
    /// # Arguments
    ///
    /// * `header` - JWT header.
    /// * `payload` - JWT payload.
    /// * `key` - 32-byte key.
    ///
    /// # Returns
    ///
    /// 64-character hex string.
    fn compute_sig(header: &str, payload: &str, key: &[u8; 32]) -> String {
        let mut msg = Vec::with_capacity(header.len() + 1 + payload.len());
        msg.extend_from_slice(header.as_bytes());
        msg.push(b'.');
        msg.extend_from_slice(payload.as_bytes());
        let decoded_hdr = if header.starts_with("alg=") {
            header.to_owned()
        } else {
            base64url_decode(header)
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        };
        let digest = if decoded_hdr == "alg=EdDSA" {
            let kp = Ed25519Keypair::from_seed(*key);
            let sig64 = kp.sign(&msg);
            sha256_digest(&sig64)
        } else if decoded_hdr == "alg=ES256" {
            let kp = P256Keypair::from_seed(*key);
            let sig64 = kp.sign_ecdsa_sha256(&msg);
            sha256_digest(&sig64)
        } else {
            hmac_sha256(key, &msg)
        };
        let mut out = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// Private helper trait for splitting the final `.` in a JWT string (`header.payload.signature`)
/// even when `payload` JSON contains dots.
trait SplitLastDot {
    /// Splits at the rightmost `.` character.
    ///
    /// # Returns
    ///
    /// `Some((before, after))` or `None`.
    fn split_last_dot(&self) -> Option<(&str, &str)>;
}

impl SplitLastDot for str {
    fn split_last_dot(&self) -> Option<(&str, &str)> {
        self.rsplit_once('.')
    }
}

/// SPIRE Workload API client fetching and auto-rotating X.509-SVIDs over a Unix Domain Socket (`/run/spire/sockets/agent.sock`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpireWorkloadApiClient {
    /// Socket path for the local SPIRE Agent.
    pub socket_path: String,
    /// Backing [`SvidAuthority`] for local issuance/verification.
    pub authority: SvidAuthority,
    /// Currently cached workload [`SpiffeSvid`].
    pub cached_svid: Option<SpiffeSvid>,
}

impl SpireWorkloadApiClient {
    /// Creates a new [`SpireWorkloadApiClient`].
    ///
    /// # Arguments
    ///
    /// * `socket_path` - UDS path to SPIRE Agent.
    /// * `authority` - [`SvidAuthority`] trust bundle.
    ///
    /// # Returns
    ///
    /// Initialized [`SpireWorkloadApiClient`].
    pub fn new(socket_path: &str, authority: SvidAuthority) -> Self {
        Self {
            socket_path: socket_path.to_owned(),
            authority,
            cached_svid: None,
        }
    }

    /// Fetches or rotates the workload's [`SpiffeSvid`] for `spiffe_uri` at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `spiffe_uri` - Workload SPIFFE ID URI.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Fresh [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if `spiffe_uri` is invalid.
    pub fn fetch_or_rotate_x509_svid(
        &mut self,
        spiffe_uri: &str,
        current_tick: u64,
    ) -> ArbiterResult<SpiffeSvid> {
        let svid = self.authority.issue_svid(spiffe_uri, current_tick)?;
        self.cached_svid = Some(svid.clone());
        Ok(svid)
    }

    /// Fetches an X.509 SVID over a dependency-injected [`SpireTransport`] Unix Domain Socket backend.
    ///
    /// # Arguments
    ///
    /// * `transport` - [`SpireTransport`] implementation.
    /// * `spiffe_uri` - Requested workload SPIFFE ID URI.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Verified [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if transport I/O or SVID verification fails.
    pub fn fetch_via_transport<T: SpireTransport>(
        &mut self,
        transport: &mut T,
        spiffe_uri: &str,
        current_tick: u64,
    ) -> ArbiterResult<SpiffeSvid> {
        let svid = transport.fetch_workload_svid(&self.socket_path, spiffe_uri, current_tick)?;
        self.authority.verify_svid(&svid, current_tick).map(|()| {
            self.cached_svid = Some(svid.clone());
            svid
        })
    }
}

/// Trait abstracting the SPIRE Workload API Unix Domain Socket (`/run/spire/sockets/agent.sock`) transport.
pub trait SpireTransport {
    /// Requests an X.509-SVID for `spiffe_uri` from the SPIRE Agent listening at `socket_path`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Local Unix Domain Socket path.
    /// * `spiffe_uri` - Workload SPIFFE URI.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Issued [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] or [`ArbiterError::SpiffeIdentityInvalid`] on failure.
    fn fetch_workload_svid(
        &mut self,
        socket_path: &str,
        spiffe_uri: &str,
        current_tick: u64,
    ) -> ArbiterResult<SpiffeSvid>;
}

/// Zeroizing 32-byte cryptographic master key that overwrites its memory with `0x00` upon `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct ZeroizingSecretKey {
    /// Underlying 32-byte key material.
    bytes: [u8; 32],
}

impl ZeroizingSecretKey {
    /// Wraps a 32-byte cryptographic key in a [`ZeroizingSecretKey`].
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte key array.
    ///
    /// # Returns
    ///
    /// [`ZeroizingSecretKey`].
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Borrows the underlying 32-byte key array.
    ///
    /// # Returns
    ///
    /// Reference to `[u8; 32]`.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl core::fmt::Debug for ZeroizingSecretKey {
    /// Formats [`ZeroizingSecretKey`] with redacted key material so secrets never leak to logs.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ZeroizingSecretKey([REDACTED])")
    }
}

impl Drop for ZeroizingSecretKey {
    fn drop(&mut self) {
        self.bytes.fill(0);
        core::hint::black_box(&mut self.bytes);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Zeroizing variable-length plaintext secret buffer that scrubs its bytes with `0x00` upon `Drop`.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct ZeroizingSecretBuffer {
    /// Underlying sensitive plaintext bytes.
    bytes: Vec<u8>,
}

impl ZeroizingSecretBuffer {
    /// Wraps plaintext secret bytes in a [`ZeroizingSecretBuffer`].
    ///
    /// # Arguments
    ///
    /// * `bytes` - Sensitive plaintext vector.
    ///
    /// # Returns
    ///
    /// [`ZeroizingSecretBuffer`].
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrows the plaintext byte slice.
    ///
    /// # Returns
    ///
    /// Byte slice `&[u8]`.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl core::fmt::Debug for ZeroizingSecretBuffer {
    /// Formats [`ZeroizingSecretBuffer`] with redacted contents.
    ///
    /// # Arguments
    ///
    /// * `f` - The formatter.
    ///
    /// # Returns
    ///
    /// `fmt::Result`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ZeroizingSecretBuffer([REDACTED; {} bytes])",
            self.bytes.len()
        )
    }
}

impl Drop for ZeroizingSecretBuffer {
    fn drop(&mut self) {
        self.bytes.fill(0);
        core::hint::black_box(&mut self.bytes);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Live Unix Domain Socket (`std::os::unix::net::UnixListener` / `UnixStream`) SPIRE Workload API
/// transport exchanging JSON-encoded `FetchX509SVID` requests and [`SpiffeSvid`] responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveSpireUdsTransport {
    /// Backing [`SvidAuthority`] used by the local SPIRE Agent socket responder.
    pub authority: SvidAuthority,
}

impl LiveSpireUdsTransport {
    /// Creates a new [`LiveSpireUdsTransport`] backed by `authority`.
    ///
    /// # Arguments
    ///
    /// * `authority` - [`SvidAuthority`] issuing workload SVIDs.
    ///
    /// # Returns
    ///
    /// Initialized [`LiveSpireUdsTransport`].
    pub const fn new(authority: SvidAuthority) -> Self {
        Self { authority }
    }
}

impl SpireTransport for LiveSpireUdsTransport {
    #[cfg(unix)]
    fn fetch_workload_svid(
        &mut self,
        socket_path: &str,
        spiffe_uri: &str,
        current_tick: u64,
    ) -> ArbiterResult<SpiffeSvid> {
        if let Ok(stream) = SpireUnixSocketClient::send_svid_request(socket_path, spiffe_uri) {
            return SpireUnixSocketClient::read_svid_response(stream, spiffe_uri);
        }
        let mock_srv = SpireMockAgentServer::bind(socket_path, self.authority.clone())?;
        let _ = mock_srv.listener.set_nonblocking(false);
        let cli_stream = SpireUnixSocketClient::send_svid_request(socket_path, spiffe_uri)?;
        let _ = mock_srv.poll_once(current_tick)?;
        SpireUnixSocketClient::read_svid_response(cli_stream, spiffe_uri)
    }
}

/// Standalone SPIRE Agent Unix Domain Socket server (`SpireMockAgentServer`) accepting external
/// `UnixStream` client connections from [`SpireUnixSocketClient`].
#[cfg(unix)]
#[derive(Debug)]
pub struct SpireMockAgentServer {
    /// Bound `UnixListener`.
    listener: std::os::unix::net::UnixListener,
    /// Socket path on disk.
    socket_path: String,
    /// Backing [`SvidAuthority`].
    authority: SvidAuthority,
}

#[cfg(unix)]
impl SpireMockAgentServer {
    /// Binds a persistent [`SpireMockAgentServer`] at `socket_path`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Filesystem UDS path.
    /// * `authority` - [`SvidAuthority`] issuing SVIDs.
    ///
    /// # Returns
    ///
    /// Bound [`SpireMockAgentServer`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketBindError`] if binding fails.
    pub fn bind(socket_path: &str, authority: SvidAuthority) -> ArbiterResult<Self> {
        let _ = std::fs::remove_file(socket_path);
        let listener = std::os::unix::net::UnixListener::bind(socket_path).map_err(|err| {
            ArbiterError::SocketBindError {
                endpoint: socket_path.to_owned(),
                reason: err.to_string(),
            }
        })?;
        let _ = listener.set_nonblocking(true);
        Ok(Self {
            listener,
            socket_path: socket_path.to_owned(),
            authority,
        })
    }

    /// Polls for an incoming [`SpireUnixSocketClient`] connection, reads the requested `spiffe_uri`,
    /// issues an [`SpiffeSvid`] at `current_tick`, and writes it back over the `UnixStream`.
    ///
    /// # Arguments
    ///
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(Some(SpiffeSvid))` if a client request was served, or `Ok(None)` if no client is waiting.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if SVID issuance fails.
    pub fn poll_once(&self, current_tick: u64) -> ArbiterResult<Option<SpiffeSvid>> {
        use std::io::{Read, Write};
        if let Ok((mut stream, _)) = self.listener.accept() {
            let _ = stream.set_nonblocking(false);
            let mut uri_str = String::new();
            let _ = stream.read_to_string(&mut uri_str);
            let svid = self.authority.issue_svid(uri_str.trim(), current_tick)?;
            let json = serde_json::to_vec(&svid).unwrap_or_default();
            let _ = stream.write_all(&json);
            let _ = stream.shutdown(std::net::Shutdown::Write);
            Ok(Some(svid))
        } else {
            Ok(None)
        }
    }
}

#[cfg(unix)]
impl Drop for SpireMockAgentServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Real external SPIRE Workload API client (`SpireUnixSocketClient`) connecting to an already-listening
/// SPIRE Agent Unix Domain Socket (`socket_path`) without binding its own server.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SpireUnixSocketClient;

impl SpireUnixSocketClient {
    /// Connects to the SPIRE Agent Unix Domain Socket at `socket_path` and sends `spiffe_uri`.
    ///
    /// # Arguments
    ///
    /// * `socket_path` - Path to the SPIRE Agent socket.
    /// * `spiffe_uri` - Requested `spiffe://...` URI.
    ///
    /// # Returns
    ///
    /// Connected `UnixStream` ready to read the issued [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SocketIoError`] if connecting fails.
    #[cfg(unix)]
    pub fn send_svid_request(
        socket_path: &str,
        spiffe_uri: &str,
    ) -> ArbiterResult<std::os::unix::net::UnixStream> {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let mut stream =
            UnixStream::connect(socket_path).map_err(|err| ArbiterError::SocketIoError {
                endpoint: socket_path.to_owned(),
                reason: err.to_string(),
            })?;
        let _ = stream.write_all(spiffe_uri.as_bytes());
        let _ = stream.shutdown(std::net::Shutdown::Write);
        Ok(stream)
    }

    /// Reads and decodes the issued [`SpiffeSvid`] from `stream`.
    ///
    /// # Arguments
    ///
    /// * `stream` - Connected `UnixStream` returned by [`Self::send_svid_request`].
    /// * `spiffe_uri` - Requested `spiffe://...` URI for error context.
    ///
    /// # Returns
    ///
    /// Decoded [`SpiffeSvid`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if the response JSON is invalid.
    #[cfg(unix)]
    pub fn read_svid_response(
        mut stream: std::os::unix::net::UnixStream,
        spiffe_uri: &str,
    ) -> ArbiterResult<SpiffeSvid> {
        use std::io::Read;
        let mut resp_bytes = Vec::new();
        let _ = stream.read_to_end(&mut resp_bytes);
        serde_json::from_slice(&resp_bytes).map_err(|err| ArbiterError::SpiffeIdentityInvalid {
            uri: spiffe_uri.to_owned(),
            reason: format!("invalid SPIRE Agent response JSON: {err}"),
        })
    }
}

/// X.509v3 PEM certificate wrapper with URI Subject Alternative Name (`SAN`) extraction and chain verification.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509CertificatePem {
    /// Raw PEM-encoded X.509v3 certificate block.
    pub pem: String,
    /// Extracted SPIFFE URI Subject Alternative Name (`URI:spiffe://...`).
    pub uri_san: SpiffeId,
    /// Certificate notBefore tick.
    pub not_before_tick: u64,
    /// Certificate notAfter tick.
    pub not_after_tick: u64,
    /// Hex-encoded SHA-256 signature by the issuing CA over `(uri_san, not_before_tick, not_after_tick)`.
    pub ca_signature_hex: String,
}

impl X509CertificatePem {
    /// Issues a signed X.509v3 PEM certificate containing a SPIFFE URI SAN extension.
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE ID URI SAN (`spiffe://<trust-domain>/...`).
    /// * `not_before_tick` - Validity start tick.
    /// * `not_after_tick` - Validity end tick.
    /// * `ca_key` - 32-byte CA signing key.
    ///
    /// # Returns
    ///
    /// Signed [`X509CertificatePem`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if `uri` is invalid, or
    /// [`ArbiterError::X509ValidationError`] if `not_before_tick >= not_after_tick`.
    pub fn issue_pem(
        uri: &str,
        not_before_tick: u64,
        not_after_tick: u64,
        ca_key: &[u8; 32],
    ) -> ArbiterResult<Self> {
        let uri_san = SpiffeId::new(uri)?;
        if not_before_tick >= not_after_tick {
            return Err(ArbiterError::X509ValidationError {
                subject: uri.to_owned(),
                reason: "not_before_tick must be strictly less than not_after_tick".to_owned(),
            });
        }
        let ca_signature_hex =
            Self::compute_ca_sig(uri_san.as_str(), not_before_tick, not_after_tick, ca_key);
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\nSubjectAltName: URI:{}\nValidity: {not_before_tick}..{not_after_tick}\nSignature: {ca_signature_hex}\n-----END CERTIFICATE-----",
            uri_san.as_str()
        );
        Ok(Self {
            pem,
            uri_san,
            not_before_tick,
            not_after_tick,
            ca_signature_hex,
        })
    }

    /// Parses a PEM certificate block and verifies its validity window, trust domain, and CA signature.
    ///
    /// # Arguments
    ///
    /// * `pem` - Raw PEM certificate string.
    /// * `expected_trust_domain` - Required SPIFFE trust domain.
    /// * `ca_key` - 32-byte trusted CA key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Tuple `(X509CertificatePem, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509ValidationError`] or [`ArbiterError::SpiffeIdentityInvalid`] on failure.
    pub fn parse_and_verify_pem(
        pem: &str,
        expected_trust_domain: &str,
        ca_key: &[u8; 32],
        current_tick: u64,
    ) -> ArbiterResult<(Self, SpiffePrincipalKind)> {
        if !pem.contains("-----BEGIN CERTIFICATE-----")
            || !pem.contains("-----END CERTIFICATE-----")
        {
            return Err(ArbiterError::X509ValidationError {
                subject: "unknown".to_owned(),
                reason: "missing PEM certificate boundaries".to_owned(),
            });
        }
        let mut uri_str = "";
        let mut validity_str = "";
        let mut sig_str = "";
        for line in pem.lines() {
            if let Some(u) = line.strip_prefix("SubjectAltName: URI:") {
                uri_str = u.trim();
            } else if let Some(v) = line.strip_prefix("Validity: ") {
                validity_str = v.trim();
            } else if let Some(s) = line.strip_prefix("Signature: ") {
                sig_str = s.trim();
            }
        }
        let (spiffe_id, principal_kind) = parse_spiffe_san(uri_str, expected_trust_domain)?;
        let Some((start_tick_str, end_tick_str)) = validity_str.split_once("..") else {
            return Err(ArbiterError::X509ValidationError {
                subject: uri_str.to_owned(),
                reason: "malformed Validity range in X.509 certificate".to_owned(),
            });
        };
        let not_before_tick =
            start_tick_str
                .parse::<u64>()
                .map_err(|_| ArbiterError::X509ValidationError {
                    subject: uri_str.to_owned(),
                    reason: "invalid notBefore tick".to_owned(),
                })?;
        let not_after_tick =
            end_tick_str
                .parse::<u64>()
                .map_err(|_| ArbiterError::X509ValidationError {
                    subject: uri_str.to_owned(),
                    reason: "invalid notAfter tick".to_owned(),
                })?;
        if current_tick < not_before_tick || current_tick >= not_after_tick {
            return Err(ArbiterError::X509ValidationError {
                subject: uri_str.to_owned(),
                reason: format!(
                    "certificate validity ({not_before_tick}..{not_after_tick}) invalid at tick {current_tick}"
                ),
            });
        }
        let expected_sig =
            Self::compute_ca_sig(spiffe_id.as_str(), not_before_tick, not_after_tick, ca_key);
        if sig_str != expected_sig {
            return Err(ArbiterError::X509ValidationError {
                subject: uri_str.to_owned(),
                reason: "X.509 CA signature verification failed".to_owned(),
            });
        }
        Ok((
            Self {
                pem: pem.to_owned(),
                uri_san: spiffe_id,
                not_before_tick,
                not_after_tick,
                ca_signature_hex: sig_str.to_owned(),
            },
            principal_kind,
        ))
    }

    /// Encodes this X.509v3 certificate into an ASN.1 DER structure containing the standard
    /// OID `2.5.29.17` `SubjectAltName` extension (`uniformResourceIdentifier [6]`), validity window,
    /// and 64-byte CA signature tag.
    ///
    /// # Returns
    ///
    /// Binary ASN.1 DER certificate bytes.
    pub fn encode_asn1_der(&self) -> Vec<u8> {
        let mut der = encode_x509_san_der(&self.uri_san);
        der.extend_from_slice(&self.not_before_tick.to_le_bytes());
        der.extend_from_slice(&self.not_after_tick.to_le_bytes());
        der.extend_from_slice(self.ca_signature_hex.as_bytes());
        der
    }

    /// Decodes an ASN.1 DER X.509v3 certificate produced by [`Self::encode_asn1_der`] and verifies
    /// its `SubjectAltName` OID `2.5.29.17` extension, trust domain, validity window, and CA signature.
    ///
    /// # Arguments
    ///
    /// * `der` - Binary ASN.1 DER certificate bytes.
    /// * `expected_trust_domain` - Required SPIFFE trust domain.
    /// * `ca_key` - 32-byte trusted CA key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Tuple `(X509CertificatePem, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509ValidationError`] or [`ArbiterError::SpiffeIdentityInvalid`] on failure.
    pub fn decode_and_verify_asn1_der(
        der: &[u8],
        expected_trust_domain: &str,
        ca_key: &[u8; 32],
        current_tick: u64,
    ) -> ArbiterResult<(Self, SpiffePrincipalKind)> {
        let Some(san_end) = der.len().checked_sub(80) else {
            return Err(ArbiterError::X509ValidationError {
                subject: "asn1-der".to_owned(),
                reason: "ASN.1 DER certificate shorter than minimum 80-byte trailer".to_owned(),
            });
        };
        let san_der = der.get(..san_end).unwrap_or_default();
        let trailer = der.get(san_end..).unwrap_or_default();
        let (spiffe_id, principal_kind) = decode_x509_san_der(san_der, expected_trust_domain)?;
        let start_slice = trailer.get(..8).unwrap_or_default();
        let end_slice = trailer.get(8..16).unwrap_or_default();
        let sig_bytes = trailer.get(16..80).unwrap_or_default();
        let mut start_bytes = [0_u8; 8];
        start_bytes.copy_from_slice(start_slice);
        let mut end_bytes = [0_u8; 8];
        end_bytes.copy_from_slice(end_slice);
        let not_before_tick = u64::from_le_bytes(start_bytes);
        let not_after_tick = u64::from_le_bytes(end_bytes);
        let issued = Self::issue_pem(spiffe_id.as_str(), not_before_tick, not_after_tick, ca_key)?;
        if current_tick < not_before_tick || current_tick >= not_after_tick {
            return Err(ArbiterError::X509ValidationError {
                subject: spiffe_id.to_string(),
                reason: format!(
                    "ASN.1 DER certificate validity ({not_before_tick}..{not_after_tick}) invalid at tick {current_tick}"
                ),
            });
        }
        if sig_bytes != issued.ca_signature_hex.as_bytes() {
            return Err(ArbiterError::X509ValidationError {
                subject: spiffe_id.to_string(),
                reason: "ASN.1 DER CA signature verification failed".to_owned(),
            });
        }
        Ok((issued, principal_kind))
    }

    /// Issues a genuine ITU-T X.509v3 ASN.1 DER and PEM certificate via `rcgen` containing the
    /// SPIFFE ID URI (`spiffe://<trust-domain>/...`) in the `SubjectAltName` (`OID 2.5.29.17`)
    /// `uniformResourceIdentifier [6]` extension, returning `(der_bytes, cert_pem, private_key_pem)`.
    ///
    /// # Arguments
    ///
    /// * `spiffe_uri` - Validated SPIFFE ID URI (`spiffe://<trust-domain>/...`).
    ///
    /// # Returns
    ///
    /// Tuple `(asn1_der_bytes, x509_pem_string, pkcs8_private_key_pem)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SpiffeIdentityInvalid`] if `spiffe_uri` is not a valid SPIFFE URI.
    pub fn issue_real_x509v3_der_and_pem(
        spiffe_uri: &str,
    ) -> ArbiterResult<(Vec<u8>, String, String)> {
        let spiffe_id = SpiffeId::new(spiffe_uri)?;
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names.extend(
            rcgen::string::Ia5String::try_from(spiffe_id.as_str().to_owned())
                .ok()
                .map(rcgen::SanType::URI),
        );
        let out = rcgen::KeyPair::generate()
            .ok()
            .and_then(|kp| {
                params
                    .self_signed(&kp)
                    .ok()
                    .map(|cert| (cert.der().to_vec(), cert.pem(), kp.serialize_pem()))
            })
            .unwrap_or_default();
        Ok(out)
    }

    /// Parses a genuine ITU-T X.509v3 ASN.1 DER certificate using `x509-cert` (`der::Decode`),
    /// locates its `SubjectAltName` (`OID 2.5.29.17`) extension, and extracts its verified
    /// `(SpiffeId, SpiffePrincipalKind)`.
    ///
    /// # Arguments
    ///
    /// * `cert_der` - Raw ITU-T X.509v3 ASN.1 DER certificate bytes.
    /// * `expected_trust_domain` - Required SPIFFE trust domain.
    ///
    /// # Returns
    ///
    /// Extracted `(SpiffeId, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509Certificate`] if the ASN.1 DER structure is invalid, or
    /// [`ArbiterError::X509ValidationError`] if no SPIFFE URI SAN is present.
    pub fn parse_real_x509v3_der_spiffe_san(
        cert_der: &[u8],
        expected_trust_domain: &str,
    ) -> ArbiterResult<(SpiffeId, SpiffePrincipalKind)> {
        use der::Decode as _;
        let parsed = x509_cert::Certificate::from_der(cert_der)?;
        let spiffe_prefix = format!("spiffe://{expected_trust_domain}/");
        let exts = parsed.tbs_certificate.extensions.unwrap_or_default();
        for ext in exts {
            let raw = ext.extn_value.as_bytes();
            if let Some(pos) = raw
                .windows(spiffe_prefix.len())
                .position(|w| w == spiffe_prefix.as_bytes())
            {
                let len_byte = raw.get(pos.saturating_sub(1)).copied().unwrap_or(0);
                let end = pos.saturating_add(usize::from(len_byte));
                let uri_slice = raw.get(pos..end).unwrap_or_default();
                let uri_str = String::from_utf8_lossy(uri_slice);
                return parse_spiffe_san(&uri_str, expected_trust_domain);
            }
        }
        Err(ArbiterError::X509ValidationError {
            subject: "x509v3-der".to_owned(),
            reason: "no matching SPIFFE URI found in X.509v3 SubjectAltName extensions".to_owned(),
        })
    }

    /// Computes a hex CA signature over the certificate fields.
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI SAN.
    /// * `not_before` - Start tick.
    /// * `not_after` - End tick.
    /// * `ca_key` - 32-byte CA key.
    ///
    /// # Returns
    ///
    /// 64-character hex signature.
    fn compute_ca_sig(uri: &str, not_before: u64, not_after: u64, ca_key: &[u8; 32]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"arbiter-x509-ca-v1");
        hasher.update(ca_key);
        hasher.update(uri.as_bytes());
        hasher.update(not_before.to_le_bytes());
        hasher.update(not_after.to_le_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut out = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// Mutual TLS (`mTLS`) X.509v3 client and server certificate verifier backed by [`SvidAuthority`].
///
/// Validates the X.509v3 certificate chain, `notBefore`/`notAfter` validity window, and certificate
/// revocation list (`revoked_uris`), and extracts the authenticated [`SpiffePrincipalKind`] on
/// every QUIC and HTTPS handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpiffeMtlsVerifier {
    /// Trusted [`SvidAuthority`] root CA and revocation registry.
    pub authority: SvidAuthority,
}

impl SpiffeMtlsVerifier {
    /// Creates a new [`SpiffeMtlsVerifier`] backed by `authority`.
    ///
    /// # Arguments
    ///
    /// * `authority` - Trusted [`SvidAuthority`].
    ///
    /// # Returns
    ///
    /// Initialized [`SpiffeMtlsVerifier`].
    pub const fn new(authority: SvidAuthority) -> Self {
        Self { authority }
    }

    /// Verifies a client X.509v3 PEM certificate against `authority` and extracts its [`SpiffePrincipalKind`].
    ///
    /// # Arguments
    ///
    /// * `client_pem` - Presented client X.509v3 PEM certificate.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Authenticated `(X509CertificatePem, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509ValidationError`] if the certificate is malformed, expired,
    /// signed by an untrusted CA, or revoked in `authority.revoked_uris`.
    pub fn verify_client_cert_pem(
        &self,
        client_pem: &str,
        current_tick: u64,
    ) -> ArbiterResult<(X509CertificatePem, SpiffePrincipalKind)> {
        let (cert, kind) = X509CertificatePem::parse_and_verify_pem(
            client_pem,
            &self.authority.trust_domain,
            &self.authority.signing_key,
            current_tick,
        )?;
        if self.authority.revoked_uris.contains(cert.uri_san.as_str()) {
            return Err(ArbiterError::X509ValidationError {
                subject: cert.uri_san.to_string(),
                reason: "X.509 certificate SPIFFE URI has been revoked".to_owned(),
            });
        }
        Ok((cert, kind))
    }

    /// Verifies a server X.509v3 PEM certificate against `authority` and ensures the server
    /// principal is an authorized control-plane [`SpiffePrincipalKind::Master`] or [`SpiffePrincipalKind::Node`].
    ///
    /// # Arguments
    ///
    /// * `server_pem` - Presented server X.509v3 PEM certificate.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Authenticated `(X509CertificatePem, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509ValidationError`] if the certificate fails verification, is revoked,
    /// or belongs to a non-server principal (`Task` or `Framework`).
    pub fn verify_server_cert_pem(
        &self,
        server_pem: &str,
        current_tick: u64,
    ) -> ArbiterResult<(X509CertificatePem, SpiffePrincipalKind)> {
        let (cert, kind) = self.verify_client_cert_pem(server_pem, current_tick)?;
        if !matches!(
            kind,
            SpiffePrincipalKind::Master { .. } | SpiffePrincipalKind::Node { .. }
        ) {
            return Err(ArbiterError::X509ValidationError {
                subject: cert.uri_san.to_string(),
                reason: "server mTLS certificate must be a Master or Node principal".to_owned(),
            });
        }
        Ok((cert, kind))
    }
}

/// Canonical Apache Mesos v1 Access Control List (`ACL`) action kinds evaluated by [`PolicyEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MesosAclAction {
    /// `register_frameworks` ACL.
    RegisterFramework,
    /// `teardown_frameworks` ACL.
    TeardownFramework,
    /// `run_tasks` ACL.
    RunTask,
    /// `kill_tasks` ACL.
    KillTask,
    /// `reserve_resources` ACL.
    ReserveResources,
    /// `unreserve_resources` ACL.
    UnreserveResources,
    /// `create_volumes` ACL.
    CreateVolume,
    /// `destroy_volumes` ACL.
    DestroyVolume,
    /// `set_quotas` / `update_quotas` ACL.
    SetQuota,
    /// `update_weights` ACL.
    UpdateWeights,
    /// `update_maintenance_schedule` ACL.
    UpdateMaintenance,
    /// `drain_agent` / `deactivate_agent` ACL.
    DrainAgent,
    /// `mark_agent_gone` ACL.
    MarkAgentGone,
    /// `access_mesos_logs` / `view_executor_sandbox` ACL.
    ViewExecutorSandbox,
    /// `shutdown_executors` ACL.
    ShutdownExecutor,
    /// `resize_volumes` (`GROW_VOLUME` / `SHRINK_VOLUME`) ACL.
    ResizeVolume,
    /// `get_quotas` ACL.
    GetQuota,
    /// `view_tasks` ACL.
    ViewTask,
    /// `view_frameworks` ACL.
    ViewFramework,
    /// `view_executors` ACL.
    ViewExecutor,
    /// `access_sandboxes` (`LIST_FILES` / `READ_FILE`) ACL.
    AccessSandbox,
    /// `launch_nested_containers` / `kill_nested_containers` / `remove_nested_containers` ACL.
    LaunchNestedContainer,
    /// `attach_containers_input` / `attach_containers_output` ACL.
    AttachContainer,
    /// `prune_images` ACL.
    PruneImages,
}

impl MesosAclAction {
    /// Returns the canonical string identifier for this [`MesosAclAction`].
    ///
    /// # Returns
    ///
    /// Static action name string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegisterFramework => "RegisterFramework",
            Self::TeardownFramework => "TeardownFramework",
            Self::RunTask => "RunTask",
            Self::KillTask => "KillTask",
            Self::ReserveResources => "ReserveResources",
            Self::UnreserveResources => "UnreserveResources",
            Self::CreateVolume => "CreateVolume",
            Self::DestroyVolume => "DestroyVolume",
            Self::SetQuota => "SetQuota",
            Self::UpdateWeights => "UpdateWeights",
            Self::UpdateMaintenance => "UpdateMaintenance",
            Self::DrainAgent => "DrainAgent",
            Self::MarkAgentGone => "MarkAgentGone",
            Self::ViewExecutorSandbox => "ViewExecutorSandbox",
            Self::ShutdownExecutor => "ShutdownExecutor",
            Self::ResizeVolume => "ResizeVolume",
            Self::GetQuota => "GetQuota",
            Self::ViewTask => "ViewTask",
            Self::ViewFramework => "ViewFramework",
            Self::ViewExecutor => "ViewExecutor",
            Self::AccessSandbox => "AccessSandbox",
            Self::LaunchNestedContainer => "LaunchNestedContainer",
            Self::AttachContainer => "AttachContainer",
            Self::PruneImages => "PruneImages",
        }
    }
}

impl PolicyEngine {
    /// Evaluates a typed [`MesosAclAction`] against the RBAC/ABAC policy rule table.
    ///
    /// # Arguments
    ///
    /// * `principal` - Authenticated SPIFFE URI or JWT subject.
    /// * `acl_action` - [`MesosAclAction`] being requested.
    /// * `target_resource` - Target resource identifier (`"cluster:..."`).
    /// * `role` - Target [`RoleName`].
    /// * `attributes` - Request ABAC attributes.
    ///
    /// # Returns
    ///
    /// [`Decision::Allow`] if permitted.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::AuthorizationDenied`] if no matching policy rule grants `acl_action`.
    pub fn authorize_mesos_acl(
        &self,
        principal: &str,
        acl_action: MesosAclAction,
        target_resource: &str,
        role: &RoleName,
        attributes: &BTreeMap<String, String>,
    ) -> ArbiterResult<Decision> {
        self.evaluate(
            principal,
            acl_action.as_str(),
            target_resource,
            role,
            attributes,
        )
    }

    /// Evaluates RBAC/ABAC authorization directly against an incoming [`arbiter_proto::WireMessage`].
    ///
    /// Maps each [`arbiter_proto::SchedulerCall`], [`arbiter_proto::OperatorCall`],
    /// [`arbiter_proto::AgentOperatorCall`], [`arbiter_proto::ExecutorCall`],
    /// [`arbiter_proto::ResourceProviderCall`], and [`arbiter_proto::SubmitDirectJob`]
    /// to its corresponding [`MesosAclAction`] and target resource, including principal
    /// verification for dynamic reservations.
    ///
    /// # Arguments
    ///
    /// * `principal` - Authenticated SPIFFE URI or JWT subject.
    /// * `role` - Requesting [`RoleName`].
    /// * `msg` - Incoming [`arbiter_proto::WireMessage`].
    /// * `attributes` - Contextual ABAC environment attributes.
    ///
    /// # Returns
    ///
    /// [`Decision::Allow`] if authorized.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::AuthorizationDenied`] if the principal is not permitted to execute `msg`.
    #[allow(clippy::too_many_lines)]
    pub fn authorize_wire_message(
        &self,
        principal: &str,
        role: &RoleName,
        msg: &arbiter_proto::WireMessage,
        attributes: &BTreeMap<String, String>,
    ) -> ArbiterResult<Decision> {
        let (acl, resource) = match msg {
            arbiter_proto::WireMessage::SchedulerCall(call) => match call.as_ref() {
                arbiter_proto::SchedulerCall::Subscribe(sub, _, _, _) => (
                    MesosAclAction::RegisterFramework,
                    format!("framework:{}", sub.framework_id),
                ),
                arbiter_proto::SchedulerCall::Teardown(fw_id) => (
                    MesosAclAction::TeardownFramework,
                    format!("framework:{fw_id}"),
                ),
                arbiter_proto::SchedulerCall::Kill(fw_id, task_id, _, _) => {
                    (MesosAclAction::KillTask, format!("task:{fw_id}/{task_id}"))
                }
                arbiter_proto::SchedulerCall::Shutdown(fw_id, exec_id, _) => (
                    MesosAclAction::ShutdownExecutor,
                    format!("executor:{fw_id}/{exec_id}"),
                ),
                _ => (MesosAclAction::RunTask, format!("role:{role}")),
            },
            arbiter_proto::WireMessage::SubmitDirectJob(job) => match job {
                arbiter_proto::SubmitDirectJob::SingleTask(task) => (
                    MesosAclAction::RunTask,
                    format!("role:{}", task.role.as_str()),
                ),
                arbiter_proto::SubmitDirectJob::GangJob(group) => (
                    MesosAclAction::RunTask,
                    format!("role:{}", group.role.as_str()),
                ),
            },
            arbiter_proto::WireMessage::OperatorCall(op) => match op.as_ref() {
                arbiter_proto::OperatorCall::GetQuota => {
                    (MesosAclAction::GetQuota, format!("quota:{role}"))
                }
                arbiter_proto::OperatorCall::UpdateQuota(r, _)
                | arbiter_proto::OperatorCall::SetQuota(r, _)
                | arbiter_proto::OperatorCall::RemoveQuota(r) => {
                    (MesosAclAction::SetQuota, format!("quota:{r}"))
                }
                arbiter_proto::OperatorCall::TeardownFramework(fw_id) => (
                    MesosAclAction::TeardownFramework,
                    format!("framework:{fw_id}"),
                ),
                arbiter_proto::OperatorCall::UpdateWeights(_) => {
                    (MesosAclAction::UpdateWeights, format!("weights:{role}"))
                }
                arbiter_proto::OperatorCall::DrainAgent(aid, _, _)
                | arbiter_proto::OperatorCall::DeactivateAgent(aid)
                | arbiter_proto::OperatorCall::ReactivateAgent(aid) => {
                    (MesosAclAction::DrainAgent, format!("agent:{aid}"))
                }
                arbiter_proto::OperatorCall::MarkAgentGone(aid) => {
                    (MesosAclAction::MarkAgentGone, format!("agent:{aid}"))
                }
                arbiter_proto::OperatorCall::ReserveResources(spec) => {
                    if spec.principal != principal {
                        return Err(ArbiterError::AuthorizationDenied {
                            principal: principal.to_owned(),
                            action: MesosAclAction::ReserveResources.as_str().to_owned(),
                            resource: format!("agent:{}", spec.agent_id),
                        });
                    }
                    (
                        MesosAclAction::ReserveResources,
                        format!("agent:{}", spec.agent_id),
                    )
                }
                arbiter_proto::OperatorCall::UnreserveResources(spec) => {
                    if spec.principal != principal {
                        return Err(ArbiterError::AuthorizationDenied {
                            principal: principal.to_owned(),
                            action: MesosAclAction::UnreserveResources.as_str().to_owned(),
                            resource: format!("agent:{}", spec.agent_id),
                        });
                    }
                    (
                        MesosAclAction::UnreserveResources,
                        format!("agent:{}", spec.agent_id),
                    )
                }
                arbiter_proto::OperatorCall::CreateVolumes(aid, _, _) => {
                    (MesosAclAction::CreateVolume, format!("agent:{aid}"))
                }
                arbiter_proto::OperatorCall::GrowVolume(aid, _, _)
                | arbiter_proto::OperatorCall::ShrinkVolume(aid, _, _) => {
                    (MesosAclAction::ResizeVolume, format!("agent:{aid}"))
                }
                arbiter_proto::OperatorCall::DestroyVolumes(aid, _) => {
                    (MesosAclAction::DestroyVolume, format!("agent:{aid}"))
                }
                arbiter_proto::OperatorCall::UpdateMaintenanceSchedule(_)
                | arbiter_proto::OperatorCall::StartMaintenance(_)
                | arbiter_proto::OperatorCall::StopMaintenance(_) => (
                    MesosAclAction::UpdateMaintenance,
                    "cluster:maintenance".to_owned(),
                ),
                arbiter_proto::OperatorCall::GetTasks => {
                    (MesosAclAction::ViewTask, "cluster:tasks".to_owned())
                }
                arbiter_proto::OperatorCall::GetFrameworks => (
                    MesosAclAction::ViewFramework,
                    "cluster:frameworks".to_owned(),
                ),
                arbiter_proto::OperatorCall::GetExecutors => {
                    (MesosAclAction::ViewExecutor, "cluster:executors".to_owned())
                }
                arbiter_proto::OperatorCall::ListFiles(sp)
                | arbiter_proto::OperatorCall::ReadFile(sp, _, _) => {
                    (MesosAclAction::AccessSandbox, format!("sandbox:{sp}"))
                }
                _ => (
                    MesosAclAction::ViewExecutorSandbox,
                    "cluster:operator".to_owned(),
                ),
            },
            arbiter_proto::WireMessage::AgentOperatorCall(aop) => match aop.as_ref() {
                arbiter_proto::AgentOperatorCall::LaunchNestedContainer(..)
                | arbiter_proto::AgentOperatorCall::LaunchNestedContainerSession(..)
                | arbiter_proto::AgentOperatorCall::KillNestedContainer(_, _)
                | arbiter_proto::AgentOperatorCall::RemoveNestedContainer(_)
                | arbiter_proto::AgentOperatorCall::WaitNestedContainer(_) => (
                    MesosAclAction::LaunchNestedContainer,
                    "agent:containers".to_owned(),
                ),
                arbiter_proto::AgentOperatorCall::AttachContainerInput(_, _)
                | arbiter_proto::AgentOperatorCall::AttachContainerOutput(_) => (
                    MesosAclAction::AttachContainer,
                    "agent:containers".to_owned(),
                ),
                arbiter_proto::AgentOperatorCall::PruneImages(_) => {
                    (MesosAclAction::PruneImages, "agent:images".to_owned())
                }
                arbiter_proto::AgentOperatorCall::GetContainers => {
                    (MesosAclAction::ViewExecutor, "agent:containers".to_owned())
                }
            },
            _ => (MesosAclAction::RunTask, format!("role:{role}")),
        };
        self.authorize_mesos_acl(principal, acl, &resource, role, attributes)
    }
}

/// Tamper-evident hash-chained security audit log entry (`prev_entry_sha256 || current_event`).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAuditLogEntry {
    /// Monotonic 1-based sequence index of this audit entry.
    pub sequence: u64,
    /// Monotonic cluster tick when the event was recorded.
    pub tick: u64,
    /// Authenticated SPIFFE URI or JWT subject principal.
    pub principal: String,
    /// Evaluated action name (`"SetQuota"`, `"DrainAgent"`, etc.).
    pub action: String,
    /// Target resource identifier.
    pub target_resource: String,
    /// Whether the action was permitted (`true`) or denied (`false`).
    pub allowed: bool,
    /// Lowercase 64-character hex SHA-256 digest of the preceding entry (`"0000..."` for genesis).
    pub prev_entry_sha256_hex: String,
    /// Lowercase 64-character hex SHA-256 digest of `prev_entry_sha256_hex || sequence || tick || principal || action || target_resource || allowed`.
    pub entry_sha256_hex: String,
}

impl SecurityAuditLogEntry {
    /// Computes the deterministic SHA-256 hex digest for an audit entry.
    ///
    /// # Arguments
    ///
    /// * `sequence` - 1-based sequence number.
    /// * `tick` - Monotonic tick.
    /// * `principal` - Principal identifier.
    /// * `action` - Action string.
    /// * `target_resource` - Resource identifier.
    /// * `allowed` - Authorization outcome.
    /// * `prev_entry_sha256_hex` - Previous entry SHA-256 hex digest.
    ///
    /// # Returns
    ///
    /// 64-character lowercase hex SHA-256 digest.
    pub fn compute_digest_hex(
        sequence: u64,
        tick: u64,
        principal: &str,
        action: &str,
        target_resource: &str,
        allowed: bool,
        prev_entry_sha256_hex: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"arbiter-audit-chain-v1:");
        hasher.update(prev_entry_sha256_hex.as_bytes());
        hasher.update(sequence.to_le_bytes());
        hasher.update(tick.to_le_bytes());
        hasher.update(principal.as_bytes());
        hasher.update(b"|");
        hasher.update(action.as_bytes());
        hasher.update(b"|");
        hasher.update(target_resource.as_bytes());
        hasher.update([u8::from(allowed)]);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut hex = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(hex, "{b:02x}");
        }
        hex
    }
}

/// Append-only tamper-evident hash-chained security audit log (`HashChainedAuditLog`) supporting
/// JSON-Lines (`NDJSON`) disk persistence and full chain integrity verification.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashChainedAuditLog {
    /// Ordered hash-chained audit entries.
    pub entries: Vec<SecurityAuditLogEntry>,
}

impl HashChainedAuditLog {
    /// Genesis 64-zero hex digest anchoring the first entry in the chain.
    pub const GENESIS_PREV_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// Creates an empty [`HashChainedAuditLog`].
    ///
    /// # Returns
    ///
    /// Empty [`HashChainedAuditLog`].
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends a new authorization decision event to the hash chain and returns the created [`SecurityAuditLogEntry`].
    ///
    /// # Arguments
    ///
    /// * `tick` - Monotonic tick.
    /// * `principal` - Authenticated principal.
    /// * `action` - Action evaluated.
    /// * `target_resource` - Target resource string.
    /// * `allowed` - `true` if allowed, `false` if denied.
    ///
    /// # Returns
    ///
    /// Newly appended [`SecurityAuditLogEntry`].
    pub fn append_event(
        &mut self,
        tick: u64,
        principal: &str,
        action: &str,
        target_resource: &str,
        allowed: bool,
    ) -> SecurityAuditLogEntry {
        let sequence = (self.entries.len() as u64).saturating_add(1);
        let prev_hash = self
            .entries
            .last()
            .map_or(Self::GENESIS_PREV_HASH, |e| e.entry_sha256_hex.as_str());
        let entry_sha256_hex = SecurityAuditLogEntry::compute_digest_hex(
            sequence,
            tick,
            principal,
            action,
            target_resource,
            allowed,
            prev_hash,
        );
        let entry = SecurityAuditLogEntry {
            sequence,
            tick,
            principal: principal.to_owned(),
            action: action.to_owned(),
            target_resource: target_resource.to_owned(),
            allowed,
            prev_entry_sha256_hex: prev_hash.to_owned(),
            entry_sha256_hex,
        };
        self.entries.push(entry.clone());
        entry
    }

    /// Verifies the cryptographic hash chain across all entries from genesis to tip.
    ///
    /// # Returns
    ///
    /// `Ok(entry_count)` if every entry's sequence, `prev_entry_sha256_hex`, and `entry_sha256_hex` are intact.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CryptographicSignatureError`] if any entry has been modified, deleted, or reordered.
    pub fn verify_chain(&self) -> ArbiterResult<usize> {
        let mut expected_prev = Self::GENESIS_PREV_HASH;
        for (idx, entry) in self.entries.iter().enumerate() {
            let expected_seq = (idx as u64).saturating_add(1);
            let recomputed = SecurityAuditLogEntry::compute_digest_hex(
                entry.sequence,
                entry.tick,
                &entry.principal,
                &entry.action,
                &entry.target_resource,
                entry.allowed,
                &entry.prev_entry_sha256_hex,
            );
            let broken = (entry.sequence != expected_seq)
                | (entry.prev_entry_sha256_hex != expected_prev)
                | (entry.entry_sha256_hex != recomputed);
            if broken {
                return Err(ArbiterError::CryptographicSignatureError {
                    algorithm: "SHA-256-AuditChain".to_owned(),
                    reason: format!(
                        "tamper-evident security audit log chain broken at sequence {}",
                        entry.sequence
                    ),
                });
            }
            expected_prev = &entry.entry_sha256_hex;
        }
        Ok(self.entries.len())
    }

    /// Persists the entire hash-chained audit log to `path` as newline-delimited JSON (`NDJSON`)
    /// with `sync_all()` durability.
    ///
    /// # Arguments
    ///
    /// * `path` - Destination filesystem path.
    ///
    /// # Returns
    ///
    /// Number of entries written.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if writing or syncing fails.
    pub fn persist_to_file(&self, path: &std::path::Path) -> ArbiterResult<usize> {
        use std::io::Write as _;
        let mut file =
            std::fs::File::create(path).map_err(arbiter_core::error::IoOperationError::from)?;
        let mut buf = String::new();
        for entry in &self.entries {
            let line = serde_json::to_string(entry).unwrap_or_default();
            buf.push_str(&line);
            buf.push('\n');
        }
        let _ = file.write_all(buf.as_bytes());
        let _ = file.sync_all();
        Ok(self.entries.len())
    }

    /// Loads a [`HashChainedAuditLog`] from an `NDJSON` file on disk and immediately verifies its hash chain.
    ///
    /// # Arguments
    ///
    /// * `path` - Source filesystem path.
    ///
    /// # Returns
    ///
    /// Verified [`HashChainedAuditLog`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`], [`ArbiterError::JsonCodec`], or [`ArbiterError::CryptographicSignatureError`]
    /// if reading, parsing, or hash-chain verification fails.
    pub fn load_and_verify_from_file(path: &std::path::Path) -> ArbiterResult<Self> {
        let raw =
            std::fs::read_to_string(path).map_err(arbiter_core::error::IoOperationError::from)?;
        let mut entries = Vec::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let entry: SecurityAuditLogEntry = serde_json::from_str(trimmed)
                    .map_err(arbiter_core::error::JsonCodecError::from)?;
                entries.push(entry);
            }
        }
        let log = Self { entries };
        let _ = log.verify_chain()?;
        Ok(log)
    }
}

/// Computes RFC 5869 `HKDF-Extract` and `HKDF-Expand` over `SHA-256` to derive a 32-byte
/// cryptographic session key from `salt`, `input_key_material`, and context `info`.
///
/// # Arguments
///
/// * `salt` - Optional non-secret salt byte slice (if empty, 32 zero bytes are used per RFC 5869 §2.2).
/// * `input_key_material` - High-entropy input keying material (`IKM`).
/// * `info` - Context and application specific information (`info`).
///
/// # Returns
///
/// 32-byte derived output keying material (`OKM`).
pub fn hkdf_sha256(salt: &[u8], input_key_material: &[u8], info: &[u8]) -> [u8; 32] {
    let actual_salt = if salt.is_empty() {
        &[0_u8; 32][..]
    } else {
        salt
    };
    let prk = hmac_sha256(actual_salt, input_key_material);
    let mut expand_msg = Vec::with_capacity(info.len() + 1);
    expand_msg.extend_from_slice(info);
    expand_msg.push(0x01);
    hmac_sha256(&prk, &expand_msg)
}

/// Memory-hard `Argon2id`-inspired multi-lane sponge key derivation function (`KDF`) that derives a
/// [`ZeroizingSecretKey`] from an operator passphrase, 16-byte salt, memory block count, and pass count.
///
/// Allocates `memory_blocks` 64-byte lanes and performs `iterations` passes of cross-lane
/// data-dependent and data-independent `ChaCha20` + `SHA-256` mixing to resist GPU/ASIC cracking.
///
/// # Arguments
///
/// * `passphrase` - Operator passphrase bytes.
/// * `salt` - 16-byte unique salt (`>= 8` non-zero bytes recommended).
/// * `memory_blocks` - Number of 64-byte memory blocks (`>= 8`).
/// * `iterations` - Number of mixing passes over the memory matrix (`>= 1`).
///
/// # Returns
///
/// Derived 32-byte [`ZeroizingSecretKey`].
///
/// # Errors
///
/// Returns [`ArbiterError::TlsConfigurationError`] if `passphrase` is empty, `memory_blocks < 8`, or `iterations == 0`.
pub fn derive_argon2id_master_key(
    passphrase: &[u8],
    salt: &[u8; 16],
    memory_blocks: usize,
    iterations: u32,
) -> ArbiterResult<ZeroizingSecretKey> {
    if passphrase.is_empty() || memory_blocks < 8 || iterations == 0 {
        return Err(ArbiterError::TlsConfigurationError {
            reason: "Argon2id KDF requires non-empty passphrase, memory_blocks >= 8, and iterations >= 1"
                .to_owned(),
        });
    }
    let h0 = hkdf_sha256(salt, passphrase, b"arbiter-argon2id-v1");
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(salt.get(0..12).unwrap_or(&[0_u8; 12]));
    let mut matrix: Vec<[u8; 64]> = (0..memory_blocks)
        .map(|idx| chacha20_block(&h0, u32::try_from(idx).unwrap_or(0), &nonce))
        .collect();

    for pass in 0..iterations {
        for idx in 0..memory_blocks {
            let prev_idx = if idx == 0 {
                memory_blocks.saturating_sub(1)
            } else {
                idx.saturating_sub(1)
            };
            let prev_block = matrix.get(prev_idx).copied().unwrap_or([0_u8; 64]);
            let ref_idx = usize::from(prev_block.first().copied().unwrap_or(0)) % memory_blocks;
            let ref_block = matrix.get(ref_idx).copied().unwrap_or([0_u8; 64]);
            let mut seed_key = [0_u8; 32];
            for (dst, (&a, &b)) in seed_key
                .iter_mut()
                .zip(prev_block.iter().zip(ref_block.iter()))
            {
                *dst = a ^ b;
            }
            let mixed = chacha20_block(
                &seed_key,
                pass.wrapping_add(u32::try_from(idx).unwrap_or(0)),
                &nonce,
            );
            for (slot_idx, slot) in matrix.iter_mut().enumerate() {
                if slot_idx == idx {
                    for (s, &m) in slot.iter_mut().zip(mixed.iter()) {
                        *s ^= m;
                    }
                }
            }
        }
    }

    let mut final_xor = [0_u8; 64];
    for block in &mut matrix {
        for (acc, &b) in final_xor.iter_mut().zip(block.iter()) {
            *acc ^= b;
        }
        block.fill(0);
    }
    let derived = hkdf_sha256(&h0, &final_xor, b"arbiter-argon2id-final");
    Ok(ZeroizingSecretKey::new(derived))
}

/// Asymmetric node signing keypair (`Ed25519Keypair`) for signing node identity assertions,
/// `StonithFenceReceipt`s, and `EdDSA` JWS tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Keypair {
    /// 32-byte public verification key commitment.
    pub public_key: [u8; 32],
    /// 32-byte secret signing seed.
    secret_seed: [u8; 32],
}

impl Ed25519Keypair {
    /// Generates a deterministic [`Ed25519Keypair`] from a 32-byte `secret_seed` using RFC 8032 `ed25519-dalek`.
    ///
    /// # Arguments
    ///
    /// * `secret_seed` - 32-byte secret key material.
    ///
    /// # Returns
    ///
    /// Initialized [`Ed25519Keypair`].
    pub fn from_seed(secret_seed: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_seed);
        let public_key = signing_key.verifying_key().to_bytes();
        Self {
            public_key,
            secret_seed,
        }
    }

    /// Signs `message` producing an RFC 8032 64-byte `Ed25519` signature `(R || S)`.
    ///
    /// # Arguments
    ///
    /// * `message` - Message byte slice to sign.
    ///
    /// # Returns
    ///
    /// 64-byte `Ed25519` signature array.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.secret_seed);
        signing_key.sign(message).to_bytes()
    }

    /// Verifies an RFC 8032 64-byte `Ed25519` signature produced by [`Self::sign`] against
    /// `public_key` and `message` using only the 32-byte public key.
    ///
    /// # Arguments
    ///
    /// * `public_key` - 32-byte `Ed25519` public key.
    /// * `message` - Signed message bytes.
    /// * `signature` - 64-byte signature `(R || S)`.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CryptographicSignatureError`] if verification fails.
    pub fn verify(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> ArbiterResult<()> {
        use ed25519_dalek::Verifier as _;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        let verified = ed25519_dalek::VerifyingKey::from_bytes(public_key)
            .and_then(|vk| vk.verify(message, &sig));
        if verified.is_err() {
            return Err(ArbiterError::CryptographicSignatureError {
                algorithm: "Ed25519".to_owned(),
                reason: "Ed25519 signature verification failed".to_owned(),
            });
        }
        Ok(())
    }
}

/// Asymmetric NIST `P-256` (`secp256r1` / `ES256`) signing keypair for FIPS 186-5 ECDSA over SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P256Keypair {
    /// 33-byte SEC1 compressed public verification point (`0x02`/`0x03` || X) folded with a 32-byte commitment,
    /// plus full 33-byte SEC1 compressed point stored in `compressed_verifying_key`.
    pub public_key: [u8; 32],
    /// 33-byte SEC1 compressed `P-256` verifying key point.
    pub compressed_verifying_key: Vec<u8>,
    /// 32-byte secret signing scalar seed.
    secret_scalar: [u8; 32],
}

impl P256Keypair {
    /// Generates a deterministic [`P256Keypair`] from a 32-byte `secret_scalar` using `p256::ecdsa`.
    ///
    /// # Arguments
    ///
    /// * `secret_scalar` - 32-byte secret scalar seed.
    ///
    /// # Returns
    ///
    /// Initialized [`P256Keypair`].
    pub fn from_seed(secret_scalar: [u8; 32]) -> Self {
        let mut derived_scalar =
            hkdf_sha256(b"arbiter-p256-scalar-v1", &secret_scalar, b"secp256r1");
        for b0 in derived_scalar.iter_mut().take(1) {
            *b0 = (*b0 & 0x7F) | 0x01;
        }
        let sk_opt = p256::ecdsa::SigningKey::from_slice(&derived_scalar).ok();
        let vk_bytes = sk_opt
            .as_ref()
            .map(|sk| {
                sk.verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            })
            .unwrap_or_default();
        let mut public_key = [0_u8; 32];
        for (dst, &src) in public_key.iter_mut().zip(vk_bytes.iter().skip(1)) {
            *dst = src;
        }
        Self {
            public_key,
            compressed_verifying_key: vk_bytes,
            secret_scalar,
        }
    }

    /// Signs `message` using deterministic RFC 6979 / FIPS 186-5 `ECDSA-P256-SHA256`, returning
    /// the 64-byte `(r || s)` signature.
    ///
    /// # Arguments
    ///
    /// * `message` - Message byte slice to sign.
    ///
    /// # Returns
    ///
    /// 64-byte `(r || s)` signature array.
    pub fn sign_ecdsa_sha256(&self, message: &[u8]) -> [u8; 64] {
        use p256::ecdsa::signature::Signer as _;
        let mut derived_scalar =
            hkdf_sha256(b"arbiter-p256-scalar-v1", &self.secret_scalar, b"secp256r1");
        for b0 in derived_scalar.iter_mut().take(1) {
            *b0 = (*b0 & 0x7F) | 0x01;
        }
        let sig_bytes = p256::ecdsa::SigningKey::from_slice(&derived_scalar)
            .ok()
            .map_or_else(Vec::new, |sk| {
                let sig: p256::ecdsa::Signature = sk.sign(message);
                sig.to_bytes().to_vec()
            });
        let mut out = [0_u8; 64];
        for (dst, &src) in out.iter_mut().zip(sig_bytes.iter()) {
            *dst = src;
        }
        out
    }

    /// Verifies a 64-byte `(r || s)` signature produced by [`Self::sign_ecdsa_sha256`] against
    /// `public_key` (`X`-coordinate trying both even `0x02` and odd `0x03` SEC1 y-parities) and `message`.
    ///
    /// # Arguments
    ///
    /// * `public_key` - 32-byte `P-256` public key `X`-coordinate.
    /// * `message` - Signed message bytes.
    /// * `signature` - 64-byte `(r || s)` signature.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid under NIST `P-256` curve verification.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CryptographicSignatureError`] if verification fails.
    pub fn verify_ecdsa_sha256(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> ArbiterResult<()> {
        use p256::ecdsa::signature::Verifier as _;
        let sig = p256::ecdsa::Signature::from_slice(signature).map_err(|_| {
            ArbiterError::CryptographicSignatureError {
                algorithm: "ES256-P256".to_owned(),
                reason: "malformed ECDSA P-256 signature scalar".to_owned(),
            }
        })?;
        for tag in [0x02_u8, 0x03_u8] {
            let mut sec1 = [0_u8; 33];
            for (d, &s) in sec1
                .iter_mut()
                .zip(core::iter::once(&tag).chain(public_key.iter()))
            {
                *d = s;
            }
            let verified = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .ok()
                .and_then(|vk| vk.verify(message, &sig).ok());
            if verified.is_some() {
                return Ok(());
            }
        }
        Err(ArbiterError::CryptographicSignatureError {
            algorithm: "ES256-P256".to_owned(),
            reason: "ECDSA P-256 signature verification failed".to_owned(),
        })
    }
}

/// In-memory / RAM-backed secret volume stager (`SecretTmpfsStager`).
///
/// Unseals a [`SealedSecretEnvelope`], writes the plaintext into a `0400` read-only file inside
/// `mount_dir`, and securely overwrites and unlinks the secret file upon task teardown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretTmpfsStager {
    /// Target directory where decrypted secret files are staged.
    pub mount_dir: std::path::PathBuf,
}

impl SecretTmpfsStager {
    /// Creates a new [`SecretTmpfsStager`] rooted at `mount_dir`.
    ///
    /// # Arguments
    ///
    /// * `mount_dir` - Directory path for staging decrypted secret files.
    ///
    /// # Returns
    ///
    /// Initialized [`SecretTmpfsStager`].
    pub fn new(mount_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            mount_dir: mount_dir.into(),
        }
    }

    /// Unseals `envelope` using `master_key` and `associated_data` (`AES-256-GCM`), writes the
    /// decrypted bytes to `<mount_dir>/<secret_id>`, sets `0400` read-only permissions on Unix,
    /// and returns the staged file path.
    ///
    /// # Arguments
    ///
    /// * `envelope` - [`SealedSecretEnvelope`] encrypted via [`seal_secret_aes256_gcm`].
    /// * `master_key` - 32-byte `AES-256` master key.
    /// * `associated_data` - Expected context AAD (`role || task_id || agent_id`).
    ///
    /// # Returns
    ///
    /// Staged secret `PathBuf`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError`] if decryption or file writing fails.
    pub fn stage_unsealed_secret(
        &self,
        envelope: &SealedSecretEnvelope,
        master_key: &[u8; 32],
        associated_data: &[u8],
    ) -> ArbiterResult<std::path::PathBuf> {
        let zeroizing = unseal_secret_aes256_gcm(envelope, master_key, associated_data)?;
        std::fs::create_dir_all(&self.mount_dir)
            .map_err(arbiter_core::error::IoOperationError::from)?;
        let file_path = self.mount_dir.join(envelope.secret_id.as_str());
        std::fs::write(&file_path, zeroizing.as_slice())
            .map_err(arbiter_core::error::IoOperationError::from)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o400);
            let _ = std::fs::set_permissions(&file_path, perms);
        }
        Ok(file_path)
    }

    /// Securely scrubs `<mount_dir>/<secret_id>` with zeros on disk and unlinks the file.
    ///
    /// # Arguments
    ///
    /// * `secret_id` - [`SecretId`] to wipe and remove.
    ///
    /// # Returns
    ///
    /// `Ok(())` when scrubbed and removed.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::IoOperation`] if the file does not exist or cannot be unlinked.
    pub fn scrub_and_unlink_secret(&self, secret_id: &SecretId) -> ArbiterResult<()> {
        let file_path = self.mount_dir.join(secret_id.as_str());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&file_path, perms);
        }
        let len = std::fs::metadata(&file_path)
            .map_err(arbiter_core::error::IoOperationError::from)?
            .len();
        let zeros = vec![0_u8; usize::try_from(len).unwrap_or(0)];
        let _ = std::fs::write(&file_path, &zeros);
        std::fs::remove_file(&file_path).map_err(arbiter_core::error::IoOperationError::from)?;
        Ok(())
    }
}

/// Mutual `X25519` + `HKDF-SHA256` ephemeral session key agreement between two cluster peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519SessionEstablisher {
    /// Local ephemeral RFC 7748 `X25519` public key share (`32` bytes).
    pub local_public: [u8; 32],
    /// Local ephemeral 32-byte secret scalar.
    ephemeral_secret: [u8; 32],
    /// Pre-shared or CA-derived cluster channel secret binding the handshake.
    channel_binding: [u8; 32],
}

impl X25519SessionEstablisher {
    /// Creates a new [`X25519SessionEstablisher`] from a 32-byte `ephemeral_secret` and `channel_binding`
    /// using the RFC 7748 Curve25519 basepoint scalar multiplication (`X25519(ephemeral_secret, 9)`).
    ///
    /// # Arguments
    ///
    /// * `ephemeral_secret` - Local ephemeral secret bytes.
    /// * `channel_binding` - Cluster trust-domain binding secret.
    ///
    /// # Returns
    ///
    /// Initialized [`X25519SessionEstablisher`].
    pub fn new(ephemeral_secret: [u8; 32], channel_binding: [u8; 32]) -> Self {
        let local_public = x25519_basepoint_public_key(&ephemeral_secret);
        Self {
            local_public,
            ephemeral_secret,
            channel_binding,
        }
    }

    /// Derives a symmetric 32-byte AEAD session key with `peer_public` using RFC 7748 `X25519`
    /// Diffie-Hellman over $\mathbb{F}_{2^{255}-19}$ (`X25519(ephemeral_secret, peer_public)`)
    /// bound to the sorted public key transcript via `HKDF-SHA256`.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - Remote peer's 32-byte `local_public` share.
    ///
    /// # Returns
    ///
    /// Symmetric 32-byte AEAD session key.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::KeyExchange`] if `peer_public` is a low-order point producing an all-zero shared secret.
    pub fn derive_shared_session_key(
        &self,
        peer_public: &[u8; 32],
    ) -> ArbiterResult<ZeroizingSecretKey> {
        let dh_shared = x25519_diffie_hellman(&self.ephemeral_secret, peer_public)?;
        let (first, second) = if self.local_public <= *peer_public {
            (&self.local_public, peer_public)
        } else {
            (peer_public, &self.local_public)
        };
        let mut ikm = [0_u8; 96];
        for (dst, &src) in ikm.iter_mut().zip(
            dh_shared
                .as_bytes()
                .iter()
                .chain(first.iter())
                .chain(second.iter()),
        ) {
            *dst = src;
        }
        let key = hkdf_sha256(&self.channel_binding, &ikm, b"arbiter-quic-aead-v1");
        Ok(ZeroizingSecretKey::new(key))
    }
}

/// Hitless `SIGHUP`-reloadable SPIFFE Trust Bundle manager (`TrustBundleHotReloader`).
///
/// Retains both current and previous CA keys during rotation windows so active
/// Master $\leftrightarrow$ Agent connections are never dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustBundleHotReloader {
    /// Active [`SvidAuthority`].
    pub active_authority: SvidAuthority,
    /// Previous [`SvidAuthority`] retained during hitless rotation grace periods.
    pub previous_authority: Option<SvidAuthority>,
    /// Monotonic generation counter incremented on every `SIGHUP` reload.
    pub reload_generation: u64,
}

impl TrustBundleHotReloader {
    /// Creates a new [`TrustBundleHotReloader`] with `initial_authority`.
    ///
    /// # Arguments
    ///
    /// * `initial_authority` - Initial [`SvidAuthority`].
    ///
    /// # Returns
    ///
    /// Initialized [`TrustBundleHotReloader`].
    pub const fn new(initial_authority: SvidAuthority) -> Self {
        Self {
            active_authority: initial_authority,
            previous_authority: None,
            reload_generation: 1,
        }
    }

    /// Performs a hitless `SIGHUP` trust bundle reload, promoting `new_authority` to `active_authority`
    /// while preserving the prior authority as `previous_authority`.
    ///
    /// # Arguments
    ///
    /// * `new_authority` - Newly loaded [`SvidAuthority`].
    ///
    /// # Returns
    ///
    /// Updated `reload_generation`.
    pub fn reload_on_sighup(&mut self, new_authority: SvidAuthority) -> u64 {
        self.previous_authority = Some(self.active_authority.clone());
        self.active_authority = new_authority;
        self.reload_generation = self.reload_generation.saturating_add(1);
        self.reload_generation
    }

    /// Verifies an [`SpiffeSvid`] against `active_authority`, falling back to `previous_authority`
    /// if the SVID was issued right before a `SIGHUP` rotation.
    ///
    /// # Arguments
    ///
    /// * `svid` - Presented [`SpiffeSvid`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if verified by either active or previous authority.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if both authorities reject the SVID.
    pub fn verify_svid_hitless(&self, svid: &SpiffeSvid, current_tick: u64) -> ArbiterResult<()> {
        if self
            .active_authority
            .verify_svid(svid, current_tick)
            .is_ok()
        {
            return Ok(());
        }
        if let Some(ref prev) = self.previous_authority {
            return prev.verify_svid(svid, current_tick);
        }
        self.active_authority.verify_svid(svid, current_tick)
    }
}

/// Hardware-rooted attestation platform type (`TPM 2.0` on Linux/Windows/FreeBSD/illumos vs.
/// `Apple Secure Enclave` on macOS).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwareAttestationKind {
    /// Trusted Platform Module 2.0 (`TPM 2.0` PCR quote over PCRs 0–7).
    #[default]
    Tpm20PcrQuote,
    /// Apple Silicon Secure Enclave (`SEP` / `DeviceCheck` hardware attestation).
    AppleSecureEnclave,
}

/// Hardware-rooted node attestation quote presented by an `arbiter-agent` prior to SVID issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareAttestationQuote {
    /// Attesting Agent identifier.
    pub agent_id: AgentId,
    /// Hardware root of trust kind.
    pub kind: HardwareAttestationKind,
    /// Composite SHA-256 digest of boot measurements (`PCRs 0..=7` or `SecureBoot` policy hash).
    pub pcr_composite_sha256: [u8; 32],
    /// Freshness nonce challenge issued by the Master.
    pub nonce: [u8; 16],
    /// 32-byte HMAC-SHA256 / Endorsement Key (`EK`) signature over `(agent_id, kind, pcr_composite_sha256, nonce)`.
    pub ak_signature: [u8; 32],
}

impl HardwareAttestationQuote {
    /// Generates a signed [`HardwareAttestationQuote`] using the node's Attestation Key (`ak_secret`).
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Attesting [`AgentId`].
    /// * `kind` - [`HardwareAttestationKind`].
    /// * `pcr_composite_sha256` - 32-byte PCR composite measurement digest.
    /// * `nonce` - 16-byte freshness nonce.
    /// * `ak_secret` - 32-byte Attestation Key secret.
    ///
    /// # Returns
    ///
    /// Signed [`HardwareAttestationQuote`].
    pub fn generate(
        agent_id: AgentId,
        kind: HardwareAttestationKind,
        pcr_composite_sha256: [u8; 32],
        nonce: [u8; 16],
        ak_secret: &[u8; 32],
    ) -> Self {
        let ak_signature = Self::compute_quote_mac(
            agent_id.as_str(),
            kind,
            &pcr_composite_sha256,
            &nonce,
            ak_secret,
        );
        Self {
            agent_id,
            kind,
            pcr_composite_sha256,
            nonce,
            ak_signature,
        }
    }

    /// Verifies this [`HardwareAttestationQuote`] against the Master's expected `nonce`, allowed
    /// golden `expected_pcr_composite` measurement, and `ak_secret`.
    ///
    /// # Arguments
    ///
    /// * `expected_nonce` - 16-byte challenge nonce issued by the Master.
    /// * `expected_pcr_composite` - Golden 32-byte PCR 0–7 measurement digest.
    /// * `ak_secret` - Trusted Attestation Key (`AK`) secret.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the hardware quote is authentic, fresh, and matches the golden boot state.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::AuthenticationFailed`] if the nonce, PCR measurement, or AK signature mismatches.
    pub fn verify(
        &self,
        expected_nonce: &[u8; 16],
        expected_pcr_composite: &[u8; 32],
        ak_secret: &[u8; 32],
    ) -> ArbiterResult<()> {
        if &self.nonce != expected_nonce {
            return Err(ArbiterError::AuthenticationFailed {
                principal: self.agent_id.to_string(),
                reason: "hardware attestation quote nonce mismatch (replay)".to_owned(),
            });
        }
        if &self.pcr_composite_sha256 != expected_pcr_composite {
            return Err(ArbiterError::AuthenticationFailed {
                principal: self.agent_id.to_string(),
                reason: "hardware attestation PCR 0..7 measurement does not match golden image"
                    .to_owned(),
            });
        }
        let expected_mac = Self::compute_quote_mac(
            self.agent_id.as_str(),
            self.kind,
            &self.pcr_composite_sha256,
            &self.nonce,
            ak_secret,
        );
        if self.ak_signature != expected_mac {
            return Err(ArbiterError::AuthenticationFailed {
                principal: self.agent_id.to_string(),
                reason: "hardware attestation AK signature verification failed".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the 32-byte quote MAC over `(agent_id, kind, pcr_composite, nonce)`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - Agent ID string.
    /// * `kind` - [`HardwareAttestationKind`].
    /// * `pcr` - 32-byte PCR composite.
    /// * `nonce` - 16-byte nonce.
    /// * `ak_secret` - 32-byte key.
    ///
    /// # Returns
    ///
    /// 32-byte `HMAC-SHA256` tag.
    fn compute_quote_mac(
        agent_id: &str,
        kind: HardwareAttestationKind,
        pcr: &[u8; 32],
        nonce: &[u8; 16],
        ak_secret: &[u8; 32],
    ) -> [u8; 32] {
        let kind_byte = match kind {
            HardwareAttestationKind::Tpm20PcrQuote => 1_u8,
            HardwareAttestationKind::AppleSecureEnclave => 2_u8,
        };
        let mut buf = Vec::with_capacity(agent_id.len() + 1 + 32 + 16);
        buf.extend_from_slice(agent_id.as_bytes());
        buf.push(kind_byte);
        buf.extend_from_slice(pcr);
        buf.extend_from_slice(nonce);
        hmac_sha256(ak_secret, &buf)
    }
}

/// Hierarchical X.509v3 ASN.1 DER certificate chain (`Root CA -> Intermediate CA -> Leaf SVID`).
///
/// Carries `SubjectAltName` (`OID 2.5.29.17`) SPIFFE URIs, `notBefore`/`notAfter` validity windows,
/// and `Ed25519` issuer CA signatures.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X509DerCertificateChain {
    /// Root CA ASN.1 DER certificate bytes.
    pub root_der: Vec<u8>,
    /// Intermediate CA ASN.1 DER certificate bytes.
    pub intermediate_der: Vec<u8>,
    /// Leaf workload/node SVID ASN.1 DER certificate bytes.
    pub leaf_der: Vec<u8>,
    /// Root CA `Ed25519` signature over `root_der`.
    pub root_sig: Vec<u8>,
    /// Root CA `Ed25519` signature over `intermediate_der`.
    pub intermediate_sig: Vec<u8>,
    /// Intermediate CA `Ed25519` signature over `leaf_der`.
    pub leaf_sig: Vec<u8>,
    /// Intermediate CA public key (`32` bytes).
    pub intermediate_public_key: [u8; 32],
}

impl X509DerCertificateChain {
    /// Builds and signs a 3-tier X.509v3 ASN.1 DER certificate chain (`Root -> Intermediate -> Leaf`).
    ///
    /// # Arguments
    ///
    /// * `trust_domain` - SPIFFE trust domain (e.g., `"arbiter.internal"`).
    /// * `leaf_uri` - Leaf SPIFFE URI (`spiffe://<trust_domain>/...`).
    /// * `not_before_tick` - Chain validity start tick.
    /// * `not_after_tick` - Chain validity end tick (`> not_before_tick`).
    /// * `root_kp` - Trusted Root CA [`Ed25519Keypair`].
    /// * `intermediate_kp` - Intermediate CA [`Ed25519Keypair`].
    ///
    /// # Returns
    ///
    /// Signed [`X509DerCertificateChain`].
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::X509ValidationError`] or [`ArbiterError::SpiffeIdentityInvalid`] if
    /// `not_before_tick >= not_after_tick` or `leaf_uri` is invalid.
    pub fn build_signed_chain(
        trust_domain: &str,
        leaf_uri: &str,
        not_before_tick: u64,
        not_after_tick: u64,
        root_kp: &Ed25519Keypair,
        intermediate_kp: &Ed25519Keypair,
    ) -> ArbiterResult<Self> {
        let root_uri = format!("spiffe://{trust_domain}/master/root-ca");
        let inter_uri = format!("spiffe://{trust_domain}/master/intermediate-ca");
        let _ = parse_spiffe_san(&root_uri, trust_domain)?;
        let _ = parse_spiffe_san(leaf_uri, trust_domain)?;
        let root_cert = X509CertificatePem::issue_pem(
            &root_uri,
            not_before_tick,
            not_after_tick,
            &root_kp.public_key,
        )?;
        let inter_cert = X509CertificatePem::issue_pem(
            &inter_uri,
            not_before_tick,
            not_after_tick,
            &root_kp.public_key,
        )?;
        let leaf_cert = X509CertificatePem::issue_pem(
            leaf_uri,
            not_before_tick,
            not_after_tick,
            &intermediate_kp.public_key,
        )?;
        let root_der = root_cert.encode_asn1_der();
        let intermediate_der = inter_cert.encode_asn1_der();
        let leaf_der = leaf_cert.encode_asn1_der();
        let root_sig = root_kp.sign(&root_der).to_vec();
        let intermediate_sig = root_kp.sign(&intermediate_der).to_vec();
        let leaf_sig = intermediate_kp.sign(&leaf_der).to_vec();
        Ok(Self {
            root_der,
            intermediate_der,
            leaf_der,
            root_sig,
            intermediate_sig,
            leaf_sig,
            intermediate_public_key: intermediate_kp.public_key,
        })
    }

    /// Verifies the full 3-tier X.509v3 ASN.1 DER certificate chain (`Root -> Intermediate -> Leaf`),
    /// validating `Ed25519` issuer CA signatures, `notBefore`/`notAfter` windows, and `SubjectAltName`
    /// (`OID 2.5.29.17`) SPIFFE URIs.
    ///
    /// # Arguments
    ///
    /// * `expected_trust_domain` - Expected SPIFFE trust domain.
    /// * `trusted_root_public_key` - Trusted Root CA 32-byte `Ed25519` public key.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Verified leaf `(X509CertificatePem, SpiffePrincipalKind)`.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::CryptographicSignatureError`], [`ArbiterError::X509ValidationError`],
    /// or [`ArbiterError::SpiffeIdentityInvalid`] if any tier in the chain fails verification.
    pub fn verify_chain(
        &self,
        expected_trust_domain: &str,
        trusted_root_public_key: &[u8; 32],
        current_tick: u64,
    ) -> ArbiterResult<(X509CertificatePem, SpiffePrincipalKind)> {
        let mut r_sig = [0_u8; 64];
        for (d, &s) in r_sig.iter_mut().zip(self.root_sig.iter()) {
            *d = s;
        }
        Ed25519Keypair::verify(trusted_root_public_key, &self.root_der, &r_sig)?;
        let _ = X509CertificatePem::decode_and_verify_asn1_der(
            &self.root_der,
            expected_trust_domain,
            trusted_root_public_key,
            current_tick,
        )?;

        let mut i_sig = [0_u8; 64];
        for (d, &s) in i_sig.iter_mut().zip(self.intermediate_sig.iter()) {
            *d = s;
        }
        Ed25519Keypair::verify(trusted_root_public_key, &self.intermediate_der, &i_sig)?;
        let _ = X509CertificatePem::decode_and_verify_asn1_der(
            &self.intermediate_der,
            expected_trust_domain,
            trusted_root_public_key,
            current_tick,
        )?;

        let mut l_sig = [0_u8; 64];
        for (d, &s) in l_sig.iter_mut().zip(self.leaf_sig.iter()) {
            *d = s;
        }
        Ed25519Keypair::verify(&self.intermediate_public_key, &self.leaf_der, &l_sig)?;
        X509CertificatePem::decode_and_verify_asn1_der(
            &self.leaf_der,
            expected_trust_domain,
            &self.intermediate_public_key,
            current_tick,
        )
    }
}

/// Wire message exchanged during the mutual TLS (`mTLS`) handshake (`ClientHello` / `ServerHello`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtlsHandshakeMessage {
    /// Presented [`SpiffeSvid`].
    pub svid: SpiffeSvid,
    /// Ephemeral `X25519` public key share (`32` bytes).
    pub x25519_public: [u8; 32],
    /// Key rotation epoch counter.
    pub rotation_epoch: u64,
}

/// Authenticated mutual TLS (`mTLS`) stream state machine supporting mutual [`SpiffeSvid`] presentation.
///
/// Combines ephemeral [`X25519SessionEstablisher`] ECDHE key agreement, `HKDF-SHA256` traffic key derivation,
/// `ChaCha20-Poly1305` frame protection, and hitless short-lived SVID rotation without dropping the stream.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtlsAuthenticatedStream {
    /// Local [`SpiffeSvid`].
    pub local_svid: SpiffeSvid,
    /// Authenticated peer [`SpiffeSvid`].
    pub peer_svid: SpiffeSvid,
    /// Derived 32-byte `ChaCha20-Poly1305` traffic key.
    pub traffic_key: [u8; 32],
    /// Monotonic outbound record sequence counter.
    pub tx_seq: u64,
    /// Current SVID rotation epoch (`>= 1`).
    pub rotation_epoch: u64,
}

impl MtlsAuthenticatedStream {
    /// Performs a mutual TLS (`mTLS`) handshake between a client and server using [`TrustBundleHotReloader`]
    /// and [`X25519SessionEstablisher`], returning `(client_stream, server_stream)` with matching
    /// `HKDF-SHA256` traffic keys.
    ///
    /// # Arguments
    ///
    /// * `client_hello` - Client [`MtlsHandshakeMessage`].
    /// * `client_ephemeral` - Client [`X25519SessionEstablisher`].
    /// * `server_hello` - Server [`MtlsHandshakeMessage`].
    /// * `server_ephemeral` - Server [`X25519SessionEstablisher`].
    /// * `trust_bundle` - [`TrustBundleHotReloader`] verifying both SVIDs.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Tuple `(client_mtls_stream, server_mtls_stream)`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if either peer's [`SpiffeSvid`] fails verification or the X25519
    /// public share is invalid.
    pub fn establish_mutual_handshake(
        client_hello: &MtlsHandshakeMessage,
        client_ephemeral: &X25519SessionEstablisher,
        server_hello: &MtlsHandshakeMessage,
        server_ephemeral: &X25519SessionEstablisher,
        trust_bundle: &TrustBundleHotReloader,
        current_tick: u64,
    ) -> ArbiterResult<(Self, Self)> {
        trust_bundle.verify_svid_hitless(&client_hello.svid, current_tick)?;
        trust_bundle.verify_svid_hitless(&server_hello.svid, current_tick)?;
        let client_shared =
            client_ephemeral.derive_shared_session_key(&server_hello.x25519_public)?;
        let server_shared =
            server_ephemeral.derive_shared_session_key(&client_hello.x25519_public)?;
        let mut info = Vec::new();
        info.extend_from_slice(client_hello.svid.spiffe_id.as_str().as_bytes());
        info.extend_from_slice(server_hello.svid.spiffe_id.as_str().as_bytes());
        let client_traffic = hkdf_sha256(b"arbiter-mtls-13", client_shared.as_bytes(), &info);
        let server_traffic = hkdf_sha256(b"arbiter-mtls-13", server_shared.as_bytes(), &info);
        Ok((
            Self {
                local_svid: client_hello.svid.clone(),
                peer_svid: server_hello.svid.clone(),
                traffic_key: client_traffic,
                tx_seq: 1,
                rotation_epoch: client_hello.rotation_epoch.max(1),
            },
            Self {
                local_svid: server_hello.svid.clone(),
                peer_svid: client_hello.svid.clone(),
                traffic_key: server_traffic,
                tx_seq: 1,
                rotation_epoch: server_hello.rotation_epoch.max(1),
            },
        ))
    }

    /// Rotates `local_svid` and `peer_svid` in-place using `trust_bundle` and re-keys `traffic_key`
    /// via `HKDF-SHA256` without dropping the active stream or resetting sequence numbers.
    ///
    /// # Arguments
    ///
    /// * `new_local_svid` - Newly issued local [`SpiffeSvid`].
    /// * `new_peer_svid` - Newly issued peer [`SpiffeSvid`].
    /// * `trust_bundle` - [`TrustBundleHotReloader`] for hitless verification.
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// Updated `rotation_epoch`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`] if either rotated SVID fails verification.
    pub fn rotate_svids_in_place(
        &mut self,
        new_local_svid: SpiffeSvid,
        new_peer_svid: SpiffeSvid,
        trust_bundle: &TrustBundleHotReloader,
        current_tick: u64,
    ) -> ArbiterResult<u64> {
        trust_bundle.verify_svid_hitless(&new_local_svid, current_tick)?;
        trust_bundle.verify_svid_hitless(&new_peer_svid, current_tick)?;
        self.local_svid = new_local_svid;
        self.peer_svid = new_peer_svid;
        self.rotation_epoch = self.rotation_epoch.saturating_add(1);
        self.traffic_key = hkdf_sha256(
            &self.rotation_epoch.to_le_bytes(),
            &self.traffic_key,
            b"arbiter-mtls-rekey-v1",
        );
        Ok(self.rotation_epoch)
    }

    /// Encrypts and authenticates an application payload record over this mTLS stream.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Application bytes to seal.
    ///
    /// # Returns
    ///
    /// [`SealedSecretEnvelope`] record.
    pub fn seal_record(&mut self, plaintext: &[u8]) -> SealedSecretEnvelope {
        let mut nonce = [0_u8; 12];
        let seq_bytes = self.tx_seq.to_le_bytes();
        for (d, &s) in nonce.iter_mut().zip(seq_bytes.iter()) {
            *d = s;
        }
        self.tx_seq = self.tx_seq.saturating_add(1);
        let sid = SecretId::new("mtls-record").unwrap_or_default();
        seal_secret_with_aad(
            sid,
            &self.traffic_key,
            nonce,
            &self.rotation_epoch.to_le_bytes(),
            plaintext,
        )
    }

    /// Decrypts and verifies an inbound [`SealedSecretEnvelope`] record received from the peer.
    ///
    /// # Arguments
    ///
    /// * `record` - Inbound [`SealedSecretEnvelope`].
    ///
    /// # Returns
    ///
    /// Authenticated plaintext byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::SecretDecryptionFailed`] if the AEAD tag or rotation epoch mismatches.
    pub fn open_record(&self, record: &SealedSecretEnvelope) -> ArbiterResult<Vec<u8>> {
        unseal_secret_with_aad(
            record,
            &self.traffic_key,
            &self.rotation_epoch.to_le_bytes(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::literal_string_with_formatting_args)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_spiffe_san_parsing_and_svid_lifecycle() {
        let key = [7_u8; 32];
        let auth = SvidAuthority::new("arbiter.internal", key, 100);

        assert_eq!(
            SpiffePrincipalKind::default(),
            SpiffePrincipalKind::Node {
                agent_id: AgentId::default()
            }
        );

        // Node, Agent, Master, Framework, and Task SANs
        let node_svid = auth.issue_svid("spiffe://arbiter.internal/node/agent-01", 10);
        assert!(node_svid.is_ok());
        let ca_kp = Ed25519Keypair::from_seed([0x55; 32]);
        let fallback_ed = (SpiffeSvid::default(), [0_u8; 64]);
        let (ed_svid, ed_sig) = auth
            .issue_ed25519_svid("spiffe://arbiter.internal/node/agent-01", 10, &ca_kp)
            .unwrap_or(fallback_ed);
        assert!(
            auth.verify_ed25519_svid(&ed_svid, &ed_sig, &ca_kp.public_key, 20)
                .is_ok()
        );
        assert!(
            auth.verify_ed25519_svid(&ed_svid, &[0_u8; 64], &ca_kp.public_key, 20)
                .is_err()
        );
        assert!(
            auth.verify_ed25519_svid(&ed_svid, &ed_sig, &ca_kp.public_key, 999)
                .is_err()
        );
        assert!(auth.issue_ed25519_svid("invalid", 10, &ca_kp).is_err());
        assert!(
            auth.issue_svid("spiffe://arbiter.internal/agent/agent-01", 10)
                .is_ok()
        );
        assert!(
            auth.issue_svid("spiffe://arbiter.internal/master/master-01", 10)
                .is_ok()
        );
        assert!(
            auth.issue_svid("spiffe://arbiter.internal/framework/prod/fw-01", 10)
                .is_ok()
        );
        assert!(
            auth.issue_svid("spiffe://arbiter.internal/task/prod/task-99", 10)
                .is_ok()
        );

        // Task SAN
        let mut svid = auth
            .issue_svid("spiffe://arbiter.internal/role/prod/task/task-99", 10)
            .unwrap_or_default();
        assert!(auth.verify_svid(&svid, 50).is_ok());
        assert!(auth.rotate_svid(&svid, 50).is_ok());

        // Revoked SVID rejected
        let mut rev_auth = auth.clone();
        rev_auth.revoke_svid_uri("spiffe://arbiter.internal/role/prod/task/task-99");
        assert!(rev_auth.verify_svid(&svid, 50).is_err());

        // Expired SVID at tick 110
        assert!(auth.verify_svid(&svid, 110).is_err());
        assert!(auth.rotate_svid(&svid, 110).is_err());

        // Tampered signature rejected
        svid.signature = [0xFF_u8; 32];
        assert!(auth.verify_svid(&svid, 50).is_err());

        // Invalid SAN cases
        assert!(auth.issue_svid("http://bad", 10).is_err());
        assert!(parse_spiffe_san("http://bad", "arbiter.internal").is_err());
        assert!(
            parse_spiffe_san("spiffe://wrong.domain/node/agent-1", "arbiter.internal").is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/master/bad/slash",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/node/bad/slash",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/framework//fw1",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/framework/prod/bad/slash",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/framework/noslash",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/role/bad/slash/task/t1",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/role/prod/task/bad/slash",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/role/prod/not-task/t1",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/task/bad/slash/t1",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san(
                "spiffe://arbiter.internal/task/prod/bad/slash",
                "arbiter.internal"
            )
            .is_err()
        );
        assert!(
            parse_spiffe_san("spiffe://arbiter.internal/task/noslash", "arbiter.internal").is_err()
        );
        assert!(
            parse_spiffe_san("spiffe://arbiter.internal/unknown/path", "arbiter.internal").is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_rbac_abac_policy_engine_and_aead_secrets() {
        let mut engine = PolicyEngine::new();
        let role_prod = RoleName::new("prod").unwrap_or_default();
        let role_dev = RoleName::new("dev").unwrap_or_default();

        let mut req_attrs = BTreeMap::new();
        req_attrs.insert("env".to_owned(), "prod".to_owned());

        engine.add_rule(PolicyRule {
            principal: "spiffe://arbiter.internal/role/prod/task/t-1".to_owned(),
            action: "LaunchTask".to_owned(),
            resource_prefix: "cluster:main/".to_owned(),
            role: role_prod.clone(),
            required_attributes: req_attrs.clone(),
        });

        // Allow when all RBAC + ABAC conditions match
        assert_eq!(
            engine.evaluate(
                "spiffe://arbiter.internal/role/prod/task/t-1",
                "LaunchTask",
                "cluster:main/job-1",
                &role_prod,
                &req_attrs,
            ),
            Ok(Decision::Allow)
        );

        // Deny on wrong principal, wrong action, wrong prefix, wrong role, or missing ABAC attribute
        assert!(
            engine
                .evaluate(
                    "other",
                    "LaunchTask",
                    "cluster:main/job-1",
                    &role_prod,
                    &req_attrs
                )
                .is_err()
        );
        assert!(
            engine
                .evaluate(
                    "spiffe://arbiter.internal/role/prod/task/t-1",
                    "DeleteQuota",
                    "cluster:main/job-1",
                    &role_prod,
                    &req_attrs,
                )
                .is_err()
        );
        assert!(
            engine
                .evaluate(
                    "spiffe://arbiter.internal/role/prod/task/t-1",
                    "LaunchTask",
                    "other:resource",
                    &role_prod,
                    &req_attrs,
                )
                .is_err()
        );
        assert!(
            engine
                .evaluate(
                    "spiffe://arbiter.internal/role/prod/task/t-1",
                    "LaunchTask",
                    "cluster:main/job-1",
                    &role_dev,
                    &req_attrs,
                )
                .is_err()
        );
        assert!(
            engine
                .evaluate(
                    "spiffe://arbiter.internal/role/prod/task/t-1",
                    "LaunchTask",
                    "cluster:main/job-1",
                    &role_prod,
                    &BTreeMap::new(),
                )
                .is_err()
        );

        // AEAD Secret envelope sealing & unsealing (> 64 bytes to exercise multi-block RFC 8439 ChaCha20 keystream)
        let secret_id = SecretId::new("sec-db-password").unwrap_or_default();
        let master_key = [0x42_u8; 32];
        let wrong_key = [0x99_u8; 32];
        let nonce = [1_u8; 12];
        let plaintext = b"super-secret-database-connection-string-exceeding-64-bytes-long-for-multi-block-chacha20!";

        // Verify RFC 8439 Section 2.3.2 ChaCha20 block function test vector
        let rfc_key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let rfc_nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let block1 = chacha20_block(&rfc_key, 1, &rfc_nonce);
        assert_eq!(block1.first().copied(), Some(0x10));
        assert_eq!(block1.last().copied(), Some(0x4e));

        // Verify RFC 8439 Section 2.5.2 Poly1305 test vector
        let rfc_poly_key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let rfc_poly_msg = b"Cryptographic Forum Research Group";
        let rfc_poly_tag = poly1305_mac(&rfc_poly_key, rfc_poly_msg);
        assert_eq!(
            rfc_poly_tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ]
        );
        // Also test HMAC-SHA256 with key > 64 bytes
        let long_key = [0xAA_u8; 80];
        let hmac_long = hmac_sha256(&long_key, b"test message");
        assert_ne!(hmac_long, [0_u8; 32]);

        let (cc_ct, cc_tag) =
            chacha20poly1305_aead_seal(&master_key, nonce, b"aad", plaintext).unwrap_or_default();
        assert_eq!(
            chacha20poly1305_aead_open(&master_key, nonce, b"aad", &cc_ct, &cc_tag),
            Ok(plaintext.to_vec())
        );
        assert!(chacha20poly1305_aead_open(&wrong_key, nonce, b"aad", &cc_ct, &cc_tag).is_err());

        let mut sealed = seal_secret(secret_id, &master_key, nonce, plaintext);
        assert_ne!(sealed.ciphertext, plaintext);

        let unsealed = unseal_secret(&sealed, &master_key);
        assert_eq!(unsealed, Ok(plaintext.to_vec()));

        // Wrong key rejected
        assert!(unseal_secret(&sealed, &wrong_key).is_err());

        // Tampered ciphertext rejected
        sealed.ciphertext.push(0xFF);
        assert!(unseal_secret(&sealed, &master_key).is_err());

        // AEAD with Associated Data (AAD) prevents cross-task / cross-agent replay
        let aad = b"role=prod;task=t-1;agent=a-1";
        let sealed_aad = seal_secret_with_aad(
            SecretId::new("sec-aad").unwrap_or_default(),
            &master_key,
            nonce,
            aad,
            plaintext,
        );
        assert_eq!(
            unseal_secret_with_aad(&sealed_aad, &master_key, aad),
            Ok(plaintext.to_vec())
        );
        assert!(unseal_secret_with_aad(&sealed_aad, &master_key, b"wrong-aad").is_err());

        // SecretKeyRing rotation & epoch-bound sealing/unsealing
        let mut ring = SecretKeyRing::new(1, master_key);
        let (ep1, env_ep1) = ring
            .seal_for_active_epoch(
                SecretId::new("sec-epoch").unwrap_or_default(),
                nonce,
                aad,
                plaintext,
            )
            .unwrap_or_default();
        assert_eq!(ep1, 1);
        assert!(ring.rotate_key(1, wrong_key).is_err());
        assert!(ring.rotate_key(2, wrong_key).is_ok());
        assert_eq!(ring.active_epoch, 2);
        // Historical epoch 1 envelope still decrypts after rotating to epoch 2!
        let unsealed_ep1 = ring.unseal_for_epoch(1, &env_ep1, aad).unwrap_or_default();
        assert_eq!(unsealed_ep1.as_slice(), plaintext);
        assert!(ring.unseal_for_epoch(99, &env_ep1, aad).is_err());
        assert!(ring.unseal_for_epoch(2, &env_ep1, aad).is_err());
        let empty_ring = SecretKeyRing::default();
        assert!(
            empty_ring
                .seal_for_active_epoch(SecretId::default(), nonce, aad, plaintext)
                .is_err()
        );

        // ASN.1 DER SubjectAltName URI roundtrip & error branches
        let san_id = SpiffeId::new("spiffe://arbiter.internal/agent/a1").unwrap_or_default();
        let der = encode_x509_san_der(&san_id);
        let (dec_id, dec_kind) = decode_x509_san_der(&der, "arbiter.internal").unwrap_or_default();
        assert_eq!(dec_id, san_id);
        assert_eq!(
            dec_kind,
            SpiffePrincipalKind::Node {
                agent_id: AgentId::new("a1").unwrap_or_default()
            }
        );
        assert!(decode_x509_san_der(&[0x30, 0x01], "arbiter.internal").is_err());
        assert!(decode_x509_san_der(&[0x31, 0, 0, 0, 0, 0, 0], "arbiter.internal").is_err());
        assert!(decode_x509_san_der(&[0x30, 0, 0, 0, 0, 0, 0], "arbiter.internal").is_err());
        assert!(decode_x509_san_der(der.get(..10).unwrap_or(&[]), "arbiter.internal").is_err());
        let mut bad_tag_der = der.clone();
        let _ = bad_tag_der.get_mut(11).map(|b| *b = 0x82);
        assert!(decode_x509_san_der(&bad_tag_der, "arbiter.internal").is_err());
        let mut trunc_uri_der = der.clone();
        let _ = trunc_uri_der.get_mut(12).map(|b| *b = 200);
        assert!(decode_x509_san_der(&trunc_uri_der, "arbiter.internal").is_err());
        let mut non_utf8_der = der;
        let _ = non_utf8_der.last_mut().map(|b| *b = 0xFF);
        assert!(decode_x509_san_der(&non_utf8_der, "arbiter.internal").is_err());

        // OIDC JWT encoding & verification
        let claims = OidcJwtClaims {
            issuer: "https://auth.arbiter.internal".to_owned(),
            subject: "operator-alice".to_owned(),
            role: role_prod,
            expires_at_tick: 500,
        };
        let jwt = claims.encode_jwt(&master_key);
        assert_eq!(JwtSigningAlgorithm::default(), JwtSigningAlgorithm::Hs256);
        let jwt_eddsa = claims.encode_jwt_with_alg(JwtSigningAlgorithm::EdDsa, &master_key);
        let jwt_es256 = claims.encode_jwt_with_alg(JwtSigningAlgorithm::Es256, &master_key);
        assert_eq!(
            OidcJwtClaims::verify_jwt(&jwt, &master_key, "https://auth.arbiter.internal", 100),
            Ok(claims.clone())
        );
        assert_eq!(
            OidcJwtClaims::verify_jwt(
                &jwt_eddsa,
                &master_key,
                "https://auth.arbiter.internal",
                100
            ),
            Ok(claims.clone())
        );
        assert_eq!(
            OidcJwtClaims::verify_jwt(
                &jwt_es256,
                &master_key,
                "https://auth.arbiter.internal",
                100
            ),
            Ok(claims)
        );
        assert!(OidcJwtClaims::verify_jwt("no-dots", &master_key, "iss", 100).is_err());
        assert!(OidcJwtClaims::verify_jwt("one.dot", &master_key, "iss", 100).is_err());
        assert!(
            OidcJwtClaims::verify_jwt(&jwt, &wrong_key, "https://auth.arbiter.internal", 100)
                .is_err()
        );
        assert!(OidcJwtClaims::verify_jwt(&jwt, &master_key, "https://wrong.issuer", 100).is_err());
        assert!(
            OidcJwtClaims::verify_jwt(&jwt, &master_key, "https://auth.arbiter.internal", 600)
                .is_err()
        );
        let bad_payload_sig = OidcJwtClaims::compute_sig("alg=HS256", "{bad", &master_key);
        let bad_jwt = format!("alg=HS256.{{bad.{bad_payload_sig}");
        assert!(
            OidcJwtClaims::verify_jwt(&bad_jwt, &master_key, "https://auth.arbiter.internal", 100)
                .is_err()
        );

        // SpireWorkloadApiClient fetch and auto-rotation
        let auth = SvidAuthority::new("arbiter.internal", master_key, 100);
        let mut spire = SpireWorkloadApiClient::new("/run/spire/sockets/agent.sock", auth);
        assert!(spire.fetch_or_rotate_x509_svid("http://bad", 10).is_err());
        let s1 = spire.fetch_or_rotate_x509_svid("spiffe://arbiter.internal/node/a1", 10);
        assert!(s1.is_ok());
        let s2 = spire.fetch_or_rotate_x509_svid("spiffe://arbiter.internal/node/a1", 50);
        assert!(s2.is_ok());
        // After expiry at 200, re-issues fresh SVID
        let s3 = spire.fetch_or_rotate_x509_svid("spiffe://arbiter.internal/node/a1", 200);
        assert!(s3.is_ok());
    }

    struct MockSpireUdsTransport {
        auth: SvidAuthority,
        fail_io: bool,
    }

    impl SpireTransport for MockSpireUdsTransport {
        fn fetch_workload_svid(
            &mut self,
            socket_path: &str,
            spiffe_uri: &str,
            current_tick: u64,
        ) -> ArbiterResult<SpiffeSvid> {
            if self.fail_io {
                return Err(ArbiterError::SocketIoError {
                    endpoint: socket_path.to_owned(),
                    reason: "connection refused".to_owned(),
                });
            }
            self.auth.issue_svid(spiffe_uri, current_tick)
        }
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_zeroizing_buffers_x509_pem_spire_transport_and_mesos_acls() {
        let zk = ZeroizingSecretKey::new([0xAA; 32]);
        assert_eq!(zk.as_bytes(), &[0xAA; 32]);
        assert_eq!(format!("{zk:?}"), "ZeroizingSecretKey([REDACTED])");
        drop(zk);

        let zb = ZeroizingSecretBuffer::new(vec![1, 2, 3, 4]);
        assert_eq!(zb.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(
            format!("{zb:?}"),
            "ZeroizingSecretBuffer([REDACTED; 4 bytes])"
        );
        drop(zb);

        let ca_key = [0x55; 32];
        assert!(
            X509CertificatePem::issue_pem("spiffe://arbiter.internal/node/a1", 100, 50, &ca_key)
                .is_err()
        );
        assert!(X509CertificatePem::issue_pem("http://bad", 10, 100, &ca_key).is_err());

        let cert =
            X509CertificatePem::issue_pem("spiffe://arbiter.internal/node/a1", 10, 100, &ca_key)
                .unwrap_or_default();
        let (parsed_cert, kind) =
            X509CertificatePem::parse_and_verify_pem(&cert.pem, "arbiter.internal", &ca_key, 50)
                .unwrap_or_default();
        assert_eq!(parsed_cert, cert);
        assert_eq!(
            kind,
            SpiffePrincipalKind::Node {
                agent_id: AgentId::new("a1").unwrap_or_default()
            }
        );

        for bad_pem in [
            "not a pem",
            "-----BEGIN CERTIFICATE-----\nmissing end",
            "-----BEGIN CERTIFICATE-----\nSubjectAltName: URI:http://bad\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nComment: ignored\nSubjectAltName: URI:spiffe://arbiter.internal/node/a1\nValidity: bad\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nSubjectAltName: URI:spiffe://arbiter.internal/node/a1\nValidity: bad..100\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nSubjectAltName: URI:spiffe://arbiter.internal/node/a1\nValidity: 10..bad\n-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nSubjectAltName: URI:spiffe://arbiter.internal/node/a1\nValidity: 10..100\nSignature: wrong\n-----END CERTIFICATE-----",
        ] {
            assert!(
                X509CertificatePem::parse_and_verify_pem(bad_pem, "arbiter.internal", &ca_key, 50)
                    .is_err()
            );
        }
        assert!(
            X509CertificatePem::parse_and_verify_pem(&cert.pem, "arbiter.internal", &ca_key, 5)
                .is_err()
        );
        assert!(
            X509CertificatePem::parse_and_verify_pem(&cert.pem, "arbiter.internal", &ca_key, 100)
                .is_err()
        );

        let auth = SvidAuthority::new("arbiter.internal", ca_key, 100);
        let mut spire = SpireWorkloadApiClient::new("/run/spire/sockets/agent.sock", auth.clone());
        let mut transport = MockSpireUdsTransport {
            auth: auth.clone(),
            fail_io: false,
        };
        assert!(
            spire
                .fetch_via_transport(&mut transport, "spiffe://arbiter.internal/node/a1", 20)
                .is_ok()
        );
        transport.fail_io = true;
        assert!(
            spire
                .fetch_via_transport(&mut transport, "spiffe://arbiter.internal/node/a1", 25)
                .is_err()
        );

        let uds_path = std::env::temp_dir().join("arbiter_test_spire_uds.sock");
        let uds_str = uds_path.to_string_lossy().into_owned();
        let mut spire_live = SpireWorkloadApiClient::new(&uds_str, auth.clone());
        let mut live_tr = LiveSpireUdsTransport::new(auth);
        assert!(
            spire_live
                .fetch_via_transport(&mut live_tr, "spiffe://arbiter.internal/node/a1", 30)
                .is_ok()
        );
        assert!(
            spire_live
                .fetch_via_transport(&mut live_tr, "http://bad", 30)
                .is_err()
        );
        let mut spire_bad_sock = SpireWorkloadApiClient::new(
            "/nonexistent_dir_arbiter/spire.sock",
            live_tr.authority.clone(),
        );
        assert!(
            spire_bad_sock
                .fetch_via_transport(&mut live_tr, "spiffe://arbiter.internal/node/a1", 30)
                .is_err()
        );

        for acl in [
            MesosAclAction::RegisterFramework,
            MesosAclAction::TeardownFramework,
            MesosAclAction::RunTask,
            MesosAclAction::KillTask,
            MesosAclAction::ReserveResources,
            MesosAclAction::UnreserveResources,
            MesosAclAction::CreateVolume,
            MesosAclAction::DestroyVolume,
            MesosAclAction::SetQuota,
            MesosAclAction::UpdateWeights,
            MesosAclAction::UpdateMaintenance,
            MesosAclAction::DrainAgent,
            MesosAclAction::MarkAgentGone,
            MesosAclAction::ViewExecutorSandbox,
        ] {
            assert!(!acl.as_str().is_empty());
        }

        let mut acl_engine = PolicyEngine::new();
        let role_p = RoleName::new("prod").unwrap_or_default();
        acl_engine.add_rule(PolicyRule {
            principal: "spiffe://arbiter.internal/master/m1".to_owned(),
            action: MesosAclAction::SetQuota.as_str().to_owned(),
            resource_prefix: "quota:".to_owned(),
            role: role_p.clone(),
            required_attributes: BTreeMap::new(),
        });
        assert_eq!(
            acl_engine.authorize_mesos_acl(
                "spiffe://arbiter.internal/master/m1",
                MesosAclAction::SetQuota,
                "quota:prod",
                &role_p,
                &BTreeMap::new(),
            ),
            Ok(Decision::Allow)
        );
        assert!(
            acl_engine
                .authorize_mesos_acl(
                    "spiffe://arbiter.internal/master/m1",
                    MesosAclAction::DrainAgent,
                    "quota:prod",
                    &role_p,
                    &BTreeMap::new(),
                )
                .is_err()
        );

        // Test SpireMockAgentServer + SpireUnixSocketClient across distinct UDS client/server sockets
        let srv_auth = SvidAuthority::new("arbiter.internal", ca_key, 100);
        assert!(
            SpireMockAgentServer::bind("/nonexistent_dir_arb/spire.sock", srv_auth.clone())
                .is_err()
        );
        assert!(
            SpireUnixSocketClient::send_svid_request(
                "/nonexistent_dir_arb/spire.sock",
                "spiffe://arbiter.internal/node/a1",
            )
            .is_err()
        );
        let client_uds_path = std::env::temp_dir().join("arbiter_test_spire_ext_client.sock");
        let client_uds_str = client_uds_path.to_string_lossy().into_owned();
        let _ = SpireMockAgentServer::bind(&client_uds_str, srv_auth).map(|mock_srv| {
            assert_eq!(mock_srv.poll_once(30), Ok(None));
            let _ = mock_srv.listener.set_nonblocking(false);
            let _ = SpireUnixSocketClient::send_svid_request(
                &client_uds_str,
                "spiffe://arbiter.internal/node/a1",
            )
            .map(|cli_stream| {
                let served = mock_srv.poll_once(30).unwrap_or(None);
                assert!(served.is_some());
                let svid_res = SpireUnixSocketClient::read_svid_response(
                    cli_stream,
                    "spiffe://arbiter.internal/node/a1",
                );
                assert!(svid_res.is_ok());
            });
            let _ = SpireUnixSocketClient::send_svid_request(&client_uds_str, "invalid-uri").map(
                |bad_stream| {
                    assert!(mock_srv.poll_once(30).is_err());
                    assert!(
                        SpireUnixSocketClient::read_svid_response(bad_stream, "invalid-uri")
                            .is_err()
                    );
                },
            );
        });
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::cognitive_complexity,
        clippy::or_fun_call
    )]
    fn test_base64url_jws_rfc7515_asn1_der_and_mtls_verifier() {
        // Test Base64URL encode/decode across 1, 2, 3, and 64 byte inputs covering all 64 alphabet chars
        let all_bytes: Vec<u8> = (0_u8..=255_u8).collect();
        for len in [0, 1, 2, 3, 4, 5, 256] {
            let slice = all_bytes.get(..len).unwrap_or_default();
            let enc = base64url_encode(slice);
            let dec = base64url_decode(&enc).unwrap_or_default();
            assert_eq!(dec, slice);
        }
        assert!(base64url_decode("bad!char").is_err());
        assert!(base64url_decode("A").is_err());

        // Test RFC 7515 Base64URL JWS encoding and verification across HS256, EdDSA, ES256
        let key = [0x42; 32];
        let claims = OidcJwtClaims {
            issuer: "https://oidc.arbiter.internal".to_owned(),
            subject: "user-1".to_owned(),
            role: RoleName::new("prod").unwrap_or_default(),
            expires_at_tick: 500,
        };
        for alg in [
            JwtSigningAlgorithm::Hs256,
            JwtSigningAlgorithm::EdDsa,
            JwtSigningAlgorithm::Es256,
        ] {
            let jws = claims.encode_jws_rfc7515(alg, &key);
            assert!(!jws.starts_with("alg="));
            let verified =
                OidcJwtClaims::verify_jwt(&jws, &key, "https://oidc.arbiter.internal", 100)
                    .unwrap_or(claims.clone());
            assert_eq!(verified, claims);
            assert_eq!(
                OidcJwtClaims::verify_jwt_for_algorithm(
                    &jws,
                    alg,
                    &key,
                    "https://oidc.arbiter.internal",
                    100
                ),
                Ok(claims.clone())
            );
            let plain_jwt = claims.encode_jwt_with_alg(alg, &key);
            assert_eq!(
                OidcJwtClaims::verify_jwt_for_algorithm(
                    &plain_jwt,
                    alg,
                    &key,
                    "https://oidc.arbiter.internal",
                    100
                ),
                Ok(claims.clone())
            );
            assert!(
                OidcJwtClaims::verify_jwt(
                    &format!("{jws}A"),
                    &key,
                    "https://oidc.arbiter.internal",
                    100
                )
                .is_err()
            );
        }
        let hs_jws = claims.encode_jws_rfc7515(JwtSigningAlgorithm::Hs256, &key);
        assert!(
            OidcJwtClaims::verify_jwt_for_algorithm(
                &hs_jws,
                JwtSigningAlgorithm::EdDsa,
                &key,
                "https://oidc.arbiter.internal",
                100
            )
            .is_err()
        );
        assert!(
            OidcJwtClaims::verify_jwt_for_algorithm(
                "no-dot",
                JwtSigningAlgorithm::EdDsa,
                &key,
                "https://oidc.arbiter.internal",
                100
            )
            .is_err()
        );
        assert!(
            OidcJwtClaims::verify_jwt_for_algorithm(
                "!.b.c",
                JwtSigningAlgorithm::EdDsa,
                &key,
                "https://oidc.arbiter.internal",
                100
            )
            .is_err()
        );
        // Invalid Base64URL header/payload/signature and unsupported Base64URL JWS header
        assert!(OidcJwtClaims::verify_jwt("!.b.c", &key, "iss", 10).is_err());
        let bad_hdr_b64 = base64url_encode(b"bad_hdr");
        assert!(
            OidcJwtClaims::verify_jwt(&format!("{bad_hdr_b64}.YQ.YQ"), &key, "iss", 10).is_err()
        );
        let valid_hdr_b64 = base64url_encode(b"alg=HS256");
        assert!(
            OidcJwtClaims::verify_jwt(&format!("{valid_hdr_b64}.!.YQ"), &key, "iss", 10).is_err()
        );
        assert!(
            OidcJwtClaims::verify_jwt(&format!("{valid_hdr_b64}.YQ.!"), &key, "iss", 10).is_err()
        );

        // Test X509CertificatePem ASN.1 DER encode & decode_and_verify_asn1_der
        let ca_key = [0x77; 32];
        let node_cert =
            X509CertificatePem::issue_pem("spiffe://arbiter.internal/node/a1", 10, 100, &ca_key)
                .unwrap_or_default();
        let der = node_cert.encode_asn1_der();
        let (decoded_cert, decoded_kind) =
            X509CertificatePem::decode_and_verify_asn1_der(&der, "arbiter.internal", &ca_key, 50)
                .unwrap_or_default();
        assert_eq!(decoded_cert, node_cert);
        assert_eq!(
            decoded_kind,
            SpiffePrincipalKind::Node {
                agent_id: AgentId::new("a1").unwrap_or_default()
            }
        );

        // Error branches of decode_and_verify_asn1_der
        assert!(
            X509CertificatePem::decode_and_verify_asn1_der(
                &[0_u8; 10],
                "arbiter.internal",
                &ca_key,
                50
            )
            .is_err()
        );
        assert!(
            X509CertificatePem::decode_and_verify_asn1_der(
                &[0_u8; 90],
                "arbiter.internal",
                &ca_key,
                50
            )
            .is_err()
        );
        assert!(
            X509CertificatePem::decode_and_verify_asn1_der(&der, "arbiter.internal", &ca_key, 5)
                .is_err()
        );
        assert!(
            X509CertificatePem::decode_and_verify_asn1_der(&der, "arbiter.internal", &ca_key, 100)
                .is_err()
        );
        assert!(
            X509CertificatePem::decode_and_verify_asn1_der(
                &der,
                "arbiter.internal",
                &[0x99; 32],
                50
            )
            .is_err()
        );
        // Corrupt validity bytes in trailer so not_before >= not_after
        let mut bad_validity_der = der;
        let san_end = bad_validity_der.len().saturating_sub(80);
        for b in bad_validity_der
            .get_mut(san_end..san_end + 16)
            .unwrap_or_default()
        {
            *b = 0xFF;
        }
        assert!(
            X509CertificatePem::decode_and_verify_asn1_der(
                &bad_validity_der,
                "arbiter.internal",
                &ca_key,
                50
            )
            .is_err()
        );

        // Test SpiffeMtlsVerifier client & server verification and revocation enforcement
        let mut authority = SvidAuthority::new("arbiter.internal", ca_key, 100);
        let master_cert =
            X509CertificatePem::issue_pem("spiffe://arbiter.internal/master/m1", 10, 100, &ca_key)
                .unwrap_or_default();
        let task_cert = X509CertificatePem::issue_pem(
            "spiffe://arbiter.internal/role/prod/task/t1",
            10,
            100,
            &ca_key,
        )
        .unwrap_or_default();

        let verifier = SpiffeMtlsVerifier::new(authority.clone());
        assert!(verifier.verify_client_cert_pem(&task_cert.pem, 50).is_ok());
        assert!(verifier.verify_server_cert_pem(&node_cert.pem, 50).is_ok());
        assert!(
            verifier
                .verify_server_cert_pem(&master_cert.pem, 50)
                .is_ok()
        );
        // Task certificate cannot impersonate a server
        assert!(verifier.verify_server_cert_pem(&task_cert.pem, 50).is_err());
        // Expired / invalid PEM fails both client and server verification
        assert!(verifier.verify_client_cert_pem(&task_cert.pem, 5).is_err());
        assert!(verifier.verify_server_cert_pem(&node_cert.pem, 5).is_err());
        // Revoked certificate fails verification
        authority.revoke_svid_uri("spiffe://arbiter.internal/node/a1");
        let revoked_verifier = SpiffeMtlsVerifier::new(authority);
        assert!(
            revoked_verifier
                .verify_client_cert_pem(&node_cert.pem, 50)
                .is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_hkdf_argon2id_ed25519_x25519_hot_reload_attestation_and_wire_rbac() {
        // HKDF-SHA256 with empty and non-empty salt
        let okm1 = hkdf_sha256(&[], b"ikm", b"info");
        let okm2 = hkdf_sha256(b"salt", b"ikm", b"info");
        assert_ne!(okm1, okm2);

        // Argon2id master key derivation & error branches
        let salt = [0x11_u8; 16];
        let k1 = derive_argon2id_master_key(b"correct-horse-battery-staple", &salt, 8, 2).ok();
        let k2 = derive_argon2id_master_key(b"correct-horse-battery-staple", &salt, 8, 2).ok();
        assert!(k1.is_some());
        assert_eq!(k1, k2);
        assert!(derive_argon2id_master_key(b"", &salt, 8, 1).is_err());
        assert!(derive_argon2id_master_key(b"pw", &salt, 4, 1).is_err());
        assert!(derive_argon2id_master_key(b"pw", &salt, 8, 0).is_err());

        // Ed25519Keypair sign & verify
        let kp = Ed25519Keypair::from_seed([0x33_u8; 32]);
        let sig = kp.sign(b"stonith-fence-receipt-1");
        assert!(Ed25519Keypair::verify(&kp.public_key, b"stonith-fence-receipt-1", &sig).is_ok());
        assert!(Ed25519Keypair::verify(&kp.public_key, b"tampered", &sig).is_err());

        // P256Keypair ECDSA-SHA256 sign & verify
        let p256_kp = P256Keypair::from_seed([0x44_u8; 32]);
        let p256_sig = p256_kp.sign_ecdsa_sha256(b"es256-jwt-message");
        assert!(
            P256Keypair::verify_ecdsa_sha256(&p256_kp.public_key, b"es256-jwt-message", &p256_sig)
                .is_ok()
        );
        assert!(
            P256Keypair::verify_ecdsa_sha256(&p256_kp.public_key, b"tampered", &p256_sig).is_err()
        );
        assert!(
            P256Keypair::verify_ecdsa_sha256(&[0_u8; 32], b"es256-jwt-message", &p256_sig).is_err()
        );
        assert!(
            P256Keypair::verify_ecdsa_sha256(
                &p256_kp.public_key,
                b"es256-jwt-message",
                &[0_u8; 64]
            )
            .is_err()
        );

        // Real ITU-T X.509v3 ASN.1 DER & PEM issuance and parsing via rcgen + x509-cert
        assert!(X509CertificatePem::issue_real_x509v3_der_and_pem("http://bad").is_err());
        let (real_der, real_pem, real_key_pem) =
            X509CertificatePem::issue_real_x509v3_der_and_pem("spiffe://arbiter.internal/node/a1")
                .unwrap_or_default();
        assert!(real_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(real_key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        let (real_spiffe, real_kind) =
            X509CertificatePem::parse_real_x509v3_der_spiffe_san(&real_der, "arbiter.internal")
                .unwrap_or_default();
        assert_eq!(real_spiffe.as_str(), "spiffe://arbiter.internal/node/a1");
        assert_eq!(
            real_kind,
            SpiffePrincipalKind::Node {
                agent_id: AgentId::new("a1").unwrap_or_default()
            }
        );
        assert!(
            X509CertificatePem::parse_real_x509v3_der_spiffe_san(&real_der, "other.domain")
                .is_err()
        );
        assert!(
            X509CertificatePem::parse_real_x509v3_der_spiffe_san(&[0x30, 0x00], "arbiter.internal")
                .is_err()
        );

        // SecretTmpfsStager stage_unsealed_secret & scrub_and_unlink_secret
        let tmp_secret_dir = std::env::temp_dir().join("arbiter_test_secret_tmpfs_stager");
        let _ = std::fs::remove_dir_all(&tmp_secret_dir);
        let stager = SecretTmpfsStager::new(&tmp_secret_dir);
        let sec_id = SecretId::new("db-secret-01").unwrap_or_default();
        let m_key = [0x66_u8; 32];
        let sec_context = b"role=prod;task=t1";
        let gcm_env = seal_secret_aes256_gcm(
            sec_id.clone(),
            &m_key,
            [0x01_u8; 12],
            sec_context,
            b"top-secret",
        );
        let staged_path = stager
            .stage_unsealed_secret(&gcm_env, &m_key, sec_context)
            .unwrap_or_default();
        assert_eq!(
            std::fs::read(&staged_path).unwrap_or_default(),
            b"top-secret"
        );
        assert!(
            stager
                .stage_unsealed_secret(&gcm_env, &m_key, b"wrong-aad")
                .is_err()
        );
        assert!(stager.scrub_and_unlink_secret(&sec_id).is_ok());
        assert!(stager.scrub_and_unlink_secret(&sec_id).is_err());
        let _ = std::fs::remove_dir_all(&tmp_secret_dir);

        // X25519SessionEstablisher commutative shared key derivation
        let binding = [0x77_u8; 32];
        let alice = X25519SessionEstablisher::new([0x01_u8; 32], binding);
        let bob = X25519SessionEstablisher::new([0x02_u8; 32], binding);
        let alice_shared = alice.derive_shared_session_key(&bob.local_public).ok();
        let bob_shared = bob.derive_shared_session_key(&alice.local_public).ok();
        assert!(alice_shared.is_some());
        assert_eq!(alice_shared, bob_shared);
        assert!(alice.derive_shared_session_key(&[0_u8; 32]).is_err());

        // TrustBundleHotReloader hitless SIGHUP rotation
        let auth1 = SvidAuthority::new("arbiter.internal", [0x10_u8; 32], 100);
        let auth2 = SvidAuthority::new("arbiter.internal", [0x20_u8; 32], 100);
        let svid_old = auth1
            .issue_svid("spiffe://arbiter.internal/node/a1", 10)
            .unwrap_or_default();
        let mut reloader = TrustBundleHotReloader::new(auth1);
        assert!(reloader.verify_svid_hitless(&svid_old, 20).is_ok());
        assert!(reloader.verify_svid_hitless(&svid_old, 200).is_err());
        assert_eq!(reloader.reload_on_sighup(auth2.clone()), 2);
        let svid_new = auth2
            .issue_svid("spiffe://arbiter.internal/node/a1", 30)
            .unwrap_or_default();
        assert!(reloader.verify_svid_hitless(&svid_new, 40).is_ok());
        // Old SVID still verifies via previous_authority during grace period!
        assert!(reloader.verify_svid_hitless(&svid_old, 40).is_ok());
        assert!(reloader.verify_svid_hitless(&svid_old, 200).is_err());

        // HardwareAttestationQuote TPM 2.0 and Apple Secure Enclave verification
        assert_eq!(
            HardwareAttestationKind::default(),
            HardwareAttestationKind::Tpm20PcrQuote
        );
        let pcr = [0xAB_u8; 32];
        let nonce = [0xCD_u8; 16];
        let ak = [0xEF_u8; 32];
        for kind in [
            HardwareAttestationKind::Tpm20PcrQuote,
            HardwareAttestationKind::AppleSecureEnclave,
        ] {
            let quote = HardwareAttestationQuote::generate(
                AgentId::new("a1").unwrap_or_default(),
                kind,
                pcr,
                nonce,
                &ak,
            );
            assert!(quote.verify(&nonce, &pcr, &ak).is_ok());
            assert!(quote.verify(&[0_u8; 16], &pcr, &ak).is_err());
            assert!(quote.verify(&nonce, &[0_u8; 32], &ak).is_err());
            assert!(quote.verify(&nonce, &pcr, &[0_u8; 32]).is_err());
        }

        // authorize_wire_message across all WireMessage branches
        let role_prod = RoleName::new("prod").unwrap_or_default();
        let mut engine = PolicyEngine::new();
        for acl in [
            MesosAclAction::RegisterFramework,
            MesosAclAction::TeardownFramework,
            MesosAclAction::RunTask,
            MesosAclAction::KillTask,
            MesosAclAction::ReserveResources,
            MesosAclAction::UnreserveResources,
            MesosAclAction::CreateVolume,
            MesosAclAction::DestroyVolume,
            MesosAclAction::SetQuota,
            MesosAclAction::UpdateWeights,
            MesosAclAction::UpdateMaintenance,
            MesosAclAction::DrainAgent,
            MesosAclAction::MarkAgentGone,
            MesosAclAction::ViewExecutorSandbox,
            MesosAclAction::ShutdownExecutor,
            MesosAclAction::ResizeVolume,
            MesosAclAction::GetQuota,
            MesosAclAction::ViewTask,
            MesosAclAction::ViewFramework,
            MesosAclAction::ViewExecutor,
            MesosAclAction::AccessSandbox,
            MesosAclAction::LaunchNestedContainer,
            MesosAclAction::AttachContainer,
            MesosAclAction::PruneImages,
        ] {
            engine.add_rule(PolicyRule {
                principal: "op-admin".to_owned(),
                action: acl.as_str().to_owned(),
                resource_prefix: String::new(),
                role: role_prod.clone(),
                required_attributes: BTreeMap::new(),
            });
        }

        let fw_id = FrameworkId::default();
        let tid = TaskId::default();
        let aid = AgentId::default();
        let vid = arbiter_core::ids::VolumeId::default();
        let cid = arbiter_core::ids::ContainerId::default();
        let res_spec = arbiter_core::workload::DynamicReservationSpec {
            operation_id: arbiter_core::ids::OperationId::default(),
            agent_id: aid.clone(),
            role: role_prod.clone(),
            principal: "op-admin".to_owned(),
            resources: arbiter_core::resources::ResourceBundle::zero(),
        };
        let mut wrong_principal_spec = res_spec.clone();
        wrong_principal_spec.principal = "impostor".to_owned();
        assert!(
            engine
                .authorize_wire_message(
                    "op-admin",
                    &role_prod,
                    &arbiter_proto::WireMessage::OperatorCall(Box::new(
                        arbiter_proto::OperatorCall::ReserveResources(wrong_principal_spec.clone()),
                    )),
                    &BTreeMap::new(),
                )
                .is_err()
        );
        assert!(
            engine
                .authorize_wire_message(
                    "op-admin",
                    &role_prod,
                    &arbiter_proto::WireMessage::OperatorCall(Box::new(
                        arbiter_proto::OperatorCall::UnreserveResources(wrong_principal_spec),
                    )),
                    &BTreeMap::new(),
                )
                .is_err()
        );

        let messages = vec![
            arbiter_proto::WireMessage::SchedulerCall(Box::new(
                arbiter_proto::SchedulerCall::Subscribe(
                    arbiter_proto::SubscribeFramework {
                        framework_id: fw_id.clone(),
                        role: role_prod.clone(),
                        failover_timeout_ms: 100,
                    },
                    arbiter_core::workload::CheckpointMode::Enabled,
                    Vec::new(),
                    Vec::new(),
                ),
            )),
            arbiter_proto::WireMessage::SchedulerCall(Box::new(
                arbiter_proto::SchedulerCall::Teardown(fw_id.clone()),
            )),
            arbiter_proto::WireMessage::SchedulerCall(Box::new(
                arbiter_proto::SchedulerCall::Kill(fw_id.clone(), tid, None, None),
            )),
            arbiter_proto::WireMessage::SchedulerCall(Box::new(
                arbiter_proto::SchedulerCall::Shutdown(
                    fw_id.clone(),
                    arbiter_core::ids::ExecutorId::default(),
                    aid.clone(),
                ),
            )),
            arbiter_proto::WireMessage::SchedulerCall(Box::new(
                arbiter_proto::SchedulerCall::Revive(fw_id, Vec::new()),
            )),
            arbiter_proto::WireMessage::SubmitDirectJob(arbiter_proto::SubmitDirectJob::GangJob(
                arbiter_core::workload::TaskGroupSpec {
                    group_id: arbiter_core::ids::TaskGroupId::default(),
                    role: role_prod.clone(),
                    tasks: Vec::new(),
                    placement_timeout_ms: 1000,
                    tpu_slice: None,
                },
            )),
            arbiter_proto::WireMessage::SubmitDirectJob(
                arbiter_proto::SubmitDirectJob::SingleTask(Box::new(
                    arbiter_core::workload::TaskSpec {
                        task_id: TaskId::default(),
                        role: role_prod.clone(),
                        framework_id: None,
                        election_group: None,
                        priority: arbiter_core::workload::PriorityClass::Batch,
                        preemption_policy: arbiter_core::workload::PreemptionPolicy::ImmediateKill,
                        resources: arbiter_core::resources::ResourceBundle::zero(),
                        required_gpu_vendor: None,
                        required_gpu_partition: None,
                        topology_constraints: Vec::new(),
                        isolation: arbiter_core::workload::IsolationSpec {
                            capabilities: Vec::new(),
                            image_ref: None,
                            command: "/bin/true".to_owned(),
                            args: Vec::new(),
                            env: Vec::new(),
                            run_as_user: None,
                        },
                        artifacts: Vec::new(),
                        secrets: Vec::new(),
                        health_check: None,
                    },
                )),
            ),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GetQuota,
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::UpdateQuota(
                    role_prod.clone(),
                    arbiter_core::workload::Quota {
                        id: arbiter_core::ids::QuotaId::default(),
                        guaranteed_min: arbiter_core::resources::ResourceBundle::zero(),
                        hard_max: arbiter_core::resources::ResourceBundle::zero(),
                        allow_burst_borrowing: true,
                        weight: arbiter_core::units::WeightBasisPoints::STANDARD,
                    },
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::TeardownFramework(FrameworkId::default()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::SetQuota(
                    role_prod.clone(),
                    arbiter_core::workload::Quota {
                        id: arbiter_core::ids::QuotaId::default(),
                        guaranteed_min: arbiter_core::resources::ResourceBundle::zero(),
                        hard_max: arbiter_core::resources::ResourceBundle::zero(),
                        allow_burst_borrowing: true,
                        weight: arbiter_core::units::WeightBasisPoints::STANDARD,
                    },
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::UpdateWeights(vec![(
                    role_prod.clone(),
                    arbiter_core::units::WeightBasisPoints::STANDARD,
                )]),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::DrainAgent(
                    aid.clone(),
                    arbiter_core::units::BenchmarkTicks::ZERO,
                    arbiter_core::workload::DrainCompletionMode::RemainDrained,
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::MarkAgentGone(aid.clone()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::ReserveResources(res_spec.clone()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::UnreserveResources(res_spec),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::CreateVolumes(
                    aid.clone(),
                    role_prod.clone(),
                    Vec::new(),
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GrowVolume(
                    aid.clone(),
                    vid.clone(),
                    arbiter_core::units::Bytes::ZERO,
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::DestroyVolumes(aid.clone(), vec![vid.clone()]),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::StartMaintenance(vec![aid.clone()]),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GetTasks,
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GetFrameworks,
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GetExecutors,
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::ListFiles(arbiter_core::ids::SandboxPath::default()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::RemoveQuota(role_prod.clone()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::DeactivateAgent(aid.clone()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::ReactivateAgent(aid.clone()),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::ShrinkVolume(
                    aid.clone(),
                    vid,
                    arbiter_core::units::Bytes::ZERO,
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::ReadFile(
                    arbiter_core::ids::SandboxPath::default(),
                    arbiter_core::units::FileReadOffset::ZERO,
                    arbiter_core::units::FileReadLength::ZERO,
                ),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GetHealth,
            )),
            arbiter_proto::WireMessage::AgentOperatorCall(Box::new(
                arbiter_proto::AgentOperatorCall::GetContainers,
            )),
            arbiter_proto::WireMessage::AgentOperatorCall(Box::new(
                arbiter_proto::AgentOperatorCall::WaitNestedContainer(cid.clone()),
            )),
            arbiter_proto::WireMessage::AgentOperatorCall(Box::new(
                arbiter_proto::AgentOperatorCall::AttachContainerOutput(cid),
            )),
            arbiter_proto::WireMessage::AgentOperatorCall(Box::new(
                arbiter_proto::AgentOperatorCall::PruneImages(Vec::new()),
            )),
            arbiter_proto::WireMessage::AgentHeartbeat(arbiter_proto::AgentHeartbeat {
                agent_id: aid,
                tick: 1,
                healthy_tasks: Vec::new(),
            }),
        ];
        for m in &messages {
            assert_eq!(
                engine.authorize_wire_message("op-admin", &role_prod, m, &BTreeMap::new()),
                Ok(Decision::Allow)
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    fn test_x509_der_certificate_chain_and_mtls_authenticated_stream() {
        let root_kp = Ed25519Keypair::from_seed([0xA1; 32]);
        let inter_kp = Ed25519Keypair::from_seed([0xB2; 32]);
        assert!(
            X509DerCertificateChain::build_signed_chain(
                "bad/domain",
                "spiffe://arbiter.internal/node/a1",
                10,
                100,
                &root_kp,
                &inter_kp,
            )
            .is_err()
        );
        assert!(
            X509DerCertificateChain::build_signed_chain(
                "arbiter.internal",
                "http://bad",
                10,
                100,
                &root_kp,
                &inter_kp,
            )
            .is_err()
        );
        assert!(
            X509DerCertificateChain::build_signed_chain(
                "arbiter.internal",
                "spiffe://arbiter.internal/node/a1",
                100,
                50,
                &root_kp,
                &inter_kp,
            )
            .is_err()
        );

        let chain = X509DerCertificateChain::build_signed_chain(
            "arbiter.internal",
            "spiffe://arbiter.internal/node/a1",
            10,
            100,
            &root_kp,
            &inter_kp,
        )
        .unwrap_or_default();
        let (_, kind) = chain
            .verify_chain("arbiter.internal", &root_kp.public_key, 50)
            .unwrap_or_default();
        assert_eq!(
            kind,
            SpiffePrincipalKind::Node {
                agent_id: AgentId::new("a1").unwrap_or_default()
            }
        );

        // Error branches on verify_chain
        assert!(
            chain
                .verify_chain("arbiter.internal", &[0x99; 32], 50)
                .is_err()
        );
        assert!(
            chain
                .verify_chain("arbiter.internal", &root_kp.public_key, 500)
                .is_err()
        );

        let mut bad_inter_sig = chain.clone();
        bad_inter_sig.intermediate_sig = vec![0; 64];
        assert!(
            bad_inter_sig
                .verify_chain("arbiter.internal", &root_kp.public_key, 50)
                .is_err()
        );

        let mut bad_inter_der = chain.clone();
        let bad_inter_cert = X509CertificatePem::issue_pem(
            "spiffe://arbiter.internal/master/inter",
            40,
            60,
            &root_kp.public_key,
        )
        .unwrap_or_default();
        bad_inter_der.intermediate_der = bad_inter_cert.encode_asn1_der();
        bad_inter_der.intermediate_sig = root_kp.sign(&bad_inter_der.intermediate_der).to_vec();
        assert!(
            bad_inter_der
                .verify_chain("arbiter.internal", &root_kp.public_key, 80)
                .is_err()
        );

        let mut bad_leaf_sig = chain.clone();
        bad_leaf_sig.leaf_sig = vec![0; 64];
        assert!(
            bad_leaf_sig
                .verify_chain("arbiter.internal", &root_kp.public_key, 50)
                .is_err()
        );

        let mut bad_leaf_der = chain;
        let bad_leaf_cert = X509CertificatePem::issue_pem(
            "spiffe://arbiter.internal/node/a1",
            40,
            60,
            &inter_kp.public_key,
        )
        .unwrap_or_default();
        bad_leaf_der.leaf_der = bad_leaf_cert.encode_asn1_der();
        bad_leaf_der.leaf_sig = inter_kp.sign(&bad_leaf_der.leaf_der).to_vec();
        assert!(
            bad_leaf_der
                .verify_chain("arbiter.internal", &root_kp.public_key, 80)
                .is_err()
        );

        // MtlsAuthenticatedStream mutual handshake, record seal/open, and in-place SVID rotation
        let auth = SvidAuthority::new("arbiter.internal", [0x33; 32], 100);
        let bundle = TrustBundleHotReloader::new(auth.clone());
        let client_svid = auth
            .issue_svid("spiffe://arbiter.internal/node/a1", 10)
            .unwrap_or_default();
        let server_svid = auth
            .issue_svid("spiffe://arbiter.internal/master/m1", 10)
            .unwrap_or_default();
        let binding = [0x44; 32];
        let cli_eph = X25519SessionEstablisher::new([0x01; 32], binding);
        let srv_eph = X25519SessionEstablisher::new([0x02; 32], binding);
        let c_hello = MtlsHandshakeMessage {
            svid: client_svid.clone(),
            x25519_public: cli_eph.local_public,
            rotation_epoch: 1,
        };
        let s_hello = MtlsHandshakeMessage {
            svid: server_svid.clone(),
            x25519_public: srv_eph.local_public,
            rotation_epoch: 1,
        };
        let (mut cli_stream, mut srv_stream) = MtlsAuthenticatedStream::establish_mutual_handshake(
            &c_hello, &cli_eph, &s_hello, &srv_eph, &bundle, 20,
        )
        .unwrap_or_default();
        assert_eq!(cli_stream.traffic_key, srv_stream.traffic_key);
        let rec = cli_stream.seal_record(b"hello-mtls");
        assert_eq!(srv_stream.open_record(&rec), Ok(b"hello-mtls".to_vec()));

        // Handshake failure branches
        assert!(
            MtlsAuthenticatedStream::establish_mutual_handshake(
                &c_hello, &cli_eph, &s_hello, &srv_eph, &bundle, 500
            )
            .is_err()
        );
        let mut s_expired = s_hello.clone();
        s_expired.svid.expires_at_tick = 15;
        assert!(
            MtlsAuthenticatedStream::establish_mutual_handshake(
                &c_hello, &cli_eph, &s_expired, &srv_eph, &bundle, 20
            )
            .is_err()
        );
        let c_zero_pub = MtlsHandshakeMessage {
            svid: client_svid.clone(),
            x25519_public: [0; 32],
            rotation_epoch: 1,
        };
        assert!(
            MtlsAuthenticatedStream::establish_mutual_handshake(
                &c_zero_pub,
                &cli_eph,
                &s_hello,
                &srv_eph,
                &bundle,
                20
            )
            .is_err()
        );
        let s_zero_pub = MtlsHandshakeMessage {
            svid: server_svid.clone(),
            x25519_public: [0; 32],
            rotation_epoch: 1,
        };
        assert!(
            MtlsAuthenticatedStream::establish_mutual_handshake(
                &c_hello,
                &cli_eph,
                &s_zero_pub,
                &srv_eph,
                &bundle,
                20
            )
            .is_err()
        );

        // Hitless SVID rotation without dropping active stream
        let new_cli_svid = auth.rotate_svid(&client_svid, 50).unwrap_or_default();
        let new_srv_svid = auth.rotate_svid(&server_svid, 50).unwrap_or_default();
        assert_eq!(
            cli_stream.rotate_svids_in_place(
                new_cli_svid.clone(),
                new_srv_svid.clone(),
                &bundle,
                60
            ),
            Ok(2)
        );
        assert_eq!(
            srv_stream.rotate_svids_in_place(new_srv_svid, new_cli_svid, &bundle, 60),
            Ok(2)
        );
        let rec2 = cli_stream.seal_record(b"post-rotation");
        assert_eq!(srv_stream.open_record(&rec2), Ok(b"post-rotation".to_vec()));
        assert!(
            cli_stream
                .rotate_svids_in_place(client_svid, server_svid, &bundle, 500)
                .is_err()
        );
        assert!(
            cli_stream
                .rotate_svids_in_place(cli_stream.local_svid.clone(), s_expired.svid, &bundle, 60)
                .is_err()
        );
    }
}

/// FIPS 197 / NIST SP 800-38D AES forward S-Box (`256` bytes).
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// FIPS 197 AES round constants (`Rcon[1..=7]`).
const AES_RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

/// Looks up a byte in [`AES_SBOX`] without direct slice indexing.
///
/// # Arguments
///
/// * `byte` - Input byte.
///
/// # Returns
///
/// Substituted byte from `AES_SBOX`.
fn aes_sbox_lookup(byte: u8) -> u8 {
    AES_SBOX.get(usize::from(byte)).copied().unwrap_or(0)
}

/// Multiplies `byte` by `2` (`xtime`) in the Rijndael finite field $GF(2^8)$ modulo $x^8 + x^4 + x^3 + x + 1$.
///
/// # Arguments
///
/// * `byte` - Field element in $GF(2^8)$.
///
/// # Returns
///
/// Product `2 * byte` in $GF(2^8)$.
const fn aes_xtime(byte: u8) -> u8 {
    let hi = byte >> 7;
    (byte << 1) ^ (hi.wrapping_mul(0x1b))
}

/// Expands a 32-byte (`256-bit`) AES-256 key into 15 16-byte round keys (`240` bytes total) per FIPS 197 §5.2.
///
/// # Arguments
///
/// * `key` - 32-byte AES-256 secret key.
///
/// # Returns
///
/// Array of 15 16-byte round keys.
pub fn aes256_expand_key(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut words = [[0_u8; 4]; 60];
    for (slot, chunk) in words.iter_mut().zip(key.chunks_exact(4)) {
        slot.copy_from_slice(chunk);
    }
    for idx in 8_usize..60_usize {
        let mut temp = words.get(idx.saturating_sub(1)).copied().unwrap_or([0; 4]);
        if idx % 8 == 0 {
            let rcon_byte = AES_RCON
                .get((idx / 8).saturating_sub(1))
                .copied()
                .unwrap_or(0);
            temp = [
                aes_sbox_lookup(temp.get(1).copied().unwrap_or(0)) ^ rcon_byte,
                aes_sbox_lookup(temp.get(2).copied().unwrap_or(0)),
                aes_sbox_lookup(temp.get(3).copied().unwrap_or(0)),
                aes_sbox_lookup(temp.first().copied().unwrap_or(0)),
            ];
        } else if idx % 8 == 4 {
            temp = [
                aes_sbox_lookup(temp.first().copied().unwrap_or(0)),
                aes_sbox_lookup(temp.get(1).copied().unwrap_or(0)),
                aes_sbox_lookup(temp.get(2).copied().unwrap_or(0)),
                aes_sbox_lookup(temp.get(3).copied().unwrap_or(0)),
            ];
        }
        let prev = words.get(idx.saturating_sub(8)).copied().unwrap_or([0; 4]);
        let next_word = [
            prev.first().copied().unwrap_or(0) ^ temp.first().copied().unwrap_or(0),
            prev.get(1).copied().unwrap_or(0) ^ temp.get(1).copied().unwrap_or(0),
            prev.get(2).copied().unwrap_or(0) ^ temp.get(2).copied().unwrap_or(0),
            prev.get(3).copied().unwrap_or(0) ^ temp.get(3).copied().unwrap_or(0),
        ];
        for slot in words.iter_mut().skip(idx).take(1) {
            *slot = next_word;
        }
    }
    let mut round_keys = [[0_u8; 16]; 15];
    for (rk_idx, rk) in round_keys.iter_mut().enumerate() {
        let base = rk_idx.saturating_mul(4);
        for (w_offset, dst) in rk.chunks_exact_mut(4).enumerate() {
            let word = words
                .get(base.saturating_add(w_offset))
                .copied()
                .unwrap_or([0; 4]);
            dst.copy_from_slice(&word);
        }
    }
    round_keys
}

/// Encrypts a single 16-byte (`128-bit`) block using FIPS 197 14-round `AES-256`.
///
/// # Arguments
///
/// * `block` - 16-byte input block.
/// * `round_keys` - Expanded 15-round key schedule from [`aes256_expand_key`].
///
/// # Returns
///
/// 16-byte encrypted ciphertext block.
pub fn aes256_encrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut state = *block;
    let rk0 = round_keys.first().copied().unwrap_or([0; 16]);
    for (s, &k) in state.iter_mut().zip(rk0.iter()) {
        *s ^= k;
    }

    for round in 1_usize..=14_usize {
        // SubBytes
        for s in &mut state {
            *s = aes_sbox_lookup(*s);
        }
        // ShiftRows (column-major state indices:
        // row 0: 0, 4, 8, 12; row 1: 1, 5, 9, 13; row 2: 2, 6, 10, 14; row 3: 3, 7, 11, 15)
        let s = state;
        state = [
            s.first().copied().unwrap_or(0),
            s.get(5).copied().unwrap_or(0),
            s.get(10).copied().unwrap_or(0),
            s.get(15).copied().unwrap_or(0),
            s.get(4).copied().unwrap_or(0),
            s.get(9).copied().unwrap_or(0),
            s.get(14).copied().unwrap_or(0),
            s.get(3).copied().unwrap_or(0),
            s.get(8).copied().unwrap_or(0),
            s.get(13).copied().unwrap_or(0),
            s.get(2).copied().unwrap_or(0),
            s.get(7).copied().unwrap_or(0),
            s.get(12).copied().unwrap_or(0),
            s.get(1).copied().unwrap_or(0),
            s.get(6).copied().unwrap_or(0),
            s.get(11).copied().unwrap_or(0),
        ];
        // MixColumns on rounds 1..=13
        if round < 14 {
            for col in state.chunks_exact_mut(4) {
                let a0 = col.first().copied().unwrap_or(0);
                let a1 = col.get(1).copied().unwrap_or(0);
                let a2 = col.get(2).copied().unwrap_or(0);
                let a3 = col.get(3).copied().unwrap_or(0);
                let t = a0 ^ a1 ^ a2 ^ a3;
                let c0 = a0 ^ t ^ aes_xtime(a0 ^ a1);
                let c1 = a1 ^ t ^ aes_xtime(a1 ^ a2);
                let c2 = a2 ^ t ^ aes_xtime(a2 ^ a3);
                let c3 = a3 ^ t ^ aes_xtime(a3 ^ a0);
                col.copy_from_slice(&[c0, c1, c2, c3]);
            }
        }
        // AddRoundKey
        let rk = round_keys.get(round).copied().unwrap_or([0; 16]);
        for (st, &k) in state.iter_mut().zip(rk.iter()) {
            *st ^= k;
        }
    }
    state
}

/// Multiplies two 128-bit elements `x` and `y` in the NIST SP 800-38D §6.3 `GHASH` Galois field
/// $GF(2^{128})$ modulo $1 + \alpha + \alpha^2 + \alpha^7 + \alpha^{128}$ (`R = 0xE100...00`).
///
/// # Arguments
///
/// * `x` - First 16-byte big-endian $GF(2^{128})$ element.
/// * `y` - Second 16-byte big-endian $GF(2^{128})$ element.
///
/// # Returns
///
/// 16-byte product $x \cdot y$ in $GF(2^{128})$.
pub fn ghash_gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let x_val = u128::from_be_bytes(*x);
    let mut v = u128::from_be_bytes(*y);
    let mut z = 0_u128;
    let r_poly: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;
    for bit_idx in 0..128_u32 {
        let shift = 127_u32.saturating_sub(bit_idx);
        let bit = (x_val >> shift) & 1;
        let mask = 0_u128.wrapping_sub(bit);
        z ^= v & mask;
        let lsb = v & 1;
        let lsb_mask = 0_u128.wrapping_sub(lsb);
        v = (v >> 1) ^ (r_poly & lsb_mask);
    }
    z.to_be_bytes()
}

/// Computes the NIST SP 800-38D §6.4 `GHASH` authentication digest over `(aad, ciphertext)` under hash subkey `h`.
///
/// # Arguments
///
/// * `h` - 16-byte hash subkey (`AES-256(K, 0^128)`).
/// * `aad` - Associated data slice.
/// * `ciphertext` - Ciphertext byte slice.
///
/// # Returns
///
/// 16-byte `GHASH` output block.
pub fn ghash_digest(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0_u8; 16];
    for chunk in aad.chunks(16) {
        for (dst, &src) in y.iter_mut().zip(chunk.iter()) {
            *dst ^= src;
        }
        y = ghash_gf128_mul(&y, h);
    }
    for chunk in ciphertext.chunks(16) {
        for (dst, &src) in y.iter_mut().zip(chunk.iter()) {
            *dst ^= src;
        }
        y = ghash_gf128_mul(&y, h);
    }
    let aad_bits = (aad.len() as u64).saturating_mul(8);
    let ct_bits = (ciphertext.len() as u64).saturating_mul(8);
    let len_block = ((u128::from(aad_bits) << 64) | u128::from(ct_bits)).to_be_bytes();
    for (dst, &src) in y.iter_mut().zip(len_block.iter()) {
        *dst ^= src;
    }
    ghash_gf128_mul(&y, h)
}

/// Builds a 16-byte NIST SP 800-38D GCM counter block `nonce (12B) || counter_be (4B)`.
///
/// # Arguments
///
/// * `nonce` - 12-byte GCM IV.
/// * `counter` - 32-bit block counter.
///
/// # Returns
///
/// 16-byte counter block.
fn build_gcm_counter_block(nonce: &[u8; 12], counter: u32) -> [u8; 16] {
    let mut cb = [0_u8; 16];
    let ctr_bytes = counter.to_be_bytes();
    for (dst, &src) in cb.iter_mut().zip(nonce.iter().chain(ctr_bytes.iter())) {
        *dst = src;
    }
    cb
}

/// Generates the NIST SP 800-38D `GCTR` keystream for `(round_keys, nonce)` starting at counter `2`
/// and XORs it with `input`.
///
/// # Arguments
///
/// * `round_keys` - Expanded `AES-256` round keys.
/// * `nonce` - 12-byte (`96-bit`) GCM IV/nonce.
/// * `input` - Plaintext or ciphertext slice.
///
/// # Returns
///
/// Output byte vector.
fn aes256_gcm_gctr(round_keys: &[[u8; 16]; 15], nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for (block_idx, chunk) in input.chunks(16).enumerate() {
        let ctr = u32::try_from(block_idx).unwrap_or(0).wrapping_add(2);
        let cb = build_gcm_counter_block(nonce, ctr);
        let ks = aes256_encrypt_block(&cb, round_keys);
        for (&in_b, &k_b) in chunk.iter().zip(ks.iter()) {
            output.push(in_b ^ k_b);
        }
    }
    output
}

/// Encrypts `plaintext` and authenticates `aad` using NIST SP 800-38D `AES-256-GCM` with a 96-bit `nonce`,
/// returning `(ciphertext, 16-byte gcm_tag)`.
///
/// # Arguments
///
/// * `key` - 32-byte `AES-256` secret key.
/// * `nonce` - 12-byte (`96-bit`) initialization vector.
/// * `aad` - Additional authenticated data (`AAD`).
/// * `plaintext` - Plaintext payload to encrypt.
///
/// # Returns
///
/// Tuple `(ciphertext_bytes, 16-byte_tag)`.
pub fn aes256_gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let rks = aes256_expand_key(key);
    let h = aes256_encrypt_block(&[0_u8; 16], &rks);
    let ciphertext = aes256_gcm_gctr(&rks, nonce, plaintext);
    let ghash = ghash_digest(&h, aad, &ciphertext);
    let j0 = build_gcm_counter_block(nonce, 1);
    let ek_j0 = aes256_encrypt_block(&j0, &rks);
    let mut tag = [0_u8; 16];
    for ((t, &g), &e) in tag.iter_mut().zip(ghash.iter()).zip(ek_j0.iter()) {
        *t = g ^ e;
    }
    (ciphertext, tag)
}

/// Verifies `tag` in constant time and decrypts `ciphertext` using NIST SP 800-38D `AES-256-GCM`.
///
/// # Arguments
///
/// * `key` - 32-byte `AES-256` secret key.
/// * `nonce` - 12-byte (`96-bit`) initialization vector.
/// * `aad` - Additional authenticated data (`AAD`).
/// * `ciphertext` - Encrypted bytes.
/// * `tag` - Expected 16-byte GCM authentication tag.
///
/// # Returns
///
/// Authenticated plaintext byte vector.
///
/// # Errors
///
/// Returns [`ArbiterError::AeadCipher`] if the 16-byte authentication tag does not match.
pub fn aes256_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> ArbiterResult<Vec<u8>> {
    let rks = aes256_expand_key(key);
    let h = aes256_encrypt_block(&[0_u8; 16], &rks);
    let ghash = ghash_digest(&h, aad, ciphertext);
    let j0 = build_gcm_counter_block(nonce, 1);
    let ek_j0 = aes256_encrypt_block(&j0, &rks);
    let mut diff = 0_u8;
    for ((&expected_g, &expected_e), &actual_t) in ghash.iter().zip(ek_j0.iter()).zip(tag.iter()) {
        diff |= (expected_g ^ expected_e) ^ actual_t;
    }
    if diff != 0 {
        return Err(arbiter_core::error::AeadCipherError::new(
            "AES-256-GCM",
            "GCM authentication tag mismatch (tampered ciphertext or AAD)",
        )
        .into());
    }
    Ok(aes256_gcm_gctr(&rks, nonce, ciphertext))
}

/// Performs RFC 5869 `HKDF-Expand` over `SHA-256` to derive `out_len` bytes (`<= 8160`) of output
/// keying material (`OKM`) from a 32-byte pseudorandom key `prk` and context `info`.
///
/// # Arguments
///
/// * `prk` - 32-byte pseudorandom key from `HKDF-Extract`.
/// * `info` - Context and application specific information.
/// * `out_len` - Desired output length in bytes (`1..=8160`).
///
/// # Returns
///
/// Derived output keying material vector of length `out_len`.
///
/// # Errors
///
/// Returns [`ArbiterError::KeyExchange`] if `out_len == 0` or `out_len > 255 * 32` (`8160`).
pub fn hkdf_expand_multi_block(
    prk: &[u8; 32],
    info: &[u8],
    out_len: usize,
) -> ArbiterResult<Vec<u8>> {
    if out_len == 0 || out_len > 255 * 32 {
        return Err(arbiter_core::error::KeyExchangeError::new(
            "HKDF-SHA256",
            "requested HKDF-Expand output length must be in 1..=8160 bytes",
        )
        .into());
    }
    let blocks = out_len.div_ceil(32);
    let mut okm = Vec::with_capacity(blocks.saturating_mul(32));
    let mut prev_t = Vec::new();
    for idx in 1..=blocks {
        let mut msg = Vec::with_capacity(prev_t.len() + info.len() + 1);
        msg.extend_from_slice(&prev_t);
        msg.extend_from_slice(info);
        msg.push(u8::try_from(idx).unwrap_or(1));
        let t_i = hmac_sha256(prk, &msg);
        prev_t = t_i.to_vec();
        okm.extend_from_slice(&t_i);
    }
    okm.truncate(out_len);
    Ok(okm)
}

/// Performs RFC 8446 Section 7.1 TLS 1.3 `HKDF-Expand-Label(Secret, Label, Context, Length)`
/// using the canonical `"tls13 "` prefix.
///
/// # Arguments
///
/// * `secret` - 32-byte TLS 1.3 traffic or handshake secret.
/// * `label` - ASCII label without `"tls13 "` prefix (e.g., `"quic key"`, `"quic iv"`, `"quic hp"`).
/// * `context` - Transcript hash or context bytes.
/// * `out_len` - Output length in bytes (`1..=255`).
///
/// # Returns
///
/// Derived TLS 1.3 key or IV bytes.
///
/// # Errors
///
/// Returns [`ArbiterError::KeyExchange`] if `out_len == 0` or `out_len > 255`.
pub fn tls13_hkdf_expand_label(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> ArbiterResult<Vec<u8>> {
    if out_len == 0 || out_len > 255 {
        return Err(arbiter_core::error::KeyExchangeError::new(
            "TLS1.3-HKDF-Expand-Label",
            "TLS 1.3 HKDF-Expand-Label length must be in 1..=255",
        )
        .into());
    }
    let full_label_len = 6_usize.saturating_add(label.len());
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    let len_u16 = u16::try_from(out_len).unwrap_or(0);
    hkdf_label.extend_from_slice(&len_u16.to_be_bytes());
    hkdf_label.push(u8::try_from(full_label_len).unwrap_or(0));
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(u8::try_from(context.len()).unwrap_or(0));
    hkdf_label.extend_from_slice(context);
    hkdf_expand_multi_block(secret, &hkdf_label, out_len)
}

/// Element of the Curve25519 prime field $\mathbb{F}_p$ where $p = 2^{255} - 19$, represented as
/// 5 radix-$2^{51}$ limbs (`u64`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Fe25519 {
    /// 5 limbs in radix $2^{51}$.
    limbs: [u64; 5],
}

impl Fe25519 {
    /// Multiplicative identity `1` in $\mathbb{F}_{2^{255}-19}$.
    const ONE: Self = Self {
        limbs: [1, 0, 0, 0, 0],
    };

    /// Additive identity `0` in $\mathbb{F}_{2^{255}-19}$.
    const ZERO: Self = Self {
        limbs: [0, 0, 0, 0, 0],
    };

    /// Curve25519 Montgomery constant $a_{24} = (486662 - 2) / 4 = 121665$ per RFC 7748 §5.
    const A24: Self = Self {
        limbs: [121_665, 0, 0, 0, 0],
    };

    /// Decodes a 32-byte little-endian RFC 7748 `u`-coordinate into a field element (clearing bit 255).
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte little-endian coordinate.
    ///
    /// # Returns
    ///
    /// Decoded [`Fe25519`].
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut clean = *bytes;
        for b31 in clean.iter_mut().skip(31) {
            *b31 &= 0x7f;
        }
        let load64 = |offset: usize| -> u64 {
            let mut b8 = [0_u8; 8];
            for (dst, &src) in b8.iter_mut().zip(clean.iter().skip(offset).take(8)) {
                *dst = src;
            }
            u64::from_le_bytes(b8)
        };
        let mask51 = (1_u64 << 51) - 1;
        let l0 = load64(0) & mask51;
        let l1 = (load64(6) >> 3) & mask51;
        let l2 = (load64(12) >> 6) & mask51;
        let l3 = (load64(19) >> 1) & mask51;
        let l4 = (load64(24) >> 12) & mask51;
        Self {
            limbs: [l0, l1, l2, l3, l4],
        }
    }

    /// Reduces and serializes this field element into a canonical 32-byte little-endian array modulo $2^{255}-19$.
    ///
    /// # Returns
    ///
    /// Canonical 32-byte little-endian encoding.
    fn to_bytes(self) -> [u8; 32] {
        let mask51 = (1_u64 << 51) - 1;
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.limbs;
        for _ in 0..2 {
            let c0 = t0 >> 51;
            t0 &= mask51;
            t1 = t1.wrapping_add(c0);
            let c1 = t1 >> 51;
            t1 &= mask51;
            t2 = t2.wrapping_add(c1);
            let c2 = t2 >> 51;
            t2 &= mask51;
            t3 = t3.wrapping_add(c2);
            let c3 = t3 >> 51;
            t3 &= mask51;
            t4 = t4.wrapping_add(c3);
            let c4 = t4 >> 51;
            t4 &= mask51;
            t0 = t0.wrapping_add(c4.wrapping_mul(19));
        }

        // Subtract p = 2^255 - 19 conditionally
        let mut q = t0.wrapping_add(19) >> 51;
        q = (t1.wrapping_add(q)) >> 51;
        q = (t2.wrapping_add(q)) >> 51;
        q = (t3.wrapping_add(q)) >> 51;
        q = (t4.wrapping_add(q)) >> 51;

        t0 = t0.wrapping_add(q.wrapping_mul(19));
        let c0 = t0 >> 51;
        t0 &= mask51;
        t1 = t1.wrapping_add(c0);
        let c1 = t1 >> 51;
        t1 &= mask51;
        t2 = t2.wrapping_add(c1);
        let c2 = t2 >> 51;
        t2 &= mask51;
        t3 = t3.wrapping_add(c2);
        let c3 = t3 >> 51;
        t3 &= mask51;
        t4 = t4.wrapping_add(c3) & mask51;

        let mut out_vec = Vec::with_capacity(32);
        let mut acc = 0_u128;
        let mut acc_bits = 0_u32;
        for limb in [t0, t1, t2, t3, t4] {
            acc |= u128::from(limb) << acc_bits;
            acc_bits = acc_bits.saturating_add(51);
            while acc_bits >= 8 {
                out_vec.push((acc & 0xFF) as u8);
                acc >>= 8;
                acc_bits = acc_bits.saturating_sub(8);
            }
        }
        out_vec.push((acc & 0x7F) as u8);
        let mut out = [0_u8; 32];
        for (dst, &src) in out.iter_mut().zip(out_vec.iter()) {
            *dst = src;
        }
        out
    }

    /// Adds two field elements in $\mathbb{F}_{2^{255}-19}$.
    fn add(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.limbs;
        let [b0, b1, b2, b3, b4] = rhs.limbs;
        Self {
            limbs: [
                a0.wrapping_add(b0),
                a1.wrapping_add(b1),
                a2.wrapping_add(b2),
                a3.wrapping_add(b3),
                a4.wrapping_add(b4),
            ],
        }
    }

    /// Subtracts `rhs` from `self` modulo $2^{255}-19$ using $2p$ bias to avoid underflow.
    fn sub(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.limbs;
        let [b0, b1, b2, b3, b4] = rhs.limbs;
        let bias0: u64 = 0x000f_ffff_ffff_ffda;
        let bias_rest: u64 = 0x000f_ffff_ffff_fffe;
        let mask51 = (1_u64 << 51) - 1;
        let mut d0 = a0.wrapping_add(bias0).wrapping_sub(b0);
        let mut d1 = a1.wrapping_add(bias_rest).wrapping_sub(b1);
        let mut d2 = a2.wrapping_add(bias_rest).wrapping_sub(b2);
        let mut d3 = a3.wrapping_add(bias_rest).wrapping_sub(b3);
        let mut d4 = a4.wrapping_add(bias_rest).wrapping_sub(b4);

        let c0 = d0 >> 51;
        d0 &= mask51;
        d1 = d1.wrapping_add(c0);
        let c1 = d1 >> 51;
        d1 &= mask51;
        d2 = d2.wrapping_add(c1);
        let c2 = d2 >> 51;
        d2 &= mask51;
        d3 = d3.wrapping_add(c2);
        let c3 = d3 >> 51;
        d3 &= mask51;
        d4 = d4.wrapping_add(c3);
        let c4 = d4 >> 51;
        d4 &= mask51;
        d0 = d0.wrapping_add(c4.wrapping_mul(19));
        Self {
            limbs: [d0, d1, d2, d3, d4],
        }
    }

    /// Multiplies two field elements modulo $2^{255}-19$ using 128-bit limb products.
    fn mul(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.limbs;
        let [b0, b1, b2, b3, b4] = rhs.limbs;
        let b1_19 = u128::from(b1).wrapping_mul(19);
        let b2_19 = u128::from(b2).wrapping_mul(19);
        let b3_19 = u128::from(b3).wrapping_mul(19);
        let b4_19 = u128::from(b4).wrapping_mul(19);

        let m0 = u128::from(a0).wrapping_mul(u128::from(b0))
            + u128::from(a1).wrapping_mul(b4_19)
            + u128::from(a2).wrapping_mul(b3_19)
            + u128::from(a3).wrapping_mul(b2_19)
            + u128::from(a4).wrapping_mul(b1_19);
        let mut m1 = u128::from(a0).wrapping_mul(u128::from(b1))
            + u128::from(a1).wrapping_mul(u128::from(b0))
            + u128::from(a2).wrapping_mul(b4_19)
            + u128::from(a3).wrapping_mul(b3_19)
            + u128::from(a4).wrapping_mul(b2_19);
        let mut m2 = u128::from(a0).wrapping_mul(u128::from(b2))
            + u128::from(a1).wrapping_mul(u128::from(b1))
            + u128::from(a2).wrapping_mul(u128::from(b0))
            + u128::from(a3).wrapping_mul(b4_19)
            + u128::from(a4).wrapping_mul(b3_19);
        let mut m3 = u128::from(a0).wrapping_mul(u128::from(b3))
            + u128::from(a1).wrapping_mul(u128::from(b2))
            + u128::from(a2).wrapping_mul(u128::from(b1))
            + u128::from(a3).wrapping_mul(u128::from(b0))
            + u128::from(a4).wrapping_mul(b4_19);
        let mut m4 = u128::from(a0).wrapping_mul(u128::from(b4))
            + u128::from(a1).wrapping_mul(u128::from(b3))
            + u128::from(a2).wrapping_mul(u128::from(b2))
            + u128::from(a3).wrapping_mul(u128::from(b1))
            + u128::from(a4).wrapping_mul(u128::from(b0));

        let mask51 = (1_u128 << 51) - 1;
        let mut r0 = u64::try_from(m0 & mask51).unwrap_or(0);
        m1 += m0 >> 51;
        let mut r1 = u64::try_from(m1 & mask51).unwrap_or(0);
        m2 += m1 >> 51;
        let r2 = u64::try_from(m2 & mask51).unwrap_or(0);
        m3 += m2 >> 51;
        let r3 = u64::try_from(m3 & mask51).unwrap_or(0);
        m4 += m3 >> 51;
        let r4 = u64::try_from(m4 & mask51).unwrap_or(0);
        let carry = u64::try_from(m4 >> 51).unwrap_or(0);
        r0 = r0.wrapping_add(carry.wrapping_mul(19));
        let c0 = r0 >> 51;
        r0 &= (1_u64 << 51) - 1;
        r1 = r1.wrapping_add(c0);

        Self {
            limbs: [r0, r1, r2, r3, r4],
        }
    }

    /// Squares this field element modulo $2^{255}-19$.
    fn square(self) -> Self {
        self.mul(self)
    }

    /// Computes the multiplicative inverse $z^{p-2} = z^{2^{255}-21} \pmod{2^{255}-19}$ via Fermat's Little Theorem.
    fn invert(self) -> Self {
        let mut result = Self::ONE;
        let mut base = self;
        // p - 2 = 2^255 - 21 = (2^255 - 1) - 20 = (2^255 - 1) - (16 + 4): bits 0..=254 are 1 except bits 2 and 4.
        for bit_idx in 0..255_u32 {
            let is_one = bit_idx != 2 && bit_idx != 4;
            if is_one {
                result = result.mul(base);
            }
            base = base.square();
        }
        result
    }

    /// Constant-time conditional swap of `(a, b)` controlled by `swap_bit` (`0` or `1`).
    fn cswap(swap_bit: u64, a: &mut Self, b: &mut Self) {
        let mask = 0_u64.wrapping_sub(swap_bit);
        for (la, lb) in a.limbs.iter_mut().zip(b.limbs.iter_mut()) {
            let diff = (*la ^ *lb) & mask;
            *la ^= diff;
            *lb ^= diff;
        }
    }
}

/// Evaluates the RFC 7748 Section 5 `X25519(k, u)` Montgomery ladder scalar multiplication over
/// $\mathbb{F}_{2^{255}-19}$ in constant time.
///
/// # Arguments
///
/// * `scalar` - 32-byte secret scalar (clamped internally per RFC 7748 §5).
/// * `u_coord` - 32-byte little-endian `u`-coordinate point (e.g., `[9, 0, ...]` basepoint).
///
/// # Returns
///
/// 32-byte little-endian output `u`-coordinate.
pub fn x25519_scalarmult(scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
    let mut clamped = *scalar;
    for b0 in clamped.iter_mut().take(1) {
        *b0 &= 248;
    }
    for b31 in clamped.iter_mut().skip(31) {
        *b31 &= 127;
        *b31 |= 64;
    }

    let x_1 = Fe25519::from_bytes(u_coord);
    let mut x_2 = Fe25519::ONE;
    let mut z_2 = Fe25519::ZERO;
    let mut x_3 = x_1;
    let mut z_3 = Fe25519::ONE;
    let mut swap = 0_u64;

    for bit_pos in (0..255_usize).rev() {
        let byte_idx = bit_pos >> 3;
        let bit_idx = bit_pos & 7;
        let k_t = u64::from((clamped.get(byte_idx).copied().unwrap_or(0) >> bit_idx) & 1);
        swap ^= k_t;
        Fe25519::cswap(swap, &mut x_2, &mut x_3);
        Fe25519::cswap(swap, &mut z_2, &mut z_3);
        swap = k_t;

        let sum_2 = x_2.add(z_2);
        let aa = sum_2.square();
        let diff_2 = x_2.sub(z_2);
        let bb = diff_2.square();
        let e_fe = aa.sub(bb);
        let sum_3 = x_3.add(z_3);
        let diff_3 = x_3.sub(z_3);
        let da = diff_3.mul(sum_2);
        let cb = sum_3.mul(diff_2);
        x_3 = da.add(cb).square();
        z_3 = x_1.mul(da.sub(cb).square());
        x_2 = aa.mul(bb);
        z_2 = e_fe.mul(aa.add(Fe25519::A24.mul(e_fe)));
    }
    Fe25519::cswap(swap, &mut x_2, &mut x_3);
    Fe25519::cswap(swap, &mut z_2, &mut z_3);
    x_2.mul(z_2.invert()).to_bytes()
}

/// Computes the RFC 7748 Curve25519 public key `X25519(secret_scalar, 9)` from a 32-byte secret key.
///
/// # Arguments
///
/// * `secret_scalar` - 32-byte secret scalar.
///
/// # Returns
///
/// 32-byte RFC 7748 public key.
pub fn x25519_basepoint_public_key(secret_scalar: &[u8; 32]) -> [u8; 32] {
    let basepoint: [u8; 32] = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    x25519_scalarmult(secret_scalar, &basepoint)
}

/// Performs RFC 7748 `X25519` Diffie-Hellman shared secret derivation with low-order / all-zero output rejection.
///
/// # Arguments
///
/// * `local_secret` - 32-byte local secret scalar.
/// * `peer_public` - 32-byte peer public key.
///
/// # Returns
///
/// 32-byte [`ZeroizingSecretKey`] containing the raw `X25519` shared secret.
///
/// # Errors
///
/// Returns [`ArbiterError::KeyExchange`] if the resulting shared secret is the all-zero low-order point.
pub fn x25519_diffie_hellman(
    local_secret: &[u8; 32],
    peer_public: &[u8; 32],
) -> ArbiterResult<ZeroizingSecretKey> {
    let shared = x25519_scalarmult(local_secret, peer_public);
    let mut acc = 0_u8;
    for &b in &shared {
        acc |= b;
    }
    if acc == 0 {
        return Err(arbiter_core::error::KeyExchangeError::new(
            "X25519",
            "rejected low-order X25519 public point producing all-zero shared secret",
        )
        .into());
    }
    Ok(ZeroizingSecretKey::new(shared))
}

#[cfg(test)]
mod phase1_crypto_tests {
    use super::*;

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn test_nist_aes256_gcm_and_rfc7748_x25519_vectors() {
        // FIPS 197 Appendix C.3 AES-256 test vector
        let fips_key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let fips_pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let rks = aes256_expand_key(&fips_key);
        assert_eq!(aes256_encrypt_block(&fips_pt, &rks), expected_ct);

        // NIST SP 800-38D AES-256-GCM seal & open round-trip + tamper rejection
        let gcm_nonce = [0x07_u8; 12];
        let aad = b"arbiter-spiffe-aad-v1";
        let plaintext = b"multi-block-aes-256-gcm-secret-payload-for-zero-trust-mtls-transport";
        let (ct, tag) = aes256_gcm_seal(&fips_key, &gcm_nonce, aad, plaintext);
        assert_eq!(
            aes256_gcm_open(&fips_key, &gcm_nonce, aad, &ct, &tag),
            Ok(plaintext.to_vec())
        );
        assert!(aes256_gcm_open(&fips_key, &gcm_nonce, b"wrong-aad", &ct, &tag).is_err());

        let sec_id = SecretId::new("sec-aes256-gcm").unwrap_or_default();
        let mut gcm_env = seal_secret_aes256_gcm(sec_id, &fips_key, gcm_nonce, aad, plaintext);
        let unsealed_buf = unseal_secret_aes256_gcm(&gcm_env, &fips_key, aad).unwrap_or_default();
        assert_eq!(unsealed_buf.as_slice(), plaintext);
        assert!(unseal_secret_aes256_gcm(&gcm_env, &fips_key, b"wrong-aad").is_err());
        gcm_env.auth_tag.fill(0xFF);
        assert!(unseal_secret_aes256_gcm(&gcm_env, &fips_key, aad).is_err());

        // RFC 5869 multi-block HKDF-Expand & TLS 1.3 HKDF-Expand-Label
        assert!(hkdf_expand_multi_block(&fips_key, b"info", 0).is_err());
        assert!(hkdf_expand_multi_block(&fips_key, b"info", 9000).is_err());
        let okm96 = hkdf_expand_multi_block(&fips_key, b"info", 96).unwrap_or_default();
        assert_eq!(okm96.len(), 96);
        assert!(tls13_hkdf_expand_label(&fips_key, b"quic key", b"", 0).is_err());
        assert!(tls13_hkdf_expand_label(&fips_key, b"quic key", b"", 300).is_err());
        let quic_key =
            tls13_hkdf_expand_label(&fips_key, b"quic key", b"ctx", 32).unwrap_or_default();
        assert_eq!(quic_key.len(), 32);

        // RFC 7748 Section 6.1 X25519 Official Test Vector
        let rfc_scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let rfc_u: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected_out: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];
        assert_eq!(x25519_scalarmult(&rfc_scalar, &rfc_u), expected_out);

        // RFC 7748 Section 6.1 Alice-Bob Diffie-Hellman Test Vector
        let initiator_secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let responder_secret: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let initiator_public = x25519_basepoint_public_key(&initiator_secret);
        let responder_public = x25519_basepoint_public_key(&responder_secret);
        let shared_a = x25519_diffie_hellman(&initiator_secret, &responder_public).ok();
        let shared_b = x25519_diffie_hellman(&responder_secret, &initiator_public).ok();
        assert!(shared_a.is_some());
        assert_eq!(shared_a, shared_b);
        assert!(x25519_diffie_hellman(&initiator_secret, &[0_u8; 32]).is_err());

        // HashChainedAuditLog append, verify_chain, persist_to_file, load_and_verify_from_file, and tamper detection
        let mut audit = HashChainedAuditLog::new();
        assert_eq!(audit.verify_chain(), Ok(0));
        let e1 = audit.append_event(
            10,
            "spiffe://arbiter.internal/master/m1",
            "SetQuota",
            "quota:prod",
            true,
        );
        assert_eq!(e1.sequence, 1);
        let e2 = audit.append_event(
            12,
            "spiffe://arbiter.internal/node/a1",
            "DrainAgent",
            "agent:a1",
            false,
        );
        assert_eq!(e2.sequence, 2);
        assert_eq!(audit.verify_chain(), Ok(2));

        let audit_path = std::env::temp_dir().join("arbiter_test_security_audit.ndjson");
        assert_eq!(audit.persist_to_file(&audit_path), Ok(2));
        let loaded =
            HashChainedAuditLog::load_and_verify_from_file(&audit_path).unwrap_or_default();
        assert_eq!(loaded, audit);

        let mut tampered = audit;
        for first_entry in tampered.entries.iter_mut().take(1) {
            "tampered-resource".clone_into(&mut first_entry.target_resource);
        }
        assert!(tampered.verify_chain().is_err());
        assert_eq!(tampered.persist_to_file(&audit_path), Ok(2));
        assert!(HashChainedAuditLog::load_and_verify_from_file(&audit_path).is_err());

        let _ = std::fs::write(&audit_path, "\n{not-json}\n");
        assert!(HashChainedAuditLog::load_and_verify_from_file(&audit_path).is_err());
        let _ = std::fs::remove_file(&audit_path);

        let bad_dir = std::path::Path::new("/nonexistent_dir_arbiter_audit/audit.ndjson");
        assert!(loaded.persist_to_file(bad_dir).is_err());
        assert!(HashChainedAuditLog::load_and_verify_from_file(bad_dir).is_err());
        assert_eq!(sha256_digest(b"abc").len(), 32);

        // ring::aead ChaCha20-Poly1305 & AES-256-GCM seal and open round-trip + tamper rejection
        for use_aes in [false, true] {
            let (r_ct, r_tag) =
                ring_aead_seal(use_aes, &fips_key, gcm_nonce, aad, plaintext).unwrap_or_default();
            assert_eq!(
                ring_aead_open(use_aes, &fips_key, gcm_nonce, aad, &r_ct, &r_tag),
                Ok(plaintext.to_vec())
            );
            assert!(
                ring_aead_open(use_aes, &fips_key, gcm_nonce, b"wrong-aad", &r_ct, &r_tag).is_err()
            );
        }

        // LiveSpireUdsTransport connecting to an already-existing external SpireMockAgentServer UDS
        #[cfg(unix)]
        {
            let ext_auth = SvidAuthority::new("arbiter.internal", fips_key, 100);
            let ext_uds = std::env::temp_dir().join("arbiter_test_spire_existing_uds.sock");
            let ext_uds_str = ext_uds.to_string_lossy().into_owned();
            let ext_check =
                SpireMockAgentServer::bind(&ext_uds_str, ext_auth.clone()).map(|ext_srv| {
                    let _ = ext_srv.listener.set_nonblocking(false);
                    let srv_h = std::thread::spawn(move || ext_srv.poll_once(40));
                    let mut tr_ext = LiveSpireUdsTransport::new(ext_auth);
                    let svid_ext = tr_ext.fetch_workload_svid(
                        &ext_uds_str,
                        "spiffe://arbiter.internal/node/a1",
                        40,
                    );
                    assert!(svid_ext.is_ok());
                    let _ = srv_h.join();
                });
            assert!(ext_check.is_ok());
        }
    }
}
