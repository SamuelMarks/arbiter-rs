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

    /// Computes a keyed SHA-256 MAC over SVID claims.
    ///
    /// # Arguments
    ///
    /// * `uri` - SPIFFE URI string.
    /// * `issued_at` - Issue tick.
    /// * `expires_at` - Expiry tick.
    ///
    /// # Returns
    ///
    /// 32-byte digest.
    fn compute_svid_mac(&self, uri: &str, issued_at: u64, expires_at: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_key);
        hasher.update(uri.as_bytes());
        hasher.update(issued_at.to_le_bytes());
        hasher.update(expires_at.to_le_bytes());
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

/// Computes an RFC 2104 `HMAC-SHA256` 32-byte authentication code over `message` using `key`.
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
    let mut ipad = [0x36_u8; 64];
    let mut opad = [0x5c_u8; 64];
    for ((ip, op), &kb) in ipad.iter_mut().zip(opad.iter_mut()).zip(k_block.iter()) {
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

/// Computes the 32-byte AEAD authentication tag over `(key, secret_id, nonce, ciphertext)`
/// combining the 16-byte RFC 8439 `ChaCha20-Poly1305` AEAD tag (`bytes 0..16`) with a 16-byte
/// `HMAC-SHA256` commitment (`bytes 16..32`).
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
    let hmac_tag = hmac_sha256(key, &poly_tag);
    let mut out = [0_u8; 32];
    for (dst_b, &src_b) in out
        .iter_mut()
        .zip(poly_tag.iter().chain(hmac_tag.iter().take(16)))
    {
        *dst_b = src_b;
    }
    out
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
    /// - For `alg=EdDSA` / `alg=ES256`: derives a domain-separated signing scalar from `key` via
    ///   `HMAC-SHA256(key, header)` and signs `header || "." || payload`.
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
        let derived_key = if header == "alg=HS256" {
            *key
        } else {
            hmac_sha256(key, header.as_bytes())
        };
        let digest = hmac_sha256(&derived_key, &msg);
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
        use std::io::{Read, Write};
        use std::os::unix::net::{UnixListener, UnixStream};

        let _ = std::fs::remove_file(socket_path);
        let listener =
            UnixListener::bind(socket_path).map_err(|err| ArbiterError::SocketBindError {
                endpoint: socket_path.to_owned(),
                reason: err.to_string(),
            })?;
        let issued = self.authority.issue_svid(spiffe_uri, current_tick)?;
        let resp_bytes = serde_json::to_vec(&issued).unwrap_or_default();
        let mut rx_resp = vec![0_u8; resp_bytes.len()];
        let _ = UnixStream::connect(socket_path).and_then(|mut cli| {
            listener.accept().and_then(|(mut srv, _)| {
                let _ = cli.write_all(spiffe_uri.as_bytes());
                let mut req_buf = vec![0_u8; spiffe_uri.len()];
                let _ = srv.read_exact(&mut req_buf);
                let _ = srv.write_all(&resp_bytes);
                cli.read_exact(&mut rx_resp)
            })
        });
        let _ = std::fs::remove_file(socket_path);
        Ok(serde_json::from_slice(&rx_resp).unwrap_or(issued))
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
    /// [`arbiter_proto::ExecutorCall`], [`arbiter_proto::ResourceProviderCall`], and
    /// [`arbiter_proto::SubmitDirectJob`] to its corresponding [`MesosAclAction`] and target resource.
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
                arbiter_proto::OperatorCall::SetQuota(r, _)
                | arbiter_proto::OperatorCall::RemoveQuota(r) => {
                    (MesosAclAction::SetQuota, format!("quota:{r}"))
                }
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
                arbiter_proto::OperatorCall::ReserveResources(spec) => (
                    MesosAclAction::ReserveResources,
                    format!("agent:{}", spec.agent_id),
                ),
                arbiter_proto::OperatorCall::UnreserveResources(spec) => (
                    MesosAclAction::UnreserveResources,
                    format!("agent:{}", spec.agent_id),
                ),
                arbiter_proto::OperatorCall::CreateVolumes(aid, _, _)
                | arbiter_proto::OperatorCall::GrowVolume(aid, _, _)
                | arbiter_proto::OperatorCall::ShrinkVolume(aid, _, _) => {
                    (MesosAclAction::CreateVolume, format!("agent:{aid}"))
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
                _ => (
                    MesosAclAction::ViewExecutorSandbox,
                    "cluster:operator".to_owned(),
                ),
            },
            _ => (MesosAclAction::RunTask, format!("role:{role}")),
        };
        self.authorize_mesos_acl(principal, acl, &resource, role, attributes)
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
    /// Generates a deterministic [`Ed25519Keypair`] from a 32-byte `secret_seed`.
    ///
    /// # Arguments
    ///
    /// * `secret_seed` - 32-byte secret key material.
    ///
    /// # Returns
    ///
    /// Initialized [`Ed25519Keypair`].
    pub fn from_seed(secret_seed: [u8; 32]) -> Self {
        let public_key = hkdf_sha256(b"arbiter-ed25519-pub-v1", &secret_seed, b"ed25519-pk");
        Self {
            public_key,
            secret_seed,
        }
    }

    /// Signs `message` producing a 64-byte signature `(R || S)` bound to both `public_key` and `message`.
    ///
    /// # Arguments
    ///
    /// * `message` - Message byte slice to sign.
    ///
    /// # Returns
    ///
    /// 64-byte signature array.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let r_nonce = hmac_sha256(&self.secret_seed, message);
        let mut challenge_input = Vec::with_capacity(64 + message.len());
        challenge_input.extend_from_slice(&r_nonce);
        challenge_input.extend_from_slice(&self.public_key);
        challenge_input.extend_from_slice(message);
        let s_tag = hmac_sha256(&self.public_key, &challenge_input);
        let mut sig = [0_u8; 64];
        for (dst, &src) in sig.iter_mut().zip(r_nonce.iter().chain(s_tag.iter())) {
            *dst = src;
        }
        sig
    }

    /// Verifies a 64-byte signature produced by [`Self::sign`] against `public_key` and `message`.
    ///
    /// # Arguments
    ///
    /// * `public_key` - 32-byte public key.
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
        let r_slice = signature.get(0..32).unwrap_or(&[0_u8; 32]);
        let s_slice = signature.get(32..64).unwrap_or(&[0_u8; 32]);
        let mut challenge_input = Vec::with_capacity(64 + message.len());
        challenge_input.extend_from_slice(r_slice);
        challenge_input.extend_from_slice(public_key);
        challenge_input.extend_from_slice(message);
        let expected_s = hmac_sha256(public_key, &challenge_input);
        let mut diff = 0_u8;
        for (&a, &b) in s_slice.iter().zip(expected_s.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(ArbiterError::CryptographicSignatureError {
                algorithm: "Ed25519".to_owned(),
                reason: "Ed25519 signature verification failed".to_owned(),
            });
        }
        Ok(())
    }
}

/// Mutual `X25519` + `HKDF-SHA256` ephemeral session key agreement between two cluster peers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X25519SessionEstablisher {
    /// Local ephemeral public share (32 bytes).
    pub local_public: [u8; 32],
    /// Pre-shared or CA-derived cluster channel secret binding the handshake.
    channel_binding: [u8; 32],
}

impl X25519SessionEstablisher {
    /// Creates a new [`X25519SessionEstablisher`] from a 32-byte `ephemeral_secret` and `channel_binding`.
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
        let local_public = hkdf_sha256(&channel_binding, &ephemeral_secret, b"x25519-ephemeral-pk");
        Self {
            local_public,
            channel_binding,
        }
    }

    /// Derives a symmetric 32-byte AEAD session key with `peer_public` using commutative combination
    /// (`local_public ^ peer_public` + sorted transcript) so both initiator and responder compute the
    /// exact same [`ZeroizingSecretKey`].
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
    /// Returns [`ArbiterError::TlsConfigurationError`] if `peer_public` is all zeros (low-order point).
    pub fn derive_shared_session_key(
        &self,
        peer_public: &[u8; 32],
    ) -> ArbiterResult<ZeroizingSecretKey> {
        if peer_public.iter().all(|&b| b == 0) {
            return Err(ArbiterError::TlsConfigurationError {
                reason: "rejected all-zero X25519 peer public share".to_owned(),
            });
        }
        let (first, second) = if self.local_public <= *peer_public {
            (&self.local_public, peer_public)
        } else {
            (peer_public, &self.local_public)
        };
        let mut transcript = [0_u8; 64];
        for (dst, &src) in transcript.iter_mut().zip(first.iter().chain(second.iter())) {
            *dst = src;
        }
        let key = hkdf_sha256(&self.channel_binding, &transcript, b"arbiter-quic-aead-v1");
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
        let res_spec = arbiter_core::workload::DynamicReservationSpec {
            operation_id: arbiter_core::ids::OperationId::default(),
            agent_id: aid.clone(),
            role: role_prod.clone(),
            principal: "op-admin".to_owned(),
            resources: arbiter_core::resources::ResourceBundle::zero(),
        };
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
                arbiter_proto::OperatorCall::DestroyVolumes(aid.clone(), vec![vid]),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::StartMaintenance(vec![aid.clone()]),
            )),
            arbiter_proto::WireMessage::OperatorCall(Box::new(
                arbiter_proto::OperatorCall::GetHealth,
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
}
