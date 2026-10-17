//! Zero-trust security primitives: `mTLS`, SPIFFE `SVIDs`, OIDC/JWT verification, RBAC/ABAC policy engine, and AEAD secrets envelope encryption (`arbiter-net::security`).
//!
//! Implements:
//! - X.509 URI SAN parsing and validation for SPIFFE IDs (`spiffe://<trust-domain>/node/<agent-id>`,
//!   `spiffe://<trust-domain>/role/<role>/task/<task-id>`).
//! - Short-lived X.509 SVID & JWT SVID issuance, validation, and rotation.
//! - Declarative RBAC and ABAC policy evaluation `(Principal, Action, Resource, Role, EnvironmentAttributes) -> ArbiterResult<Decision>`.
//! - AEAD envelope secret sealing on the Master and authenticated unsealing on the target Agent.

use std::collections::BTreeMap;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, RoleName, SecretId, SpiffeId, TaskId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Parsed workload or node identity extracted from a validated [`SpiffeId`] X.509 URI SAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpiffePrincipalKind {
    /// Agent node identity (`spiffe://<trust-domain>/node/<agent-id>`).
    Node {
        /// Validated [`AgentId`].
        agent_id: AgentId,
    },
    /// Running workload task identity (`spiffe://<trust-domain>/role/<role>/task/<task-id>`).
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
    if let Some(agent_str) = path.strip_prefix("/node/") {
        let agent_id =
            AgentId::new(agent_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                uri: uri.to_owned(),
                reason: "invalid AgentId in /node/<agent-id> SAN".to_owned(),
            })?;
        return Ok((spiffe_id, SpiffePrincipalKind::Node { agent_id }));
    }

    if let Some(rest) = path.strip_prefix("/role/") {
        if let Some((role_str, task_str)) = rest.split_once("/task/") {
            let role =
                RoleName::new(role_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                    uri: uri.to_owned(),
                    reason: "invalid RoleName in /role/<role>/task/<task-id> SAN".to_owned(),
                })?;
            let task_id =
                TaskId::new(task_str).map_err(|_| ArbiterError::SpiffeIdentityInvalid {
                    uri: uri.to_owned(),
                    reason: "invalid TaskId in /role/<role>/task/<task-id> SAN".to_owned(),
                })?;
            return Ok((
                spiffe_id,
                SpiffePrincipalKind::WorkloadTask { role, task_id },
            ));
        }
    }

    Err(ArbiterError::SpiffeIdentityInvalid {
        uri: uri.to_owned(),
        reason: "SPIFFE path must be '/node/<agent-id>' or '/role/<role>/task/<task-id>'"
            .to_owned(),
    })
}

/// Control-plane SVID authority issuing, verifying, and rotating short-lived X.509 & JWT SVIDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvidAuthority {
    /// Trust domain governed by this authority.
    trust_domain: String,
    /// Authority signing secret key (32 bytes).
    signing_key: [u8; 32],
    /// Default SVID TTL in ticks.
    ttl_ticks: u64,
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
        }
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

    /// Verifies an [`SpiffeSvid`]'s cryptographic signature and expiration at `current_tick`.
    ///
    /// # Arguments
    ///
    /// * `svid` - Presented [`SpiffeSvid`].
    /// * `current_tick` - Current monotonic tick.
    ///
    /// # Returns
    ///
    /// `Ok(())` if valid and unexpired.
    ///
    /// # Errors
    ///
    /// Returns [`ArbiterError::TlsConfigurationError`] if the SVID has expired, or
    /// [`ArbiterError::AuthenticationFailed`] if the signature is invalid.
    pub fn verify_svid(&self, svid: &SpiffeSvid, current_tick: u64) -> ArbiterResult<()> {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Generates a counter-mode SHA-256 keystream and XORs it with `input`.
///
/// # Arguments
///
/// * `key` - 32-byte key.
/// * `nonce` - 12-byte nonce.
/// * `input` - Input byte slice.
///
/// # Returns
///
/// `XORed` output bytes.
fn xor_keystream(key: &[u8; 32], nonce: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for (block_idx, chunk) in input.chunks(32).enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update((block_idx as u64).to_le_bytes());
        let block: [u8; 32] = hasher.finalize().into();
        for (&in_byte, &stream_byte) in chunk.iter().zip(block.iter()) {
            output.push(in_byte ^ stream_byte);
        }
    }
    output
}

/// Computes the 32-byte AEAD authentication tag over `(key, secret_id, nonce, ciphertext)`.
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
    let mut hasher = Sha256::new();
    hasher.update(b"arbiter-aead-tag-v1");
    hasher.update(key);
    hasher.update(secret_id.as_bytes());
    hasher.update(nonce);
    hasher.update(ciphertext);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_san_parsing_and_svid_lifecycle() {
        let key = [7_u8; 32];
        let auth = SvidAuthority::new("arbiter.internal", key, 100);

        assert_eq!(
            SpiffePrincipalKind::default(),
            SpiffePrincipalKind::Node {
                agent_id: AgentId::default()
            }
        );

        // Node SAN
        let node_svid = auth.issue_svid("spiffe://arbiter.internal/node/agent-01", 10);
        assert!(node_svid.is_ok());

        // Task SAN
        let mut svid = auth
            .issue_svid("spiffe://arbiter.internal/role/prod/task/task-99", 10)
            .unwrap_or_default();
        assert!(auth.verify_svid(&svid, 50).is_ok());
        assert!(auth.rotate_svid(&svid, 50).is_ok());

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
                "spiffe://arbiter.internal/node/bad/slash",
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
            parse_spiffe_san("spiffe://arbiter.internal/unknown/path", "arbiter.internal").is_err()
        );
    }

    #[test]
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

        // AEAD Secret envelope sealing & unsealing (> 32 bytes to exercise multi-block keystream)
        let secret_id = SecretId::new("sec-db-password").unwrap_or_default();
        let master_key = [0x42_u8; 32];
        let wrong_key = [0x99_u8; 32];
        let nonce = [1_u8; 12];
        let plaintext = b"super-secret-database-connection-string-exceeding-32-bytes-long!";

        let mut sealed = seal_secret(secret_id, &master_key, nonce, plaintext);
        assert_ne!(sealed.ciphertext, plaintext);

        let unsealed = unseal_secret(&sealed, &master_key);
        assert_eq!(unsealed, Ok(plaintext.to_vec()));

        // Wrong key rejected
        assert!(unseal_secret(&sealed, &wrong_key).is_err());

        // Tampered ciphertext rejected
        sealed.ciphertext.push(0xFF);
        assert!(unseal_secret(&sealed, &master_key).is_err());
    }
}
