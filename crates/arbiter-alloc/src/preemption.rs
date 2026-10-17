//! Preemption and idle quota borrowing engine (`arbiter-alloc::preemption`).
//!
//! Implements:
//! - Idle quota borrowing: computes unused `guaranteed_min` quota capacity across roles that can be
//!   lent out as `Revocable` resources to opportunistic (`SpotPreemptible` / `Batch`) workloads in
//!   roles with `allow_burst_borrowing == true`.
//! - Minimum-disruption eviction solver: when a high-priority workload or quota owner arrives and
//!   an Agent's free resources are insufficient, selects the minimal victim set of lower-priority /
//!   revocable tasks (expanding any gang-affiliated tasks atomically) whose eviction frees sufficient
//!   capacity, emitting structured [`PreemptionPlan`] commands.

use std::collections::BTreeSet;

use arbiter_core::error::{ArbiterError, ArbiterResult};
use arbiter_core::ids::{AgentId, RoleName, TaskGroupId, TaskId};
use arbiter_core::resources::ResourceBundle;
use arbiter_core::workload::{PreemptionPolicy, PriorityClass, Quota, TaskSpec};
use serde::{Deserialize, Serialize};

/// Command action emitted by the preemption solver for an evicted victim task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvictionAction {
    /// Trigger checkpoint (`SIGUSR1`) and suspend the task.
    CheckpointAndSuspend,
    /// Send graceful `SIGTERM` before reclamation.
    GracefulSigterm,
    /// Terminate immediately (`SIGKILL` / `TerminateJobObject` / `jail_remove`).
    ImmediateKill,
}

/// Active running task descriptor on an Agent considered during preemption solving.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunningTaskInstance {
    /// Task identifier.
    pub task_id: TaskId,
    /// Optional gang group identifier (`Some` if part of an atomic gang).
    pub group_id: Option<TaskGroupId>,
    /// Hosting agent identifier.
    pub agent_id: AgentId,
    /// Role owning the task.
    pub role: RoleName,
    /// Priority tier of the running task.
    pub priority: PriorityClass,
    /// Configured preemption policy.
    pub preemption_policy: PreemptionPolicy,
    /// Resources currently held by this task.
    pub allocated_resources: ResourceBundle,
    /// Whether this task is running on borrowed revocable resources.
    pub is_revocable: bool,
}

/// Structured preemption execution plan produced by the eviction solver.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreemptionPlan {
    /// Target Agent where preemption will occur.
    pub agent_id: AgentId,
    /// Ordered list of `(TaskId, EvictionAction)` victim commands.
    pub victims: Vec<(TaskId, EvictionAction)>,
    /// Total resources that will be available on the Agent after evicting `victims`.
    pub post_eviction_available: ResourceBundle,
}

/// Computes the idle guaranteed quota of a lender role that can be borrowed as `Revocable` capacity.
///
/// # Arguments
///
/// * `lender_quota` - The lender role's [`Quota`] policy.
/// * `lender_allocated` - Currently allocated [`ResourceBundle`] of the lender role.
/// * `borrower_quota` - The borrower role's [`Quota`] policy.
/// * `borrower_allocated` - Currently allocated [`ResourceBundle`] of the borrower role.
/// * `request` - Requested [`ResourceBundle`] for the opportunistic task.
///
/// # Returns
///
/// The borrowable [`ResourceBundle`] if `borrower_quota.allow_burst_borrowing` is `true`,
/// the borrower stays within `borrower_quota.hard_max`, and the lender has sufficient idle
/// `guaranteed_min` capacity.
///
/// # Errors
///
/// Returns [`ArbiterError::QuotaExceeded`] if burst borrowing is disabled or `hard_max` is exceeded,
/// or [`ArbiterError::InsufficientResources`] if the lender's idle guaranteed capacity is smaller
/// than `request`.
pub fn evaluate_idle_quota_borrow(
    lender_quota: &Quota,
    lender_allocated: &ResourceBundle,
    borrower_quota: &Quota,
    borrower_allocated: &ResourceBundle,
    request: &ResourceBundle,
) -> ArbiterResult<ResourceBundle> {
    if !borrower_quota.allow_burst_borrowing {
        return Err(ArbiterError::QuotaExceeded {
            role: borrower_quota.id.to_string(),
            resource: "burst_borrowing_disabled".to_owned(),
        });
    }

    let borrower_after = borrower_allocated.try_add(request)?;
    if !borrower_quota.hard_max.contains(&borrower_after) {
        return Err(ArbiterError::QuotaExceeded {
            role: borrower_quota.id.to_string(),
            resource: "hard_max".to_owned(),
        });
    }

    // Compute idle guaranteed capacity of the lender: max(0, guaranteed_min - allocated)
    let idle_lender = ResourceBundle {
        cpu: lender_quota
            .guaranteed_min
            .cpu
            .saturating_sub(lender_allocated.cpu),
        memory: lender_quota
            .guaranteed_min
            .memory
            .saturating_sub(lender_allocated.memory),
        hugepages: lender_quota
            .guaranteed_min
            .hugepages
            .saturating_sub(lender_allocated.hugepages),
        gpu_compute: lender_quota
            .guaranteed_min
            .gpu_compute
            .saturating_sub(lender_allocated.gpu_compute),
        gpu_vram: lender_quota
            .guaranteed_min
            .gpu_vram
            .saturating_sub(lender_allocated.gpu_vram),
        tpu_chips: lender_quota
            .guaranteed_min
            .tpu_chips
            .saturating_sub(lender_allocated.tpu_chips),
        disk: lender_quota
            .guaranteed_min
            .disk
            .saturating_sub(lender_allocated.disk),
        network_bandwidth: lender_quota
            .guaranteed_min
            .network_bandwidth
            .saturating_sub(lender_allocated.network_bandwidth),
        ports: lender_quota.guaranteed_min.ports.clone(),
    };

    if !idle_lender.contains(request) {
        return Err(ArbiterError::InsufficientResources {
            resource: "idle_guaranteed_quota".to_owned(),
            requested: request.cpu.get(),
            available: idle_lender.cpu.get(),
        });
    }

    Ok(request.clone())
}

/// Solves for the minimum-disruption victim set on `agent_id` to free enough resources for `incoming`.
///
/// Only tasks with:
/// - `preemption_policy != PreemptionPolicy::NonPreemptible`, AND
/// - `priority < incoming.priority` OR (`is_revocable && quota_reclaim`)
///
/// are eligible for eviction.
///
/// Eligible candidates are ordered by:
/// 1. `is_revocable` (`true` evicted first).
/// 2. `priority` (lowest [`PriorityClass`] evicted first).
/// 3. `task_id` (deterministic tie-breaker).
///
/// If a selected victim belongs to a `group_id` (gang), all other preemptible tasks on the agent
/// belonging to the same `group_id` are co-evicted together to preserve gang atomicity.
///
/// # Arguments
///
/// * `incoming` - Incoming high-priority [`TaskSpec`].
/// * `agent_id` - Target [`AgentId`].
/// * `current_free` - Currently unallocated [`ResourceBundle`] on the Agent.
/// * `running_tasks` - Slice of [`RunningTaskInstance`]s currently executing on the Agent.
/// * `quota_reclaim` - Whether the incoming task is reclaiming its own guaranteed quota from revocable borrowers.
///
/// # Returns
///
/// Minimal [`PreemptionPlan`] whose eviction satisfies `incoming.resources`.
///
/// # Errors
///
/// Returns [`ArbiterError::PreemptionFailed`] if evicting all eligible victims still cannot
/// satisfy `incoming.resources`.
pub fn solve_minimum_disruption_preemption(
    incoming: &TaskSpec,
    agent_id: &AgentId,
    current_free: &ResourceBundle,
    running_tasks: &[RunningTaskInstance],
    quota_reclaim: bool,
) -> ArbiterResult<PreemptionPlan> {
    if current_free.contains(&incoming.resources) {
        return Ok(PreemptionPlan {
            agent_id: agent_id.clone(),
            victims: Vec::new(),
            post_eviction_available: current_free.clone(),
        });
    }

    // Filter eligible preemptible tasks on this agent.
    let mut eligible: Vec<&RunningTaskInstance> = running_tasks
        .iter()
        .filter(|t| {
            &t.agent_id == agent_id
                && !matches!(t.preemption_policy, PreemptionPolicy::NonPreemptible)
                && (t.priority < incoming.priority || (quota_reclaim && t.is_revocable))
        })
        .collect();

    // Sort: revocable first (!is_revocable ascending), then lowest priority first, then task_id.
    eligible.sort_by(|a, b| {
        (!a.is_revocable, a.priority, &a.task_id).cmp(&(!b.is_revocable, b.priority, &b.task_id))
    });

    let mut accumulated = current_free.clone();
    let mut selected_ids: BTreeSet<TaskId> = BTreeSet::new();
    let mut victims: Vec<(TaskId, EvictionAction)> = Vec::new();

    for candidate in &eligible {
        if selected_ids.contains(&candidate.task_id) {
            continue;
        }

        // If candidate is part of a gang, include all eligible members of that gang on this agent.
        let batch_to_evict: Vec<&RunningTaskInstance> = candidate.group_id.as_ref().map_or_else(
            || vec![*candidate],
            |gid| {
                eligible
                    .iter()
                    .copied()
                    .filter(|t| {
                        t.group_id.as_ref() == Some(gid) && !selected_ids.contains(&t.task_id)
                    })
                    .collect()
            },
        );

        for victim in batch_to_evict {
            let action = match victim.preemption_policy {
                PreemptionPolicy::CheckpointAndSuspend => EvictionAction::CheckpointAndSuspend,
                PreemptionPolicy::GracefulSigterm => EvictionAction::GracefulSigterm,
                PreemptionPolicy::ImmediateKill | PreemptionPolicy::NonPreemptible => {
                    EvictionAction::ImmediateKill
                }
            };
            accumulated = accumulated.try_add(&victim.allocated_resources)?;
            selected_ids.insert(victim.task_id.clone());
            victims.push((victim.task_id.clone(), action));
        }

        if accumulated.contains(&incoming.resources) {
            return Ok(PreemptionPlan {
                agent_id: agent_id.clone(),
                victims,
                post_eviction_available: accumulated,
            });
        }
    }

    Err(ArbiterError::PreemptionFailed {
        workload: incoming.task_id.to_string(),
        reason: "insufficient preemptible capacity on agent".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use arbiter_core::ids::QuotaId;
    use arbiter_core::units::{Bytes, Millicores, WeightBasisPoints};
    use arbiter_core::workload::IsolationSpec;

    use super::*;

    fn make_bundle(cpu_m: u64, mem_b: u64) -> ResourceBundle {
        ResourceBundle {
            cpu: Millicores::new(cpu_m),
            memory: Bytes::new(mem_b),
            ..ResourceBundle::zero()
        }
    }

    fn make_incoming(cpu_m: u64, priority: PriorityClass) -> TaskSpec {
        TaskSpec {
            task_id: TaskId::new("incoming-urgent").unwrap_or_default(),
            role: RoleName::new("prod").unwrap_or_default(),
            framework_id: None,
            election_group: None,
            priority,
            preemption_policy: PreemptionPolicy::NonPreemptible,
            resources: make_bundle(cpu_m, 1024),
            required_gpu_vendor: None,
            required_gpu_partition: None,
            topology_constraints: Vec::new(),
            isolation: IsolationSpec {
                capabilities: Vec::new(),
                image_ref: None,
                command: "/bin/serve".to_owned(),
                args: Vec::new(),
                env: Vec::new(),
                run_as_user: None,
            },
            artifacts: Vec::new(),
            secrets: Vec::new(),
            health_check: None,
        }
    }

    #[test]
    fn test_idle_quota_borrowing() {
        let lender_q = Quota {
            id: QuotaId::new("q-prod").unwrap_or_default(),
            guaranteed_min: make_bundle(32_000, 64_000),
            hard_max: make_bundle(64_000, 128_000),
            allow_burst_borrowing: true,
            weight: WeightBasisPoints::STANDARD,
        };
        let lender_alloc = make_bundle(8_000, 16_000); // 24_000m idle guaranteed

        let mut borrower_q = Quota {
            id: QuotaId::new("q-spot").unwrap_or_default(),
            guaranteed_min: ResourceBundle::zero(),
            hard_max: make_bundle(32_000, 64_000),
            allow_burst_borrowing: true,
            weight: WeightBasisPoints::STANDARD,
        };
        let borrower_alloc = make_bundle(4_000, 8_000);

        // Valid borrow of 16_000m
        let req = make_bundle(16_000, 16_000);
        assert_eq!(
            evaluate_idle_quota_borrow(
                &lender_q,
                &lender_alloc,
                &borrower_q,
                &borrower_alloc,
                &req
            ),
            Ok(req.clone())
        );

        // Request fits borrower's hard_max (4_000m + 26_000m = 30_000m <= 32_000m),
        // but exceeds lender's idle guaranteed (26_000m > 24_000m)
        let req_exceeds_lender = make_bundle(26_000, 16_000);
        assert!(
            evaluate_idle_quota_borrow(
                &lender_q,
                &lender_alloc,
                &borrower_q,
                &borrower_alloc,
                &req_exceeds_lender
            )
            .is_err()
        );

        // Borrower exceeds its own hard_max (4_000m + 30_000m = 34_000m > 32_000m)
        let req_too_big = make_bundle(30_000, 16_000);
        assert!(
            evaluate_idle_quota_borrow(
                &lender_q,
                &ResourceBundle::zero(),
                &borrower_q,
                &borrower_alloc,
                &req_too_big
            )
            .is_err()
        );

        // Borrower has allow_burst_borrowing == false
        borrower_q.allow_burst_borrowing = false;
        assert!(
            evaluate_idle_quota_borrow(
                &lender_q,
                &lender_alloc,
                &borrower_q,
                &borrower_alloc,
                &req
            )
            .is_err()
        );

        // Overflow on borrower_allocated.try_add
        borrower_q.allow_burst_borrowing = true;
        let max_alloc = make_bundle(u64::MAX, 0);
        assert!(
            evaluate_idle_quota_borrow(&lender_q, &lender_alloc, &borrower_q, &max_alloc, &req)
                .is_err()
        );
    }

    fn sample_running_tasks(agent_id: &AgentId) -> Vec<RunningTaskInstance> {
        let gid = TaskGroupId::new("gang-spot").unwrap_or_default();
        let other_ag = AgentId::new("agent-2").unwrap_or_default();
        [
            (
                "other-agent-task",
                &other_ag,
                None,
                PriorityClass::Revocable,
                PreemptionPolicy::ImmediateKill,
                32_000,
                true,
            ),
            (
                "protected-db",
                agent_id,
                None,
                PriorityClass::Batch,
                PreemptionPolicy::NonPreemptible,
                16_000,
                false,
            ),
            (
                "high-non-revocable",
                agent_id,
                None,
                PriorityClass::SystemCritical,
                PreemptionPolicy::GracefulSigterm,
                16_000,
                false,
            ),
            (
                "batch-1",
                agent_id,
                None,
                PriorityClass::Batch,
                PreemptionPolicy::ImmediateKill,
                8_000,
                false,
            ),
            (
                "gang-m1",
                agent_id,
                Some(gid.clone()),
                PriorityClass::SpotPreemptible,
                PreemptionPolicy::CheckpointAndSuspend,
                6_000,
                true,
            ),
            (
                "gang-m2",
                agent_id,
                Some(gid),
                PriorityClass::SpotPreemptible,
                PreemptionPolicy::GracefulSigterm,
                6_000,
                true,
            ),
        ]
        .into_iter()
        .map(|(id, ag, grp, prio, pol, cpu, rev)| RunningTaskInstance {
            task_id: TaskId::new(id).unwrap_or_default(),
            group_id: grp,
            agent_id: ag.clone(),
            role: RoleName::new("r").unwrap_or_default(),
            priority: prio,
            preemption_policy: pol,
            allocated_resources: make_bundle(cpu, 2048),
            is_revocable: rev,
        })
        .collect()
    }

    #[test]
    fn test_minimum_disruption_preemption_and_gang_eviction() {
        let agent_id = AgentId::new("agent-1").unwrap_or_default();
        let incoming = make_incoming(16_000, PriorityClass::ProductionHigh);

        let plenty_free = make_bundle(32_000, 10_000);
        let plan0 =
            solve_minimum_disruption_preemption(&incoming, &agent_id, &plenty_free, &[], false)
                .unwrap_or_default();
        assert!(plan0.victims.is_empty());

        let running = sample_running_tasks(&agent_id);
        let low_free = make_bundle(4_000, 2048);
        let plan =
            solve_minimum_disruption_preemption(&incoming, &agent_id, &low_free, &running, true)
                .unwrap_or_default();
        assert_eq!(plan.victims.len(), 2);

        let incoming_22k = make_incoming(22_000, PriorityClass::ProductionHigh);
        let plan_22k = solve_minimum_disruption_preemption(
            &incoming_22k,
            &agent_id,
            &low_free,
            &running,
            false,
        )
        .unwrap_or_default();
        assert_eq!(plan_22k.victims.len(), 3);

        let incoming_64k = make_incoming(64_000, PriorityClass::ProductionHigh);
        assert!(
            solve_minimum_disruption_preemption(
                &incoming_64k,
                &agent_id,
                &low_free,
                &running,
                false
            )
            .is_err()
        );

        let same_prio_incoming = make_incoming(16_000, PriorityClass::SpotPreemptible);
        assert!(
            solve_minimum_disruption_preemption(
                &same_prio_incoming,
                &agent_id,
                &low_free,
                &running,
                true
            )
            .is_ok()
        );

        let max_mem_free = make_bundle(0, u64::MAX);
        assert!(
            solve_minimum_disruption_preemption(
                &incoming,
                &agent_id,
                &max_mem_free,
                &running,
                true
            )
            .is_err()
        );
    }
}
