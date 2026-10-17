//! Composable isolator pipeline and lifecycle trait (`arbiter-iso::pipeline`).
//!
//! Defines the [`Isolator`] trait (`prepare`, `isolate`, `update_limits`, `usage`, `checkpoint`, `cleanup`)
//! and [`IsolatorPipeline`] which chains OS-specific, accelerator, network, and storage isolators
//! atomically, rolling back already-prepared stages if any downstream stage fails.

use arbiter_core::error::ArbiterResult;
use arbiter_core::ids::TaskId;
use arbiter_core::resources::ResourceBundle;
use serde::{Deserialize, Serialize};

/// Sandbox preparation output produced by an [`Isolator::prepare`] stage.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPreparation {
    /// Whitelisted device paths to expose inside the sandbox (e.g., `"/dev/nvidia0"`).
    pub device_mounts: Vec<String>,
    /// Environment variables to inject into the task process.
    pub injected_env: Vec<(String, String)>,
    /// OS-specific enforcement commands or config files applied during preparation.
    pub applied_commands: Vec<String>,
}

/// Live resource usage snapshot reported by an [`Isolator::usage`] hook.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolatorUsageReport {
    /// Task identifier.
    pub task_id: TaskId,
    /// Measured resource consumption.
    pub consumed: ResourceBundle,
}

/// Pluggable task isolation stage interface.
pub trait Isolator {
    /// Returns the name of this isolator stage.
    ///
    /// # Returns
    ///
    /// Static isolator stage name.
    fn name(&self) -> &'static str;

    /// Prepares the isolation environment (e.g., creating `cgroups`, Jails, Zones, Job Objects)
    /// prior to process spawning.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Initial resource limits.
    ///
    /// # Returns
    ///
    /// [`SandboxPreparation`] directives.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if preparation fails.
    fn prepare(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation>;

    /// Binds a spawned OS process (`pid`) into the prepared isolation container/sandbox.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `pid` - OS process identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful process attachment.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if process attachment fails.
    fn isolate(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()>;

    /// Dynamically updates resource limits for a running task in-place.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `new_limits` - Updated [`ResourceBundle`] limits.
    ///
    /// # Returns
    ///
    /// `Ok(())` on update.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if limit update fails.
    fn update_limits(&mut self, task_id: &TaskId, new_limits: &ResourceBundle)
    -> ArbiterResult<()>;

    /// Queries live resource consumption of the isolated task.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// [`IsolatorUsageReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if usage collection fails.
    fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport>;

    /// Checkpoints the running task state to `checkpoint_dir` prior to preemption/migration.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `checkpoint_dir` - Target filesystem path for checkpoint image.
    ///
    /// # Returns
    ///
    /// `Ok(())` on checkpoint completion.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if checkpointing fails.
    fn checkpoint(&mut self, task_id: &TaskId, checkpoint_dir: &str) -> ArbiterResult<()>;

    /// Tears down and cleans up all kernel/OS isolation state for `task_id` (also used for STONITH fencing).
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` on cleanup completion.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if cleanup fails.
    fn cleanup(&mut self, task_id: &TaskId) -> ArbiterResult<()>;
}

/// Atomic pipeline chaining multiple [`Isolator`] stages with automatic rollback on partial preparation failure.
pub struct IsolatorPipeline {
    /// Ordered isolator stages.
    stages: Vec<Box<dyn Isolator>>,
}

impl IsolatorPipeline {
    /// Creates an empty [`IsolatorPipeline`].
    ///
    /// # Returns
    ///
    /// Empty [`IsolatorPipeline`].
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Appends an [`Isolator`] stage to the pipeline.
    ///
    /// # Arguments
    ///
    /// * `stage` - Boxed [`Isolator`] implementation.
    pub fn add_stage(&mut self, stage: Box<dyn Isolator>) {
        self.stages.push(stage);
    }

    /// Returns the number of stages in the pipeline.
    ///
    /// # Returns
    ///
    /// Stage count.
    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }

    /// Runs `prepare` across all stages in order. If stage `k` fails, automatically calls
    /// `cleanup` in reverse order on stages `0..k` before returning the error.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `limits` - Initial resource bundle.
    ///
    /// # Returns
    ///
    /// Merged [`SandboxPreparation`] across all stages.
    ///
    /// # Errors
    ///
    /// Returns the [`ArbiterError`](arbiter_core::error::ArbiterError) from the failing stage after rolling back earlier stages.
    pub fn prepare_all(
        &mut self,
        task_id: &TaskId,
        limits: &ResourceBundle,
    ) -> ArbiterResult<SandboxPreparation> {
        let mut combined = SandboxPreparation::default();
        let mut prepared_count = 0_usize;
        let mut prepare_err = None;

        for stage in &mut self.stages {
            match stage.prepare(task_id, limits) {
                Ok(prep) => {
                    combined.device_mounts.extend(prep.device_mounts);
                    combined.injected_env.extend(prep.injected_env);
                    combined.applied_commands.extend(prep.applied_commands);
                    prepared_count += 1;
                }
                Err(err) => {
                    prepare_err = Some(err);
                    break;
                }
            }
        }

        if let Some(err) = prepare_err {
            for stage in self.stages.iter_mut().take(prepared_count).rev() {
                let _ = stage.cleanup(task_id);
            }
            return Err(err);
        }

        Ok(combined)
    }

    /// Binds `pid` across all stages in order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `pid` - OS process ID.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all stages have isolated `pid`.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn isolate_all(&mut self, task_id: &TaskId, pid: u32) -> ArbiterResult<()> {
        for stage in &mut self.stages {
            stage.isolate(task_id, pid)?;
        }
        Ok(())
    }

    /// Updates limits across all stages in order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `new_limits` - Updated resource limits.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn update_limits_all(
        &mut self,
        task_id: &TaskId,
        new_limits: &ResourceBundle,
    ) -> ArbiterResult<()> {
        for stage in &mut self.stages {
            stage.update_limits(task_id, new_limits)?;
        }
        Ok(())
    }

    /// Aggregates resource usage across all stages.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// Combined [`IsolatorUsageReport`].
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn usage_all(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
        let mut total = ResourceBundle::zero();
        for stage in &self.stages {
            let report = stage.usage(task_id)?;
            total = total.try_add(&report.consumed)?;
        }
        Ok(IsolatorUsageReport {
            task_id: task_id.clone(),
            consumed: total,
        })
    }

    /// Checkpoints the task across all stages in order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    /// * `checkpoint_dir` - Target checkpoint directory.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an [`ArbiterError`](arbiter_core::error::ArbiterError) if any stage fails.
    pub fn checkpoint_all(&mut self, task_id: &TaskId, checkpoint_dir: &str) -> ArbiterResult<()> {
        for stage in &mut self.stages {
            stage.checkpoint(task_id, checkpoint_dir)?;
        }
        Ok(())
    }

    /// Cleans up all stages in reverse order.
    ///
    /// # Arguments
    ///
    /// * `task_id` - Task identifier.
    ///
    /// # Returns
    ///
    /// `Ok(())` when all stages have cleaned up.
    ///
    /// # Errors
    ///
    /// Returns the first [`ArbiterError`](arbiter_core::error::ArbiterError) encountered after attempting cleanup on all stages.
    pub fn cleanup_all(&mut self, task_id: &TaskId) -> ArbiterResult<()> {
        let mut first_err = None;
        for stage in self.stages.iter_mut().rev() {
            if let Err(err) = stage.cleanup(task_id) {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(())
    }
}

impl Default for IsolatorPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use arbiter_core::error::ArbiterError;
    use arbiter_core::units::Millicores;

    use super::*;

    #[derive(Clone, Copy)]
    enum MockStageMode {
        Healthy(u64),
        FailPrepare,
        FailAllOps,
    }

    struct MockStage {
        mode: MockStageMode,
    }

    impl MockStage {
        const fn ok() -> Self {
            Self {
                mode: MockStageMode::Healthy(500),
            }
        }
    }

    impl Isolator for MockStage {
        fn name(&self) -> &'static str {
            "MockStage"
        }

        fn prepare(
            &mut self,
            _task_id: &TaskId,
            _limits: &ResourceBundle,
        ) -> ArbiterResult<SandboxPreparation> {
            if matches!(
                self.mode,
                MockStageMode::FailPrepare | MockStageMode::FailAllOps
            ) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "prepare failed".to_owned(),
                });
            }
            Ok(SandboxPreparation {
                device_mounts: vec!["/dev/null".to_owned()],
                injected_env: vec![("K".to_owned(), "V".to_owned())],
                applied_commands: vec!["prepare".to_owned()],
            })
        }

        fn isolate(&mut self, _task_id: &TaskId, _pid: u32) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "isolate failed".to_owned(),
                });
            }
            Ok(())
        }

        fn update_limits(
            &mut self,
            _task_id: &TaskId,
            _new_limits: &ResourceBundle,
        ) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "update failed".to_owned(),
                });
            }
            Ok(())
        }

        fn usage(&self, task_id: &TaskId) -> ArbiterResult<IsolatorUsageReport> {
            match self.mode {
                MockStageMode::Healthy(cpu_val) => {
                    let mut b = ResourceBundle::zero();
                    b.cpu = Millicores::new(cpu_val);
                    Ok(IsolatorUsageReport {
                        task_id: task_id.clone(),
                        consumed: b,
                    })
                }
                MockStageMode::FailPrepare | MockStageMode::FailAllOps => {
                    Err(ArbiterError::SandboxError {
                        mechanism: self.name().to_owned(),
                        reason: "usage failed".to_owned(),
                    })
                }
            }
        }

        fn checkpoint(&mut self, _task_id: &TaskId, _checkpoint_dir: &str) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "checkpoint failed".to_owned(),
                });
            }
            Ok(())
        }

        fn cleanup(&mut self, _task_id: &TaskId) -> ArbiterResult<()> {
            if matches!(self.mode, MockStageMode::FailAllOps) {
                return Err(ArbiterError::SandboxError {
                    mechanism: self.name().to_owned(),
                    reason: "cleanup failed".to_owned(),
                });
            }
            Ok(())
        }
    }

    #[test]
    fn test_isolator_pipeline_lifecycle_and_atomic_rollback() {
        let tid = TaskId::new("task-iso-1").unwrap_or_default();
        let limits = ResourceBundle::zero();

        let mut pipeline = IsolatorPipeline::default();
        pipeline.add_stage(Box::new(MockStage::ok()));
        pipeline.add_stage(Box::new(MockStage::ok()));
        assert_eq!(pipeline.stage_count(), 2);

        let prep = pipeline.prepare_all(&tid, &limits).unwrap_or_default();
        assert_eq!(prep.applied_commands.len(), 2);
        assert!(pipeline.isolate_all(&tid, 1234).is_ok());
        assert!(pipeline.update_limits_all(&tid, &limits).is_ok());
        let usage = pipeline.usage_all(&tid).unwrap_or_default();
        assert_eq!(usage.consumed.cpu, Millicores::new(1000));
        assert!(pipeline.checkpoint_all(&tid, "/tmp/ckpt").is_ok());
        assert!(pipeline.cleanup_all(&tid).is_ok());

        // Atomic rollback when stage 2 prepare fails: stage 1 cleanup is invoked
        let mut p_rollback = IsolatorPipeline::new();
        p_rollback.add_stage(Box::new(MockStage::ok()));
        p_rollback.add_stage(Box::new(MockStage {
            mode: MockStageMode::FailPrepare,
        }));
        assert!(p_rollback.prepare_all(&tid, &limits).is_err());

        // Overflow in usage_all try_add
        let mut p_ovf = IsolatorPipeline::new();
        p_ovf.add_stage(Box::new(MockStage {
            mode: MockStageMode::Healthy(u64::MAX),
        }));
        p_ovf.add_stage(Box::new(MockStage::ok()));
        assert!(p_ovf.usage_all(&tid).is_err());

        // Error propagation on isolate, update_limits, usage, checkpoint, and cleanup (2 failing cleanup stages)
        let mut p_err = IsolatorPipeline::new();
        p_err.add_stage(Box::new(MockStage {
            mode: MockStageMode::FailAllOps,
        }));
        p_err.add_stage(Box::new(MockStage {
            mode: MockStageMode::FailAllOps,
        }));
        assert!(p_err.isolate_all(&tid, 1).is_err());
        assert!(p_err.update_limits_all(&tid, &limits).is_err());
        assert!(p_err.usage_all(&tid).is_err());
        assert!(p_err.checkpoint_all(&tid, "/tmp").is_err());
        assert!(p_err.cleanup_all(&tid).is_err());
    }
}
