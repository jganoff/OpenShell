// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod isolation backend (RFC 0012 runtime-selectable contract).
//!
//! This is the today-hardened, shared-kernel placement: the supervisor builds
//! the boundary in the same process that operates it. It implements the
//! object-safe boxed state chain
//! (`Attached -> Claimed -> Bound -> Ready -> Running`) over the existing
//! supervisor primitives without changing their behavior:
//! `create_netns_for_proxy` (network), `run_networking` (proxy mediation +
//! procfs identity source), the pre-exec ceiling in `spawn_workload`
//! (filesystem/Landlock + syscall/seccomp), and procfs (identity).
//!
//! Each transition consumes the prior state by value, so the call order, and
//! thus "no workload before the boundary is ready", is enforced by
//! construction. The runtime collaborators (OPA engine, provider credentials,
//! event channels, ...) are captured in [`InPodConfig`] when the factory is
//! built; `claim` then binds the policy, workload, sandbox identity, and the
//! execution domain.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;

use async_trait::async_trait;

use openshell_core::activity::ActivitySender;
use openshell_core::denial::DenialEvent;
use openshell_core::policy::NetworkMode;
use openshell_core::provider_credentials::ProviderCredentialState;
use openshell_isolation::contract::{
    AttachedBoundary, BackendCapabilities, BackendError, BackendPlacement, BoundBoundary,
    BoundaryEvent, BoundaryExec, BoundaryExitStatus, BoundaryPortForward, BoundaryProcess,
    BoundarySignal, CONTRACT_VERSION, ClaimContext, ClaimedBoundary, ConfirmationCapability,
    EventSource, ExecSession, ExecSpec, IdentityEvidenceKind, IdentitySource,
    IsolationBackendFactory, ReadyBoundary, ResourceBinding, RunningBoundary,
    VerifiedBoundaryDescriptor,
};
use openshell_supervisor_network::identity_source::ProcfsIdentitySource;
use openshell_supervisor_network::opa::OpaEngine;
use openshell_supervisor_network::run::{Networking, run_networking};
use openshell_supervisor_process::boundary_io::NetnsPortForward;
use openshell_supervisor_process::run::{AgentSignaler, SpawnedAgent, spawn_workload};
use tokio::sync::mpsc::UnboundedSender;

use crate::event_source::InPodEvents;

#[cfg(target_os = "linux")]
use openshell_supervisor_process::netns::{NetworkNamespace, create_netns_for_proxy};

/// The registered id for the in-pod backend.
pub const IN_POD_BACKEND_ID: &str = "in-pod";

/// Version of the in-pod [`ResourceBinding`] payload encoding.
pub const IN_POD_RESOURCE_BINDING_VERSION: u32 = 1;

// ============================================================================
// Resource binding (execution / device domain)
// ============================================================================
//
// The in-pod backend relies on container-runtime inheritance for the execution
// domain: the supervisor and every child it spawns run in the pod's cgroup with
// the device set the CRI granted the container. The backend does not enter a
// new cgroup or remap devices, so it can only honor an "inherited" allocation.
// The payload records the supervisor's own cgroup line plus a device-mode byte;
// `confirm` rejects any binding that requests an explicit/widened device set,
// because the in-pod backend cannot enforce one.

const DEVICE_MODE_INHERITED: u8 = 0;
const DEVICE_MODE_EXPLICIT: u8 = 1;

/// Build the in-pod resource binding from the supervisor's current cgroup, with
/// devices inherited from the container runtime.
#[must_use]
pub fn in_pod_resource_binding() -> ResourceBinding {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mut payload = Vec::with_capacity(cgroup.len() + 1);
    payload.push(DEVICE_MODE_INHERITED);
    payload.extend_from_slice(cgroup.as_bytes());
    ResourceBinding::new(IN_POD_RESOURCE_BINDING_VERSION, payload)
}

/// Build a binding that requests an explicit device set. The in-pod backend
/// cannot enforce this; `confirm` rejects it. Used by conformance tests.
#[cfg(test)]
#[must_use]
pub fn explicit_device_binding(devices: &[&str]) -> ResourceBinding {
    let joined = devices.join(",");
    let mut payload = Vec::with_capacity(joined.len() + 1);
    payload.push(DEVICE_MODE_EXPLICIT);
    payload.extend_from_slice(joined.as_bytes());
    ResourceBinding::new(IN_POD_RESOURCE_BINDING_VERSION, payload)
}

/// Verify the claimed execution domain is one the in-pod backend can preserve:
/// container-runtime inheritance, never an explicit/widened device allocation.
fn verify_inherited_resource_domain(binding: &ResourceBinding) -> Result<(), BackendError> {
    if binding.version() != IN_POD_RESOURCE_BINDING_VERSION {
        return Err(BackendError::Confirm(format!(
            "unsupported in-pod resource binding version {}",
            binding.version()
        )));
    }
    match binding.payload().first() {
        Some(&DEVICE_MODE_INHERITED) => Ok(()),
        Some(&DEVICE_MODE_EXPLICIT) => Err(BackendError::Confirm(
            "in-pod backend cannot enforce an explicit or widened device allocation; \
             only container-runtime inheritance is supported"
                .to_string(),
        )),
        _ => Err(BackendError::Confirm(
            "malformed in-pod resource binding payload".to_string(),
        )),
    }
}

// ============================================================================
// Config and factory
// ============================================================================

/// Runtime collaborators the in-pod lifecycle calls need, captured once when the
/// factory is built. Move-once values (the event senders) are held behind a
/// `Mutex<Option<_>>` so the `&self` factory/state methods can take them exactly
/// when the matching transition fires. Policy, workload, and sandbox identity
/// are *not* here; they arrive via [`ClaimContext`].
pub struct InPodConfig {
    pub network_enabled: bool,
    pub process_enabled: bool,
    pub opa_engine: Option<Arc<OpaEngine>>,
    pub retained_proto: Option<openshell_core::proto::SandboxPolicy>,
    pub entrypoint_pid: Arc<AtomicU32>,
    pub provider_credentials: ProviderCredentialState,
    /// Child environment for the agent, resolved at startup. Mutated in place by
    /// `bind` if the GCE metadata loopback server fails to come up.
    pub provider_env: Mutex<HashMap<String, String>>,
    pub sandbox_name: Option<String>,
    pub openshell_endpoint: Option<String>,
    pub inference_routes: Option<String>,
    pub ssh_socket_path: Option<String>,
    /// Proxy-side denial / activity senders (consumed by `bind`).
    pub denial_tx: Mutex<Option<UnboundedSender<DenialEvent>>>,
    pub activity_tx: Mutex<Option<ActivitySender>>,
    /// Bypass-monitor denial / activity senders (consumed by `start_agent`).
    #[cfg(target_os = "linux")]
    pub bypass_denial_tx: Mutex<Option<UnboundedSender<DenialEvent>>>,
    #[cfg(target_os = "linux")]
    pub bypass_activity_tx: Mutex<Option<ActivitySender>>,
    /// Output slot: `bind` publishes the proxy's policy-local route context here
    /// so the orchestrator's policy poll loop can pick it up without reaching
    /// into in-pod-specific state through the `dyn` boundary.
    pub policy_local_slot:
        Arc<Mutex<Option<Arc<openshell_supervisor_network::policy_local::PolicyLocalContext>>>>,
}

/// The factory for the in-pod backend. Holds the per-sandbox [`InPodConfig`] and
/// hands it to the boundary on the single `attach`.
pub struct InPodBackendFactory {
    config: Mutex<Option<InPodConfig>>,
}

impl InPodBackendFactory {
    /// Build the factory from its per-sandbox runtime collaborators.
    #[must_use]
    pub fn new(config: InPodConfig) -> Self {
        Self {
            config: Mutex::new(Some(config)),
        }
    }
}

#[async_trait]
impl IsolationBackendFactory for InPodBackendFactory {
    fn backend_id(&self) -> &'static str {
        IN_POD_BACKEND_ID
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend_id: IN_POD_BACKEND_ID.to_string(),
            contract_version: CONTRACT_VERSION,
            placement: BackendPlacement::InPod,
            // Readiness is confirmed by the supervisor reading back the
            // established mediation (netns + bound proxy listener).
            confirmation: ConfirmationCapability::SupervisorReadback,
            // procfs read-and-hash of the connecting binary.
            identity: vec![IdentityEvidenceKind::Observed],
        }
    }

    async fn attach(
        &self,
        _descriptor: VerifiedBoundaryDescriptor,
    ) -> Result<Box<dyn AttachedBoundary>, BackendError> {
        let config = self
            .config
            .lock()
            .expect("in-pod config lock")
            .take()
            .ok_or_else(|| BackendError::Attach("in-pod backend already attached".to_string()))?;
        Ok(Box::new(InPodAttached { config }))
    }
}

// ============================================================================
// Lifecycle states
// ============================================================================

/// Attached: the in-pod boundary's collaborators are held; nothing established.
struct InPodAttached {
    config: InPodConfig,
}

#[async_trait]
impl AttachedBoundary for InPodAttached {
    async fn claim(
        self: Box<Self>,
        claim: ClaimContext,
    ) -> Result<Box<dyn ClaimedBoundary>, BackendError> {
        // Establish the network dimension: create the workload's network
        // namespace and install the bypass-detection rules. Filesystem, syscall,
        // and identity are established/operated later from the same claim.
        #[cfg(target_os = "linux")]
        let netns = if self.config.network_enabled {
            create_netns_for_proxy(&claim.policy).map_err(|e| BackendError::Claim(e.to_string()))?
        } else {
            None
        };

        Ok(Box::new(InPodClaimed {
            config: self.config,
            claim,
            #[cfg(target_os = "linux")]
            netns,
        }))
    }
}

/// Claimed: sandbox identity, policy, agent, and the execution domain are bound;
/// the network namespace exists.
struct InPodClaimed {
    config: InPodConfig,
    claim: ClaimContext,
    #[cfg(target_os = "linux")]
    netns: Option<NetworkNamespace>,
}

#[async_trait]
impl ClaimedBoundary for InPodClaimed {
    async fn bind(self: Box<Self>) -> Result<Box<dyn BoundBoundary>, BackendError> {
        let this = *self;
        let config = this.config;
        let claim = this.claim;
        #[cfg(target_os = "linux")]
        let netns = this.netns;

        let networking = if config.network_enabled {
            #[cfg(target_os = "linux")]
            let proxy_bind_ip = netns.as_ref().map(NetworkNamespace::host_ip);
            #[cfg(not(target_os = "linux"))]
            let proxy_bind_ip: Option<std::net::IpAddr> = None;

            // Take the senders into locals so the Mutex guards drop before the
            // await (a guard held across an await would make the future !Send).
            let denial_tx = config.denial_tx.lock().expect("denial_tx lock").take();
            let activity_tx = config.activity_tx.lock().expect("activity_tx lock").take();
            let networking = run_networking(
                &claim.policy,
                proxy_bind_ip,
                config.opa_engine.as_ref(),
                config.retained_proto.as_ref(),
                config.entrypoint_pid.clone(),
                config.process_enabled,
                &config.provider_credentials,
                Some(claim.sandbox_id.as_str()),
                config.sandbox_name.as_deref(),
                config.openshell_endpoint.as_deref(),
                config.inference_routes.as_deref(),
                denial_tx,
                activity_tx,
            )
            .await
            .map_err(|e| BackendError::Bind(e.to_string()))?;
            Some(networking)
        } else {
            None
        };

        // Start the GCE metadata loopback server inside the namespace so Go's
        // metadata client (which bypasses HTTP_PROXY) can reach it via direct
        // TCP. Must come up before start_agent; on failure the GCE env vars are
        // stripped so the SDK falls back cleanly.
        #[cfg(target_os = "linux")]
        if let Some(ns) = netns.as_ref() {
            ensure_gce_metadata_server(&config, ns).await;
        }

        // Publish the policy-local route context for the orchestrator's poll loop.
        *config
            .policy_local_slot
            .lock()
            .expect("policy_local_slot lock") =
            networking.as_ref().map(|n| n.policy_local_ctx.clone());

        // Identity source over procfs (Observed), retained for the boundary's life.
        let identity_source: Arc<dyn IdentitySource> = Arc::new(ProcfsIdentitySource {
            entrypoint_pid: config.entrypoint_pid.clone(),
        });

        // Boundary event source. The rich denial/activity aggregators consume
        // their own channels (see module docs); this stream carries boundary
        // lifecycle events the in-pod backend produces natively (termination).
        let (evt_tx, evt_rx) = tokio::sync::mpsc::unbounded_channel();
        let events: Arc<dyn EventSource> = Arc::new(InPodEvents::new(evt_rx));

        Ok(Box::new(InPodBound {
            config,
            claim,
            #[cfg(target_os = "linux")]
            netns,
            networking,
            identity_source,
            events,
            evt_tx,
        }))
    }
}

/// Bound: mediation is connected. Identity and events are available.
struct InPodBound {
    config: InPodConfig,
    claim: ClaimContext,
    #[cfg(target_os = "linux")]
    netns: Option<NetworkNamespace>,
    networking: Option<Networking>,
    identity_source: Arc<dyn IdentitySource>,
    events: Arc<dyn EventSource>,
    evt_tx: UnboundedSender<BoundaryEvent>,
}

#[async_trait]
impl BoundBoundary for InPodBound {
    fn identity_source(&self) -> Arc<dyn IdentitySource> {
        self.identity_source.clone()
    }

    fn events(&self) -> Arc<dyn EventSource> {
        self.events.clone()
    }

    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        // Execution-domain check: reject any binding the in-pod backend cannot
        // preserve (an explicit/widened device set).
        verify_inherited_resource_domain(&self.claim.resource_binding)?;

        // Effective-mediation check (fail closed). In proxy mode the only egress
        // is through the proxy bound inside the workload netns; if the namespace
        // or the proxy listener is absent, the boundary does not safely gate
        // egress, so we must not produce Ready.
        //
        // Note: this confirms mediation *structure*. The nftables bypass-
        // detection ruleset still uses `policy accept` with protocol-specific
        // rejects (see `netns/nft_ruleset.rs`); hardening it to a true
        // default-deny is tracked as remaining Step 5 work and is NOT certified
        // here.
        if self.config.network_enabled
            && matches!(self.claim.policy.network.mode, NetworkMode::Proxy)
        {
            #[cfg(target_os = "linux")]
            if self.netns.is_none() {
                return Err(BackendError::Confirm(
                    "proxy mode requires a workload network namespace; none established"
                        .to_string(),
                ));
            }
            let proxy_up = self
                .networking
                .as_ref()
                .and_then(|n| n.proxy.as_ref())
                .is_some();
            if !proxy_up {
                return Err(BackendError::Confirm(
                    "proxy listener is not bound; egress mediation is not in effect".to_string(),
                ));
            }
        }

        Ok(Box::new(InPodReady {
            config: self.config,
            claim: self.claim,
            #[cfg(target_os = "linux")]
            netns: self.netns,
            networking: self.networking,
            identity_source: self.identity_source,
            events: self.events,
            evt_tx: self.evt_tx,
        }))
    }
}

/// Ready: enforcement and mediation are confirmed. Only agent start is allowed.
struct InPodReady {
    config: InPodConfig,
    claim: ClaimContext,
    #[cfg(target_os = "linux")]
    netns: Option<NetworkNamespace>,
    networking: Option<Networking>,
    identity_source: Arc<dyn IdentitySource>,
    events: Arc<dyn EventSource>,
    evt_tx: UnboundedSender<BoundaryEvent>,
}

#[async_trait]
impl ReadyBoundary for InPodReady {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        let this = *self;
        let config = this.config;
        let claim = this.claim;
        #[cfg(target_os = "linux")]
        let netns = this.netns;
        let networking = this.networking;

        #[cfg(target_os = "linux")]
        let netns_fd = netns.as_ref().and_then(NetworkNamespace::ns_fd);
        #[cfg(not(target_os = "linux"))]
        let netns_fd: Option<std::os::unix::io::RawFd> = None;

        let port_forward: Arc<dyn BoundaryPortForward> = Arc::new(NetnsPortForward { netns_fd });
        let exec: Arc<dyn BoundaryExec> = Arc::new(InPodExec);

        let agent: Arc<dyn BoundaryProcess> = if config.process_enabled {
            let spec = &claim.agent;
            let ca_file_paths = networking.as_ref().and_then(|n| n.ca_file_paths.clone());
            let provider_env = config
                .provider_env
                .lock()
                .expect("provider_env lock")
                .clone();

            #[cfg(target_os = "linux")]
            let bypass_denial_tx = config
                .bypass_denial_tx
                .lock()
                .expect("bypass_denial_tx lock")
                .take();
            #[cfg(target_os = "linux")]
            let bypass_activity_tx = config
                .bypass_activity_tx
                .lock()
                .expect("bypass_activity_tx lock")
                .take();

            let spawned = spawn_workload(
                &spec.program,
                &spec.args,
                spec.workdir.as_deref(),
                spec.timeout_secs,
                spec.interactive,
                Some(claim.sandbox_id.as_str()),
                config.openshell_endpoint.as_deref(),
                config.ssh_socket_path.clone(),
                &claim.policy,
                config.entrypoint_pid.clone(),
                config.provider_credentials.clone(),
                provider_env,
                ca_file_paths,
                #[cfg(target_os = "linux")]
                netns.as_ref(),
                #[cfg(target_os = "linux")]
                bypass_denial_tx,
                #[cfg(target_os = "linux")]
                bypass_activity_tx,
            )
            .await
            .map_err(|e| BackendError::Process(e.to_string()))?;

            Arc::new(InPodAgentProcess::running(spawned))
        } else {
            // Network-only (sidecar/legacy) mode: no workload in this pod. The
            // boundary is held open until a shutdown signal. This is a legacy
            // split mode, not a gated external workload.
            Arc::new(InPodAgentProcess::hold_open())
        };

        Ok(Box::new(InPodRunning {
            agent,
            identity_source: this.identity_source,
            exec,
            port_forward,
            events: this.events,
            evt_tx: this.evt_tx,
            _networking: networking,
            #[cfg(target_os = "linux")]
            _netns: netns,
        }))
    }
}

/// Running: the agent is started behind the boundary. Exec, connect, wait, and
/// signal are available.
struct InPodRunning {
    agent: Arc<dyn BoundaryProcess>,
    identity_source: Arc<dyn IdentitySource>,
    exec: Arc<dyn BoundaryExec>,
    port_forward: Arc<dyn BoundaryPortForward>,
    events: Arc<dyn EventSource>,
    evt_tx: UnboundedSender<BoundaryEvent>,
    /// Held to keep the proxy task and network namespace alive for the boundary's
    /// life; dropped (with the running state) tears them down.
    _networking: Option<Networking>,
    #[cfg(target_os = "linux")]
    _netns: Option<NetworkNamespace>,
}

impl RunningBoundary for InPodRunning {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.agent.clone()
    }
    fn identity_source(&self) -> Arc<dyn IdentitySource> {
        self.identity_source.clone()
    }
    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }
    fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }
    fn events(&self) -> Arc<dyn EventSource> {
        self.events.clone()
    }
}

impl Drop for InPodRunning {
    fn drop(&mut self) {
        // Surface boundary teardown on the event stream so a subscriber is not
        // left silently waiting. Best-effort: the receiver may already be gone.
        let _ = self.evt_tx.send(BoundaryEvent::BoundaryTerminated {
            reason: "in-pod boundary torn down".to_string(),
        });
    }
}

// ============================================================================
// Agent process handle
// ============================================================================

/// The agent process running inside the in-pod boundary. `wait` returns a stable
/// terminal status across repeated calls; signals go through the lock-free
/// pid-based [`AgentSignaler`] so they never contend with an in-flight `wait`.
struct InPodAgentProcess {
    pid: Option<u32>,
    signaler: Option<AgentSignaler>,
    waiter: tokio::sync::Mutex<AgentWaitState>,
}

enum AgentWaitState {
    Running(SpawnedAgent),
    HoldOpen,
    Done(BoundaryExitStatus),
}

impl InPodAgentProcess {
    fn running(spawned: SpawnedAgent) -> Self {
        Self {
            pid: Some(spawned.pid()),
            signaler: Some(spawned.signaler()),
            waiter: tokio::sync::Mutex::new(AgentWaitState::Running(spawned)),
        }
    }

    fn hold_open() -> Self {
        Self {
            pid: None,
            signaler: None,
            waiter: tokio::sync::Mutex::new(AgentWaitState::HoldOpen),
        }
    }
}

#[async_trait]
impl BoundaryProcess for InPodAgentProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        // Holding the lock across the wait serializes repeated callers: the first
        // performs the wait and caches the status; later callers block on the
        // lock, then observe the cached `Done`. Signals never take this lock.
        let mut guard = self.waiter.lock().await;
        match &mut *guard {
            AgentWaitState::Done(status) => Ok(*status),
            AgentWaitState::HoldOpen => {
                crate::wait_for_shutdown_signal().await;
                let status = BoundaryExitStatus::Exited(0);
                *guard = AgentWaitState::Done(status);
                Ok(status)
            }
            AgentWaitState::Running(agent) => {
                let code = agent
                    .wait()
                    .await
                    .map_err(|e| BackendError::Process(e.to_string()))?;
                let status = BoundaryExitStatus::Exited(code);
                *guard = AgentWaitState::Done(status);
                Ok(status)
            }
        }
    }

    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        let Some(signaler) = self.signaler.as_ref() else {
            // Network-only hold-open: no workload process to signal.
            return Ok(());
        };
        let result = match signal {
            BoundarySignal::Term => signaler.term(),
            BoundarySignal::Kill => signaler.kill(),
            BoundarySignal::Int => signaler.interrupt(),
            BoundarySignal::Hup => signaler.hangup(),
        };
        result.map_err(|e| BackendError::Process(e.to_string()))
    }

    async fn terminate(&self) -> Result<(), BackendError> {
        let Some(signaler) = self.signaler.as_ref() else {
            return Ok(());
        };
        signaler
            .term()
            .map_err(|e| BackendError::Process(e.to_string()))
    }

    fn diagnostic_pid(&self) -> Option<u32> {
        self.pid
    }
}

// ============================================================================
// Exec (SSH adoption pending)
// ============================================================================

/// In-pod exec interface. The live SSH server still spawns workload shells
/// directly (inside `spawn_workload`); routing those through an owned
/// [`ExecSession`] (stdio/PTY/wait) is the remaining live-adoption refactor, so
/// this returns an explicit error rather than a half-wired session.
struct InPodExec;

#[async_trait]
impl BoundaryExec for InPodExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        Err(BackendError::Process(
            "in-pod BoundaryExec is not yet the live SSH exec path; SSH execs directly. \
             Wiring ExecSession stdio/PTY through this interface is pending (see POC handoff)."
                .to_string(),
        ))
    }
}

// ============================================================================
// GCE metadata loopback server
// ============================================================================

/// Bring up the GCE metadata loopback server inside the network namespace,
/// stripping the GCE env vars from the agent's environment if it fails so the
/// Go SDK falls back cleanly.
#[cfg(target_os = "linux")]
async fn ensure_gce_metadata_server(config: &InPodConfig, ns: &NetworkNamespace) {
    use std::time::Duration;
    use tokio::time::timeout;
    use tracing::{info, warn};

    if !config
        .provider_credentials
        .snapshot()
        .child_env
        .contains_key("GCE_METADATA_HOST")
    {
        return;
    }

    let ctx =
        crate::google_cloud_metadata::MetadataContext::new(config.provider_credentials.clone());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    match ns
        .bind_tcp_in_netns(openshell_core::google_cloud::METADATA_LOOPBACK_ADDR)
        .await
    {
        Ok(listener) => {
            tokio::spawn(crate::metadata_server::run(listener, ctx, ready_tx));
            if let Ok(Ok(addr)) = timeout(Duration::from_secs(5), ready_rx).await {
                info!(addr = %addr, "GCE metadata loopback server ready");
            } else {
                warn!("GCE metadata server failed to become ready, removing metadata env vars");
                strip_gce_env(config);
            }
        }
        Err(e) => {
            warn!(error = %e, "GCE metadata server bind failed, Go SDK may not discover credentials");
            strip_gce_env(config);
        }
    }
}

/// Remove the GCE metadata env vars from both the agent's child env and the
/// provider credential state.
#[cfg(target_os = "linux")]
fn strip_gce_env(config: &InPodConfig) {
    let mut env = config.provider_env.lock().expect("provider_env lock");
    env.remove("GCE_METADATA_HOST");
    env.remove("GCE_METADATA_IP");
    env.remove("METADATA_SERVER_DETECTION");
    drop(env);
    config
        .provider_credentials
        .remove_env_key("GCE_METADATA_HOST");
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::policy::{
        FilesystemPolicy, LandlockPolicy, NetworkPolicy, ProcessPolicy, SandboxPolicy,
    };
    use openshell_isolation::AgentSpec;
    use openshell_isolation::contract::{BackendRegistry, BoundaryDescriptor};

    /// A minimal in-pod config with networking and the workload disabled, so the
    /// lifecycle runs without root, a network namespace, or a gateway.
    fn minimal_config() -> InPodConfig {
        InPodConfig {
            network_enabled: false,
            process_enabled: false,
            opa_engine: None,
            retained_proto: None,
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
            provider_credentials: ProviderCredentialState::from_environment(
                0,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
            provider_env: Mutex::new(HashMap::new()),
            sandbox_name: None,
            openshell_endpoint: None,
            inference_routes: None,
            ssh_socket_path: None,
            denial_tx: Mutex::new(None),
            activity_tx: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_denial_tx: Mutex::new(None),
            #[cfg(target_os = "linux")]
            bypass_activity_tx: Mutex::new(None),
            policy_local_slot: Arc::new(Mutex::new(None)),
        }
    }

    fn block_mode_policy() -> SandboxPolicy {
        SandboxPolicy {
            version: 1,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy {
                mode: NetworkMode::Block,
                proxy: None,
            },
            landlock: LandlockPolicy::default(),
            process: ProcessPolicy::default(),
        }
    }

    fn descriptor() -> BoundaryDescriptor {
        BoundaryDescriptor {
            version: CONTRACT_VERSION,
            backend_id: IN_POD_BACKEND_ID.to_string(),
            payload: Vec::new(),
        }
    }

    // ----- Resource binding / execution domain -----

    #[test]
    fn inherited_resource_domain_accepted() {
        assert!(verify_inherited_resource_domain(&in_pod_resource_binding()).is_ok());
    }

    #[test]
    fn widened_device_set_rejected() {
        // A binding requesting an explicit device set (e.g. a GPU) cannot be
        // enforced in-pod and must be rejected at confirmation.
        let binding = explicit_device_binding(&["nvidia0", "nvidiactl"]);
        assert!(matches!(
            verify_inherited_resource_domain(&binding),
            Err(BackendError::Confirm(_))
        ));
    }

    #[test]
    fn wrong_binding_version_rejected() {
        let binding = ResourceBinding::new(
            IN_POD_RESOURCE_BINDING_VERSION + 1,
            vec![DEVICE_MODE_INHERITED],
        );
        assert!(verify_inherited_resource_domain(&binding).is_err());
    }

    // ----- Factory and registry -----

    #[test]
    fn factory_advertises_in_pod_capabilities() {
        let factory = InPodBackendFactory::new(minimal_config());
        assert_eq!(factory.backend_id(), IN_POD_BACKEND_ID);
        let caps = factory.capabilities();
        assert_eq!(caps.contract_version, CONTRACT_VERSION);
        assert_eq!(caps.placement, BackendPlacement::InPod);
        assert!(caps.identity.contains(&IdentityEvidenceKind::Observed));
    }

    #[test]
    fn registry_selects_in_pod_backend() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, _verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("resolve");
        assert_eq!(factory.backend_id(), IN_POD_BACKEND_ID);
    }

    #[test]
    fn registry_rejects_duplicate_in_pod() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("first register");
        assert!(
            registry
                .register(Arc::new(InPodBackendFactory::new(minimal_config())))
                .is_err()
        );
    }

    #[test]
    fn registry_rejects_unknown_backend() {
        let registry = BackendRegistry::new();
        let descriptor = BoundaryDescriptor {
            version: CONTRACT_VERSION,
            backend_id: "nonexistent".to_string(),
            payload: Vec::new(),
        };
        assert!(
            registry
                .resolve(descriptor, "nonexistent")
                .map(|_| ())
                .is_err()
        );
    }

    #[test]
    fn registry_rejects_admission_mismatch() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        // The descriptor names in-pod, but admission expects a different backend.
        assert!(
            registry
                .resolve(descriptor(), "some-other-backend")
                .map(|_| ())
                .is_err()
        );
    }

    // ----- Lifecycle (no root / no netns) -----

    /// Drive the real in-pod chain attach -> claim -> bind -> confirm and prove
    /// confirmation fails closed when the claimed device set cannot be enforced.
    /// Confirmation failure consumes the bound state, so start is unreachable.
    #[tokio::test]
    async fn confirm_rejects_widened_devices_through_lifecycle() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("resolve");

        let attached = factory.attach(verified).await.expect("attach");
        let claim = ClaimContext {
            sandbox_id: "test-sandbox".to_string(),
            policy: block_mode_policy(),
            agent: AgentSpec {
                program: "true".to_string(),
                args: vec![],
                workdir: None,
                timeout_secs: 0,
                interactive: false,
            },
            resource_binding: explicit_device_binding(&["nvidia0"]),
        };
        let claimed = attached.claim(claim).await.expect("claim");
        let bound = claimed.bind().await.expect("bind");
        // `confirm` consumes the bound state; on rejection there is no ready
        // boundary to start an agent from. (`Box<dyn ReadyBoundary>` is not
        // `Debug`, so match rather than `expect_err`.)
        let result = bound.confirm().await;
        assert!(matches!(result, Err(BackendError::Confirm(_))));
    }

    /// The bound state exposes a single-consumer event source: a second
    /// subscription fails explicitly rather than returning an empty stream.
    #[tokio::test]
    async fn bound_event_source_is_single_consumer() {
        let mut registry = BackendRegistry::new();
        registry
            .register(Arc::new(InPodBackendFactory::new(minimal_config())))
            .expect("register");
        let (factory, verified) = registry
            .resolve(descriptor(), IN_POD_BACKEND_ID)
            .expect("resolve");
        let attached = factory.attach(verified).await.expect("attach");
        let claim = ClaimContext {
            sandbox_id: "test-sandbox".to_string(),
            policy: block_mode_policy(),
            agent: AgentSpec {
                program: "true".to_string(),
                args: vec![],
                workdir: None,
                timeout_secs: 0,
                interactive: false,
            },
            resource_binding: in_pod_resource_binding(),
        };
        let claimed = attached.claim(claim).await.expect("claim");
        let bound = claimed.bind().await.expect("bind");
        let events = bound.events();
        assert!(events.subscribe().is_ok());
        assert!(events.subscribe().is_err());
    }
}
