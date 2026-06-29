// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime-selectable Isolation Backend contract (RFC 0012 POC).
//!
//! This module is the object-safe, runtime-selectable contract the supervisor
//! drives. A backend registers an [`IsolationBackendFactory`] under a
//! `backend_id`; the supervisor resolves it from a [`BackendRegistry`] against a
//! verified [`BoundaryDescriptor`] and advances the boundary through a fixed
//! chain of boxed states:
//!
//! ```text
//! Attached -> Claimed -> Bound -> Ready -> Running
//! ```
//!
//! Each transition consumes the prior state by value (`self: Box<Self>`), and no
//! state type has a public constructor, so a stage cannot be skipped or
//! replayed. The supervisor holds no `match`/downcast on concrete backends: the
//! registry is the only lookup by `backend_id`, and everything past it is a
//! `Box<dyn _>` / `Arc<dyn _>`.
//!
//! The in-pod backend (`openshell-sandbox`) and the supervisor drive this
//! contract directly; two mock factories and the conformance tests below
//! exercise it against a second, heterogeneous backend.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite};

pub use openshell_core::policy::SandboxPolicy;

/// The contract version a backend's `BackendCapabilities` must agree on.
pub const CONTRACT_VERSION: u32 = 1;

// ============================================================================
// Errors
// ============================================================================

/// Classified failures at the common contract boundary.
///
/// Only [`BackendError::is_retryable`] cases may be retried by the supervisor,
/// and a retry must reuse the same backend and boundary; no error downgrades
/// isolation.
#[derive(Debug)]
pub enum BackendError {
    /// Descriptor missing, malformed, unsupported, or mismatched against admission.
    Descriptor(String),
    /// No factory registered for the resolved `backend_id`.
    NotRegistered(String),
    /// Attachment denied or verification failed (terminal for this instance).
    Attach(String),
    /// Boundary temporarily unavailable. The only retryable class.
    Unavailable(String),
    /// Claim binding failed.
    Claim(String),
    /// Mediation bind failed.
    Bind(String),
    /// Readiness confirmation failed (do not start workload code).
    Confirm(String),
    /// Process start or exec failure.
    Process(String),
    /// The boundary terminated; new exec/connect must be rejected.
    Terminated(String),
}

/// Coarse, machine-readable classification of a [`BackendError`]. The error's
/// variant and message carry the structured context (which operation failed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorKind {
    /// Descriptor, version, backend, or capability mismatch.
    Invalid,
    /// Authenticated attachment or claim rejection.
    Denied,
    /// Boundary temporarily unavailable (the only retryable kind, at attach).
    Unavailable,
    /// Claim, bind, confirmation, start, or runtime operation failure.
    Failed,
    /// The boundary terminated.
    Terminated,
}

impl BackendError {
    /// Whether the supervisor may retry, reusing the same backend and boundary.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }

    /// The machine-readable kind for this error.
    #[must_use]
    pub fn kind(&self) -> BackendErrorKind {
        match self {
            Self::Descriptor(_) | Self::NotRegistered(_) => BackendErrorKind::Invalid,
            Self::Attach(_) => BackendErrorKind::Denied,
            Self::Unavailable(_) => BackendErrorKind::Unavailable,
            Self::Claim(_) | Self::Bind(_) | Self::Confirm(_) | Self::Process(_) => {
                BackendErrorKind::Failed
            }
            Self::Terminated(_) => BackendErrorKind::Terminated,
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(m) => write!(f, "descriptor error: {m}"),
            Self::NotRegistered(m) => write!(f, "backend not registered: {m}"),
            Self::Attach(m) => write!(f, "attachment failed: {m}"),
            Self::Unavailable(m) => write!(f, "boundary unavailable: {m}"),
            Self::Claim(m) => write!(f, "claim failed: {m}"),
            Self::Bind(m) => write!(f, "bind failed: {m}"),
            Self::Confirm(m) => write!(f, "confirmation failed: {m}"),
            Self::Process(m) => write!(f, "process error: {m}"),
            Self::Terminated(m) => write!(f, "boundary terminated: {m}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Why an identity resolution failed. Resolution failure fails closed; it never
/// yields `Observed` evidence.
#[derive(Debug)]
pub enum ResolveError {
    /// No process owns the flow (stale or unknown reference).
    NotFound,
    /// Resolution attempted but could not produce trustworthy evidence.
    Failed(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "flow not found"),
            Self::Failed(m) => write!(f, "identity resolution failed: {m}"),
        }
    }
}

impl std::error::Error for ResolveError {}

// ============================================================================
// Descriptor and registry
// ============================================================================

/// The common descriptor envelope.
///
/// The driver materializes it for the admitted backend; the payload is
/// backend-specific (its integrity, sandbox binding, authentication, freshness,
/// and replay protection belong to that backend's design).
#[derive(Debug, Clone)]
pub struct BoundaryDescriptor {
    /// Contract version this descriptor targets.
    pub version: u32,
    /// The backend the supervisor must instantiate.
    pub backend_id: String,
    /// Backend-specific attachment data.
    pub payload: Vec<u8>,
}

/// Trusted expectations from the authenticated admission record.
///
/// Retained by [`VerifiedBoundaryDescriptor`] after common verification. The
/// supervisor checks the descriptor and factory against these; a backend cannot
/// lower them.
#[derive(Debug, Clone)]
pub struct AdmittedBoundaryRequirements {
    /// The backend admission selected.
    pub backend_id: String,
    /// The contract version that must match exactly.
    pub contract_version: u32,
    /// Digest of the admitted policy (opaque here).
    pub policy_digest: Vec<u8>,
    /// The confirmation mechanism the backend must provide.
    pub required_confirmation: ConfirmationKind,
    /// The minimum identity assurance the backend must reach.
    pub minimum_identity: Assurance,
}

/// A descriptor that has passed registry verification against the admitted
/// requirements.
///
/// Minted only by [`BackendRegistry::resolve`]; no public constructor, so an
/// unverified descriptor cannot reach a factory.
pub struct VerifiedBoundaryDescriptor {
    descriptor: BoundaryDescriptor,
    requirements: AdmittedBoundaryRequirements,
}

impl VerifiedBoundaryDescriptor {
    /// The verified backend id.
    #[must_use]
    pub fn backend_id(&self) -> &str {
        &self.descriptor.backend_id
    }
    /// The backend-specific payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.descriptor.payload
    }
    /// The contract version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.descriptor.version
    }
    /// The admitted requirements this descriptor was verified against.
    #[must_use]
    pub fn requirements(&self) -> &AdmittedBoundaryRequirements {
        &self.requirements
    }
}

/// Maps `backend_id` to its factory. The only lookup-by-id in the system; the
/// supervisor lifecycle never branches on a concrete backend.
#[derive(Default)]
pub struct BackendRegistry {
    factories: HashMap<String, Arc<dyn IsolationBackendFactory>>,
}

impl BackendRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a factory. Rejects a duplicate `backend_id`.
    pub fn register(
        &mut self,
        factory: Arc<dyn IsolationBackendFactory>,
    ) -> Result<(), BackendError> {
        let id = factory.backend_id().to_string();
        if self.factories.contains_key(&id) {
            return Err(BackendError::Descriptor(format!(
                "duplicate backend id {id:?}"
            )));
        }
        // A factory must agree on its own contract version up front.
        let caps = factory.capabilities();
        if caps.contract_version != CONTRACT_VERSION {
            return Err(BackendError::Descriptor(format!(
                "backend {id:?} targets contract version {}, supervisor speaks {CONTRACT_VERSION}",
                caps.contract_version
            )));
        }
        self.factories.insert(id, factory);
        Ok(())
    }

    /// Verify a descriptor against the admitted requirements and resolve its
    /// factory. Fails closed and never falls back to another backend:
    ///
    /// - the descriptor version must equal [`CONTRACT_VERSION`];
    /// - the descriptor's `backend_id` must equal the admitted id;
    /// - a factory must be registered for that id, agreeing on its id;
    /// - the factory's contract version must match the admitted version exactly;
    /// - the factory must offer the required confirmation kind; and
    /// - the factory's maximum identity must meet the admitted minimum.
    pub fn resolve(
        &self,
        descriptor: BoundaryDescriptor,
        requirements: &AdmittedBoundaryRequirements,
    ) -> Result<(Arc<dyn IsolationBackendFactory>, VerifiedBoundaryDescriptor), BackendError> {
        if descriptor.version != CONTRACT_VERSION {
            return Err(BackendError::Descriptor(format!(
                "descriptor version {} unsupported (expected {CONTRACT_VERSION})",
                descriptor.version
            )));
        }
        if descriptor.backend_id != requirements.backend_id {
            return Err(BackendError::Descriptor(format!(
                "descriptor backend {:?} does not match admitted backend {:?}",
                descriptor.backend_id, requirements.backend_id
            )));
        }
        let factory = self
            .factories
            .get(&descriptor.backend_id)
            .ok_or_else(|| BackendError::NotRegistered(descriptor.backend_id.clone()))?
            .clone();
        // Defense in depth: the resolved factory must agree on its id.
        if factory.backend_id() != descriptor.backend_id {
            return Err(BackendError::Descriptor(format!(
                "registry returned backend {:?} for id {:?}",
                factory.backend_id(),
                descriptor.backend_id
            )));
        }
        let caps = factory.capabilities();
        if caps.contract_version != requirements.contract_version {
            return Err(BackendError::Descriptor(format!(
                "backend {:?} speaks contract version {}, admission requires {}",
                descriptor.backend_id, caps.contract_version, requirements.contract_version
            )));
        }
        if !caps
            .confirmation
            .contains(&requirements.required_confirmation)
        {
            return Err(BackendError::Descriptor(format!(
                "backend {:?} cannot provide required confirmation {:?}",
                descriptor.backend_id, requirements.required_confirmation
            )));
        }
        if caps.maximum_identity < requirements.minimum_identity {
            return Err(BackendError::Descriptor(format!(
                "backend {:?} maximum identity {:?} below admitted minimum {:?}",
                descriptor.backend_id, caps.maximum_identity, requirements.minimum_identity
            )));
        }
        Ok((
            factory,
            VerifiedBoundaryDescriptor {
                descriptor,
                requirements: requirements.clone(),
            },
        ))
    }
}

/// Builds and attaches a concrete backend. Registered once per `backend_id`.
#[async_trait]
pub trait IsolationBackendFactory: Send + Sync {
    /// The backend this factory builds.
    fn backend_id(&self) -> &'static str;
    /// What the backend can do, checked before attachment.
    fn capabilities(&self) -> BackendCapabilities;
    /// Attach to the exact admitted boundary. Attachment identifies the
    /// pre-existing or lazily-created boundary; policy, workload, identity, and
    /// resources are bound by the later `claim`.
    async fn attach(
        &self,
        descriptor: VerifiedBoundaryDescriptor,
    ) -> Result<Box<dyn AttachedBoundary>, BackendError>;
}

// ============================================================================
// Capabilities
// ============================================================================

/// Where a backend places enforcement (audit/admission only; never read by
/// per-connection policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendPlacement {
    /// Built in the agent's own container, in the supervisor's process.
    InPod,
    /// Privileged network setup in a same-pod sidecar; supervisor with the agent.
    Sidecar,
    /// Privileged per-node daemon installs the boundary.
    NodeEnforcer,
    /// Supervisor in a separate pod from the agent.
    SplitPod,
    /// Agent in a microVM guest.
    MicroVm,
    /// Single-pod outer sandbox (gVisor/Kata/Firecracker).
    OuterSandbox,
}

/// How a backend confirms effective enforcement at readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationKind {
    /// The supervisor observes effective enforcement directly.
    Direct,
    /// The backend returns verified attestation the supervisor checks.
    Attested,
}

/// What a backend supports, so admission can reject a workload it cannot place.
///
/// The backend id is the factory's; an exact contract version implies support
/// for every field of that `SandboxPolicy` version. Confirmation kind and
/// maximum identity assurance are the only negotiated security capabilities.
#[derive(Debug, Clone)]
pub struct BackendCapabilities {
    /// The contract version the backend speaks (matched exactly).
    pub contract_version: u32,
    /// Where it places enforcement.
    pub placement: BackendPlacement,
    /// The confirmation mechanisms it can provide.
    pub confirmation: Vec<ConfirmationKind>,
    /// The strongest identity assurance it can produce.
    pub maximum_identity: Assurance,
}

// ============================================================================
// Claim and execution domain
// ============================================================================

/// The agent workload to run inside the boundary.
pub use crate::AgentSpec;

/// Opaque, versioned, integrity-bound description of the compute driver's
/// execution and device domain.
///
/// Covers the cgroup identity, runtime security context, and resolved device
/// allocation. The common crate never interprets the payload; allocating the
/// domain is the compute driver's job.
#[derive(Debug, Clone)]
pub struct ResourceBinding {
    version: u32,
    payload: Vec<u8>,
}

impl ResourceBinding {
    /// Build a binding from a driver-minted, integrity-bound payload.
    #[must_use]
    pub fn new(version: u32, payload: Vec<u8>) -> Self {
        Self { version, payload }
    }
    /// The binding version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }
    /// The opaque payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// What `claim` binds to a boundary: identity, policy, workload, and the
/// execution domain the agent and every exec must preserve.
pub struct ClaimContext {
    /// Which sandbox this is.
    pub sandbox_id: String,
    /// Policy across all four dimensions.
    pub policy: SandboxPolicy,
    /// The workload to run.
    pub agent: AgentSpec,
    /// The compute driver's execution and device domain.
    pub resource_binding: ResourceBinding,
}

// ============================================================================
// Lifecycle states
// ============================================================================

/// Boundary control retained by the supervisor from `attach`, independent of the
/// lifecycle state.
///
/// `shutdown` is idempotent and owns cleanup on every terminal path;
/// `wait_terminated` reports boundary loss distinct from agent exit.
#[async_trait]
pub trait BoundaryControl: Send + Sync {
    /// Await boundary-level termination (distinct from agent exit).
    async fn wait_terminated(&self) -> Result<(), BackendError>;
    /// Idempotently release the boundary and its delegated resources.
    async fn shutdown(&self) -> Result<(), BackendError>;
}

/// The exact admitted boundary, attached. No workload may run yet.
#[async_trait]
pub trait AttachedBoundary: Send {
    /// Boundary control, retained by the supervisor across later transitions.
    fn control(&self) -> Arc<dyn BoundaryControl>;
    /// Bind sandbox identity, policy, agent, and resources.
    async fn claim(
        self: Box<Self>,
        claim: ClaimContext,
    ) -> Result<Box<dyn ClaimedBoundary>, BackendError>;
}

/// Bound to a sandbox. Mediation is not yet connected.
#[async_trait]
pub trait ClaimedBoundary: Send {
    /// Bring up mediation and create the identity and event interfaces.
    async fn bind(self: Box<Self>) -> Result<Box<dyn BoundBoundary>, BackendError>;
}

/// Mediation connected. Identity and events are available; the workload is not.
#[async_trait]
pub trait BoundBoundary: Send {
    /// The proxy's backend-neutral source of workload connections.
    fn mediation_ingress(&self) -> Arc<dyn MediationIngress>;
    /// The per-connection identity resolver (retained by the proxy).
    fn identity_source(&self) -> Arc<dyn IdentitySource>;
    /// The boundary event stream source (retained by the orchestrator).
    fn events(&self) -> Arc<dyn EventSource>;
    /// Confirm effective enforcement and mediation. Fails closed.
    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError>;
}

/// Enforcement and mediation confirmed. The agent may start; nothing else has.
#[async_trait]
pub trait ReadyBoundary: Send {
    /// Start the agent entrypoint behind the boundary and return its handle.
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError>;
}

/// The agent is running behind the boundary. Exec, connect, wait, and signal
/// are available. All interface accessors return owned `Arc`s so a consumer can
/// retain them past any later state consumption.
pub trait RunningBoundary: Send + Sync {
    /// The agent process handle.
    fn agent(&self) -> Arc<dyn BoundaryProcess>;
    /// The in-boundary exec interface.
    fn exec(&self) -> Arc<dyn BoundaryExec>;
    /// The loopback port-forward interface.
    fn port_forward(&self) -> Arc<dyn BoundaryPortForward>;
}

// ============================================================================
// Process and exec
// ============================================================================

/// Placement-neutral terminal status of a boundary process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryExitStatus {
    /// Exited with a code.
    Exited(i32),
    /// Killed by a signal.
    Signaled(i32),
}

/// Placement-neutral signal to deliver to a boundary process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundarySignal {
    /// Graceful terminate.
    Term,
    /// Forceful kill.
    Kill,
    /// Interrupt.
    Int,
    /// Hangup.
    Hup,
}

/// A process running inside the boundary, owned by its boundary state. `wait`
/// returns one stable status however many times it is called; a host PID, if
/// useful, is diagnostics-only and never the handle.
#[async_trait]
pub trait BoundaryProcess: Send + Sync {
    /// Await terminal status (stable across repeated calls).
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError>;
    /// Deliver a signal to the process or its group.
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError>;
    /// Terminate the process and release its resources.
    async fn terminate(&self) -> Result<(), BackendError>;
    /// Optional host PID, for diagnostics only.
    fn diagnostic_pid(&self) -> Option<u32> {
        None
    }
}

/// A boxed async writer into a boundary process's stdin.
pub type BoundaryInput = Box<dyn AsyncWrite + Send + Unpin>;
/// A boxed async reader from a boundary process's stdout or stderr.
pub type BoundaryOutput = Box<dyn AsyncRead + Send + Unpin>;

/// A PTY attached to an exec session.
#[async_trait]
pub trait BoundaryTerminal: Send + Sync {
    /// Resize the terminal.
    async fn resize(&self, cols: u16, rows: u16) -> Result<(), BackendError>;
}

/// An owned exec session: the process handle plus its stdio and optional PTY.
/// Owning the process keeps it alive after `exec` returns (the legacy
/// `kill_on_drop` handle did not).
pub struct ExecSession {
    /// The spawned process.
    pub process: Arc<dyn BoundaryProcess>,
    /// Stdin writer, if not a PTY-merged stream.
    pub stdin: Option<BoundaryInput>,
    /// Stdout reader.
    pub stdout: BoundaryOutput,
    /// Stderr reader, distinct from stdout for non-PTY exec.
    pub stderr: Option<BoundaryOutput>,
    /// PTY control, present when a terminal was requested.
    pub terminal: Option<Arc<dyn BoundaryTerminal>>,
}

/// What to run inside the boundary via [`BoundaryExec`].
#[derive(Debug, Clone)]
pub struct ExecSpec {
    /// Program to run.
    pub program: String,
    /// Program arguments.
    pub args: Vec<String>,
    /// Extra environment over the boundary's base.
    pub env: Vec<(String, String)>,
    /// Working directory, if any.
    pub workdir: Option<String>,
    /// Whether to allocate a PTY.
    pub pty: bool,
}

/// In-boundary process entry, consumed by the SSH server and supervisor session.
#[async_trait]
pub trait BoundaryExec: Send + Sync {
    /// Spawn `spec` inside the boundary, returning an owned session.
    async fn exec(&self, spec: ExecSpec) -> Result<ExecSession, BackendError>;
}

// ============================================================================
// Port forward
// ============================================================================

/// A loopback-only target inside the boundary, validated at construction.
#[derive(Debug, Clone)]
pub struct LoopbackTarget {
    host: IpAddr,
    port: u16,
}

impl LoopbackTarget {
    /// Build a loopback target, rejecting any non-loopback host.
    pub fn new(host: IpAddr, port: u16) -> Result<Self, BackendError> {
        if !host.is_loopback() {
            return Err(BackendError::Process(format!(
                "port-forward target {host} is not loopback"
            )));
        }
        Ok(Self { host, port })
    }
    /// The loopback host.
    #[must_use]
    pub fn host(&self) -> IpAddr {
        self.host
    }
    /// The target port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// A bidirectional byte stream into the boundary.
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> DuplexStream for T {}

/// An open connection into a boundary loopback target.
pub type BoundaryConn = Box<dyn DuplexStream>;

/// Loopback port-forward, consumed by the SSH server and supervisor session.
#[async_trait]
pub trait BoundaryPortForward: Send + Sync {
    /// Connect to `target` inside the boundary.
    async fn connect(&self, target: LoopbackTarget) -> Result<BoundaryConn, BackendError>;
}

// ============================================================================
// Mediation ingress
// ============================================================================

/// A workload connection delivered to the proxy, with its identity token.
pub struct MediatedConnection {
    /// The workload connection stream.
    pub stream: BoundaryConn,
    /// The opaque per-connection token the proxy resolves via [`IdentitySource`].
    pub flow: Flow,
}

/// The proxy's backend-neutral source of workload connections. In-pod wraps the
/// proxy's local listener; a delegated backend pulls from its private transport.
#[async_trait]
pub trait MediationIngress: Send + Sync {
    /// Await the next mediated workload connection.
    async fn accept(&self) -> Result<MediatedConnection, BackendError>;
}

// ============================================================================
// Identity
// ============================================================================

/// How trustworthy an [`Evidence`] is.
///
/// Ordered for policy: binary-scoped rules require [`Assurance::Observed`] or
/// higher, and [`Assurance::Claimed`] counts as [`Assurance::None`] for them.
/// [`Assurance::Attested`] is defined narrowly: fresh, boundary- and flow-bound
/// evidence verified against an observer and trust root outside the agent's
/// adversary domain. Evidence that does not meet that bar is not `Attested`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Assurance {
    /// No identity available.
    None,
    /// Asserted by the workload, unverified.
    Claimed,
    /// The backend read and hashed the binary itself.
    Observed,
    /// Verified out-of-band attestation, per the narrow definition above.
    Attested,
}

/// Who is behind a connection, with enough provenance to scope a rule to a binary.
#[derive(Debug, Clone)]
pub struct Evidence {
    /// How trustworthy the rest of the fields are.
    pub assurance: Assurance,
    /// Absolute path of the connecting binary.
    pub binary_path: PathBuf,
    /// SHA-256 of the connecting binary, hex-encoded. `None` when unavailable;
    /// never an empty string.
    pub binary_sha256: Option<String>,
    /// Ancestor process binaries, nearest first.
    pub ancestors: Vec<PathBuf>,
    /// Absolute script/interpreter paths drawn from the process cmdlines.
    pub cmdline_paths: Vec<PathBuf>,
}

/// The answer to "who is behind this connection".
#[derive(Debug, Clone)]
pub enum Identity {
    /// Identity evidence for the connection's owning process.
    Evidence(Evidence),
    /// The backend cannot provide identity for this boundary.
    Unsupported,
}

/// An opaque, versioned per-connection token the backend resolves to a process.
///
/// The supervisor never interprets it. The in-pod backend keys it on the
/// workload-side TCP peer port; a cross-kernel backend defines its own token
/// shape under a new version rather than widening this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    version: u8,
    token: Vec<u8>,
}

impl Flow {
    /// The in-pod flow token: the workload-side TCP peer port.
    #[must_use]
    pub fn in_pod_peer_port(port: u16) -> Self {
        Self {
            version: 1,
            token: port.to_be_bytes().to_vec(),
        }
    }
    /// An opaque backend-defined token under `version`.
    #[must_use]
    pub fn opaque(version: u8, token: Vec<u8>) -> Self {
        Self { version, token }
    }
    /// The token version.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }
    /// The raw token bytes.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }
}

/// Identity resolver consumed by the proxy on the per-connection hot path. Fails
/// closed: a failure returns `Err`, never `Observed` evidence.
#[async_trait]
pub trait IdentitySource: Send + Sync {
    /// Resolve who is behind the connection referenced by `flow`.
    async fn resolve(&self, flow: Flow) -> Result<Identity, ResolveError>;
}

// ============================================================================
// Events
// ============================================================================

/// A boundary observability event drained by the orchestrator. Security events
/// must not be dropped silently under backpressure.
#[derive(Debug, Clone)]
pub enum BoundaryEvent {
    /// A connection was denied by policy.
    Denial {
        /// Destination host.
        host: String,
        /// Destination port.
        port: u16,
        /// Why it was denied.
        reason: String,
    },
    /// An allowed connection, for anonymous activity accounting.
    Activity {
        /// Destination host.
        host: String,
        /// Destination port.
        port: u16,
    },
    /// A proxy-bypass attempt was detected.
    Bypass {
        /// What was detected.
        detail: String,
    },
    /// The boundary terminated underneath the supervisor.
    BoundaryTerminated {
        /// Why it terminated.
        reason: String,
    },
}

/// A stream of [`BoundaryEvent`]s.
pub type EventStream = Pin<Box<dyn Stream<Item = BoundaryEvent> + Send>>;

/// Boundary event source. A single-consumer source returns an explicit error on
/// a second subscription rather than a silently empty stream.
pub trait EventSource: Send + Sync {
    /// Subscribe to the boundary's event stream.
    fn subscribe(&self) -> Result<EventStream, BackendError>;
}

#[cfg(test)]
mod tests;
