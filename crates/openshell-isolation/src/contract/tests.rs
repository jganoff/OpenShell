// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance harness for the runtime-selectable contract.
//!
//! Two materially different mock factories (`Primary`, `Secondary`) with
//! distinct concrete state structs (each generic over a marker, so each kind
//! monomorphizes to its own types) prove the registry holds heterogeneous
//! factories behind `dyn` with no enum over concrete state, and that one driver
//! runs both unchanged.

use std::marker::PhantomData;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use futures::StreamExt;

use super::*;

// ---------------------------------------------------------------------------
// Marker kinds: two materially different backends.
// ---------------------------------------------------------------------------

trait MockKind: Send + Sync + 'static {
    const BACKEND_ID: &'static str;
    fn assurance() -> Assurance;
}

struct Primary;
impl MockKind for Primary {
    const BACKEND_ID: &'static str = "mock-primary";
    fn assurance() -> Assurance {
        Assurance::Observed
    }
}

struct Secondary;
impl MockKind for Secondary {
    const BACKEND_ID: &'static str = "mock-secondary";
    fn assurance() -> Assurance {
        Assurance::Attested
    }
}

// ---------------------------------------------------------------------------
// Runtime interfaces (shared across kinds where behavior is identical).
// ---------------------------------------------------------------------------

struct MockProcess {
    status: BoundaryExitStatus,
    alive: AtomicBool,
    signals: Mutex<Vec<BoundarySignal>>,
}

impl MockProcess {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            status: BoundaryExitStatus::Exited(0),
            alive: AtomicBool::new(true),
            signals: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl BoundaryProcess for MockProcess {
    async fn wait(&self) -> Result<BoundaryExitStatus, BackendError> {
        // Stable across repeated calls.
        Ok(self.status)
    }
    async fn signal(&self, signal: BoundarySignal) -> Result<(), BackendError> {
        self.signals.lock().unwrap().push(signal);
        Ok(())
    }
    async fn terminate(&self) -> Result<(), BackendError> {
        self.alive.store(false, Ordering::SeqCst);
        Ok(())
    }
    fn diagnostic_pid(&self) -> Option<u32> {
        Some(4242)
    }
}

/// Boundary control retained from `attach`: idempotent shutdown, terminate wait.
struct MockControl {
    shut_down: AtomicBool,
}

impl MockControl {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            shut_down: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl BoundaryControl for MockControl {
    async fn wait_terminated(&self) -> Result<(), BackendError> {
        Ok(())
    }
    async fn shutdown(&self) -> Result<(), BackendError> {
        // Idempotent: a second call is a no-op success.
        self.shut_down.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// Mediation ingress: hands the proxy a connection plus its flow token.
struct MockIngress;

#[async_trait]
impl MediationIngress for MockIngress {
    async fn accept(&self) -> Result<MediatedConnection, BackendError> {
        let (near, _far) = tokio::io::duplex(64);
        Ok(MediatedConnection {
            stream: Box::new(near),
            flow: Flow::in_pod_peer_port(40000),
        })
    }
}

struct MockIdentity<K>(PhantomData<K>);

#[async_trait]
impl<K: MockKind> IdentitySource for MockIdentity<K> {
    async fn resolve(&self, _flow: Flow) -> Result<Identity, ResolveError> {
        Ok(Identity::Evidence(Evidence {
            assurance: K::assurance(),
            binary_path: PathBuf::from("/usr/bin/agent"),
            binary_sha256: Some("deadbeef".to_string()),
            ancestors: vec![],
            cmdline_paths: vec![],
        }))
    }
}

/// An identity source that fails resolution; it must surface `Err`, never
/// `Observed`.
struct FailingIdentity;

#[async_trait]
impl IdentitySource for FailingIdentity {
    async fn resolve(&self, _flow: Flow) -> Result<Identity, ResolveError> {
        Err(ResolveError::Failed("hash unavailable".to_string()))
    }
}

/// A single-consumer event source: the second subscription errors rather than
/// returning a silently empty stream.
struct MockEvents {
    taken: AtomicBool,
}

impl MockEvents {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            taken: AtomicBool::new(false),
        })
    }
}

impl EventSource for MockEvents {
    fn subscribe(&self) -> Result<EventStream, BackendError> {
        if self.taken.swap(true, Ordering::SeqCst) {
            return Err(BackendError::Bind(
                "event source is single-consumer".to_string(),
            ));
        }
        Ok(Box::pin(futures::stream::iter(vec![
            BoundaryEvent::Denial {
                host: "evil.test".to_string(),
                port: 443,
                reason: "no matching allow rule".to_string(),
            },
            BoundaryEvent::Activity {
                host: "api.test".to_string(),
                port: 443,
            },
            BoundaryEvent::BoundaryTerminated {
                reason: "agent exited".to_string(),
            },
        ])))
    }
}

struct MockExec;

#[async_trait]
impl BoundaryExec for MockExec {
    async fn exec(&self, _spec: ExecSpec) -> Result<ExecSession, BackendError> {
        let (_near, far) = tokio::io::duplex(64);
        let (out_r, _out_w) = tokio::io::duplex(64);
        let (err_r, _err_w) = tokio::io::duplex(64);
        Ok(ExecSession {
            process: MockProcess::new(),
            stdin: Some(Box::new(far)),
            stdout: Box::new(out_r),
            stderr: Some(Box::new(err_r)),
            terminal: None,
        })
    }
}

struct MockPortForward;

#[async_trait]
impl BoundaryPortForward for MockPortForward {
    async fn connect(&self, _target: LoopbackTarget) -> Result<BoundaryConn, BackendError> {
        let (near, far) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut far = far;
            let mut buf = [0u8; 4];
            if far.read_exact(&mut buf).await.is_ok() {
                let _ = far.write_all(&buf).await;
            }
        });
        Ok(Box::new(near))
    }
}

// ---------------------------------------------------------------------------
// Boxed lifecycle states (distinct concrete struct per kind).
// ---------------------------------------------------------------------------

struct MockAttached<K> {
    control: Arc<MockControl>,
    _k: PhantomData<K>,
}
struct MockClaimed<K> {
    control: Arc<MockControl>,
    _k: PhantomData<K>,
}
struct MockBound<K> {
    control: Arc<MockControl>,
    ingress: Arc<MockIngress>,
    identity: Arc<MockIdentity<K>>,
    events: Arc<MockEvents>,
}
struct MockReady<K> {
    control: Arc<MockControl>,
    _k: PhantomData<K>,
}
struct MockRunning<K> {
    process: Arc<MockProcess>,
    exec: Arc<MockExec>,
    port_forward: Arc<MockPortForward>,
    _control: Arc<MockControl>,
    _k: PhantomData<K>,
}

#[async_trait]
impl<K: MockKind> AttachedBoundary for MockAttached<K> {
    fn control(&self) -> Arc<dyn BoundaryControl> {
        self.control.clone()
    }
    async fn claim(
        self: Box<Self>,
        _claim: ClaimContext,
    ) -> Result<Box<dyn ClaimedBoundary>, BackendError> {
        Ok(Box::new(MockClaimed::<K> {
            control: self.control,
            _k: PhantomData,
        }))
    }
}

#[async_trait]
impl<K: MockKind> ClaimedBoundary for MockClaimed<K> {
    async fn bind(self: Box<Self>) -> Result<Box<dyn BoundBoundary>, BackendError> {
        Ok(Box::new(MockBound::<K> {
            control: self.control,
            ingress: Arc::new(MockIngress),
            identity: Arc::new(MockIdentity(PhantomData)),
            events: MockEvents::new(),
        }))
    }
}

#[async_trait]
impl<K: MockKind> BoundBoundary for MockBound<K> {
    fn mediation_ingress(&self) -> Arc<dyn MediationIngress> {
        self.ingress.clone()
    }
    fn identity_source(&self) -> Arc<dyn IdentitySource> {
        self.identity.clone()
    }
    fn events(&self) -> Arc<dyn EventSource> {
        self.events.clone()
    }
    async fn confirm(self: Box<Self>) -> Result<Box<dyn ReadyBoundary>, BackendError> {
        Ok(Box::new(MockReady::<K> {
            control: self.control,
            _k: PhantomData,
        }))
    }
}

#[async_trait]
impl<K: MockKind> ReadyBoundary for MockReady<K> {
    async fn start_agent(self: Box<Self>) -> Result<Box<dyn RunningBoundary>, BackendError> {
        Ok(Box::new(MockRunning::<K> {
            process: MockProcess::new(),
            exec: Arc::new(MockExec),
            port_forward: Arc::new(MockPortForward),
            _control: self.control,
            _k: PhantomData,
        }))
    }
}

impl<K: MockKind> RunningBoundary for MockRunning<K> {
    fn agent(&self) -> Arc<dyn BoundaryProcess> {
        self.process.clone()
    }
    fn exec(&self) -> Arc<dyn BoundaryExec> {
        self.exec.clone()
    }
    fn port_forward(&self) -> Arc<dyn BoundaryPortForward> {
        self.port_forward.clone()
    }
}

struct MockFactory<K>(PhantomData<K>);

#[async_trait]
impl<K: MockKind> IsolationBackendFactory for MockFactory<K> {
    fn backend_id(&self) -> &'static str {
        K::BACKEND_ID
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            contract_version: CONTRACT_VERSION,
            placement: BackendPlacement::InPod,
            confirmation: vec![ConfirmationKind::Direct],
            maximum_identity: K::assurance(),
        }
    }
    async fn attach(
        &self,
        descriptor: VerifiedBoundaryDescriptor,
    ) -> Result<Box<dyn AttachedBoundary>, BackendError> {
        assert_eq!(descriptor.backend_id(), K::BACKEND_ID);
        Ok(Box::new(MockAttached::<K> {
            control: MockControl::new(),
            _k: PhantomData,
        }))
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

fn registry() -> BackendRegistry {
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(MockFactory::<Primary>(PhantomData)))
        .expect("register primary");
    reg.register(Arc::new(MockFactory::<Secondary>(PhantomData)))
        .expect("register secondary");
    reg
}

fn descriptor(backend_id: &str) -> BoundaryDescriptor {
    BoundaryDescriptor {
        version: CONTRACT_VERSION,
        backend_id: backend_id.to_string(),
        payload: vec![],
    }
}

fn requirements(backend_id: &str) -> AdmittedBoundaryRequirements {
    AdmittedBoundaryRequirements {
        backend_id: backend_id.to_string(),
        contract_version: CONTRACT_VERSION,
        policy_digest: vec![],
        required_confirmation: ConfirmationKind::Direct,
        minimum_identity: Assurance::None,
    }
}

fn claim_ctx() -> ClaimContext {
    ClaimContext {
        sandbox_id: "sb-1".to_string(),
        policy: SandboxPolicy {
            version: 1,
            filesystem: openshell_core::policy::FilesystemPolicy::default(),
            network: openshell_core::policy::NetworkPolicy::default(),
            landlock: openshell_core::policy::LandlockPolicy::default(),
            process: openshell_core::policy::ProcessPolicy::default(),
        },
        agent: AgentSpec {
            program: "/bin/true".to_string(),
            args: vec![],
            workdir: None,
            timeout_secs: 0,
            interactive: false,
        },
        resource_binding: ResourceBinding::new(1, b"cgroup:/sandbox/sb-1".to_vec()),
    }
}

/// The backend-independent driver. Identical for every backend: this is the
/// proof that adding a backend needs no supervisor lifecycle change.
async fn drive(
    reg: &BackendRegistry,
    descriptor: BoundaryDescriptor,
    admitted: &str,
) -> Result<Box<dyn RunningBoundary>, BackendError> {
    let (factory, verified) = reg.resolve(descriptor, &requirements(admitted))?;
    let attached = factory.attach(verified).await?;
    // Boundary control is retained from attach across consuming transitions.
    let _control = attached.control();
    let claimed = attached.claim(claim_ctx()).await?;
    let bound = claimed.bind().await?;
    // Mediation, identity, and events are available at Bound; retain them as
    // owned Arcs across the confirm/start transitions.
    let _ingress = bound.mediation_ingress();
    let _early_identity = bound.identity_source();
    let _early_events = bound.events();
    let ready = bound.confirm().await?;
    ready.start_agent().await
}

// ---------------------------------------------------------------------------
// Registry and descriptor.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_selects_correct_backend() {
    let reg = registry();
    let (f, _v) = reg
        .resolve(
            descriptor("mock-secondary"),
            &requirements("mock-secondary"),
        )
        .expect("resolve");
    assert_eq!(f.backend_id(), "mock-secondary");
}

#[test]
fn registry_rejects_duplicate_registration() {
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(MockFactory::<Primary>(PhantomData)))
        .expect("first");
    let err = reg
        .register(Arc::new(MockFactory::<Primary>(PhantomData)))
        .expect_err("duplicate must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
}

#[test]
fn registry_rejects_unknown_backend() {
    let reg = registry();
    let err = reg
        .resolve(descriptor("nope"), &requirements("nope"))
        .map(|_| ())
        .expect_err("unknown must fail");
    assert!(matches!(err, BackendError::NotRegistered(_)));
}

#[test]
fn registry_rejects_descriptor_admission_mismatch_without_fallback() {
    let reg = registry();
    // Descriptor names primary, admission says secondary: must fail, and must
    // not silently fall back to either backend.
    let err = reg
        .resolve(descriptor("mock-primary"), &requirements("mock-secondary"))
        .map(|_| ())
        .expect_err("mismatch must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
}

#[test]
fn registry_rejects_unsupported_version() {
    let reg = registry();
    let mut d = descriptor("mock-primary");
    d.version = CONTRACT_VERSION + 1;
    let err = reg
        .resolve(d, &requirements("mock-primary"))
        .map(|_| ())
        .expect_err("bad version must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
}

#[test]
fn registry_rejects_capability_shortfall() {
    let reg = registry();
    // Admission requires Attested identity; mock-primary's maximum is Observed.
    let mut req = requirements("mock-primary");
    req.minimum_identity = Assurance::Attested;
    let err = reg
        .resolve(descriptor("mock-primary"), &req)
        .map(|_| ())
        .expect_err("capability shortfall must fail");
    assert!(matches!(err, BackendError::Descriptor(_)));
    // Secondary (maximum Attested) satisfies the same requirement.
    assert!(
        reg.resolve(descriptor("mock-secondary"), &{
            let mut r = requirements("mock-secondary");
            r.minimum_identity = Assurance::Attested;
            r
        })
        .is_ok()
    );
}

// ---------------------------------------------------------------------------
// Lifecycle: one driver, two heterogeneous backends, no consumer change.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_driver_runs_both_backends() {
    let reg = registry();
    // The exact same driver code runs a backend with distinct concrete state
    // structs; the registry holds them behind `dyn`, no enum.
    let primary = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("primary lifecycle");
    let secondary = drive(&reg, descriptor("mock-secondary"), "mock-secondary")
        .await
        .expect("secondary lifecycle");

    // Both expose a usable agent process handle past start_agent.
    assert_eq!(
        primary.agent().wait().await.expect("wait"),
        BoundaryExitStatus::Exited(0)
    );
    assert_eq!(
        secondary.agent().wait().await.expect("wait"),
        BoundaryExitStatus::Exited(0)
    );
}

#[tokio::test]
async fn runtime_interfaces_survive_lifecycle_consumption() {
    let reg = registry();
    let (factory, verified) = reg
        .resolve(descriptor("mock-primary"), &requirements("mock-primary"))
        .expect("resolve");
    let attached = factory.attach(verified).await.expect("attach");
    let control = attached.control();
    let claimed = attached.claim(claim_ctx()).await.expect("claim");
    let bound = claimed.bind().await.expect("bind");

    // Grab the identity source at Bound, then consume the bound state with
    // confirm. The retained Arcs must remain usable afterward.
    let identity = bound.identity_source();
    let ready = bound.confirm().await.expect("confirm");
    let _running = ready.start_agent().await.expect("start");

    let resolved = identity
        .resolve(Flow::in_pod_peer_port(40000))
        .await
        .expect("resolve after consumption");
    match resolved {
        Identity::Evidence(e) => assert_eq!(e.assurance, Assurance::Observed),
        Identity::Unsupported => panic!("expected evidence"),
    }
    // Control retained from attach is still usable; shutdown is idempotent.
    control.shutdown().await.expect("shutdown");
    control.shutdown().await.expect("idempotent shutdown");
}

// ---------------------------------------------------------------------------
// Process and I/O.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_process_survives_and_wait_is_stable() {
    let reg = registry();
    let running = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("lifecycle");
    let agent = running.agent();
    // Survives start_agent returning; wait is stable across repeated calls.
    assert_eq!(
        agent.wait().await.expect("wait 1"),
        BoundaryExitStatus::Exited(0)
    );
    assert_eq!(
        agent.wait().await.expect("wait 2"),
        BoundaryExitStatus::Exited(0)
    );
    agent.signal(BoundarySignal::Term).await.expect("signal");
}

#[tokio::test]
async fn exec_session_owns_its_process_and_streams() {
    let reg = registry();
    let running = drive(&reg, descriptor("mock-primary"), "mock-primary")
        .await
        .expect("lifecycle");
    let session = running
        .exec()
        .exec(ExecSpec {
            program: "/bin/sh".to_string(),
            args: vec!["-c".to_string(), "true".to_string()],
            env: vec![],
            workdir: None,
            pty: false,
        })
        .await
        .expect("exec");
    // The exec'd process survives `exec` returning, and stdout/stderr are distinct.
    assert!(session.stderr.is_some());
    assert!(session.stdin.is_some());
    assert_eq!(
        session.process.wait().await.expect("exec wait"),
        BoundaryExitStatus::Exited(0)
    );
}

#[tokio::test]
async fn mediation_ingress_yields_connection_and_flow() {
    let reg = registry();
    let (factory, verified) = reg
        .resolve(descriptor("mock-primary"), &requirements("mock-primary"))
        .expect("resolve");
    let attached = factory.attach(verified).await.expect("attach");
    let claimed = attached.claim(claim_ctx()).await.expect("claim");
    let bound = claimed.bind().await.expect("bind");
    let conn = bound.mediation_ingress().accept().await.expect("accept");
    assert_eq!(conn.flow, Flow::in_pod_peer_port(40000));
}

#[tokio::test]
async fn port_forward_rejects_non_loopback() {
    let target = LoopbackTarget::new("8.8.8.8".parse().unwrap(), 53);
    assert!(target.is_err());
    let loopback = LoopbackTarget::new("127.0.0.1".parse().unwrap(), 8080).expect("loopback ok");
    assert_eq!(loopback.port(), 8080);
}

// ---------------------------------------------------------------------------
// Identity and events.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_failure_fails_closed() {
    let id = FailingIdentity;
    let r = id.resolve(Flow::in_pod_peer_port(1234)).await;
    assert!(r.is_err());
}

#[tokio::test]
async fn attested_outranks_observed_in_policy_order() {
    // The same consumer logic accepts local Observed and mock Attested evidence.
    async fn admits_binary_rule(id: &dyn IdentitySource) -> bool {
        match id.resolve(Flow::in_pod_peer_port(1)).await {
            Ok(Identity::Evidence(e)) => e.assurance >= Assurance::Observed,
            _ => false,
        }
    }
    assert!(admits_binary_rule(&MockIdentity::<Primary>(PhantomData)).await);
    assert!(admits_binary_rule(&MockIdentity::<Secondary>(PhantomData)).await);
    assert!(Assurance::Attested > Assurance::Observed);
}

#[test]
fn second_event_subscription_fails_explicitly() {
    let events = MockEvents::new();
    assert!(events.subscribe().is_ok());
    assert!(events.subscribe().is_err());
}

#[tokio::test]
async fn events_carry_denials_and_termination() {
    let events = MockEvents::new();
    let stream = events.subscribe().expect("subscribe");
    let collected: Vec<BoundaryEvent> = stream.collect().await;
    let denials = collected
        .iter()
        .filter(|e| matches!(e, BoundaryEvent::Denial { .. }))
        .count();
    let terminated = collected
        .iter()
        .filter(|e| matches!(e, BoundaryEvent::BoundaryTerminated { .. }))
        .count();
    assert_eq!(denials, 1);
    assert_eq!(terminated, 1);
}

// ---------------------------------------------------------------------------
// Errors.
// ---------------------------------------------------------------------------

#[test]
fn error_kinds_map_and_only_unavailable_retries() {
    assert_eq!(
        BackendError::Descriptor("x".into()).kind(),
        BackendErrorKind::Invalid
    );
    assert_eq!(
        BackendError::Attach("x".into()).kind(),
        BackendErrorKind::Denied
    );
    assert_eq!(
        BackendError::Unavailable("x".into()).kind(),
        BackendErrorKind::Unavailable
    );
    assert_eq!(
        BackendError::Confirm("x".into()).kind(),
        BackendErrorKind::Failed
    );
    assert_eq!(
        BackendError::Terminated("x".into()).kind(),
        BackendErrorKind::Terminated
    );
    assert!(BackendError::Unavailable("x".into()).is_retryable());
    assert!(!BackendError::Confirm("x".into()).is_retryable());
}
