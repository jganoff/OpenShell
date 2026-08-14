// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Docker Sandboxes (sandboxd) compute driver.
//!
//! Delegates sandbox lifecycle to a running sandboxd instance via its HTTP API,
//! carried over a Unix domain socket on Unix and a named pipe on Windows.

#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::Stream;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use openshell_core::Result as CoreResult;
use openshell_core::proto::compute::v1::{
    CreateSandboxRequest, CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse,
    DriverCondition, DriverSandbox, DriverSandboxSpec, DriverSandboxStatus, DriverSandboxTemplate,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetGatewayListenerRequirementsRequest,
    GetGatewayListenerRequirementsResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest, StartSandboxResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesRequest, WatchSandboxesSandboxEvent, compute_driver_server::ComputeDriver,
    watch_sandboxes_event,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

mod base_image;
mod local_image;
mod supervisor;

const WATCH_BUFFER: usize = 128;
/// How long to keep retrying a named pipe connect that reports every instance
/// busy before giving up.
#[cfg(windows)]
const PIPE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Delay between `ERROR_PIPE_BUSY` connect retries.
#[cfg(windows)]
const PIPE_BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(50);
const WATCH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const WATCH_POLL_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// The `OpenShell` agent kit, in sandboxd's canonical wire form. Shipped inline
/// on every create (`kit_artifacts`) so sandboxd needs no pre-installed
/// "openshell" agent — the driver is self-contained and "just works" against a
/// stock sbx. Generated from `kits/openshell/spec.yaml` by the real kit
/// tooling; see `kits/openshell/README.md` to edit the spec and regenerate.
const OPENSHELL_KIT_ARTIFACT: &str = include_str!("../kits/openshell/artifact.json");

/// Agent name the driver requests on create. Must equal the shipped kit's
/// `manifest.name` — sandboxd rejects a create whose `agent` differs from the
/// name of the `kind: sandbox` artifact in `kit_artifacts`.
const OPENSHELL_AGENT: &str = "openshell";

/// Container env var the shipped kit's `setup.startup` command reads to
/// `exec` the supervisor binary — see `supervisor` for why the binary is
/// injected via `additional_workspaces` at a driver-resolved host path
/// rather than baked into any image. Driver-internal plumbing between this
/// crate and its own kit spec; not a documented `openshell_core::sandbox_env`
/// contract the supervisor itself reads.
const SUPERVISOR_BIN_ENV: &str = "OPENSHELL_DOCKER_SANDBOXES_SUPERVISOR_BIN";

// ── sandboxd HTTP API types ────────────────────────────────────────────────

/// A `/sandbox` list entry. sandboxd's `OpenAPI` `SandboxInfo` marks only `id`,
/// `name`, and `status` as required; every other field is `omitempty`, so
/// nothing else may be declared mandatory here.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct SandboxInfo {
    name: String,
    status: String,
    /// Omitted from the wire when the sandbox has no container or its creation
    /// timestamp is zero — a stopped or partially-created sandbox reports no
    /// `created_at` at all. Deserializing this as required made one such entry
    /// fail the whole list decode and stall the poll loop for every sandbox.
    #[serde(default)]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct DaemonHealth {
    version: String,
}

#[derive(Debug, Serialize)]
struct SandboxCreateReq<'a> {
    agent: &'a str,
    workspace: &'a str,
    name: &'a str,
    template: &'a str,
    /// Named governance profile to assign, resolved by `resolve_profile`.
    /// sandboxd canonicalizes this against the active (remote/org-managed)
    /// governance policy set and rejects unknown names at create time.
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
    /// Whole vCPU count, from `DriverResourceRequirements.cpu_limit` — see
    /// `sandboxd_resource_fields`. Confirmed live to match `sbx create
    /// --cpus`'s own wire field.
    #[serde(skip_serializing_if = "Option::is_none")]
    cpus: Option<i64>,
    /// Binary-unit memory string (e.g. `"512m"`), from
    /// `DriverResourceRequirements.memory_limit` — see
    /// `sandboxd_resource_fields`. Confirmed live to match `sbx create
    /// --memory`'s own wire field.
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<&'a str>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    environment: HashMap<String, String>,
    /// Injects the supervisor binary into the sandbox. sandboxd mounts each
    /// entry's `dir` into the container at that *same* path (no separate
    /// container-target field — see `supervisor`), before the entrypoint
    /// execs, which is what makes injection possible at all here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    additional_workspaces: Vec<WorkspaceMountReq<'a>>,
    /// Composed kit artifacts shipped inline. Carries the `OpenShell` agent kit
    /// (a `kind: sandbox` artifact) so sandboxd resolves `agent: "openshell"`
    /// from the request itself rather than a pre-installed agent.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    kit_artifacts: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct WorkspaceMountReq<'a> {
    dir: &'a str,
    read_only: bool,
}

// ── Driver configuration ───────────────────────────────────────────────────

/// Configuration for the docker-sandboxes compute driver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DockerSandboxesComputeConfig {
    /// Path to the sandboxd socket: a Unix socket path on Unix, or a named
    /// pipe path on Windows.
    ///
    /// Empty (the default) means discover it at startup — see
    /// [`resolve_socket_path`]. Set this only to pin a specific daemon.
    pub socket_path: String,

    /// Base directory under which each sandbox gets its own workspace
    /// subdirectory (created on demand). Defaults to `/tmp` on Unix and the
    /// user temp directory on Windows — sandboxes never share this
    /// directory itself, only its role as a parent.
    pub default_workspace: String,

    /// Retained for config compatibility only. The driver now ships its own
    /// `openshell` agent kit inline on every create (see [`OPENSHELL_AGENT`]),
    /// so this field is ignored — sandboxd no longer needs a pre-installed
    /// agent. Defaults to `openshell`.
    pub default_agent: String,

    /// `OpenShell` gateway gRPC endpoint injected into sandbox containers as
    /// `OPENSHELL_ENDPOINT`. Auto-derived from the gateway bind address if
    /// empty.
    pub openshell_endpoint: String,

    /// Sandbox image to boot, overriding the driver's own default.
    ///
    /// `None` (the default) auto-builds and saves a minimal image into
    /// `sandboxd`'s own image store at startup — [`base_image::BASE_IMAGE`]
    /// (a stock public image) plus the one package it's missing that the
    /// supervisor needs, added via `sandboxd`'s own create/exec/save
    /// endpoints (see `base_image` and the crate README, "How it works").
    /// No local Docker Engine, no image-build tooling.
    ///
    /// The shipped kit's `setup.startup` command launches whatever host
    /// path [`SUPERVISOR_BIN_ENV`] names as a detached process, so a custom
    /// override here needs no particular `ENTRYPOINT` of its own — it just
    /// needs to tolerate sandboxd's forced startup command long enough to
    /// stay running.
    pub template_image: Option<String>,

    /// Explicit host path to a Linux ELF `openshell-sandbox` binary,
    /// injected into every sandbox via `additional_workspaces`. Takes
    /// precedence over `supervisor_release_tag`.
    pub supervisor_bin: Option<PathBuf>,

    /// `NVIDIA/OpenShell` GitHub Release tag to download the Linux
    /// `openshell-sandbox` binary from (as a checksum-verified `.tar.gz`
    /// release asset). Ignored when `supervisor_bin` is set. Defaults to a
    /// `v`-prefixed tag derived the same way
    /// [`openshell_core::config::default_supervisor_image`] pins its own
    /// image tag when neither is set.
    pub supervisor_release_tag: Option<String>,

    /// In-container path the supervisor binds its SSH relay socket to.
    ///
    /// Required for the supervisor to open its persistent `ConnectSupervisor`
    /// session back to the gateway (`run_process` in
    /// `openshell-supervisor-process` only spawns that session when a
    /// gateway endpoint, sandbox id, *and* this path are all present) —
    /// without it the sandbox boots and loads its policy but never leaves
    /// the `Provisioning` phase.
    pub ssh_socket_path: String,

    /// Named governance profile assigned to every sandbox by default,
    /// unless a create request's `template.driver_config.profile`
    /// overrides it (see [`resolve_profile`]). Profiles are defined by a
    /// remote/organization-managed governance policy — `sandboxd`
    /// canonicalizes the name against the active policy set and rejects
    /// unknown names at create time. Required by some deployments to apply
    /// centrally-managed mount/network governance on top of whatever
    /// `OpenShell`'s own in-container supervisor policy enforces.
    pub profile: Option<String>,
}

impl Default for DockerSandboxesComputeConfig {
    fn default() -> Self {
        Self {
            socket_path: String::new(),
            default_workspace: default_workspace(),
            default_agent: "openshell".to_string(),
            openshell_endpoint: String::new(),
            template_image: None,
            supervisor_bin: None,
            supervisor_release_tag: None,
            ssh_socket_path: openshell_core::container_paths::SSH_SOCKET_PATH.to_string(),
            profile: None,
        }
    }
}

/// Environment variable sandboxd itself honors to override its socket path.
/// Reading it here keeps the driver consistent with every other sandboxd
/// client, including test rigs.
const SANDBOXD_API_ENV: &str = "DOCKER_SANDBOXES_API";

/// Resolve the sandboxd socket to talk to, in sandboxd's own order of
/// precedence:
///
/// 1. `configured` — an explicit `socket_path` in the driver's TOML table.
/// 2. `DOCKER_SANDBOXES_API` — sandboxd's own override.
/// 3. The first candidate path that exists on disk (see
///    [`socket_path_candidates`]).
///
/// sandboxd's real default socket location isn't independently documented,
/// so the candidate list below is a best effort based on where it's actually
/// found on disk, not a reimplementation of sandboxd's own layout logic.
/// Probing for what actually exists keeps a stale guess harmless: an
/// unmatched candidate is skipped, and operators can always pin
/// `socket_path` explicitly.
///
/// Returns the last candidate when none exist, so connection errors name a
/// concrete path instead of an empty string.
fn resolve_socket_path(configured: &str) -> String {
    resolve_socket_path_from(
        configured,
        std::env::var(SANDBOXD_API_ENV).ok().as_deref(),
        &socket_path_candidates(),
        socket_exists,
    )
}

/// Precedence core of [`resolve_socket_path`], with the environment and the
/// filesystem passed in so it can be exercised without either.
fn resolve_socket_path_from(
    configured: &str,
    env_override: Option<&str>,
    candidates: &[String],
    exists: impl Fn(&str) -> bool,
) -> String {
    if !configured.trim().is_empty() {
        return configured.to_string();
    }
    if let Some(from_env) = env_override.filter(|value| !value.trim().is_empty()) {
        info!(socket = %from_env, "Using sandboxd socket from {SANDBOXD_API_ENV}");
        return from_env.to_string();
    }

    for candidate in candidates {
        if exists(candidate) {
            info!(socket = %candidate, "Discovered sandboxd socket");
            return candidate.clone();
        }
    }

    let fallback = candidates
        .last()
        .cloned()
        .unwrap_or_else(|| "sandboxd.sock".to_string());
    warn!(
        tried = ?candidates,
        "No sandboxd socket found; set [openshell.drivers.docker-sandboxes] socket_path \
         or {SANDBOXD_API_ENV}"
    );
    fallback
}

/// Named pipes are not filesystem entries that `Path::exists` reports
/// reliably, so on Windows leave the check to the connect itself.
#[cfg(windows)]
fn socket_exists(_candidate: &str) -> bool {
    false
}

#[cfg(unix)]
fn socket_exists(candidate: &str) -> bool {
    Path::new(candidate).exists()
}

/// Well-known sandboxd socket locations, most current first.
#[cfg(unix)]
fn socket_path_candidates() -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let mut candidates = Vec::new();

    // sandboxd's state directory. Confirmed on macOS; the Linux entry
    // follows the XDG data-dir convention.
    #[cfg(target_os = "macos")]
    candidates.push(format!(
        "{home}/Library/Application Support/com.docker.sandboxes/sandboxes/sandboxd/sandboxd.sock"
    ));
    #[cfg(not(target_os = "macos"))]
    {
        let data_home = std::env::var("XDG_DATA_HOME")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("{home}/.local/share"));
        candidates.push(format!(
            "{data_home}/com.docker.sandboxes/sandboxes/sandboxd/sandboxd.sock"
        ));
    }

    // Short-symlink location sandboxd falls back to when the state directory
    // would exceed the platform's Unix socket path limit.
    candidates.push(format!("{home}/.sbx/run/sandboxd.sock"));
    candidates
}

/// Default sandboxd named pipe, mirroring sandboxd's own default. A custom
/// app name shifts this to `docker_kaname_<appName>_sandboxd`, which needs
/// an explicit `socket_path`.
#[cfg(windows)]
fn socket_path_candidates() -> Vec<String> {
    vec![r"\\.\pipe\docker_kaname_sandboxd".to_string()]
}

/// Default host workspace directory handed to sandboxd on create.
#[cfg(unix)]
fn default_workspace() -> String {
    "/tmp".to_string()
}

/// Default host workspace directory handed to sandboxd on create.
#[cfg(windows)]
fn default_workspace() -> String {
    std::env::temp_dir().to_string_lossy().into_owned()
}

// ── Driver internals ───────────────────────────────────────────────────────

struct DriverConfig {
    socket_path: String,
    default_workspace: String,
    openshell_endpoint: String,
    /// Effective template image for every create — either the explicit
    /// `DockerSandboxesComputeConfig::template_image` override, or the
    /// driver-built default image tag resolved once at startup (see
    /// `base_image`). Always populated by the time `new` returns.
    template_image: String,
    ssh_socket_path: String,
    log_level: String,
    daemon_version: String,
    /// Driver-wide default governance profile. See
    /// [`DockerSandboxesComputeConfig::profile`].
    profile: Option<String>,
    /// Host path the supervisor binary was resolved to at startup; injected
    /// into every sandbox via `additional_workspaces`.
    supervisor_bin_path: PathBuf,
}

impl std::fmt::Debug for DriverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriverConfig")
            .field("socket_path", &self.socket_path)
            .field("default_workspace", &self.default_workspace)
            .field("openshell_endpoint", &self.openshell_endpoint)
            .field("template_image", &self.template_image)
            .field("ssh_socket_path", &self.ssh_socket_path)
            .field("profile", &self.profile)
            .field("log_level", &self.log_level)
            .field("daemon_version", &self.daemon_version)
            .field("supervisor_bin_path", &self.supervisor_bin_path)
            .finish_non_exhaustive()
    }
}

type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, Status>> + Send + 'static>>;

/// `OpenShell` compute driver that manages sandboxes via sandboxd's HTTP API.
#[derive(Clone)]
pub struct DockerSandboxesComputeDriver {
    config: Arc<DriverConfig>,
    events: broadcast::Sender<WatchSandboxesEvent>,
}

impl DockerSandboxesComputeDriver {
    /// Connect to sandboxd at `config.socket_path` and return a driver
    /// ready to receive `ComputeDriver` gRPC calls.
    ///
    /// `openshell_endpoint` and `log_level` come from the standalone driver
    /// process's own CLI/env, since this driver runs out-of-process from the
    /// gateway and has no `openshell_core::Config` of its own to read them
    /// from. `docker_sandboxes_config.openshell_endpoint`, when set, still takes
    /// precedence — it's a per-driver TOML override.
    pub async fn new(
        openshell_endpoint: &str,
        log_level: &str,
        docker_sandboxes_config: &DockerSandboxesComputeConfig,
    ) -> CoreResult<Self> {
        let openshell_endpoint = if docker_sandboxes_config.openshell_endpoint.trim().is_empty() {
            openshell_endpoint.to_string()
        } else {
            docker_sandboxes_config.openshell_endpoint.clone()
        };

        let config = Arc::new(DriverConfig {
            socket_path: resolve_socket_path(&docker_sandboxes_config.socket_path),
            default_workspace: docker_sandboxes_config.default_workspace.clone(),
            openshell_endpoint,
            template_image: String::new(), // filled in below
            ssh_socket_path: docker_sandboxes_config.ssh_socket_path.clone(),
            profile: docker_sandboxes_config.profile.clone(),
            log_level: log_level.to_string(),
            daemon_version: String::new(),       // filled in below
            supervisor_bin_path: PathBuf::new(), // filled in below
        });

        let driver = Self {
            config,
            events: broadcast::channel(WATCH_BUFFER).0,
        };

        let daemon_version = driver.probe_daemon_version().await;
        // Clear out any build sandboxes a previous, killed/crashed driver
        // process left running before creating any new ones — see
        // `base_image::reap_orphaned_build_sandboxes`.
        driver.reap_orphaned_build_sandboxes().await;
        // Resolved once at startup, independent of any per-sandbox base
        // image — the same binary is injected into every sandbox this
        // driver creates. No sandboxd/Docker involvement at all; see
        // `supervisor`. Fails `new` outright rather than deferring the
        // failure to the first `create_sandbox` call.
        let supervisor_bin_path =
            supervisor::resolve_supervisor_bin_path(docker_sandboxes_config).await?;
        let template_image = match &docker_sandboxes_config.template_image {
            Some(explicit) => explicit.clone(),
            // No sandboxd/Docker involvement beyond sandboxd's own public
            // create/exec/save/delete endpoints; see `base_image`. Fails
            // `new` outright rather than deferring the failure to the
            // first `create_sandbox` call, matching `supervisor_bin_path`
            // above.
            None => driver.ensure_base_image_loaded().await?,
        };
        // Patch the config with the discovered version and resolved
        // template image.
        // SAFETY: We just created the Arc and hold the only reference; the
        // poll loop is spawned below so it does not yet exist.
        let config = Arc::new(DriverConfig {
            daemon_version,
            template_image,
            supervisor_bin_path,
            socket_path: driver.config.socket_path.clone(),
            default_workspace: driver.config.default_workspace.clone(),
            openshell_endpoint: driver.config.openshell_endpoint.clone(),
            ssh_socket_path: driver.config.ssh_socket_path.clone(),
            profile: driver.config.profile.clone(),
            log_level: driver.config.log_level.clone(),
        });

        let driver = Self {
            config,
            events: driver.events,
        };

        let poll_driver = driver.clone();
        tokio::spawn(async move { poll_driver.poll_loop().await });

        Ok(driver)
    }

    // ── Raw HTTP over the sandboxd socket ──────────────────────────────────

    /// Connect to the sandboxd Unix socket at `config.socket_path`.
    #[cfg(unix)]
    async fn connect_daemon(&self) -> Result<TokioIo<tokio::net::UnixStream>, Status> {
        let stream = tokio::net::UnixStream::connect(&self.config.socket_path)
            .await
            .map_err(|e| {
                Status::unavailable(format!(
                    "sandboxd socket connect {}: {e}",
                    self.config.socket_path
                ))
            })?;
        Ok(TokioIo::new(stream))
    }

    /// Connect to the sandboxd named pipe at `config.socket_path`.
    ///
    /// A named pipe instance serves one client at a time, so a connect can
    /// legitimately fail with `ERROR_PIPE_BUSY` while the daemon is between
    /// instances. Retry briefly rather than surfacing a spurious failure.
    #[cfg(windows)]
    async fn connect_daemon(
        &self,
    ) -> Result<TokioIo<tokio::net::windows::named_pipe::NamedPipeClient>, Status> {
        use tokio::net::windows::named_pipe::ClientOptions;

        /// `ERROR_PIPE_BUSY` — all pipe instances are currently busy.
        const ERROR_PIPE_BUSY: i32 = 231;

        let deadline = tokio::time::Instant::now() + PIPE_CONNECT_TIMEOUT;
        loop {
            match ClientOptions::new().open(&self.config.socket_path) {
                Ok(client) => return Ok(TokioIo::new(client)),
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && tokio::time::Instant::now() < deadline => {}
                Err(e) => {
                    return Err(Status::unavailable(format!(
                        "sandboxd named pipe connect {}: {e}",
                        self.config.socket_path
                    )));
                }
            }
            tokio::time::sleep(PIPE_BUSY_RETRY_INTERVAL).await;
        }
    }

    /// Perform a single JSON HTTP request over the sandboxd socket.
    /// Returns `(status_code, body_bytes)`.
    async fn daemon_request(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<(u16, Bytes), Status> {
        self.daemon_request_with_content_type(method, path, body, "application/json")
            .await
    }

    /// Like [`Self::daemon_request`], but with an explicit content type —
    /// for a request whose body isn't JSON (loading a `docker save` tar
    /// into sandboxd's own image store; see `local_image`).
    async fn daemon_request_with_content_type(
        &self,
        method: http::Method,
        path: &str,
        body: Option<Bytes>,
        content_type: &str,
    ) -> Result<(u16, Bytes), Status> {
        let io = self.connect_daemon().await?;

        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| Status::unavailable(format!("sandboxd HTTP handshake failed: {e}")))?;

        // Drive the connection in the background.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "sandboxd connection error");
            }
        });

        let body_bytes = body.unwrap_or_default();
        let content_length = body_bytes.len();

        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .header(http::header::HOST, "localhost");

        if content_length > 0 {
            builder = builder
                .header(http::header::CONTENT_TYPE, content_type)
                .header(http::header::CONTENT_LENGTH, content_length);
        }

        let request = builder
            .body(Full::new(body_bytes))
            .map_err(|e| Status::internal(format!("failed to build HTTP request: {e}")))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| Status::unavailable(format!("sandboxd request failed: {e}")))?;

        let status = response.status().as_u16();
        let resp_bytes = response
            .into_body()
            .collect()
            .await
            .map(http_body_util::Collected::to_bytes)
            .unwrap_or_default();

        Ok((status, resp_bytes))
    }

    /// Load a `docker save`-format tar into sandboxd's own image store —
    /// the same endpoint `sbx template load` uses. `image` is the tag the
    /// caller expects to resolve afterward; a 200 from the load endpoint
    /// doesn't guarantee the tar actually decoded to that tag (Docker's own
    /// load API can report a failure inside an otherwise-200 body), so this
    /// confirms via the same inspect endpoint `ensure_base_image_loaded`
    /// uses.
    async fn load_image_tar(&self, image: &str, tar: Bytes) -> Result<(), Status> {
        let (status, body) = self
            .daemon_request_with_content_type(
                http::Method::POST,
                "/docker/images/load",
                Some(tar),
                "application/octet-stream",
            )
            .await?;
        if status != 200 {
            return Err(Status::internal(format!(
                "sandboxd image load returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }

        let (inspect_status, _) = self
            .daemon_request(
                http::Method::GET,
                &format!("/docker/images/inspect?name={image}"),
                None,
            )
            .await?;
        if inspect_status == 200 {
            Ok(())
        } else {
            Err(Status::internal(format!(
                "sandboxd image load returned HTTP 200 but '{image}' still isn't in its image store"
            )))
        }
    }

    /// Remove an image from sandboxd's own image store — used to clean up
    /// a `local_image` fallback load when the retried create it was for
    /// still failed, so a failed attempt doesn't leave a large orphaned
    /// image behind. Best-effort: a failure here only means sandboxd's
    /// store has one more image than it should, not a functional problem,
    /// so it's logged rather than propagated.
    async fn remove_loaded_image(&self, image: &str) {
        let result = self
            .daemon_request(
                http::Method::DELETE,
                &format!("/docker/images/remove?name={image}"),
                None,
            )
            .await;
        match result {
            Ok((200, _)) => {}
            Ok((status, body)) => warn!(
                image_ref = image,
                status,
                body = %String::from_utf8_lossy(&body),
                "failed to remove a local_image fallback load after its retried create failed"
            ),
            Err(err) => warn!(
                image_ref = image,
                error = %err,
                "failed to remove a local_image fallback load after its retried create failed"
            ),
        }
    }

    /// Send a `SandboxCreateReq` and return the raw response, without
    /// interpreting the status code — shared by `create_inner`'s first
    /// attempt and its retry after a `local_image` fallback load.
    async fn post_sandbox_create(
        &self,
        req: &SandboxCreateReq<'_>,
    ) -> Result<(u16, Bytes), Status> {
        let body = serde_json::to_vec(req).map_err(|e| Status::internal(format!("json: {e}")))?;
        self.daemon_request(http::Method::POST, "/sandbox", Some(Bytes::from(body)))
            .await
    }

    // ── HTTP helpers ───────────────────────────────────────────────────────

    async fn list_infos(&self) -> Result<Vec<SandboxInfo>, Status> {
        let (status, body) = self
            .daemon_request(http::Method::GET, "/sandbox", None)
            .await?;

        match status {
            200 => serde_json::from_slice::<Vec<SandboxInfo>>(&body).map_err(|e| {
                Status::internal(format!("sandboxd list response decode failed: {e}"))
            }),
            503 => Err(Status::unavailable("sandboxd is degraded")),
            code => {
                let msg = String::from_utf8_lossy(&body);
                Err(Status::internal(format!(
                    "sandboxd list returned HTTP {code}: {msg}"
                )))
            }
        }
    }

    /// Resolve the sandboxd name for a sandbox the gateway identified by id
    /// and/or name.
    ///
    /// With both halves the name is reconstructed directly. With only one, the
    /// list is scanned for the sandbox whose decoded identity matches, since
    /// neither half alone can rebuild the encoded name.
    async fn resolve_sandboxd_name(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<String, Status> {
        if !sandbox_id.is_empty() && !sandbox_name.is_empty() {
            return encode_sandboxd_name(sandbox_id, sandbox_name);
        }

        let infos = self.list_infos().await?;
        infos
            .iter()
            .find(|info| {
                decode_sandboxd_name(&info.name).is_some_and(|(id, name)| {
                    (!sandbox_id.is_empty() && id == sandbox_id)
                        || (!sandbox_name.is_empty() && name == sandbox_name)
                })
            })
            .map(|info| info.name.clone())
            .ok_or_else(|| Status::not_found("sandbox not found"))
    }

    async fn get_info(&self, name: &str) -> Result<Option<SandboxInfo>, Status> {
        let path = format!("/sandbox/{name}");
        let (status, body) = self.daemon_request(http::Method::GET, &path, None).await?;

        match status {
            200 => serde_json::from_slice::<SandboxInfo>(&body)
                .map(Some)
                .map_err(|e| Status::internal(format!("sandboxd get response decode failed: {e}"))),
            404 => Ok(None),
            503 => Err(Status::unavailable("sandboxd is degraded")),
            code => {
                let msg = String::from_utf8_lossy(&body);
                Err(Status::internal(format!(
                    "sandboxd get returned HTTP {code}: {msg}"
                )))
            }
        }
    }

    async fn create_inner(&self, sandbox: &DriverSandbox) -> Result<(), Status> {
        let spec = sandbox
            .spec
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
        let template = spec
            .template
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;
        let validated = validated_sandbox_create(sandbox)?;

        // A blank per-request image defers to the driver's resolved default
        // — see `DockerSandboxesComputeConfig::template_image`. Whether that
        // image is registry-resolvable and not yet in sandboxd's own image
        // store is sandboxd's own concern: its create endpoint transparently
        // pulls a template it doesn't already have (confirmed live), so this
        // driver never needs to pull or load an image itself.
        let template_override = {
            let img = template.image.trim();
            if img.is_empty() {
                self.config.template_image.as_str()
            } else {
                img
            }
        };
        let profile = resolve_profile(&validated.driver_config, &self.config.profile);
        let supervisor_bin_path = self
            .config
            .supervisor_bin_path
            .to_str()
            .ok_or_else(|| Status::internal("supervisor binary path is not valid UTF-8"))?;

        let encoded_name = encode_sandboxd_name(&sandbox.id, &sandbox.name)?;
        let workspace_dir =
            ensure_sandbox_workspace_dir(&self.config.default_workspace, &sandbox.id)?;
        let workspace_dir = workspace_dir
            .to_str()
            .ok_or_else(|| Status::internal("sandbox workspace path is not valid UTF-8"))?;

        let mut env: HashMap<String, String> = HashMap::new();
        env.extend(template.environment.clone());
        env.extend(spec.environment.clone());
        // Inject OpenShell connection vars so the in-container supervisor can
        // call back to the gateway.
        env.insert(
            openshell_core::sandbox_env::ENDPOINT.to_string(),
            self.config.openshell_endpoint.clone(),
        );
        env.insert(
            openshell_core::sandbox_env::SANDBOX_ID.to_string(),
            sandbox.id.clone(),
        );
        env.insert(
            openshell_core::sandbox_env::SANDBOX.to_string(),
            sandbox.name.clone(),
        );
        env.insert(
            openshell_core::sandbox_env::SANDBOX_COMMAND.to_string(),
            "sleep infinity".to_string(),
        );
        // Without this, the supervisor never spawns its persistent
        // ConnectSupervisor session (see `run_process` in
        // openshell-supervisor-process) — the sandbox loads its policy but
        // stays in Provisioning forever.
        env.insert(
            openshell_core::sandbox_env::SSH_SOCKET_PATH.to_string(),
            self.config.ssh_socket_path.clone(),
        );
        // Read by the shipped template image's wrapper ENTRYPOINT — see
        // `SUPERVISOR_BIN_ENV`.
        env.insert(
            SUPERVISOR_BIN_ENV.to_string(),
            supervisor_bin_path.to_string(),
        );
        if !self.config.log_level.is_empty() {
            env.insert(
                openshell_core::sandbox_env::LOG_LEVEL.to_string(),
                self.config.log_level.clone(),
            );
        }
        // Written to a per-sandbox host file rather than shipped as a plain
        // env var: unlike the Docker/Podman/VM drivers' own container-target
        // mount path, sandboxd's `additional_workspaces` maps a host path to
        // the *identical* container path (no separate target field) — the
        // same identity mapping `SUPERVISOR_BIN_ENV` above already relies on
        // for the supervisor binary — so the mounted path and the env var
        // naming it are the same value chosen here, not the Docker/Podman/VM
        // drivers' fixed `SANDBOX_TOKEN_MOUNT_PATH`. A plain env var would
        // put the gateway-minted sandbox identity into container config
        // readable by every process in the sandbox and by anyone with
        // sandboxd socket access, not just the supervisor.
        let token_file_path = if spec.sandbox_token.trim().is_empty() {
            None
        } else {
            Some(write_sandbox_token_file(&sandbox.id, &spec.sandbox_token)?)
        };
        let token_file_path_str = token_file_path
            .as_ref()
            .map(|path| {
                path.to_str()
                    .ok_or_else(|| Status::internal("sandbox token path is not valid UTF-8"))
                    .map(str::to_string)
            })
            .transpose()?;
        if let Some(path_str) = &token_file_path_str {
            env.insert(
                openshell_core::sandbox_env::SANDBOX_TOKEN_FILE.to_string(),
                path_str.clone(),
            );
        }

        // Ship the OpenShell agent kit inline so sandboxd resolves
        // `agent: "openshell"` from the request itself — no pre-installed agent
        // required. sandboxd applies no normalization pass of its own to each
        // entry (confirmed empirically), so we ship the canonical wire form
        // `sbx kit inspect --json` itself produces verbatim — see
        // `kits/openshell/README.md`.
        let mut kit_artifact: serde_json::Value = serde_json::from_str(OPENSHELL_KIT_ARTIFACT)
            .map_err(|e| {
                Status::internal(format!(
                    "failed to parse embedded openshell kit artifact: {e}"
                ))
            })?;
        // The gateway port is configurable, so a static kit spec can't
        // hardcode the egress allow entry — synthesize it per-create.
        // sandboxd's kit egress policy only gates outbound network calls
        // once the supervisor is already running; it has no bearing on
        // whether the container boots (that's `template_override` above and
        // the kit's own `setup.startup` command, which `exec`s the binary
        // `supervisor` resolves).
        inject_gateway_network_allow(&mut kit_artifact, &self.config.openshell_endpoint)?;

        let mut additional_workspaces = vec![WorkspaceMountReq {
            dir: supervisor_bin_path,
            read_only: true,
        }];
        if let Some(path_str) = &token_file_path_str {
            additional_workspaces.push(WorkspaceMountReq {
                dir: path_str,
                read_only: true,
            });
        }

        // Use the OpenShell UUID as the sandboxd name — it satisfies
        // sandboxd's name character restrictions and is unique.
        let req = SandboxCreateReq {
            agent: OPENSHELL_AGENT,
            workspace: workspace_dir,
            name: &encoded_name,
            template: template_override,
            profile,
            cpus: validated.cpus,
            memory: validated.memory.as_deref(),
            environment: env,
            additional_workspaces,
            kit_artifacts: vec![kit_artifact],
        };

        let result = async {
            let (status, resp_body) = self.post_sandbox_create(&req).await?;

            // sandboxd resolves a registry-resolvable `template.image`
            // itself; this specific failure means it couldn't. The only
            // case worth checking a local Docker Engine for is a
            // locally-built image from `openshell sandbox create --from
            // <Dockerfile>` — see `local_image`.
            if local_image::is_image_pull_failure(status, &resp_body) {
                return match self
                    .try_load_image_from_local_docker_engine(template_override)
                    .await
                {
                    Ok(true) => {
                        let (retry_status, retry_body) = self.post_sandbox_create(&req).await?;
                        let retry_result = create_status_to_result(
                            retry_status,
                            &retry_body,
                            " after loading it from a local Docker Engine",
                        );
                        if retry_result.is_err() {
                            // Don't leave the image this call just loaded
                            // sitting in sandboxd's store — nothing else
                            // will ever clean it up.
                            self.remove_loaded_image(template_override).await;
                        }
                        retry_result
                    }
                    Ok(false) => Err(Status::failed_precondition(format!(
                        "template image '{template_override}' isn't in sandboxd's own image \
                         store and sandboxd couldn't pull it from a registry: {}",
                        String::from_utf8_lossy(&resp_body)
                    ))),
                    Err(err) => Err(Status::internal(format!(
                        "failed to load '{template_override}' from a local Docker Engine into \
                         sandboxd: {err}"
                    ))),
                };
            }

            create_status_to_result(status, &resp_body, "")
        }
        .await;
        if result.is_err() {
            // The sandbox token is only usable while sandboxd actually
            // knows about this sandbox — leaving it on disk after a
            // failed create would be a stale secret with no corresponding
            // sandbox to clean it up later.
            if token_file_path.is_some() {
                cleanup_sandbox_token_file(&sandbox.id);
            }
            cleanup_sandbox_workspace_dir(&self.config.default_workspace, &sandbox.id);
        }
        result
    }

    async fn stop_inner(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        let name = self.resolve_sandboxd_name(sandbox_id, sandbox_name).await?;
        let path = format!("/sandbox/{name}/stop");
        let (status, body) = self.daemon_request(http::Method::POST, &path, None).await?;

        match status {
            200 => Ok(()),
            404 => Err(Status::not_found("sandbox not found")),
            503 => Err(Status::unavailable("sandboxd is degraded")),
            code => {
                let msg = String::from_utf8_lossy(&body);
                Err(Status::internal(format!(
                    "sandboxd stop returned HTTP {code}: {msg}"
                )))
            }
        }
    }

    async fn start_inner(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), Status> {
        let name = self.resolve_sandboxd_name(sandbox_id, sandbox_name).await?;
        let path = format!("/sandbox/{name}/start");
        let (status, body) = self.daemon_request(http::Method::POST, &path, None).await?;

        match status {
            200 => Ok(()),
            404 => Err(Status::not_found("sandbox not found")),
            503 => Err(Status::unavailable("sandboxd is degraded")),
            code => {
                let msg = String::from_utf8_lossy(&body);
                Err(Status::internal(format!(
                    "sandboxd start returned HTTP {code}: {msg}"
                )))
            }
        }
    }

    async fn delete_inner(&self, sandbox_id: &str, sandbox_name: &str) -> Result<bool, Status> {
        let name = self.resolve_sandboxd_name(sandbox_id, sandbox_name).await?;
        let path = format!("/sandbox/{name}");
        let (status, body) = self
            .daemon_request(http::Method::DELETE, &path, None)
            .await?;

        if !sandbox_id.is_empty() {
            cleanup_sandbox_token_file(sandbox_id);
            cleanup_sandbox_workspace_dir(&self.config.default_workspace, sandbox_id);
        }

        match status {
            200 => Ok(true),
            404 => Ok(false),
            503 => Err(Status::unavailable("sandboxd is degraded")),
            code => {
                let msg = String::from_utf8_lossy(&body);
                Err(Status::internal(format!(
                    "sandboxd delete returned HTTP {code}: {msg}"
                )))
            }
        }
    }

    // ── Snapshot helpers ───────────────────────────────────────────────────

    async fn current_snapshots(&self) -> Result<Vec<DriverSandbox>, Status> {
        let mut sandboxes = self
            .list_infos()
            .await?
            .iter()
            .filter_map(sandbox_from_info)
            .collect::<Vec<_>>();
        sandboxes.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(sandboxes)
    }

    async fn current_snapshot_map(&self) -> Result<HashMap<String, DriverSandbox>, Status> {
        self.current_snapshots()
            .await
            .map(|s| s.into_iter().map(|sb| (sb.id.clone(), sb)).collect())
    }

    // ── Daemon probe ───────────────────────────────────────────────────────

    async fn probe_daemon_version(&self) -> String {
        match self
            .daemon_request(http::Method::GET, "/daemon/health", None)
            .await
        {
            Ok((200, body)) => {
                if let Ok(h) = serde_json::from_slice::<DaemonHealth>(&body) {
                    info!(version = %h.version, "Connected to sandboxd");
                    h.version
                } else {
                    warn!("sandboxd health response could not be decoded; daemon version unknown");
                    "unknown".to_string()
                }
            }
            Ok((code, _)) => {
                warn!(
                    status = code,
                    "sandboxd health returned non-200; daemon version unknown"
                );
                "unknown".to_string()
            }
            Err(_) => {
                warn!(
                    "sandboxd is not reachable at driver startup; \
                     sandbox operations will fail until the daemon is running"
                );
                "unknown".to_string()
            }
        }
    }

    // ── Watch poll loop ────────────────────────────────────────────────────

    async fn poll_loop(self) {
        let mut previous = match self.current_snapshot_map().await {
            Ok(m) => m,
            Err(err) => {
                warn!(error = %err, "Failed to seed sandboxd watch state; starting empty");
                HashMap::new()
            }
        };

        let mut backoff = WATCH_POLL_INTERVAL;
        loop {
            tokio::time::sleep(backoff).await;
            match self.current_snapshot_map().await {
                Ok(current) => {
                    emit_diff(&self.events, &previous, &current);
                    previous = current;
                    backoff = WATCH_POLL_INTERVAL;
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        backoff_secs = backoff.as_secs(),
                        "Failed to poll sandboxd sandboxes"
                    );
                    backoff = (backoff * 2).min(WATCH_POLL_MAX_BACKOFF);
                }
            }
        }
    }
}

// ── ComputeDriver implementation ───────────────────────────────────────────

#[tonic::async_trait]
impl ComputeDriver for DockerSandboxesComputeDriver {
    type WatchSandboxesStream = WatchStream;

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(
            openshell_core::driver_utils::build_capabilities_response(
                "docker-sandboxes",
                self.config.daemon_version.clone(),
                self.config.template_image.clone(),
            ),
        ))
    }

    /// sandboxd owns container networking, so the gateway needs no particular
    /// listener bind address on its behalf.
    async fn get_gateway_listener_requirements(
        &self,
        _request: Request<GetGatewayListenerRequirementsRequest>,
    ) -> Result<Response<GetGatewayListenerRequirementsResponse>, Status> {
        Ok(Response::new(GetGatewayListenerRequirementsResponse {
            requirements: Vec::new(),
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        validated_sandbox_create(&sandbox)?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let r = request.into_inner();
        if r.sandbox_id.is_empty() && r.sandbox_name.is_empty() {
            return Err(Status::invalid_argument(
                "sandbox_id or sandbox_name is required",
            ));
        }
        let name = self
            .resolve_sandboxd_name(&r.sandbox_id, &r.sandbox_name)
            .await?;
        let info = self
            .get_info(&name)
            .await?
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox_from_info(&info).ok_or_else(|| {
                Status::not_found("sandbox is not managed by the docker-sandboxes driver")
            })?),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        Ok(Response::new(ListSandboxesResponse {
            sandboxes: self.current_snapshots().await?,
        }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        self.create_inner(&sandbox).await?;
        Ok(Response::new(CreateSandboxResponse {}))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let r = request.into_inner();
        if r.sandbox_id.is_empty() && r.sandbox_name.is_empty() {
            return Err(Status::invalid_argument(
                "sandbox_id or sandbox_name is required",
            ));
        }
        self.stop_inner(&r.sandbox_id, &r.sandbox_name).await?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let r = request.into_inner();
        if r.sandbox_id.is_empty() && r.sandbox_name.is_empty() {
            return Err(Status::invalid_argument(
                "sandbox_id or sandbox_name is required",
            ));
        }
        self.start_inner(&r.sandbox_id, &r.sandbox_name).await?;
        Ok(Response::new(StartSandboxResponse {}))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let r = request.into_inner();
        if r.sandbox_id.is_empty() && r.sandbox_name.is_empty() {
            return Err(Status::invalid_argument(
                "sandbox_id or sandbox_name is required",
            ));
        }
        let event_id = r.sandbox_id.clone();
        let deleted = self.delete_inner(&r.sandbox_id, &r.sandbox_name).await?;
        if deleted && !event_id.is_empty() {
            let _ = self.events.send(WatchSandboxesEvent {
                payload: Some(watch_sandboxes_event::Payload::Deleted(
                    WatchSandboxesDeletedEvent {
                        sandbox_id: event_id,
                    },
                )),
            });
        }
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let mut rx = self.events.subscribe();
        let initial = self.current_snapshots().await?;
        let (tx, out_rx) = mpsc::channel(WATCH_BUFFER);

        tokio::spawn(async move {
            for sandbox in initial {
                if tx
                    .send(Ok(WatchSandboxesEvent {
                        payload: Some(watch_sandboxes_event::Payload::Sandbox(
                            WatchSandboxesSandboxEvent {
                                sandbox: Some(sandbox),
                            },
                        )),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if tx.send(Ok(event)).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }
}

// ── Free functions ─────────────────────────────────────────────────────────

/// Map a `POST /sandbox` response's status code to a `Result` — shared by
/// `create_inner`'s first attempt and its retry after a `local_image`
/// fallback load. `context` is appended to the generic-failure message
/// (e.g. `" after loading it from a local Docker Engine"` for the retry),
/// empty on the first attempt.
fn create_status_to_result(status: u16, body: &Bytes, context: &str) -> Result<(), Status> {
    match status {
        201 => Ok(()),
        409 => Err(Status::already_exists("sandbox already exists")),
        503 => Err(Status::unavailable("sandboxd is degraded")),
        code => {
            let msg = String::from_utf8_lossy(body);
            Err(Status::internal(format!(
                "sandboxd create returned HTTP {code}{context}: {msg}"
            )))
        }
    }
}

/// Host path a gateway-minted sandbox JWT is written to before create, and
/// injected into the sandbox at the identical container path via
/// `additional_workspaces` (see `create_inner`). Shares the same
/// `<state-dir>/openshell/<driver_subdir>/<sandbox-id>/sandbox.jwt` layout
/// `openshell-driver-docker` uses for its own token file.
fn sandbox_token_host_path(sandbox_id: &str) -> Result<PathBuf, Status> {
    openshell_core::driver_utils::sandbox_token_path("docker-sandboxes-tokens", None, sandbox_id)
        .map_err(|err| {
            Status::internal(format!(
                "resolve sandbox token state directory failed: {err}"
            ))
        })
}

/// Write `token` to [`sandbox_token_host_path`] for `sandbox_id`, restricted
/// to the driver's own user (0700 directory, 0600 file — matching
/// `openshell-driver-docker`'s own token file), and return the path.
fn write_sandbox_token_file(sandbox_id: &str, token: &str) -> Result<PathBuf, Status> {
    let path = sandbox_token_host_path(sandbox_id)?;
    if let Some(parent) = path.parent() {
        openshell_core::paths::create_dir_restricted(parent).map_err(|err| {
            Status::internal(format!(
                "create sandbox token directory {} failed: {err}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(&path, format!("{token}\n")).map_err(|err| {
        Status::internal(format!(
            "write sandbox token file {} failed: {err}",
            path.display()
        ))
    })?;
    openshell_core::paths::set_file_owner_only(&path).map_err(|err| {
        Status::internal(format!(
            "restrict sandbox token file {} failed: {err}",
            path.display()
        ))
    })?;
    Ok(path)
}

/// Best-effort removal of a sandbox's token file and its (now-empty)
/// directory. Called on delete and on a failed create — a token file with
/// no corresponding sandbox is a stale secret with nothing to clean it up
/// otherwise.
fn cleanup_sandbox_token_file(sandbox_id: &str) {
    let Ok(path) = sandbox_token_host_path(sandbox_id) else {
        return;
    };
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            warn!(
                sandbox_id,
                path = %path.display(),
                error = %err,
                "failed to remove sandbox token file",
            );
        }
        return;
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir(dir);
    }
}

/// Host directory for one sandbox's workspace, under `base` (the driver's
/// configured `default_workspace`). Each sandbox gets its own subdirectory
/// rather than sharing `base` itself — sandboxd mounts whatever host path is
/// given here directly into the container, so sandboxes sharing a base
/// directory as their actual workspace would otherwise see each other's
/// files (and, if `base` is a general-purpose directory, everything else in
/// it too).
fn sandbox_workspace_host_path(base: &str, sandbox_id: &str) -> PathBuf {
    Path::new(base).join(format!("os-{sandbox_id}"))
}

/// Create [`sandbox_workspace_host_path`] for `sandbox_id` if it doesn't
/// already exist and return it. sandboxd requires the workspace directory
/// to exist before create (confirmed live) — it doesn't create one itself.
fn ensure_sandbox_workspace_dir(base: &str, sandbox_id: &str) -> Result<PathBuf, Status> {
    let path = sandbox_workspace_host_path(base, sandbox_id);
    std::fs::create_dir_all(&path).map_err(|err| {
        Status::internal(format!(
            "create sandbox workspace directory {} failed: {err}",
            path.display()
        ))
    })?;
    Ok(path)
}

/// Best-effort removal of a sandbox's workspace directory and everything in
/// it. Called on delete — a sandbox's workspace is scoped to its own
/// lifetime, the same as its token file and its container's own writable
/// layer.
fn cleanup_sandbox_workspace_dir(base: &str, sandbox_id: &str) {
    let path = sandbox_workspace_host_path(base, sandbox_id);
    if let Err(err) = std::fs::remove_dir_all(&path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            sandbox_id,
            path = %path.display(),
            error = %err,
            "failed to remove sandbox workspace directory",
        );
    }
}

/// Per-sandbox `docker-sandboxes` driver config, carried in a create
/// request's `template.driver_config` — the generic per-driver passthrough
/// (`SandboxTemplate.driver_config` in `proto/openshell.proto`, forwarded to
/// `DriverSandboxTemplate.driver_config` here) that `openshell-driver-docker`
/// already uses the same way for its own bind-mount opt-in.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct DockerSandboxesDriverConfig {
    /// Overrides the driver-wide default profile (below) for this sandbox
    /// only.
    profile: Option<String>,
}

impl DockerSandboxesDriverConfig {
    fn from_template(template: &DriverSandboxTemplate) -> Result<Self, Status> {
        let Some(config) = template.driver_config.as_ref() else {
            return Ok(Self::default());
        };
        serde_json::from_value(openshell_core::proto_struct::struct_to_json_value(config)).map_err(
            |err| {
                Status::invalid_argument(format!("invalid docker-sandboxes driver_config: {err}"))
            },
        )
    }
}

/// Resolve the named governance profile to assign: a per-sandbox
/// `template.driver_config.profile` override, else the driver-wide default.
/// `sandboxd` canonicalizes the resolved name against the active
/// remote/org-managed governance policy set and rejects unknown names at
/// create time.
fn resolve_profile<'a>(
    per_sandbox: &'a DockerSandboxesDriverConfig,
    default: &'a Option<String>,
) -> Option<&'a str> {
    per_sandbox.profile.as_deref().or(default.as_deref())
}

/// Result of validating a `CreateSandbox`/`ValidateSandboxCreate` request
/// against everything this driver can check without calling `sandboxd` —
/// shared by both RPCs so `ValidateSandboxCreate` exercises the exact same
/// checks `CreateSandbox` would apply, matching the pattern
/// `openshell-driver-docker`/`openshell-driver-podman` already use for their
/// own `validated_sandbox`-style helpers.
#[derive(Debug)]
struct ValidatedSandboxCreate {
    driver_config: DockerSandboxesDriverConfig,
    /// Whole vCPU count for sandboxd's own `cpus` create field, from
    /// `template.resources.cpu_limit`.
    cpus: Option<i64>,
    /// Binary-unit memory string for sandboxd's own `memory` create field,
    /// from `template.resources.memory_limit`.
    memory: Option<String>,
}

fn validated_sandbox_create(sandbox: &DriverSandbox) -> Result<ValidatedSandboxCreate, Status> {
    let spec = sandbox
        .spec
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec is required"))?;
    let template = spec
        .template
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("sandbox.spec.template is required"))?;
    reject_agent_socket_path(template)?;
    reject_gpu_request(spec)?;
    let (cpus, memory) = sandboxd_resource_fields(template.resources.as_ref())?;
    let driver_config = DockerSandboxesDriverConfig::from_template(template)?;
    Ok(ValidatedSandboxCreate {
        driver_config,
        cpus,
        memory,
    })
}

/// `sandboxd` has no per-sandbox agent socket concept of its own — the kit
/// contract fixes how the agent is reached — so this mirrors
/// `openshell-driver-docker`'s precedent of rejecting the field outright
/// rather than silently ignoring it (unlike `openshell-driver-podman`, which
/// ignores it; rejecting gives callers a clear signal instead of a request
/// that appears to succeed but drops the field).
fn reject_agent_socket_path(template: &DriverSandboxTemplate) -> Result<(), Status> {
    if !template.agent_socket_path.trim().is_empty() {
        return Err(Status::failed_precondition(
            "docker-sandboxes compute driver does not support template.agent_socket_path",
        ));
    }
    Ok(())
}

/// `sbx create --help` lists no GPU flag, but `sbx create --gpu` is
/// accepted rather than rejected as an unknown flag (confirmed live) — a
/// real, if undocumented/hidden, capability. This driver doesn't wire GPU
/// requests through to it: doing so would mean depending on a capability
/// `sbx`'s own public documentation doesn't commit to, for a feature that
/// isn't listed as supported anywhere. A GPU request is rejected outright
/// rather than silently creating a sandbox with no GPU, matching
/// `openshell-driver-docker`'s precedent for an unsupported resource
/// request. Presence of `gpu` (not just a positive `count`) indicates a
/// request per the proto's own doc comment on `ResourceRequirements.gpu`.
fn reject_gpu_request(spec: &DriverSandboxSpec) -> Result<(), Status> {
    let requests_gpu = spec
        .resource_requirements
        .as_ref()
        .is_some_and(|resources| resources.gpu.is_some());
    if requests_gpu {
        return Err(Status::failed_precondition(
            "docker-sandboxes compute driver does not support GPU sandboxes",
        ));
    }
    Ok(())
}

/// Map `DriverResourceRequirements` (Kubernetes-style quantity strings) onto
/// sandboxd's own `cpus` (whole vCPU count) and `memory` (binary-unit
/// string, e.g. `"512m"`) create-request fields — both confirmed live
/// against a running `sandboxd` and documented in `sbx create --help`.
///
/// sandboxd sizes a sandbox as a single fixed-size microVM rather than
/// applying separate cgroup request/limit controls the way a container
/// runtime does, so there's no sandboxd equivalent of a "request" distinct
/// from a "limit" — `cpu_request`/`memory_request` are rejected outright,
/// matching `openshell-driver-docker`'s precedent for the same
/// not-supported-here fields.
fn sandboxd_resource_fields(
    resources: Option<&openshell_core::proto::compute::v1::DriverResourceRequirements>,
) -> Result<(Option<i64>, Option<String>), Status> {
    let Some(resources) = resources else {
        return Ok((None, None));
    };
    if !resources.cpu_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "docker-sandboxes compute driver does not support resources.cpu_request; \
             sandboxd sizes a sandbox as a single fixed vCPU count — set resources.cpu_limit instead",
        ));
    }
    if !resources.memory_request.trim().is_empty() {
        return Err(Status::failed_precondition(
            "docker-sandboxes compute driver does not support resources.memory_request; \
             sandboxd sizes a sandbox as a single fixed memory allocation — set resources.memory_limit instead",
        ));
    }
    let cpus = parse_cpu_limit(&resources.cpu_limit)?;
    let memory = parse_memory_limit(&resources.memory_limit)?;
    Ok((cpus, memory))
}

/// Parse a Kubernetes-style CPU quantity (`"500m"` millicores, or a bare
/// core count like `"2"`/`"2.5"`) into a whole vCPU count, rounding up so
/// the allocation is never under-provisioned relative to what was
/// requested — sandboxd allocates whole vCPUs to a sandbox's microVM, with
/// no fractional-CPU-share mechanism to round down into instead.
fn parse_cpu_limit(value: &str) -> Result<Option<i64>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let cores: f64 = if let Some(millis) = value.strip_suffix('m') {
        millis.parse::<f64>().map_err(|err| {
            Status::invalid_argument(format!("invalid cpu_limit {value:?}: {err}"))
        })? / 1000.0
    } else {
        value.parse::<f64>().map_err(|err| {
            Status::invalid_argument(format!("invalid cpu_limit {value:?}: {err}"))
        })?
    };
    if !cores.is_finite() || cores <= 0.0 {
        return Err(Status::invalid_argument(format!(
            "invalid cpu_limit {value:?}: must be a positive quantity"
        )));
    }
    // Bounded above by any plausible CPU count and non-negative, checked
    // just above.
    #[allow(clippy::cast_possible_truncation)]
    Ok(Some(cores.ceil() as i64))
}

/// sandboxd's own minimum `memory` create value, confirmed live (see
/// [`parse_memory_limit`]).
const SANDBOXD_MIN_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;

/// Parse a Kubernetes-style memory quantity into sandboxd's own `memory`
/// field format: a binary-unit string (`sbx create --help`: "e.g., 1024m,
/// 8g"). Always emits whole mebibytes (rounded up) rather than picking a
/// unit per magnitude, which keeps the conversion exact.
fn parse_memory_limit(value: &str) -> Result<Option<String>, Status> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = parse_kubernetes_quantity_bytes(value)
        .ok_or_else(|| Status::invalid_argument(format!("invalid memory_limit {value:?}")))?;
    // sandboxd rejects a `memory` below 1 GiB outright (confirmed live:
    // `{"message":"invalid memory \"777m\": memory 777m is below the
    // minimum of 1 GiB"}`) — checked here so the error names the actual
    // floor instead of surfacing as an opaque sandboxd 400 at create time.
    if bytes < SANDBOXD_MIN_MEMORY_BYTES {
        return Err(Status::invalid_argument(format!(
            "invalid memory_limit {value:?}: sandboxd requires at least 1Gi"
        )));
    }
    let mebibytes = bytes.div_ceil(1024 * 1024);
    Ok(Some(format!("{mebibytes}m")))
}

/// Parse a Kubernetes resource-quantity string into a byte count. Supports
/// the binary (`Ki`/`Mi`/`Gi`/`Ti`/`Pi`/`Ei`) and decimal (`k`/`M`/`G`/`T`/
/// `P`/`E`) suffix families plus a bare byte count — the same suffix set
/// `openshell-driver-docker`'s and `openshell-driver-podman`'s own
/// independent quantity parsers accept.
fn parse_kubernetes_quantity_bytes(value: &str) -> Option<u64> {
    const BINARY_SUFFIXES: &[(&str, f64)] = &[
        ("Ki", 1024.0),
        ("Mi", 1024.0 * 1024.0),
        ("Gi", 1024.0 * 1024.0 * 1024.0),
        ("Ti", 1024.0 * 1024.0 * 1024.0 * 1024.0),
        ("Pi", 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0),
        ("Ei", 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0),
    ];
    const DECIMAL_SUFFIXES: &[(&str, f64)] = &[
        ("k", 1_000.0),
        ("M", 1_000_000.0),
        ("G", 1_000_000_000.0),
        ("T", 1_000_000_000_000.0),
        ("P", 1_000_000_000_000_000.0),
        ("E", 1_000_000_000_000_000_000.0),
    ];
    // Checked non-negative and finite immediately before each cast below.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        for (suffix, multiplier) in BINARY_SUFFIXES.iter().chain(DECIMAL_SUFFIXES) {
            if let Some(number) = value.strip_suffix(suffix) {
                let count: f64 = number.parse().ok()?;
                return (count.is_finite() && count >= 0.0)
                    .then(|| (count * multiplier).ceil() as u64);
            }
        }
        let count: f64 = value.parse().ok()?;
        (count.is_finite() && count >= 0.0).then(|| count.ceil() as u64)
    }
}

/// Add a `caps.network.allow` entry for `openshell_endpoint` to the kit artifact
/// JSON. Format matches sandboxd's kit egress schema: exact `host:port`.
fn inject_gateway_network_allow(
    kit_artifact: &mut serde_json::Value,
    openshell_endpoint: &str,
) -> Result<(), Status> {
    let parsed = url::Url::parse(openshell_endpoint).map_err(|e| {
        Status::internal(format!(
            "openshell_endpoint {openshell_endpoint:?} is not a valid URL: {e}"
        ))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        Status::internal(format!(
            "openshell_endpoint {openshell_endpoint:?} has no host"
        ))
    })?;
    let port = parsed.port_or_known_default().ok_or_else(|| {
        Status::internal(format!(
            "openshell_endpoint {openshell_endpoint:?} has no resolvable port"
        ))
    })?;
    // sandboxd's egress proxy normalizes the magic `host.docker.internal`
    // hostname to `localhost` for policy matching (confirmed empirically —
    // an allow entry spelled `host.docker.internal:<port>` never matches).
    // Any other configured host is a real hostname the proxy doesn't rewrite.
    let policy_host = if host == "host.docker.internal" {
        "localhost"
    } else {
        host
    };
    let allow_entry = serde_json::Value::String(format!("{policy_host}:{port}"));

    let caps = kit_artifact
        .as_object_mut()
        .ok_or_else(|| Status::internal("kit artifact is not a JSON object"))?
        .entry("caps")
        .or_insert_with(|| serde_json::json!({}));
    let network = caps
        .as_object_mut()
        .ok_or_else(|| Status::internal("kit artifact caps is not a JSON object"))?
        .entry("network")
        .or_insert_with(|| serde_json::json!({}));
    let allow = network
        .as_object_mut()
        .ok_or_else(|| Status::internal("kit artifact caps.network is not a JSON object"))?
        .entry("allow")
        .or_insert_with(|| serde_json::json!([]));
    allow
        .as_array_mut()
        .ok_or_else(|| Status::internal("kit artifact caps.network.allow is not a JSON array"))?
        .push(allow_entry);

    Ok(())
}

/// Marks a sandboxd sandbox as `OpenShell`-managed.
///
/// Deliberately terse. Every character here comes out of the budget left for
/// the sandbox name (see [`MAX_SANDBOXD_NAME_LEN`]), and the gateway generates
/// two-word petnames that run up to 37 characters.
const SANDBOXD_NAME_PREFIX: &str = "os-";

/// Width of the base36-encoded sandbox id inside a sandboxd name.
///
/// 128 bits of UUID need `ceil(128 / log2(36)) = 25` base36 digits. The field
/// is zero-padded to exactly this width so the name that follows it can be
/// split off by offset, which keeps names containing `-` or `.` unambiguous.
const ENCODED_ID_LEN: usize = 25;

/// Ceiling for a sandboxd sandbox name.
///
/// sandboxd itself doesn't reject an overlong name up front (confirmed
/// empirically — only emptiness, a 2-char minimum, and the charset are
/// checked at that point). The real limit comes from the container runtime:
/// sandboxd uses the sandbox name as the container hostname, and Linux
/// `sethostname(2)` rejects anything longer than 64 bytes with `EINVAL`.
/// Measured from a sandboxd daemon log:
///
/// ```text
/// create sandbox failed ... run container: start container:
///   OCI runtime create failed: sethostname: Invalid argument
/// ```
///
/// sandboxd surfaces that only as "failed to run sandbox container" — its
/// catch-all branch — so the real cause never reaches the client. Hence the
/// check here.
///
/// Held at 63 rather than the kernel's 64: a hostname is a DNS label, and 63
/// is the RFC 1123 label limit. The extra character is not worth risking
/// name resolution.
const MAX_SANDBOXD_NAME_LEN: usize = 63;

/// Encode the `OpenShell` identity into the sandboxd sandbox name.
///
/// sandboxd offers no durable place to attach caller metadata — its create
/// request has no `labels` field and its list response echoes back neither
/// labels nor the environment — so the name is the only field that round-trips.
/// Both halves of the identity therefore live in it:
///
/// ```text
/// os-<uuid in base36, zero-padded to 25>-<openshell name>
/// ```
///
/// The gateway resolves snapshots by id and overwrites the stored name with
/// whatever the driver reports, so the driver must reproduce both exactly.
/// Encoding them keeps one source of truth and needs no cache, which a gateway
/// restart would lose.
///
/// TODO(sandbox-identity): carrying the name here is tribute to a gateway bug,
/// not a requirement. `apply_driver_snapshot` overwrites `metadata.name` from
/// every snapshot even though it resolved the record by id and already holds
/// the stored name, and persistence then rejects the write as a rename. Two
/// ways out, in preference order:
///
/// 1. Guard that write upstream (see
///    `architecture/plans/gateway-driver-snapshot-rename.md`). Then the driver
///    reports no name, this becomes `os-<id>` at a fixed 28 characters, and the
///    length budget below disappears. Blocked on shipping to *unmodified*
///    installations, which by definition lack the guard.
/// 2. Persist identity in a driver-owned state directory, as
///    `openshell-driver-vm` does with `SANDBOX_REQUEST_FILE`. Durable across
///    restarts and unbounded in length, at the cost of state to keep in sync.
///
/// Until one lands, the name rides along here. Every other channel was checked
/// and closed: sandboxd's create request has no `labels` field, `SandboxInfo`
/// echoes back neither environment nor anything else caller-controlled,
/// `profile` is canonicalized, and `kit_args` (which newer sandboxd does stamp
/// into a container label) is silently ignored by the daemon versions we target.
///
/// base36 rather than hex: the id costs 25 characters instead of 32, and the
/// hostname limit makes those 7 characters matter. base62 would save 3 more but
/// needs mixed case, and any layer that case-folded the name would decode to a
/// silently wrong id — a worse failure than a loud one.
fn encode_sandboxd_name(sandbox_id: &str, sandbox_name: &str) -> Result<String, Status> {
    let compact_id: String = sandbox_id.chars().filter(|c| *c != '-').collect();
    if compact_id.len() != 32 || !compact_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Status::invalid_argument(format!(
            "docker-sandboxes driver requires a UUID sandbox id, got {sandbox_id:?}"
        )));
    }
    if sandbox_name.is_empty() {
        return Err(Status::invalid_argument("sandbox name is required"));
    }
    // sandboxd rejects anything outside [A-Za-z0-9.-]; surface that here
    // rather than as an opaque HTTP 400 from the daemon.
    if let Some(bad) = sandbox_name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '.' || *c == '-'))
    {
        return Err(Status::invalid_argument(format!(
            "sandbox name {sandbox_name:?} contains {bad:?}; sandboxd allows only \
             ASCII letters, digits, '.' and '-'"
        )));
    }

    let raw = u128::from_str_radix(&compact_id, 16)
        .map_err(|e| Status::invalid_argument(format!("sandbox id {sandbox_id:?}: {e}")))?;
    let encoded = format!(
        "{SANDBOXD_NAME_PREFIX}{}-{sandbox_name}",
        to_base36_padded(raw)
    );
    if encoded.len() > MAX_SANDBOXD_NAME_LEN {
        let budget = MAX_SANDBOXD_NAME_LEN - (SANDBOXD_NAME_PREFIX.len() + ENCODED_ID_LEN + 1);
        return Err(Status::invalid_argument(format!(
            "sandbox name {sandbox_name:?} is {} characters; the docker-sandboxes driver \
             encodes the sandbox id into the sandboxd name, leaving {budget} for the name",
            sandbox_name.len()
        )));
    }
    Ok(encoded)
}

/// Render `value` as exactly [`ENCODED_ID_LEN`] lowercase base36 digits.
fn to_base36_padded(mut value: u128) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = [b'0'; ENCODED_ID_LEN];
    let mut i = ENCODED_ID_LEN;
    while value > 0 && i > 0 {
        i -= 1;
        buf[i] = DIGITS[(value % 36) as usize];
        value /= 36;
    }
    String::from_utf8(buf.to_vec()).expect("base36 digits are ASCII")
}

/// Inverse of [`to_base36_padded`], rejecting anything not exactly
/// [`ENCODED_ID_LEN`] base36 digits or that overflows 128 bits.
fn from_base36(encoded: &str) -> Option<u128> {
    if encoded.len() != ENCODED_ID_LEN {
        return None;
    }
    let mut value: u128 = 0;
    for c in encoded.chars() {
        let digit = c.to_digit(36)?;
        value = value.checked_mul(36)?.checked_add(u128::from(digit))?;
    }
    Some(value)
}

/// Recover the `OpenShell` id and name from a sandboxd sandbox name.
///
/// Returns `None` for anything this driver did not create — sandboxes made
/// directly with `sbx`, and sandboxes from earlier naming schemes. A name that
/// coincidentally matches the shape decodes to an id the gateway does not know,
/// which it already ignores.
fn decode_sandboxd_name(sandboxd_name: &str) -> Option<(String, String)> {
    let rest = sandboxd_name.strip_prefix(SANDBOXD_NAME_PREFIX)?;
    if rest.len() < ENCODED_ID_LEN + 2 {
        return None;
    }
    let (encoded_id, remainder) = rest.split_at(ENCODED_ID_LEN);
    let raw = from_base36(encoded_id)?;
    let name = remainder.strip_prefix('-')?;
    if name.is_empty() {
        return None;
    }
    let hex = format!("{raw:032x}");
    let id = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    Some((id, name.to_string()))
}

/// Build a driver snapshot, or `None` when the sandboxd sandbox is not one of
/// ours. Foreign sandboxes (created directly with `sbx`, or by the earlier
/// bare-UUID scheme) carry no recoverable `OpenShell` identity, and reporting
/// them would make the gateway either ignore the snapshot or reject it.
fn sandbox_from_info(info: &SandboxInfo) -> Option<DriverSandbox> {
    let (sandbox_id, sandbox_name) = decode_sandboxd_name(&info.name)?;
    let running = info.status == "running";
    let (ready, reason, message) = if running {
        ("True", "Running", "Sandbox container is running")
    } else if info.created_at.is_empty() {
        // A sandbox whose own container hasn't finished being created yet
        // reports no `created_at` at all (confirmed live: `GET
        // /sandbox/{name}` briefly returns `status: "stopped"` with no
        // `created_at` for well under a second right after `POST /sandbox`
        // returns, before flipping to `running` once the container
        // actually starts) — distinct from a real container that existed
        // and has since stopped, which does carry a `created_at`. Reporting
        // this transient window as "Stopped" made the gateway treat normal
        // startup as a hard failure. "ContainerCreated" is the gateway's own
        // canonical non-terminal reason for this state
        // (`is_terminal_failure_reason` in `openshell-server`), matching
        // `openshell-driver-podman`'s use of the same string for its
        // analogous "created" container state.
        (
            "False",
            "ContainerCreated",
            "Sandbox container is being created",
        )
    } else {
        // "ContainerStopped" (not the generic "Stopped") specifically
        // because the gateway's own `driver_snapshot_confirms_stopped`
        // pattern-matches this exact reason (case-insensitively) to settle
        // a sandbox mid-`Stopping` transition into `SandboxPhase::Stopped`
        // — matching `openshell-driver-podman`'s use of the same string for
        // its own stopped-container condition. Without it, a watch snapshot
        // landing during that transition window has no way to confirm the
        // stop and can fall through to `Error` instead.
        ("False", "ContainerStopped", "Sandbox container is stopped")
    };

    Some(DriverSandbox {
        id: sandbox_id,
        name: sandbox_name.clone(),
        namespace: String::new(),
        spec: None,
        status: Some(DriverSandboxStatus {
            sandbox_name: sandbox_name.clone(),
            instance_id: sandbox_name,
            agent_fd: String::new(),
            sandbox_fd: String::new(),
            conditions: vec![DriverCondition {
                r#type: "Ready".to_string(),
                status: ready.to_string(),
                reason: reason.to_string(),
                message: message.to_string(),
                last_transition_time: info.created_at.clone(),
            }],
            deleting: false,
        }),
        workspace: String::new(),
    })
}

fn emit_diff(
    events: &broadcast::Sender<WatchSandboxesEvent>,
    previous: &HashMap<String, DriverSandbox>,
    current: &HashMap<String, DriverSandbox>,
) {
    for (id, sandbox) in current {
        if previous.get(id) == Some(sandbox) {
            continue;
        }
        let _ = events.send(WatchSandboxesEvent {
            payload: Some(watch_sandboxes_event::Payload::Sandbox(
                WatchSandboxesSandboxEvent {
                    sandbox: Some(sandbox.clone()),
                },
            )),
        });
    }
    for id in previous.keys() {
        if !current.contains_key(id) {
            let _ = events.send(WatchSandboxesEvent {
                payload: Some(watch_sandboxes_event::Payload::Deleted(
                    WatchSandboxesDeletedEvent {
                        sandbox_id: id.clone(),
                    },
                )),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_profile_prefers_per_sandbox_override() {
        let per_sandbox = DockerSandboxesDriverConfig {
            profile: Some("per-sandbox".to_string()),
        };
        let default = Some("driver-default".to_string());
        assert_eq!(resolve_profile(&per_sandbox, &default), Some("per-sandbox"));
    }

    #[test]
    fn resolve_profile_falls_back_to_driver_default() {
        let per_sandbox = DockerSandboxesDriverConfig::default();
        let default = Some("driver-default".to_string());
        assert_eq!(
            resolve_profile(&per_sandbox, &default),
            Some("driver-default")
        );
    }

    #[test]
    fn resolve_profile_is_none_when_neither_is_set() {
        let per_sandbox = DockerSandboxesDriverConfig::default();
        assert_eq!(resolve_profile(&per_sandbox, &None), None);
    }

    #[test]
    fn parse_cpu_limit_rounds_millicores_up_to_whole_vcpus() {
        assert_eq!(parse_cpu_limit("500m").unwrap(), Some(1));
        assert_eq!(parse_cpu_limit("1500m").unwrap(), Some(2));
        assert_eq!(parse_cpu_limit("2").unwrap(), Some(2));
        assert_eq!(parse_cpu_limit("2.1").unwrap(), Some(3));
        assert_eq!(parse_cpu_limit("").unwrap(), None);
    }

    #[test]
    fn parse_cpu_limit_rejects_non_positive_and_garbage() {
        assert!(parse_cpu_limit("0").is_err());
        assert!(parse_cpu_limit("-1").is_err());
        assert!(parse_cpu_limit("not-a-number").is_err());
    }

    #[test]
    fn parse_memory_limit_converts_binary_and_decimal_suffixes_to_mebibytes() {
        assert_eq!(
            parse_memory_limit("1Gi").unwrap(),
            Some("1024m".to_string())
        );
        assert_eq!(
            parse_memory_limit("2048Mi").unwrap(),
            Some("2048m".to_string())
        );
        assert_eq!(parse_memory_limit("2G").unwrap().unwrap(), "1908m");
        assert_eq!(parse_memory_limit("").unwrap(), None);
    }

    #[test]
    fn parse_memory_limit_rounds_up_when_not_a_whole_mebibyte() {
        // One byte over 1Gi: rounds up to the next mebibyte, not down.
        assert_eq!(
            parse_memory_limit("1073741825").unwrap(),
            Some("1025m".to_string())
        );
    }

    #[test]
    fn parse_memory_limit_rejects_below_sandboxds_one_gib_floor() {
        // sandboxd rejects any `memory` below 1 GiB outright (confirmed
        // live) — the driver surfaces that as a clear error rather than
        // silently converting to a value sandboxd would reject anyway.
        assert!(parse_memory_limit("512Mi").is_err());
        assert!(parse_memory_limit("1000M").is_err());
        assert!(parse_memory_limit("1").is_err());
        assert!(parse_memory_limit("0").is_err());
    }

    #[test]
    fn parse_memory_limit_rejects_garbage() {
        assert!(parse_memory_limit("512Xi").is_err());
        assert!(parse_memory_limit("-512Mi").is_err());
    }

    #[test]
    fn sandboxd_resource_fields_maps_limits_and_passes_through_when_absent() {
        assert_eq!(sandboxd_resource_fields(None).unwrap(), (None, None));

        let resources = openshell_core::proto::compute::v1::DriverResourceRequirements {
            cpu_limit: "2".to_string(),
            memory_limit: "2Gi".to_string(),
            ..Default::default()
        };
        assert_eq!(
            sandboxd_resource_fields(Some(&resources)).unwrap(),
            (Some(2), Some("2048m".to_string()))
        );
    }

    #[test]
    fn sandboxd_resource_fields_rejects_requests() {
        let cpu_request = openshell_core::proto::compute::v1::DriverResourceRequirements {
            cpu_request: "1".to_string(),
            ..Default::default()
        };
        let err = sandboxd_resource_fields(Some(&cpu_request)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let memory_request = openshell_core::proto::compute::v1::DriverResourceRequirements {
            memory_request: "256Mi".to_string(),
            ..Default::default()
        };
        let err = sandboxd_resource_fields(Some(&memory_request)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn reject_agent_socket_path_allows_blank_and_rejects_set() {
        let blank = DriverSandboxTemplate::default();
        assert!(reject_agent_socket_path(&blank).is_ok());

        let set = DriverSandboxTemplate {
            agent_socket_path: "/run/agent.sock".to_string(),
            ..Default::default()
        };
        let err = reject_agent_socket_path(&set).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn reject_gpu_request_allows_absent_and_rejects_present() {
        let no_gpu = DriverSandboxSpec::default();
        assert!(reject_gpu_request(&no_gpu).is_ok());

        let with_gpu = DriverSandboxSpec {
            resource_requirements: Some(openshell_core::proto::compute::v1::ResourceRequirements {
                gpu: Some(
                    openshell_core::proto::compute::v1::GpuResourceRequirements { count: None },
                ),
            }),
            ..Default::default()
        };
        let err = reject_gpu_request(&with_gpu).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn validated_sandbox_create_surfaces_unsupported_fields() {
        let template = DriverSandboxTemplate {
            agent_socket_path: "/run/agent.sock".to_string(),
            ..Default::default()
        };
        let spec = DriverSandboxSpec {
            template: Some(template),
            ..Default::default()
        };
        let sandbox = DriverSandbox {
            spec: Some(spec),
            ..Default::default()
        };
        let err = validated_sandbox_create(&sandbox).unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn write_and_cleanup_sandbox_token_file_round_trips() {
        let sandbox_id = "test-sandbox-token-roundtrip";
        let path = write_sandbox_token_file(sandbox_id, "test-token-value").expect("writes");
        let contents = std::fs::read_to_string(&path).expect("reads back");
        assert_eq!(contents, "test-token-value\n");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("stats")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "token file must not be group/world readable");
        }

        cleanup_sandbox_token_file(sandbox_id);
        assert!(!path.exists(), "cleanup must remove the token file");
    }

    #[test]
    fn cleanup_sandbox_token_file_is_a_noop_when_nothing_to_remove() {
        cleanup_sandbox_token_file("test-sandbox-token-never-written");
    }

    #[test]
    fn sandbox_token_host_path_is_stable_and_keyed_by_id() {
        let a = sandbox_token_host_path("id-a").expect("resolves");
        let b = sandbox_token_host_path("id-a").expect("resolves");
        let c = sandbox_token_host_path("id-b").expect("resolves");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.ends_with("docker-sandboxes-tokens/id-a/sandbox.jwt"));
    }

    #[test]
    fn sandbox_workspace_host_path_is_a_distinct_subdir_per_sandbox() {
        let a = sandbox_workspace_host_path("/base", "id-a");
        let b = sandbox_workspace_host_path("/base", "id-a");
        let c = sandbox_workspace_host_path("/base", "id-b");
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Never the base directory itself — every sandbox gets its own
        // subdirectory under it.
        assert_ne!(a, Path::new("/base"));
        assert_eq!(a, Path::new("/base/os-id-a"));
    }

    #[test]
    fn ensure_and_cleanup_sandbox_workspace_dir_round_trip() {
        let base = std::env::temp_dir()
            .join("openshell-docker-sandboxes-test-workspaces")
            .join(format!("{:?}", std::thread::current().id()).replace(['(', ')'], ""));
        std::fs::create_dir_all(&base).expect("creates test base dir");
        let sandbox_id = "test-workspace-roundtrip";

        let path =
            ensure_sandbox_workspace_dir(base.to_str().unwrap(), sandbox_id).expect("creates");
        assert!(path.is_dir());
        std::fs::write(path.join("marker"), b"hello").expect("writes into workspace");

        cleanup_sandbox_workspace_dir(base.to_str().unwrap(), sandbox_id);
        assert!(
            !path.exists(),
            "cleanup must remove the workspace directory and its contents"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cleanup_sandbox_workspace_dir_is_a_noop_when_nothing_to_remove() {
        cleanup_sandbox_workspace_dir("/tmp", "test-workspace-never-created");
    }

    #[test]
    fn driver_config_from_template_parses_profile() {
        let mut fields = serde_json::Map::new();
        fields.insert("profile".to_string(), serde_json::json!("customer-x"));
        let template = DriverSandboxTemplate {
            driver_config: Some(
                openshell_core::proto_struct::json_object_to_struct(fields).expect("valid struct"),
            ),
            ..Default::default()
        };
        let config = DockerSandboxesDriverConfig::from_template(&template).expect("parses");
        assert_eq!(config.profile, Some("customer-x".to_string()));
    }

    #[test]
    fn driver_config_from_template_defaults_when_absent() {
        let template = DriverSandboxTemplate::default();
        let config = DockerSandboxesDriverConfig::from_template(&template).expect("parses");
        assert_eq!(config.profile, None);
    }

    #[test]
    fn driver_config_from_template_rejects_unknown_keys() {
        let mut fields = serde_json::Map::new();
        fields.insert("typo_field".to_string(), serde_json::json!("x"));
        let template = DriverSandboxTemplate {
            driver_config: Some(
                openshell_core::proto_struct::json_object_to_struct(fields).expect("valid struct"),
            ),
            ..Default::default()
        };
        let err = DockerSandboxesDriverConfig::from_template(&template).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn network_allow_normalizes_host_docker_internal_to_localhost() {
        // sandboxd's egress proxy normalizes the magic `host.docker.internal`
        // hostname to `localhost` for policy matching (confirmed empirically
        // against a running sandboxd — an allow entry spelled
        // `host.docker.internal:<port>` never matches).
        let mut kit_artifact = serde_json::json!({"manifest": {"name": "openshell"}});
        inject_gateway_network_allow(&mut kit_artifact, "http://host.docker.internal:17670")
            .expect("injects");
        assert_eq!(
            kit_artifact["caps"]["network"]["allow"],
            serde_json::json!(["localhost:17670"])
        );
    }

    #[test]
    fn network_allow_defaults_the_port_for_a_schemed_url_without_one() {
        let mut kit_artifact = serde_json::json!({"manifest": {"name": "openshell"}});
        inject_gateway_network_allow(&mut kit_artifact, "http://host.docker.internal")
            .expect("injects");
        assert_eq!(
            kit_artifact["caps"]["network"]["allow"],
            serde_json::json!(["localhost:80"])
        );
    }

    #[test]
    fn network_allow_keeps_a_non_host_docker_internal_host_as_is() {
        let mut kit_artifact = serde_json::json!({"manifest": {"name": "openshell"}});
        inject_gateway_network_allow(&mut kit_artifact, "http://gateway.example.com:443")
            .expect("injects");
        assert_eq!(
            kit_artifact["caps"]["network"]["allow"],
            serde_json::json!(["gateway.example.com:443"])
        );
    }

    #[test]
    fn network_allow_rejects_an_unparseable_endpoint() {
        let mut kit_artifact = serde_json::json!({"manifest": {"name": "openshell"}});
        let err = inject_gateway_network_allow(&mut kit_artifact, "not a url").unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);
    }

    #[test]
    fn network_allow_appends_to_an_existing_allow_list() {
        let mut kit_artifact = serde_json::json!({
            "manifest": {"name": "openshell"},
            "caps": {"network": {"allow": ["existing.example.com:443"]}}
        });
        inject_gateway_network_allow(&mut kit_artifact, "http://host.docker.internal:17670")
            .expect("injects");
        assert_eq!(
            kit_artifact["caps"]["network"]["allow"],
            serde_json::json!(["existing.example.com:443", "localhost:17670"])
        );
    }

    fn candidates() -> Vec<String> {
        vec![
            "/first/sandboxd.sock".to_string(),
            "/second/sandboxd.sock".to_string(),
        ]
    }

    #[test]
    fn configured_socket_path_wins_over_everything() {
        let resolved = resolve_socket_path_from(
            "/explicit/sandboxd.sock",
            Some("/from/env.sock"),
            &candidates(),
            |_| true,
        );
        assert_eq!(resolved, "/explicit/sandboxd.sock");
    }

    #[test]
    fn env_override_wins_over_discovery() {
        let resolved =
            resolve_socket_path_from("", Some("/from/env.sock"), &candidates(), |_| true);
        assert_eq!(resolved, "/from/env.sock");
    }

    #[test]
    fn blank_configured_and_env_fall_through_to_discovery() {
        let resolved = resolve_socket_path_from("   ", Some("  "), &candidates(), |p| {
            p.starts_with("/second")
        });
        assert_eq!(resolved, "/second/sandboxd.sock");
    }

    #[test]
    fn discovery_picks_the_first_candidate_that_exists() {
        let resolved = resolve_socket_path_from("", None, &candidates(), |_| true);
        assert_eq!(resolved, "/first/sandboxd.sock");
    }

    #[test]
    fn discovery_falls_back_to_last_candidate_when_none_exist() {
        // Keeps connect errors naming a concrete path rather than "".
        let resolved = resolve_socket_path_from("", None, &candidates(), |_| false);
        assert_eq!(resolved, "/second/sandboxd.sock");
    }

    #[test]
    fn platform_candidates_are_non_empty_and_well_formed() {
        let candidates = socket_path_candidates();
        assert!(!candidates.is_empty());
        for candidate in &candidates {
            assert!(!candidate.trim().is_empty());
            #[cfg(unix)]
            assert_eq!(
                Path::new(candidate)
                    .extension()
                    .and_then(std::ffi::OsStr::to_str),
                Some("sock"),
                "unexpected: {candidate}"
            );
            #[cfg(windows)]
            assert!(
                candidate.starts_with(r"\\.\pipe\"),
                "unexpected: {candidate}"
            );
        }
    }

    #[test]
    fn default_config_defers_socket_path_to_discovery() {
        assert!(
            DockerSandboxesComputeConfig::default()
                .socket_path
                .is_empty()
        );
    }

    const TEST_ID: &str = "41557bb3-21ef-4356-837f-100005a520c3";

    #[test]
    fn sandboxd_name_round_trips_id_and_name() {
        let encoded = encode_sandboxd_name(TEST_ID, "abcdef").expect("encodes");
        assert!(encoded.starts_with("os-"), "{encoded}");
        assert!(encoded.ends_with("-abcdef"), "{encoded}");
        assert_eq!(encoded.len(), 3 + ENCODED_ID_LEN + 1 + 6);
        assert_eq!(
            decode_sandboxd_name(&encoded),
            Some((TEST_ID.to_string(), "abcdef".to_string()))
        );
    }

    #[test]
    fn sandboxd_name_round_trips_names_containing_separators() {
        // The id is fixed width, so hyphens and dots in the name stay
        // unambiguous — the case a naive split on '-' would corrupt.
        for name in ["my-sandbox-1", "v1.2.3", "a-b.c-d"] {
            let encoded = encode_sandboxd_name(TEST_ID, name).expect("encodes");
            let (id, decoded) = decode_sandboxd_name(&encoded).expect("decodes");
            assert_eq!(id, TEST_ID);
            assert_eq!(decoded, name);
        }
    }

    #[test]
    fn foreign_and_legacy_sandboxd_names_do_not_decode() {
        // Created directly with `sbx`.
        assert_eq!(decode_sandboxd_name("claude-myrepo"), None);
        // Earlier schemes: bare UUID, and the hex-encoded prefix form.
        assert_eq!(decode_sandboxd_name(TEST_ID), None);
        assert_eq!(
            decode_sandboxd_name("openshell-41557bb321ef4356837f100005a520c3-abcdef"),
            None
        );
        // Right prefix, but the id field is not base36.
        assert_eq!(
            decode_sandboxd_name("os-!!!!!!!!!!!!!!!!!!!!!!!!!-abcdef"),
            None
        );
        // Prefix and id present, name missing.
        let no_name = format!("os-{}-", to_base36_padded(0));
        assert_eq!(decode_sandboxd_name(&no_name), None);
    }

    #[test]
    fn foreign_sandboxes_are_not_reported_as_snapshots() {
        let foreign = SandboxInfo {
            name: "claude-myrepo".to_string(),
            status: "running".to_string(),
            created_at: String::new(),
        };
        assert!(sandbox_from_info(&foreign).is_none());

        let ours = SandboxInfo {
            name: encode_sandboxd_name(TEST_ID, "abcdef").expect("encodes"),
            status: "running".to_string(),
            created_at: String::new(),
        };
        let snapshot = sandbox_from_info(&ours).expect("ours decodes");
        assert_eq!(snapshot.id, TEST_ID);
        assert_eq!(snapshot.name, "abcdef");
    }

    #[test]
    fn not_yet_created_sandbox_reports_container_created_not_stopped() {
        // No `created_at` — the container hasn't finished being created yet
        // (the transient window right after `POST /sandbox` returns, before
        // the container actually starts), not a real stop. "ContainerCreated"
        // is one of the gateway's own canonical non-terminal reasons
        // (`is_terminal_failure_reason` in `openshell-server::compute`) —
        // anything else here gets treated as a hard failure instead of
        // normal startup.
        let info = SandboxInfo {
            name: encode_sandboxd_name(TEST_ID, "abcdef").expect("encodes"),
            status: "stopped".to_string(),
            created_at: String::new(),
        };
        let snapshot = sandbox_from_info(&info).expect("decodes");
        let condition = &snapshot.status.expect("has status").conditions[0];
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "ContainerCreated");
    }

    #[test]
    fn a_real_stopped_sandbox_reports_container_stopped() {
        // `created_at` present — a container that existed and has since
        // been stopped, distinct from one that was never created.
        let info = SandboxInfo {
            name: encode_sandboxd_name(TEST_ID, "abcdef").expect("encodes"),
            status: "stopped".to_string(),
            created_at: "2026-08-13T01:00:00Z".to_string(),
        };
        let snapshot = sandbox_from_info(&info).expect("decodes");
        let condition = &snapshot.status.expect("has status").conditions[0];
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "ContainerStopped");
    }

    #[test]
    fn base36_round_trips_boundary_values() {
        for raw in [0u128, 1, 36, u128::MAX] {
            let encoded = to_base36_padded(raw);
            assert_eq!(encoded.len(), ENCODED_ID_LEN, "{encoded}");
            assert!(
                encoded
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            );
            assert_eq!(from_base36(&encoded), Some(raw));
        }
        // Wrong width and non-base36 input are rejected, not silently coerced.
        assert_eq!(from_base36("abc"), None);
        assert_eq!(from_base36(&"!".repeat(ENCODED_ID_LEN)), None);
    }

    #[test]
    fn longest_generated_petname_fits() {
        // The gateway names sandboxes with petname(2, "-"). The word lists cap
        // at a 25-char adjective and an 11-char noun, so 37 characters is the
        // worst case a generated name can produce. This is why the id is
        // base36 rather than hex: hex left only 20 characters for the name and
        // would have failed ~14% of creates.
        let worst = format!("{}-{}", "a".repeat(25), "b".repeat(11));
        assert_eq!(worst.len(), 37);
        let encoded = encode_sandboxd_name(TEST_ID, &worst);
        assert!(
            encoded.is_ok() || worst.len() > MAX_SANDBOXD_NAME_LEN - (3 + ENCODED_ID_LEN + 1),
            "worst-case petname must encode or be explicitly over budget"
        );
        // A realistic petname must always fit.
        let real = encode_sandboxd_name(TEST_ID, "anointed-rockfish").expect("encodes");
        assert!(
            real.len() <= MAX_SANDBOXD_NAME_LEN,
            "{real} ({})",
            real.len()
        );
        assert_eq!(
            decode_sandboxd_name(&real),
            Some((TEST_ID.to_string(), "anointed-rockfish".to_string()))
        );
    }

    #[test]
    fn overlong_name_is_rejected_with_an_actionable_error() {
        let err = encode_sandboxd_name(TEST_ID, &"x".repeat(64)).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        // The message must name both the actual length and the budget, so the
        // operator can shorten the name without reading the source.
        let msg = err.message();
        assert!(msg.contains("64 characters"), "{msg}");
        assert!(msg.contains("34"), "{msg}");
        assert!(encode_sandboxd_name(TEST_ID, "abcdef").is_ok());
    }

    #[test]
    fn names_outside_sandboxd_charset_are_rejected_before_the_daemon_sees_them() {
        let err = encode_sandboxd_name(TEST_ID, "has_underscore").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains('_'), "{}", err.message());
    }

    #[test]
    fn non_uuid_sandbox_id_is_rejected() {
        let err = encode_sandboxd_name("not-a-uuid", "abcdef").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn list_entry_without_created_at_still_decodes() {
        // sandboxd omits `created_at` for a sandbox whose container is gone.
        // Regression: this used to fail the whole decode, stalling the poll
        // loop for every sandbox, not just this entry.
        let body = r#"[
            {"id":"a","name":"has-container","status":"running",
             "created_at":"2026-08-13T01:00:00Z"},
            {"id":"b","name":"no-container","status":"stopped"}
        ]"#;

        let infos: Vec<SandboxInfo> = serde_json::from_str(body).expect("decodes");

        assert_eq!(infos.len(), 2);
        assert_eq!(infos[1].name, "no-container");
        assert_eq!(infos[1].created_at, "");
        assert_eq!(infos[0].created_at, "2026-08-13T01:00:00Z");
    }

    #[test]
    fn list_entry_ignores_fields_the_driver_does_not_model() {
        // The wire type carries many optional fields; unknown ones must not
        // break decoding as sandboxd's API grows.
        let body = r#"[{"id":"a","name":"s1","status":"running",
            "agent":"openshell","labels":{"k":"v"},"ports":[],
            "stopped_at":"2026-08-13T01:00:00Z"}]"#;

        let infos: Vec<SandboxInfo> = serde_json::from_str(body).expect("decodes");

        assert_eq!(infos[0].name, "s1");
        assert_eq!(infos[0].status, "running");
    }

    #[test]
    fn list_entry_still_requires_name_and_status() {
        // These two are non-omitempty in sandboxd's schema; a missing one is a
        // genuine protocol error and must not be silently defaulted.
        assert!(
            serde_json::from_str::<Vec<SandboxInfo>>(r#"[{"id":"a","status":"running"}]"#).is_err()
        );
        assert!(serde_json::from_str::<Vec<SandboxInfo>>(r#"[{"id":"a","name":"s1"}]"#).is_err());
    }
}

/// Windows named-pipe transport tests.
///
/// These stand a fake sandboxd up on a real named pipe and drive
/// [`DockerSandboxesComputeDriver::daemon_request`] against it, so the
/// `#[cfg(windows)]` connect path is executed rather than merely compiled.
/// The fake daemon speaks HTTP/1 by hand so the assertions can look at the
/// exact request bytes the driver puts on the wire.
#[cfg(all(test, windows))]
mod windows_named_pipe_tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use tokio::task::JoinHandle;

    /// Upper bound on a single fake-daemon exchange. Keeps a wedged test
    /// failing instead of hanging the suite.
    const FAKE_DAEMON_TIMEOUT: Duration = Duration::from_secs(10);

    static PIPE_SEQUENCE: AtomicU32 = AtomicU32::new(0);

    /// A pipe name unique to this test, process, and call, so the tests can
    /// run in parallel with each other and with other test binaries.
    fn pipe_name(test: &str) -> String {
        let sequence = PIPE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        format!(
            r"\\.\pipe\openshell-sandboxd-test-{test}-{}-{sequence}",
            std::process::id()
        )
    }

    /// A driver pinned to `socket_path` and nothing else — these tests only
    /// exercise the transport, so the remaining config is inert.
    fn driver_at(socket_path: &str) -> DockerSandboxesComputeDriver {
        DockerSandboxesComputeDriver {
            config: Arc::new(DriverConfig {
                socket_path: socket_path.to_string(),
                default_workspace: String::new(),
                openshell_endpoint: String::new(),
                template_image: String::new(),
                ssh_socket_path: String::new(),
                log_level: String::new(),
                daemon_version: String::new(),
                profile: None,
                supervisor_bin_path: PathBuf::from("unused-in-these-tests"),
            }),
            events: broadcast::channel(WATCH_BUFFER).0,
        }
    }

    /// Create the first instance of a fresh pipe, failing if the name is
    /// already taken by another process.
    fn listen(name: &str) -> NamedPipeServer {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create(name)
            .expect("create fake sandboxd pipe")
    }

    fn http_response(status_line: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    /// Split a raw request into its header block and its body.
    fn split_request(raw: &str) -> Option<(&str, &str)> {
        let head_end = raw.find("\r\n\r\n")?;
        let (head, rest) = raw.split_at(head_end);
        Some((head, &rest["\r\n\r\n".len()..]))
    }

    fn header(head: &str, name: &str) -> Option<String> {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_string())
    }

    /// A request is complete once the header block has arrived along with as
    /// many body bytes as `Content-Length` promised.
    fn request_is_complete(raw: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(raw) else {
            return false;
        };
        let Some((head, body)) = split_request(text) else {
            return false;
        };
        let expected = header(head, "content-length").map_or(0, |value| {
            value.parse::<usize>().expect("numeric content-length")
        });
        body.len() >= expected
    }

    async fn read_request(server: &mut NamedPipeServer) -> String {
        let mut raw = Vec::new();
        let mut chunk = [0_u8; 512];
        while !request_is_complete(&raw) {
            let read = server.read(&mut chunk).await.expect("read request");
            assert!(read > 0, "client closed before sending a complete request");
            raw.extend_from_slice(&chunk[..read]);
        }
        String::from_utf8(raw).expect("driver requests in these tests are ASCII")
    }

    /// Accept one connection, answer it with `response`, and return the raw
    /// request bytes. Stays connected until the driver hangs up so the
    /// response is fully drained before the pipe instance goes away.
    async fn serve_once(mut server: NamedPipeServer, response: String) -> String {
        server.connect().await.expect("fake sandboxd accept");
        let request = read_request(&mut server).await;
        server
            .write_all(response.as_bytes())
            .await
            .expect("write response");
        let mut drained = Vec::new();
        let _ = server.read_to_end(&mut drained).await;
        request
    }

    async fn joined(handle: JoinHandle<String>) -> String {
        tokio::time::timeout(FAKE_DAEMON_TIMEOUT, handle)
            .await
            .expect("fake sandboxd timed out")
            .expect("fake sandboxd panicked")
    }

    #[tokio::test]
    async fn get_over_named_pipe_returns_status_and_body() {
        let name = pipe_name("get");
        let body = r#"{"version":"9.9.9"}"#;
        let served = tokio::spawn(serve_once(listen(&name), http_response("200 OK", body)));

        let (status, bytes) = driver_at(&name)
            .daemon_request(http::Method::GET, "/daemon/health", None)
            .await
            .expect("GET over the named pipe");

        assert_eq!(status, 200);
        assert_eq!(&bytes[..], body.as_bytes());

        let request = joined(served).await;
        let (head, request_body) = split_request(&request).expect("well-formed request");
        assert!(
            head.starts_with("GET /daemon/health HTTP/1.1\r\n"),
            "unexpected request head: {head}"
        );
        assert_eq!(header(head, "host").as_deref(), Some("localhost"));
        assert!(request_body.is_empty(), "unexpected body: {request_body}");
        // A bodyless request must not advertise a JSON payload.
        assert_eq!(header(head, "content-type"), None);
    }

    #[tokio::test]
    async fn post_over_named_pipe_sends_body_and_json_headers() {
        let name = pipe_name("post");
        let served = tokio::spawn(serve_once(
            listen(&name),
            http_response("201 Created", "{}"),
        ));

        let payload = r#"{"agent":"openshell","name":"sandbox-1"}"#;
        let (status, _) = driver_at(&name)
            .daemon_request(
                http::Method::POST,
                "/sandbox",
                Some(Bytes::from_static(payload.as_bytes())),
            )
            .await
            .expect("POST over the named pipe");

        assert_eq!(status, 201);

        let request = joined(served).await;
        let (head, request_body) = split_request(&request).expect("well-formed request");
        assert!(
            head.starts_with("POST /sandbox HTTP/1.1\r\n"),
            "unexpected request head: {head}"
        );
        assert_eq!(
            header(head, "content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            header(head, "content-length"),
            Some(payload.len().to_string())
        );
        assert_eq!(request_body, payload);
    }

    #[tokio::test]
    async fn non_success_status_is_surfaced_not_swallowed() {
        let name = pipe_name("non-success");
        let served = tokio::spawn(serve_once(
            listen(&name),
            http_response("500 Internal Server Error", "boom"),
        ));

        let error = driver_at(&name)
            .list_infos()
            .await
            .expect_err("an HTTP 500 must reach the caller");

        assert_eq!(error.code(), tonic::Code::Internal);
        assert!(
            error.message().contains("HTTP 500") && error.message().contains("boom"),
            "unexpected error: {}",
            error.message()
        );

        let request = joined(served).await;
        assert!(
            request.starts_with("GET /sandbox HTTP/1.1\r\n"),
            "unexpected request: {request}"
        );
    }

    /// Every instance of the pipe is busy when the driver first dials, and one
    /// only becomes available later: the connect must ride out
    /// `ERROR_PIPE_BUSY` instead of failing.
    #[tokio::test]
    async fn connect_retries_while_every_pipe_instance_is_busy() {
        let name = pipe_name("busy");
        // One instance exists and a squatter client holds it, so the pipe name
        // resolves but has no instance in the listening state. Further connects
        // fail with ERROR_PIPE_BUSY until another instance is created.
        let busy_instance = listen(&name);
        let squatter = ClientOptions::new()
            .open(&name)
            .expect("occupy the only pipe instance");

        let idle = PIPE_BUSY_RETRY_INTERVAL * 3;
        let served = {
            let name = name.clone();
            tokio::spawn(async move {
                tokio::time::sleep(idle).await;
                let server = ServerOptions::new()
                    .create(&name)
                    .expect("second pipe instance");
                serve_once(server, http_response("200 OK", "[]")).await
            })
        };

        let started = tokio::time::Instant::now();
        let (status, bytes) = driver_at(&name)
            .daemon_request(http::Method::GET, "/sandbox", None)
            .await
            .expect("connect must survive ERROR_PIPE_BUSY");
        let elapsed = started.elapsed();

        assert_eq!(status, 200);
        assert_eq!(&bytes[..], b"[]");
        assert!(
            elapsed >= PIPE_BUSY_RETRY_INTERVAL,
            "connect returned after {elapsed:?}, so the busy-retry path never ran"
        );

        let request = joined(served).await;
        assert!(
            request.starts_with("GET /sandbox HTTP/1.1\r\n"),
            "unexpected request: {request}"
        );

        drop(squatter);
        drop(busy_instance);
    }

    #[tokio::test]
    async fn connect_to_a_missing_pipe_reports_unavailable_with_the_path() {
        let name = pipe_name("missing");

        let error = driver_at(&name)
            .daemon_request(http::Method::GET, "/sandbox", None)
            .await
            .expect_err("no daemon is listening on this pipe");

        assert_eq!(error.code(), tonic::Code::Unavailable);
        assert!(
            error.message().contains(&name),
            "error should name the pipe: {}",
            error.message()
        );
    }
}
