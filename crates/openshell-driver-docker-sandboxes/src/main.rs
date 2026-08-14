// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone `docker-sandboxes` compute driver process.
//!
//! Ships the driver out-of-tree to unmodified `OpenShell` installations: it
//! serves `compute_driver.proto` over a Unix domain socket, and the gateway
//! consumes it via `--drivers docker-sandboxes --compute-driver-socket
//! <path>` (or `[openshell.drivers.docker-sandboxes] socket_path` in TOML) —
//! no core gateway changes required, since a driver name that isn't one of
//! the built-in kinds already dispatches generically to a remote socket.
//! Template mirrors `openshell-driver-vm`'s standalone binary.

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "openshell-driver-docker-sandboxes only supports running as a standalone process on Unix; \
         the gateway's remote-driver dialer is Unix-socket-only on every platform."
    );
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::net::SocketAddr;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use clap::Parser;
    use futures::Stream;
    use openshell_core::VERSION;
    use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriverServer;
    use openshell_driver_docker_sandboxes::{
        DockerSandboxesComputeConfig, DockerSandboxesComputeDriver,
    };
    use tokio::net::{UnixListener, UnixStream};
    use tracing::info;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    #[derive(Parser, Debug)]
    #[command(name = "openshell-driver-docker-sandboxes")]
    #[command(version = VERSION)]
    struct Args {
        #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_BIND")]
        bind_address: Option<SocketAddr>,

        #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
        bind_socket: Option<PathBuf>,

        #[arg(long, hide = true)]
        expected_peer_pid: Option<u32>,

        #[arg(
            long,
            env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_UNAUTHENTICATED_TCP",
            default_value_t = false
        )]
        allow_unauthenticated_tcp: bool,

        #[arg(
            long,
            env = "OPENSHELL_COMPUTE_DRIVER_ALLOW_SAME_UID_PEER",
            default_value_t = false
        )]
        allow_same_uid_peer: bool,

        #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
        log_level: String,

        #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
        openshell_endpoint: String,

        #[arg(long, env = "DOCKER_SANDBOXES_SOCKET_PATH", default_value = "")]
        sandboxd_socket_path: String,

        #[arg(long, env = "OPENSHELL_SANDBOX_WORKSPACE", default_value = "")]
        default_workspace: String,

        /// Sandbox image to boot, overriding the driver's own default. See
        /// the crate README ("How it works") for what a custom image needs
        /// to tolerate.
        #[arg(long, env = "OPENSHELL_DOCKER_SANDBOXES_TEMPLATE_IMAGE")]
        template_image: Option<String>,

        #[arg(long, env = "OPENSHELL_SUPERVISOR_BIN")]
        supervisor_bin: Option<PathBuf>,

        #[arg(long, env = "OPENSHELL_SUPERVISOR_RELEASE_TAG")]
        supervisor_release_tag: Option<String>,

        /// Named governance profile assigned to every sandbox by default,
        /// unless a create request overrides it. Defined by a
        /// remote/organization-managed governance policy; sandboxd rejects
        /// unknown names at create time.
        #[arg(long, env = "OPENSHELL_DOCKER_SANDBOXES_PROFILE")]
        profile: Option<String>,
    }

    pub fn main() -> std::process::ExitCode {
        let args = Args::parse();
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("failed to start tokio runtime: {err}");
                return std::process::ExitCode::FAILURE;
            }
        };
        match runtime.block_on(run(args)) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(err) => {
                tracing::error!(error = %err, "openshell-driver-docker-sandboxes exiting");
                std::process::ExitCode::FAILURE
            }
        }
    }

    async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
        tracing_subscriber::registry()
            .with(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        let listen_mode = compute_driver_listen_mode(&args)?;

        // Exit if the gateway that spawned us dies, so a gateway crash
        // doesn't orphan this driver (and the sandboxd polling it holds
        // open) forever.
        spawn_parent_death_watchdog();

        let mut docker_sandboxes_config = DockerSandboxesComputeConfig {
            supervisor_bin: args.supervisor_bin.clone(),
            supervisor_release_tag: args.supervisor_release_tag.clone(),
            template_image: args.template_image.clone(),
            profile: args.profile.clone(),
            ..DockerSandboxesComputeConfig::default()
        };
        if !args.sandboxd_socket_path.trim().is_empty() {
            docker_sandboxes_config.socket_path = args.sandboxd_socket_path.clone();
        }
        if !args.default_workspace.trim().is_empty() {
            docker_sandboxes_config.default_workspace = args.default_workspace.clone();
        }

        let driver = DockerSandboxesComputeDriver::new(
            &args.openshell_endpoint,
            &args.log_level,
            &docker_sandboxes_config,
        )
        .await
        .map_err(|err| format!("failed to start docker-sandboxes driver: {err}"))?;

        match listen_mode {
            ComputeDriverListenMode::Unix {
                socket_path,
                expected_peer_pid,
            } => {
                prepare_compute_driver_socket(&socket_path)?;

                info!(socket = %socket_path.display(), "Starting docker-sandboxes compute driver");
                let listener = UnixListener::bind(&socket_path)?;
                restrict_socket_permissions(&socket_path)?;
                let result = tonic::transport::Server::builder()
                    .add_service(ComputeDriverServer::new(driver))
                    .serve_with_incoming_shutdown(
                        AuthenticatedUnixIncoming::new(listener, expected_peer_pid),
                        shutdown_signal(),
                    )
                    .await;
                let _ = std::fs::remove_file(&socket_path);
                result.map_err(Into::into)
            }
            ComputeDriverListenMode::Tcp(bind_address) => {
                info!(address = %bind_address, "Starting unauthenticated dev docker-sandboxes compute driver");
                tonic::transport::Server::builder()
                    .add_service(ComputeDriverServer::new(driver))
                    .serve_with_shutdown(bind_address, shutdown_signal())
                    .await
                    .map_err(Into::into)
            }
        }
    }

    async fn shutdown_signal() {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "failed to listen for Ctrl-C");
                }
            }
            _ = terminate.recv() => {}
        }
        info!("Shutdown signal received; stopping docker-sandboxes compute driver");
    }

    /// Exit the process once our parent (the gateway that spawned us) dies.
    /// A dead parent reparents us to PID 1 (Unix) — poll for that rather
    /// than pulling in a signal-based watcher, since a lost gateway isn't
    /// latency-sensitive.
    fn spawn_parent_death_watchdog() {
        let initial_ppid = rustix::process::getppid();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if rustix::process::getppid() != initial_ppid {
                    tracing::warn!(
                        "parent process exited; shutting down docker-sandboxes compute driver"
                    );
                    std::process::exit(1);
                }
            }
        });
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ComputeDriverListenMode {
        Unix {
            socket_path: PathBuf,
            expected_peer_pid: Option<u32>,
        },
        Tcp(SocketAddr),
    }

    fn compute_driver_listen_mode(args: &Args) -> Result<ComputeDriverListenMode, String> {
        if let Some(socket_path) = args.bind_socket.clone() {
            if args.expected_peer_pid.is_none() && !args.allow_same_uid_peer {
                return Err(
                    "--expected-peer-pid is required with --bind-socket; use --allow-same-uid-peer only for local development"
                        .to_string(),
                );
            }
            return Ok(ComputeDriverListenMode::Unix {
                socket_path,
                expected_peer_pid: args.expected_peer_pid,
            });
        }

        if !args.allow_unauthenticated_tcp {
            return Err(
                "--bind-socket is required; unauthenticated TCP mode is disabled unless --allow-unauthenticated-tcp is set for local development"
                    .to_string(),
            );
        }

        let Some(bind_address) = args.bind_address else {
            return Err("--bind-address is required with --allow-unauthenticated-tcp".to_string());
        };

        Ok(ComputeDriverListenMode::Tcp(bind_address))
    }

    fn prepare_compute_driver_socket(socket_path: &Path) -> Result<(), String> {
        let Some(parent) = socket_path.parent() else {
            return Err(format!(
                "docker-sandboxes compute driver socket path '{}' has no parent directory",
                socket_path.display()
            ));
        };
        let expected_uid = current_euid();
        prepare_private_socket_dir(parent, expected_uid)?;
        remove_stale_socket(socket_path, expected_uid)
    }

    fn current_euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn prepare_private_socket_dir(socket_dir: &Path, expected_uid: u32) -> Result<(), String> {
        std::fs::create_dir_all(socket_dir)
            .map_err(|err| format!("create socket dir {}: {err}", socket_dir.display()))?;
        let metadata = std::fs::symlink_metadata(socket_dir)
            .map_err(|err| format!("stat socket dir {}: {err}", socket_dir.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "socket dir {} is a symlink; refusing to use it",
                socket_dir.display()
            ));
        }
        if !file_type.is_dir() {
            return Err(format!(
                "socket dir {} is not a directory",
                socket_dir.display()
            ));
        }
        if metadata.uid() != expected_uid {
            return Err(format!(
                "socket dir {} is owned by uid {} but current euid is {}",
                socket_dir.display(),
                metadata.uid(),
                expected_uid
            ));
        }
        std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| format!("chmod socket dir {}: {err}", socket_dir.display()))
    }

    fn remove_stale_socket(socket_path: &Path, expected_uid: u32) -> Result<(), String> {
        let metadata = match std::fs::symlink_metadata(socket_path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(format!("stat socket {}: {err}", socket_path.display())),
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "socket {} is a symlink; refusing to remove it",
                socket_path.display()
            ));
        }
        if metadata.uid() != expected_uid {
            return Err(format!(
                "socket {} is owned by uid {} but current euid is {}",
                socket_path.display(),
                metadata.uid(),
                expected_uid
            ));
        }
        if !file_type.is_socket() {
            return Err(format!(
                "socket path {} exists but is not a Unix socket",
                socket_path.display()
            ));
        }
        std::fs::remove_file(socket_path)
            .map_err(|err| format!("remove stale socket {}: {err}", socket_path.display()))
    }

    fn restrict_socket_permissions(socket_path: &Path) -> Result<(), String> {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("chmod socket {}: {err}", socket_path.display()))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PeerCredentials {
        uid: u32,
        pid: Option<i32>,
    }

    fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, String> {
        let credentials = stream
            .peer_cred()
            .map_err(|err| format!("read peer credentials: {err}"))?;
        Ok(PeerCredentials {
            uid: credentials.uid(),
            pid: credentials.pid(),
        })
    }

    fn authorize_peer_credentials(
        peer: PeerCredentials,
        driver_uid: u32,
        gateway_pid: Option<u32>,
    ) -> Result<(), String> {
        if peer.uid != driver_uid {
            return Err(format!(
                "peer uid {} does not match current euid {}",
                peer.uid, driver_uid
            ));
        }
        let Some(gateway_pid) = gateway_pid else {
            return Ok(());
        };
        let Some(peer_process_id) = peer.pid.and_then(|pid| u32::try_from(pid).ok()) else {
            return Err(format!(
                "peer pid is unavailable; expected gateway pid {gateway_pid}"
            ));
        };
        if peer_process_id != gateway_pid {
            return Err(format!(
                "peer pid {peer_process_id} does not match expected gateway pid {gateway_pid}"
            ));
        }
        Ok(())
    }

    struct AuthenticatedUnixIncoming {
        listener: UnixListener,
        expected_uid: u32,
        expected_peer_pid: Option<u32>,
    }

    impl AuthenticatedUnixIncoming {
        fn new(listener: UnixListener, expected_peer_pid: Option<u32>) -> Self {
            Self {
                listener,
                expected_uid: current_euid(),
                expected_peer_pid,
            }
        }
    }

    impl Stream for AuthenticatedUnixIncoming {
        type Item = io::Result<UnixStream>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            loop {
                match this.listener.poll_accept(cx) {
                    Poll::Ready(Ok((stream, _addr))) => {
                        let authorized = peer_credentials(&stream).and_then(|peer| {
                            authorize_peer_credentials(
                                peer,
                                this.expected_uid,
                                this.expected_peer_pid,
                            )
                        });
                        match authorized {
                            Ok(()) => return Poll::Ready(Some(Ok(stream))),
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "rejected docker-sandboxes compute driver UDS client"
                                );
                            }
                        }
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            Args, ComputeDriverListenMode, PeerCredentials, authorize_peer_credentials,
            compute_driver_listen_mode,
        };
        use clap::Parser;
        use std::path::PathBuf;

        fn base_args(extra: &[&str]) -> Vec<String> {
            let mut argv = vec![
                "openshell-driver-docker-sandboxes".to_string(),
                "--openshell-endpoint".to_string(),
                "http://host.docker.internal:17670".to_string(),
            ];
            argv.extend(extra.iter().map(ToString::to_string));
            argv
        }

        #[test]
        fn peer_authorization_accepts_matching_uid_and_pid() {
            authorize_peer_credentials(
                PeerCredentials {
                    uid: 1000,
                    pid: Some(42),
                },
                1000,
                Some(42),
            )
            .unwrap();
        }

        #[test]
        fn peer_authorization_rejects_wrong_pid() {
            let err = authorize_peer_credentials(
                PeerCredentials {
                    uid: 1000,
                    pid: Some(7),
                },
                1000,
                Some(42),
            )
            .expect_err("wrong pid should be rejected");
            assert!(err.contains("does not match expected gateway pid"));
        }

        #[test]
        fn peer_authorization_rejects_wrong_uid() {
            let err = authorize_peer_credentials(
                PeerCredentials {
                    uid: 1001,
                    pid: Some(42),
                },
                1000,
                Some(42),
            )
            .expect_err("wrong uid should be rejected");
            assert!(err.contains("does not match current euid"));
        }

        #[test]
        fn listen_mode_rejects_default_tcp() {
            let args = Args::parse_from(base_args(&[]));
            let err =
                compute_driver_listen_mode(&args).expect_err("default TCP should be disabled");
            assert!(err.contains("--bind-socket is required"));
        }

        #[test]
        fn listen_mode_rejects_bind_address_without_tcp_opt_in() {
            let args = Args::parse_from(base_args(&["--bind-address", "127.0.0.1:50061"]));
            let err = compute_driver_listen_mode(&args)
                .expect_err("TCP bind should require explicit opt-in");
            assert!(err.contains("--allow-unauthenticated-tcp"));
        }

        #[test]
        fn listen_mode_accepts_explicit_unauthenticated_tcp() {
            let args = Args::parse_from(base_args(&[
                "--allow-unauthenticated-tcp",
                "--bind-address",
                "127.0.0.1:50061",
            ]));
            assert_eq!(
                compute_driver_listen_mode(&args).unwrap(),
                ComputeDriverListenMode::Tcp("127.0.0.1:50061".parse().unwrap())
            );
        }

        #[test]
        fn listen_mode_requires_expected_peer_pid_for_uds() {
            let args = Args::parse_from(base_args(&["--bind-socket", "/tmp/compute-driver.sock"]));
            let err = compute_driver_listen_mode(&args)
                .expect_err("UDS should require gateway peer pid by default");
            assert!(err.contains("--expected-peer-pid is required"));
        }

        #[test]
        fn listen_mode_accepts_uds_with_allow_same_uid_peer() {
            let args = Args::parse_from(base_args(&[
                "--bind-socket",
                "/tmp/compute-driver.sock",
                "--allow-same-uid-peer",
            ]));
            assert_eq!(
                compute_driver_listen_mode(&args).unwrap(),
                ComputeDriverListenMode::Unix {
                    socket_path: PathBuf::from("/tmp/compute-driver.sock"),
                    expected_peer_pid: None,
                }
            );
        }
    }
}
