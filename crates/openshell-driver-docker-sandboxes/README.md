# openshell-driver-docker-sandboxes

A [`ComputeDriver`](../../proto/compute_driver.proto) that runs OpenShell sandboxes on Docker Sandboxes. Point OpenShell at a running `sandboxd`, and it creates, stops, starts, and deletes sandboxes there.

## Requirements

`sandboxd` running locally (`sbx daemon status`).

## Quick start

From a checkout of this repo:

```shell
mise run gateway:docker-sandboxes
```

This builds the gateway with the driver embedded, starts it on `127.0.0.1:18082`, and sets it as your active CLI gateway:

```shell
openshell sandbox create
openshell sandbox exec -n <name> -- echo hi
openshell sandbox delete <name>
```

See `tasks/scripts/gateway-docker-sandboxes.sh` for the environment variables that override the defaults (port, gateway name, state directory).

## Configuration

`DockerSandboxesComputeConfig` (TOML `[openshell.drivers.docker-sandboxes]`, or the standalone binary's flags in parentheses):

| Field | Default | Purpose |
|---|---|---|
| `socket_path` (`--sandboxd-socket-path`/`DOCKER_SANDBOXES_API`) | discovered at runtime | `sandboxd`'s socket. |
| `default_workspace` (`--default-workspace`) | `/tmp` (Unix) / temp dir (Windows) | Base directory for sandbox workspaces. |
| `template_image` (`--template-image`/`OPENSHELL_DOCKER_SANDBOXES_TEMPLATE_IMAGE`) | driver-managed default | Overrides the driver's default sandbox image. |
| `openshell_endpoint` (`--openshell-endpoint`, required on the standalone binary) | none | OpenShell gateway endpoint the supervisor calls back to. |
| `supervisor_bin` (`--supervisor-bin`) | unset | Explicit host path to a Linux ELF `openshell-sandbox` binary. Takes precedence over `supervisor_release_tag`. |
| `supervisor_release_tag` (`--supervisor-release-tag`/`OPENSHELL_SUPERVISOR_RELEASE_TAG`) | tracks this crate's version | Release of the supervisor binary to use. |
| `ssh_socket_path` | `/run/openshell/ssh.sock` | In-container path for the supervisor's SSH relay socket. Rarely needs overriding. |
| `profile` (`--profile`/`OPENSHELL_DOCKER_SANDBOXES_PROFILE`) | unset | Named governance profile assigned to every sandbox by default — see "Governance profiles" below. |

## Governance profiles

Some `sandboxd` deployments require every sandbox to carry a named governance profile (`sbx policy profile ls`). Two levels, per-sandbox wins:

1. **Driver-wide default** — the `profile` config field above.
2. **Per-sandbox override** — `driver_config.profile` in a create request's `SandboxTemplate.driver_config`.

An unknown profile name fails the create with a clear error.

## Known limitations

- **Locally-built images aren't visible yet.** `openshell sandbox create --from <Dockerfile>` needs the image pushed to a registry first; a registry-resolvable `template.image` works as-is.
- **No GPU support yet.**
- **No generalized out-of-process auto-spawn yet.** `docker-sandboxes-in-tree` is a local-dev stopgap.

## Architecture

```
openshell-gateway ──gRPC──▶ driver ──HTTP (UDS)──▶ sandboxd ──▶ sandbox
        ▲                                                          │
        └──────────────── supervisor connects back ────────────────┘
```

The driver talks to `sandboxd` over its local socket to create, list, stop, start, and delete sandboxes. Each sandbox runs the OpenShell supervisor, which connects back to the gateway directly — the driver isn't on that path.

The driver starts the supervisor via a kit startup command once the sandbox is already up, on top of a small default image it builds itself the first time it runs and reuses afterward; the supervisor binary itself is fetched from a release and injected into every sandbox at create time. See `base_image.rs` and `supervisor.rs`.

## Contract conformance

Tracked against `proto/compute_driver.proto`'s full `ComputeDriver` service.

### RPCs

All ten RPCs are supported: `GetCapabilities`, `GetGatewayListenerRequirements` (no requirement — `sandboxd` manages container networking directly), `ValidateSandboxCreate`, `GetSandbox`, `ListSandboxes`, `CreateSandbox`, `StopSandbox`/`StartSandbox` (the container is retained, not removed), `DeleteSandbox`, and `WatchSandboxes`.

### `DriverSandboxTemplate` / `DriverSandboxSpec` fields

| Field | Status | Notes |
|---|---|---|
| `image` | Supported | |
| `environment` | Supported | |
| `resources.cpu_limit` / `memory_limit` | Supported | Mapped to a fixed vCPU/memory size for the sandbox; `memory_limit` below 1Gi is rejected. |
| `resources.cpu_request` / `memory_request` | Rejected | A sandbox is sized once, as a fixed allocation, rather than a separate request/limit pair. |
| `resource_requirements.gpu` | Rejected | See "Known limitations". |
| `labels` | Not supported | Sandbox identity rides in the sandbox name instead. |
| `agent_socket_path` | Rejected | Not applicable to this driver's agent setup. |
| `platform_config` | Ignored (per contract) | |
| `driver_config` | Supported (`profile`) | See "Governance profiles". |
| `sandbox_token` | Supported | Delivered via a per-sandbox host file, matching the Docker/Podman/VM drivers' own convention. |

## Development

`kits/openshell/spec.yaml`/`artifact.json` are the agent kit shipped inline on every create — see `kits/openshell/README.md` to edit and regenerate.

Two ways to run the driver locally, both wrapped by `mise run gateway:docker-sandboxes`:

- **Single process** — build the gateway with `cargo build -p openshell-server --bin openshell-gateway --features docker-sandboxes-in-tree` and run it with `--drivers docker-sandboxes`.
- **Out-of-process** (what released builds do) — run `openshell-driver-docker-sandboxes` as its own binary and point the gateway at it with `--compute-driver-socket`.

For either, without a full mTLS/OIDC setup you'll need `--disable-tls`, a `--config` TOML with `[openshell.gateway.auth] allow_unauthenticated_users = true`, and a `[openshell.gateway.gateway_jwt]` block pointing at certs from `openshell-gateway generate-certs` — without it, the supervisor's policy fetch fails immediately.
