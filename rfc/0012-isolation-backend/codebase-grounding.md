# Codebase grounding (supporting material for RFC 0012)

This file backs the claims [RFC 0012](./README.md) makes about the current
system, so a reviewer can verify them. It is supporting material, not part of the
normative RFC.

Verified against the RFC's parent commit `4ee27d99` (`origin/main` has since
advanced; these references are pinned to that parent). After #1650 the supervisor
split into `openshell-supervisor-network` (proxy, OPA, procfs identity) and
`openshell-supervisor-process` (spawn, SSH, netns creation, seccomp/Landlock).
References are line-pinned and will drift; the `rg` patterns let a reviewer
re-locate them.

| Claim | Reference |
|---|---|
| Agent container's seven capabilities | `crates/openshell-driver-kubernetes/src/driver.rs:1397` (base `SYS_ADMIN`/`NET_ADMIN`/`SYS_PTRACE`/`SYSLOG`), `:1403` (`SETUID`/`SETGID`/`DAC_READ_SEARCH` under userns) |
| Spec already separated from the netns handle | `crates/openshell-supervisor-process/src/process.rs:392`/`:406` (`ProcessHandle::spawn` takes `netns: Option<&NetworkNamespace>`) |
| Six `setns(CLONE_NEWNET)` sites (plus a `CLONE_NEWNS` at `:353`) | `process.rs:549`, `ssh.rs:619`/`:1186`, `supervisor_session.rs:610`, `netns/mod.rs:226`/`:363` (`rg -n "CLONE_NEWNET" crates/openshell-supervisor-process`) |
| `nft`-absent fail-open (the invariant bug) | `crates/openshell-supervisor-process/src/netns/mod.rs:264`; logs and returns `Ok(())` at `:272`-`:277` |
| VM driver enables forwarding/MASQUERADE (host-forward assumption is load-bearing) | `crates/openshell-driver-vm/src/runtime.rs:417`/`:436` |
| No `StartSandbox` RPC (create and start fused; no driver start gate) | `proto/compute_driver.proto` has `CreateSandbox`/`StopSandbox`/`DeleteSandbox` only |
| Gateway already speaks exec/session/port-forward; no literal `Attach` | `proto/openshell.proto` (`ExecSandbox`, `ExecSandboxInteractive`, `CreateSshSession`, `ForwardTcp`) |
| Agent command via CLI/`SANDBOX_COMMAND`; no admission-bound spec field today | `crates/openshell-sandbox/src/main.rs:331`; K8s driver sets `sleep infinity` at `driver.rs:1747` |
| Init containers: `copy-self` (trusted) and `workspace-init` (agent image, root); no native sidecars today | `driver.rs:880`, `:1072`; `rg -n "restart_policy" crates/openshell-driver-kubernetes/src` |
| Network policy is OPA per-CONNECT, not the boundary; identity via procfs | `crates/openshell-supervisor-network/src/opa.rs` (`NetworkInput`: `binary_path`/`binary_sha256`/`ancestors`/`cmdline_paths`), `procfs.rs`, glued in `proxy.rs:1432` |
| Static privilege ceiling on every spawned process; OPA never evaluates exec | `process.rs:400` (`drop_privileges`, seccomp/Landlock `enforce` from `SandboxPolicy`; SSH reaches the same `enter_netns_and_sandbox`) |
