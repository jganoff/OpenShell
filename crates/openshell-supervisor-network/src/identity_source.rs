// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod [`IdentitySource`] interface (RFC 0012 runtime contract).
//!
//! This is the in-pod identity resolver. It lives in this crate on purpose: the
//! proxy that consumes identity is here, and so are procfs and the binary
//! identity cache. The interface trait lives in the lower `openshell-isolation`
//! crate, so this crate depends on the trait (network -> isolation -> core,
//! acyclic) and the proxy can call a `&dyn IdentitySource` without depending on
//! the backend.
//!
//! Adoption note: the proxy hot path still resolves identity inline through
//! [`BinaryIdentityCache`](crate::identity::BinaryIdentityCache). Routing that
//! path through this trait (so a kernel-separated backend can return `Attested`
//! evidence over a guest channel) is the remaining live-adoption refactor.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use async_trait::async_trait;
use openshell_isolation::contract::{Flow, Identity, IdentitySource, ResolveError};

/// In-pod identity resolver: reads and hashes the connecting binary from procfs,
/// so the assurance is `Observed`.
pub struct ProcfsIdentitySource {
    /// The workload entrypoint PID, whose network namespace owns the peer
    /// sockets the proxy resolves. Published once the agent starts.
    pub entrypoint_pid: Arc<AtomicU32>,
}

/// Decode the in-pod flow token (a workload-side TCP peer port). Returns `None`
/// for any other token version, so an unknown flow shape fails closed rather
/// than being misread as a port.
fn in_pod_peer_port(flow: &Flow) -> Option<u16> {
    if flow.version() != 1 {
        return None;
    }
    let token = flow.token();
    let bytes: [u8; 2] = token.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

#[async_trait]
impl IdentitySource for ProcfsIdentitySource {
    async fn resolve(&self, flow: Flow) -> Result<Identity, ResolveError> {
        // procfs resolution is Linux-only; on other targets the supervisor has
        // no procfs to read, so the boundary cannot provide identity.
        #[cfg(target_os = "linux")]
        {
            self.resolve_via_procfs(&flow)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = flow;
            Ok(Identity::Unsupported)
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcfsIdentitySource {
    fn resolve_via_procfs(&self, flow: &Flow) -> Result<Identity, ResolveError> {
        use openshell_isolation::contract::{Assurance, Evidence};
        use std::sync::atomic::Ordering;

        let Some(peer_port) = in_pod_peer_port(flow) else {
            return Err(ResolveError::Failed(format!(
                "unsupported in-pod flow token version {}",
                flow.version()
            )));
        };

        let entrypoint_pid = self.entrypoint_pid.load(Ordering::Acquire);
        if entrypoint_pid == 0 {
            // No workload yet: nothing to attribute the connection to. Fail
            // closed so a binary-scoped rule cannot match an unattributed peer.
            return Err(ResolveError::NotFound);
        }

        let (binary_path, owner_pid) =
            crate::procfs::resolve_tcp_peer_identity(entrypoint_pid, peer_port)
                .map_err(|_| ResolveError::NotFound)?;

        // Hash the live `/proc/<pid>/exe` object, not the reopened resolved
        // path: opening the magic symlink pins the inode the process is actually
        // executing, so a post-resolution swap of the path cannot launder the
        // hash. A missing digest is `None`, never an empty string, and an
        // unhashable binary fails closed (it cannot be `Observed`).
        let exe = std::path::PathBuf::from(format!("/proc/{owner_pid}/exe"));
        let binary_sha256 = match crate::procfs::file_sha256(&exe) {
            Ok(digest) => Some(digest),
            Err(_) => {
                return Err(ResolveError::Failed(
                    "could not hash connecting binary; refusing to assert Observed".to_string(),
                ));
            }
        };

        let ancestors = crate::procfs::collect_ancestor_binaries(owner_pid, entrypoint_pid);
        let cmdline_paths = crate::procfs::cmdline_absolute_paths(owner_pid);

        Ok(Identity::Evidence(Evidence {
            assurance: Assurance::Observed,
            binary_path,
            binary_sha256,
            ancestors,
            cmdline_paths,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_isolation::contract::Assurance;

    /// Stands in for the proxy: a binary-scoped rule needs `Observed` or higher.
    /// The proxy calls a `&dyn IdentitySource`, so a kernel-separated backend
    /// (returning `Attested` from a guest) would drive this exact code path.
    async fn proxy_admits_binary_rule(source: &dyn IdentitySource, flow: Flow) -> bool {
        match source.resolve(flow).await {
            Ok(Identity::Evidence(e)) => e.assurance >= Assurance::Observed,
            Ok(Identity::Unsupported) | Err(_) => false,
        }
    }

    #[tokio::test]
    async fn fails_closed_before_the_workload_starts() {
        // entrypoint_pid == 0 means no agent yet; identity must fail closed so a
        // binary-scoped rule cannot be satisfied by an unattributed connection.
        let source = ProcfsIdentitySource {
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
        };
        let flow = Flow::in_pod_peer_port(12345);
        // On Linux the empty-workload path returns NotFound; on other targets
        // there is no procfs so the boundary reports Unsupported. Both fail
        // closed for a binary-scoped rule.
        assert!(!proxy_admits_binary_rule(&source, flow).await);
    }

    #[tokio::test]
    async fn unknown_flow_version_fails_closed() {
        let source = ProcfsIdentitySource {
            entrypoint_pid: Arc::new(AtomicU32::new(4242)),
        };
        let flow = Flow::opaque(9, vec![1, 2, 3, 4]);
        assert!(!proxy_admits_binary_rule(&source, flow).await);
    }
}
