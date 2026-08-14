// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and cache the driver's default sandbox image: a minimal,
//! content-tagged diff of a stock public image ([`BASE_IMAGE`]) with the one
//! package it's missing that the supervisor needs.
//!
//! Uses only `sandboxd`'s own public HTTP surface — create, exec (as a
//! chosen user), stop, save (`sbx template save`'s underlying endpoint), and
//! delete — the same operations the `sbx` CLI itself exposes. No local
//! Docker Engine, no image-build tooling, no `docker build`/`docker save`,
//! and no reliance on anything incidental to a specific vendor image beyond
//! [`BASE_IMAGE`] tolerating `sandboxd`'s forced startup command (confirmed
//! live; see the crate README, "How it works", for why
//! `ghcr.io/nvidia/openshell-community/sandboxes/base:latest` — the default
//! every other in-tree driver uses — does not).
//!
//! `apt-get install` itself is plain, generic Debian/Ubuntu package
//! management — not anything specific to `docker/sandboxes`. It has to
//! retry past sandboxd's own generic first-boot provisioning step (an
//! automatic background `apt-get update` sandboxd runs on any kit-agent
//! sandbox that has `apt-get`, observed live holding the same dpkg/apt lock
//! for several seconds after boot).

use bytes::Bytes;
use openshell_core::{Error, Result as CoreResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DockerSandboxesComputeDriver;

/// Stock public image booted as the base for the driver's default sandbox
/// image. `docker/sandbox-templates:shell-docker` rather than a plain
/// `ubuntu:24.04` (also confirmed live to tolerate sandboxd's forced
/// startup command): a bare Ubuntu image measurably slows down sandboxd's
/// own generic first-boot provisioning step, which the startup hook waits
/// on — confirmed live, a `ubuntu:24.04`-based build sandbox's startup hook
/// took over a minute longer to even start than an otherwise-identical
/// `shell-docker`-based one. `shell-docker`'s own bundled `dockerd`/
/// `containerd` (unused by this driver) costs less than that difference.
pub const BASE_IMAGE: &str = "docker/sandbox-templates:shell-docker";

/// Packages `BASE_IMAGE` doesn't already ship that the supervisor needs:
/// `ip` (`iproute2`) for its own network namespace. `nftables` is already
/// present on `BASE_IMAGE` (confirmed live) but named here too so the built
/// image doesn't implicitly depend on that remaining true.
const REQUIRED_PACKAGES: &[&str] = &["iproute2", "nftables"];

/// Retry budget for `apt-get install` while sandboxd's own first-boot
/// provisioning still holds the dpkg/apt lock — confirmed live to clear
/// within single-digit seconds.
const APT_LOCK_RETRY_ATTEMPTS: u32 = 30;
const APT_LOCK_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

const BUILD_SANDBOX_AGENT: &str = "shell";

/// Prefix every build-sandbox name starts with — used to find orphans left
/// over from a previous driver process that crashed mid-build.
const BUILD_SANDBOX_NAME_PREFIX: &str = "openshell-sandboxes-base-build-";

#[derive(Debug, Serialize)]
struct RawSandboxCreateReq<'a> {
    agent: &'a str,
    workspace: &'a str,
    name: &'a str,
    template: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct ExecReq<'a> {
    cmd: &'a [&'a str],
    user: &'a str,
}

#[derive(Debug, Deserialize)]
struct ExecResp {
    exit_code: i64,
    #[serde(default)]
    stderr: String,
}

#[derive(Debug, Serialize)]
struct SaveReq<'a> {
    tag: &'a str,
}

#[derive(Debug, Deserialize)]
struct SandboxNameOnly {
    name: String,
}

/// Deterministic tag for the driver's default sandbox image, derived from
/// its own recipe (base image + package list) so a driver restart reuses
/// whatever a previous process already built into `sandboxd`'s image store
/// instead of rebuilding — see [`DockerSandboxesComputeDriver::ensure_base_image_loaded`].
pub fn base_image_tag() -> String {
    // `sha2` rather than `std::hash::Hasher` (`DefaultHasher`'s algorithm is
    // explicitly not guaranteed stable across Rust releases — a toolchain
    // bump could otherwise silently change this tag and force every install
    // to rebuild).
    let mut hasher = Sha256::new();
    hasher.update(BASE_IMAGE.as_bytes());
    for package in REQUIRED_PACKAGES {
        hasher.update(package.as_bytes());
    }
    hasher.update(RECIPE_VERSION.to_le_bytes());
    let digest = hasher.finalize();
    format!(
        "openshell-docker-sandboxes-base:{}",
        digest[..8].iter().fold(String::new(), |mut acc, byte| {
            use std::fmt::Write;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
    )
}

/// Bump whenever [`DockerSandboxesComputeDriver::install_required_packages`]'s
/// provisioning steps change in a way that isn't already reflected in
/// [`BASE_IMAGE`]/[`REQUIRED_PACKAGES`] (e.g. the `sandbox` user it also
/// creates) — otherwise a driver upgrade would keep reusing a
/// previously-built image tag whose contents no longer match this recipe.
const RECIPE_VERSION: u32 = 1;

impl DockerSandboxesComputeDriver {
    /// Resolve the driver's default sandbox image, building and saving it
    /// into `sandboxd`'s own image store on first use and reusing it on
    /// every later startup via its content-derived tag. Called once from
    /// `new` when the caller hasn't set an explicit `template_image`
    /// override.
    pub(crate) async fn ensure_base_image_loaded(&self) -> CoreResult<String> {
        let tag = base_image_tag();

        // Any failure here just falls through to building — a latency
        // optimization (skip a real build once a previous process already
        // did it), not a correctness requirement.
        let already_loaded = matches!(
            self.daemon_request(
                http::Method::GET,
                &format!("/docker/images/inspect?name={tag}"),
                None,
            )
            .await,
            Ok((200, _))
        );
        if already_loaded {
            tracing::info!(
                tag,
                "sandboxd already has the driver's default sandbox image loaded"
            );
            return Ok(tag);
        }

        tracing::info!(tag, "building driver's default sandbox image");
        self.build_base_image(&tag).await?;
        Ok(tag)
    }

    async fn build_base_image(&self, tag: &str) -> CoreResult<()> {
        let name = build_sandbox_name();
        self.create_build_sandbox(&name).await?;

        let result = async {
            self.install_required_packages(&name).await?;
            self.stop_build_sandbox(&name).await?;
            self.save_build_sandbox_as_tag(&name, tag).await
        }
        .await;

        if let Err(err) = self.delete_build_sandbox(&name).await {
            tracing::warn!(sandbox = name, error = %err, "failed to remove base-image build sandbox");
        }
        crate::cleanup_sandbox_workspace_dir(&self.config.default_workspace, &name);
        result
    }

    async fn create_build_sandbox(&self, name: &str) -> CoreResult<()> {
        let workspace_dir =
            crate::ensure_sandbox_workspace_dir(&self.config.default_workspace, name).map_err(
                |status| Error::config(format!("create build sandbox workspace failed: {status}")),
            )?;
        let workspace_dir = workspace_dir.to_str().ok_or_else(|| {
            Error::config("build sandbox workspace path is not valid UTF-8".to_string())
        })?;
        let req = RawSandboxCreateReq {
            agent: BUILD_SANDBOX_AGENT,
            workspace: workspace_dir,
            name,
            template: BASE_IMAGE,
            profile: self.config.profile.as_deref(),
        };
        let body = serde_json::to_vec(&req).map_err(|err| {
            Error::config(format!(
                "failed to encode build sandbox create request: {err}"
            ))
        })?;
        let (status, resp_body) = self
            .daemon_request(http::Method::POST, "/sandbox", Some(Bytes::from(body)))
            .await
            .map_err(|status| Error::config(format!("sandboxd create request failed: {status}")))?;
        if status != 201 {
            return Err(Error::config(format!(
                "sandboxd create of base-image build sandbox '{name}' returned HTTP {status}: {}",
                String::from_utf8_lossy(&resp_body)
            )));
        }
        Ok(())
    }

    async fn install_required_packages(&self, name: &str) -> CoreResult<()> {
        // `apt-get update` first, not just install: the package lists are
        // otherwise whatever sandboxd's own generic first-boot provisioning
        // step happened to leave them as (or hasn't refreshed yet), which
        // isn't a dependency this build should have on that unrelated
        // step's own timing.
        //
        // Also creates the `sandbox` user the supervisor expects some of
        // its own child processes to run as (confirmed live: absent this,
        // the supervisor fails with "explicit process user 'sandbox' was
        // not found in the image") — UID/GID 998, home `/sandbox`, matching
        // the convention `ghcr.io/nvidia/openshell-community/sandboxes/base`
        // (the image every other in-tree driver uses) already ships that
        // user with. Guarded by `id -u sandbox` so a retried attempt after
        // a partial failure doesn't try to recreate it.
        let install_cmd = format!(
            "apt-get update -qq && apt-get install -y -qq {} && \
             (id -u sandbox >/dev/null 2>&1 || \
              (groupadd -g 998 sandbox && useradd -u 998 -g 998 -m -d /sandbox -s /bin/bash sandbox))",
            REQUIRED_PACKAGES.join(" ")
        );
        let mut last_error = String::new();
        for attempt in 0..APT_LOCK_RETRY_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(APT_LOCK_RETRY_INTERVAL).await;
            }
            // Retry an exec-request failure the same as a non-zero exit —
            // the sandbox can still be transitioning to `running` this
            // soon after create (`POST /sandbox/{name}/exec` documents a
            // 409 for "not running yet"), which is exactly the kind of
            // failure this loop exists to ride out.
            match self.exec_as_root(name, &["sh", "-c", &install_cmd]).await {
                Ok((0, _)) => return Ok(()),
                Ok((exit_code, stderr)) => {
                    last_error = stderr;
                    tracing::debug!(
                        sandbox = name,
                        attempt,
                        exit_code,
                        "apt-get install attempt failed"
                    );
                }
                Err(err) => {
                    last_error = err.to_string();
                    tracing::debug!(sandbox = name, attempt, error = %err, "apt-get install exec request failed");
                }
            }
        }
        Err(Error::config(format!(
            "'{install_cmd}' did not succeed in build sandbox '{name}' after \
             {APT_LOCK_RETRY_ATTEMPTS} attempts: {last_error}"
        )))
    }

    async fn exec_as_root(&self, name: &str, cmd: &[&str]) -> CoreResult<(i64, String)> {
        let req = ExecReq { cmd, user: "root" };
        let body = serde_json::to_vec(&req)
            .map_err(|err| Error::config(format!("failed to encode exec request: {err}")))?;
        let path = format!("/sandbox/{name}/exec");
        let (status, resp_body) = self
            .daemon_request(http::Method::POST, &path, Some(Bytes::from(body)))
            .await
            .map_err(|status| Error::config(format!("sandboxd exec request failed: {status}")))?;
        if status != 200 {
            return Err(Error::config(format!(
                "sandboxd exec in build sandbox '{name}' returned HTTP {status}: {}",
                String::from_utf8_lossy(&resp_body)
            )));
        }
        let resp: ExecResp = serde_json::from_slice(&resp_body).map_err(|err| {
            Error::config(format!("failed to decode sandboxd exec response: {err}"))
        })?;
        Ok((resp.exit_code, resp.stderr))
    }

    async fn stop_build_sandbox(&self, name: &str) -> CoreResult<()> {
        let path = format!("/sandbox/{name}/stop");
        let (status, body) = self
            .daemon_request(http::Method::POST, &path, None)
            .await
            .map_err(|status| Error::config(format!("sandboxd stop request failed: {status}")))?;
        if status != 200 {
            return Err(Error::config(format!(
                "sandboxd stop of build sandbox '{name}' returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(())
    }

    /// Save the (stopped) build sandbox as `tag` in sandboxd's own image
    /// store — the same operation `sbx template save` performs.
    async fn save_build_sandbox_as_tag(&self, name: &str, tag: &str) -> CoreResult<()> {
        let req = SaveReq { tag };
        let body = serde_json::to_vec(&req)
            .map_err(|err| Error::config(format!("failed to encode save request: {err}")))?;
        let path = format!("/sandbox/{name}/save");
        let (status, resp_body) = self
            .daemon_request(http::Method::POST, &path, Some(Bytes::from(body)))
            .await
            .map_err(|status| Error::config(format!("sandboxd save request failed: {status}")))?;
        if status != 200 && status != 201 {
            return Err(Error::config(format!(
                "sandboxd save of build sandbox '{name}' as '{tag}' returned HTTP {status}: {}",
                String::from_utf8_lossy(&resp_body)
            )));
        }
        Ok(())
    }

    async fn delete_build_sandbox(&self, name: &str) -> CoreResult<()> {
        let path = format!("/sandbox/{name}");
        let (status, body) = self
            .daemon_request(http::Method::DELETE, &path, None)
            .await
            .map_err(|status| Error::config(format!("sandboxd delete request failed: {status}")))?;
        if status != 200 && status != 404 {
            return Err(Error::config(format!(
                "sandboxd delete of build sandbox '{name}' returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(())
    }

    /// Sweep and delete any leftover build sandboxes from a previous driver
    /// process that crashed/was killed mid-build. Best-effort: logs and
    /// continues on any failure rather than blocking driver startup on a
    /// `sandboxd` hiccup. Relies on [`BUILD_SANDBOX_NAME_PREFIX`]'s
    /// predictable prefix.
    pub(crate) async fn reap_orphaned_build_sandboxes(&self) {
        let (status, body) = match self
            .daemon_request(http::Method::GET, "/sandbox", None)
            .await
        {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, "failed to list sandboxes for orphaned-build-sandbox sweep");
                return;
            }
        };
        if status != 200 {
            tracing::warn!(
                status,
                "failed to list sandboxes for orphaned-build-sandbox sweep"
            );
            return;
        }
        let infos: Vec<SandboxNameOnly> = match serde_json::from_slice(&body) {
            Ok(infos) => infos,
            Err(err) => {
                tracing::warn!(error = %err, "failed to decode sandbox list for orphaned-build-sandbox sweep");
                return;
            }
        };
        for info in infos {
            if !info.name.starts_with(BUILD_SANDBOX_NAME_PREFIX) {
                continue;
            }
            tracing::warn!(
                sandbox = info.name,
                "reaping orphaned base-image build sandbox left over from a previous driver process",
            );
            if let Err(err) = self.delete_build_sandbox(&info.name).await {
                tracing::warn!(sandbox = info.name, error = %err, "failed to reap orphaned build sandbox");
            }
        }
    }
}

/// A build-sandbox name unique to this process and call, valid under
/// sandboxd's name character restrictions.
fn build_sandbox_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{BUILD_SANDBOX_NAME_PREFIX}{pid}-{seq}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_image_tag_is_stable_across_calls() {
        assert_eq!(base_image_tag(), base_image_tag());
        assert!(base_image_tag().starts_with("openshell-docker-sandboxes-base:"));
    }

    #[test]
    fn build_sandbox_name_is_prefixed_and_unique() {
        let a = build_sandbox_name();
        let b = build_sandbox_name();
        assert_ne!(a, b);
        assert!(a.starts_with(BUILD_SANDBOX_NAME_PREFIX));
        assert!(b.starts_with(BUILD_SANDBOX_NAME_PREFIX));
    }
}
