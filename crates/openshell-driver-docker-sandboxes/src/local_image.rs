// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fall back to a local Docker Engine for a `template.image` reference
//! `sandboxd` can't resolve itself.
//!
//! Scoped to exactly the tag shape `openshell sandbox create --from
//! <Dockerfile>` mints (`openshell/sandbox-from:<unix-timestamp>`, see
//! `openshell-cli/src/run.rs`) — matching the same check
//! `openshell-driver-vm` already uses for the identical case. That image
//! only ever exists in whatever Docker Engine (or Docker-API-compatible
//! Podman socket, if `DOCKER_HOST` points there — the same assumption
//! `openshell-bootstrap`'s own build step already makes) built it. Any
//! other unresolvable `template.image` is left to fail with sandboxd's own
//! error — this module never widens what a create request can run to
//! whatever else happens to be sitting in the gateway host's local engine.
//!
//! `sandboxd` resolves any registry-resolvable `template.image` itself
//! (confirmed live — see `create_inner`), so this module is only ever
//! reached after that already failed.

use bollard::Docker;
use bollard::errors::Error as BollardError;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use openshell_core::{Error, Result as CoreResult};
use serde::Deserialize;
use tracing::{info, warn};

use crate::DockerSandboxesComputeDriver;

/// A locally-built image is never expected to exceed this; it exists to
/// bound how much of it this driver ever holds in memory at once while
/// moving it into sandboxd's own store.
const MAX_LOCAL_IMAGE_TAR_BYTES: usize = 4 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    message: String,
}

/// Whether sandboxd's create response indicates it couldn't resolve
/// `template.image` from any registry — confirmed live: sandboxd returns
/// HTTP 500 with this exact `message` when it can't pull an image.
pub fn is_image_pull_failure(status: u16, body: &[u8]) -> bool {
    if status != 500 {
        return false;
    }
    serde_json::from_slice::<ErrorBody>(body)
        .is_ok_and(|b| b.message == "failed to pull sandbox image")
}

/// Whether `image_ref` is the exact tag shape `openshell sandbox create
/// --from <Dockerfile>` mints. This is the only image reference this
/// module will ever look for in a local Docker Engine — an unrestricted
/// version of this check would let any create request read whatever image
/// happens to already be present on the gateway host.
fn is_openshell_local_build_image_ref(image_ref: &str) -> bool {
    image_ref
        .strip_prefix("openshell/sandbox-from:")
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn is_docker_not_found_error(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

impl DockerSandboxesComputeDriver {
    /// Look for `image` in a local Docker Engine and, if found, load it
    /// into sandboxd's own image store so a retried create can resolve it.
    ///
    /// `Ok(true)` — found and loaded, the caller should retry its create.
    /// `Ok(false)` — `image` isn't an `OpenShell` local-build tag (in which
    /// case no local Docker Engine is ever contacted), no local Docker
    /// Engine is reachable, or it doesn't have `image` either; not an
    /// error, the caller has its own message for this case. `Err` — a
    /// local Docker Engine had `image` but exporting or loading it into
    /// sandboxd failed partway through.
    pub(crate) async fn try_load_image_from_local_docker_engine(
        &self,
        image: &str,
    ) -> CoreResult<bool> {
        if !is_openshell_local_build_image_ref(image) {
            return Ok(false);
        }

        let Ok(docker) = Docker::connect_with_local_defaults() else {
            warn!(
                image_ref = image,
                "no local Docker Engine reachable for a locally built sandbox image"
            );
            return Ok(false);
        };

        match docker.inspect_image(image).await {
            Ok(_) => {}
            Err(err) if is_docker_not_found_error(&err) => {
                warn!(
                    image_ref = image,
                    "locally built sandbox image not found in local Docker Engine"
                );
                return Ok(false);
            }
            Err(err) => {
                warn!(
                    image_ref = image,
                    error = %err,
                    "failed to inspect locally built sandbox image in local Docker Engine"
                );
                return Ok(false);
            }
        }

        let tar =
            export_image_tar(docker.export_image(image), image, MAX_LOCAL_IMAGE_TAR_BYTES).await?;
        info!(
            image_ref = image,
            bytes = tar.len(),
            "loaded locally built sandbox image from local Docker Engine, sending to sandboxd"
        );
        self.load_image_tar(image, tar)
            .await
            .map_err(|status| Error::config(format!("sandboxd request failed: {status}")))?;
        Ok(true)
    }
}

async fn export_image_tar<S, E>(stream: S, image: &str, max_bytes: usize) -> CoreResult<Bytes>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: std::fmt::Display,
{
    let mut stream = Box::pin(stream);
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| {
            Error::config(format!("failed to export local image '{image}': {err}"))
        })?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(Error::config(format!(
                "local image '{image}' exceeds the {max_bytes} byte fallback size limit"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_image_pull_failure_matches_sandboxds_exact_error_shape() {
        let body = br#"{"error":"create sandbox container: ensure template image: Error response from daemon: failed to pull image: failed to resolve image: pull access denied","message":"failed to pull sandbox image"}"#;
        assert!(is_image_pull_failure(500, body));
    }

    #[test]
    fn is_image_pull_failure_rejects_other_statuses() {
        let body = br#"{"message":"failed to pull sandbox image"}"#;
        assert!(!is_image_pull_failure(400, body));
        assert!(!is_image_pull_failure(503, body));
    }

    #[test]
    fn is_image_pull_failure_rejects_other_500_messages() {
        let body = br#"{"message":"some other internal error"}"#;
        assert!(!is_image_pull_failure(500, body));
    }

    #[test]
    fn is_image_pull_failure_rejects_unparseable_body() {
        assert!(!is_image_pull_failure(500, b"not json"));
        assert!(!is_image_pull_failure(500, b""));
    }

    #[test]
    fn is_image_pull_failure_ignores_error_only_bodies() {
        let body = br#"{"error":"something else failed"}"#;
        assert!(!is_image_pull_failure(500, body));
    }

    #[test]
    fn is_image_pull_failure_rejects_non_object_json() {
        assert!(!is_image_pull_failure(500, b"[]"));
        assert!(!is_image_pull_failure(500, b"null"));
    }

    #[test]
    fn local_build_image_ref_matches_cli_tags() {
        assert!(is_openshell_local_build_image_ref(
            "openshell/sandbox-from:1786682361"
        ));
        assert!(!is_openshell_local_build_image_ref("ubuntu:24.04"));
        assert!(!is_openshell_local_build_image_ref(
            "ghcr.io/org/openshell/sandbox-from:1"
        ));
        assert!(!is_openshell_local_build_image_ref(
            "openshell/sandbox-from:"
        ));
        assert!(!is_openshell_local_build_image_ref(
            "openshell/sandbox-from:../containers/x/archive"
        ));
        assert!(!is_openshell_local_build_image_ref(
            "openshell/sandbox-from:12ab"
        ));
    }

    #[tokio::test]
    async fn export_image_tar_concatenates_chunks_in_order() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"world")),
        ];
        let tar = export_image_tar(futures::stream::iter(chunks), "test:1", 1024)
            .await
            .unwrap();
        assert_eq!(&tar[..], b"hello world");
    }

    #[tokio::test]
    async fn export_image_tar_propagates_a_mid_stream_error() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"partial")),
            Err(std::io::Error::other("boom")),
        ];
        let err = export_image_tar(futures::stream::iter(chunks), "test:1", 1024)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("test:1"));
    }

    #[tokio::test]
    async fn export_image_tar_rejects_a_stream_over_the_size_cap() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"0123456789")),
            Ok(Bytes::from_static(b"one more byte")),
        ];
        let err = export_image_tar(futures::stream::iter(chunks), "test:1", 10)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("size limit"));
    }

    #[tokio::test]
    async fn export_image_tar_is_empty_for_an_empty_stream() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![];
        let tar = export_image_tar(futures::stream::iter(chunks), "test:1", 1024)
            .await
            .unwrap();
        assert!(tar.is_empty());
    }
}
