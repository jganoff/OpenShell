// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resolve the `openshell-sandbox` supervisor binary onto a host path this
//! driver injects into every sandbox via `additional_workspaces`.
//!
//! `sandboxd`'s generic kit-agent path never execs a kit's declared
//! `manifest.binary` as the container's entrypoint, so the driver's shipped
//! kit (`kits/openshell/spec.yaml`) instead launches the supervisor from a
//! `setup.startup` hook that `exec`s whatever host path this module resolves
//! — see the crate README ("How it works") for why that's sufficient (a
//! `startup` command sees the create request's own environment and, run as
//! `user: root`, gets full effective capabilities, independent of any
//! client connection).
//!
//! When no explicit `supervisor_bin` override is configured, the binary is
//! fetched over plain HTTPS from a public `NVIDIA/OpenShell` GitHub Release
//! asset and checksum-verified against that release's own published
//! `sha256` manifest — no OCI image, no `sandboxd`/Docker involvement at
//! all for this step.

use std::io::Read;
use std::path::{Path, PathBuf};

use openshell_core::{Error, Result as CoreResult};
use sha2::{Digest, Sha256};

use crate::DockerSandboxesComputeConfig;

/// Public GitHub repository release assets are fetched from.
const SUPERVISOR_RELEASE_REPO: &str = "NVIDIA/OpenShell";

/// Base file name of the supervisor binary, both inside the release tarball
/// and as the prefix of the tarball's own asset name
/// (`{name}-{target-triple}.tar.gz`).
const SUPERVISOR_BINARY_NAME: &str = "openshell-sandbox";

/// Asset name of the published checksum manifest, constant across releases
/// and architectures.
const CHECKSUMS_ASSET_NAME: &str = "openshell-sandbox-checksums-sha256.txt";

/// Where the driver resolves the supervisor binary from, in order.
enum SupervisorBinSource {
    /// Explicit host path to a Linux ELF, from `supervisor_bin`.
    Binary(PathBuf),
    /// A GitHub Release tag to fetch [`SUPERVISOR_BINARY_NAME`] from —
    /// either `supervisor_release_tag` or, absent that, the default tag.
    Release(String),
}

fn resolve_supervisor_bin_source(config: &DockerSandboxesComputeConfig) -> SupervisorBinSource {
    if let Some(path) = &config.supervisor_bin {
        return SupervisorBinSource::Binary(path.clone());
    }
    SupervisorBinSource::Release(
        config
            .supervisor_release_tag
            .clone()
            .unwrap_or_else(default_supervisor_release_tag),
    )
}

/// The release tag fetched when `supervisor_release_tag` isn't set,
/// mirroring the version-pinning convention every other in-tree driver
/// already uses for its own supervisor artifact
/// ([`openshell_core::config::resolve_supervisor_image_tag`]): an
/// `OPENSHELL_IMAGE_TAG`/`IMAGE_TAG` build-time override, else this crate's
/// own `CARGO_PKG_VERSION`, falling back to `"dev"` when neither resolves to
/// a real version. Numbered GitHub release tags in this repository carry a
/// `v` prefix that OCI image tags don't; the `dev` pre-release tag doesn't,
/// so the prefix is only added onto a version that actually looks numeric.
fn default_supervisor_release_tag() -> String {
    let version = openshell_core::config::resolve_supervisor_image_tag(&[
        option_env!("OPENSHELL_IMAGE_TAG").unwrap_or(""),
        option_env!("IMAGE_TAG").unwrap_or(""),
        env!("CARGO_PKG_VERSION"),
    ]);
    release_tag_for_version(&version)
}

/// Pure prefix-choosing logic split out of [`default_supervisor_release_tag`]
/// so it's testable independent of the build-time environment.
fn release_tag_for_version(version: &str) -> String {
    if version.starts_with(|c: char| c.is_ascii_digit()) {
        format!("v{version}")
    } else {
        version.to_string()
    }
}

/// Linux target triple of the binary to fetch. The binary runs *inside* the
/// sandbox VM, which `sandboxd` runs natively on the host CPU rather than
/// emulating a different one — the same single-architecture assumption
/// every other driver's supervisor artifact already makes.
fn supervisor_target_triple() -> CoreResult<&'static str> {
    if cfg!(target_arch = "x86_64") {
        Ok("x86_64-unknown-linux-gnu")
    } else if cfg!(target_arch = "aarch64") {
        Ok("aarch64-unknown-linux-gnu")
    } else {
        Err(Error::config(
            "no published openshell-sandbox release binary for this host architecture; \
             set supervisor_bin to an explicit path instead"
                .to_string(),
        ))
    }
}

/// Resolve a host path to the `openshell-sandbox` binary. This exact path
/// is used as both the `additional_workspaces` mount source and (via
/// sandboxd's identity mapping) the container target, so a caller-supplied
/// `supervisor_bin` is used directly — no copying — while a release source
/// is downloaded once and cached under a path that survives driver
/// restarts.
pub async fn resolve_supervisor_bin_path(
    config: &DockerSandboxesComputeConfig,
) -> CoreResult<PathBuf> {
    match resolve_supervisor_bin_source(config) {
        SupervisorBinSource::Binary(path) => {
            if !path.is_file() {
                return Err(Error::config(format!(
                    "supervisor_bin '{}' does not exist or is not a file",
                    path.display()
                )));
            }
            std::fs::canonicalize(&path).map_err(|err| {
                Error::config(format!(
                    "failed to resolve supervisor_bin '{}': {err}",
                    path.display()
                ))
            })
        }
        SupervisorBinSource::Release(tag) => download_and_cache_supervisor_bin(&tag).await,
    }
}

/// Release tags are interpolated directly into a URL path segment
/// (`.../releases/download/<tag>/...`); restricting the charset rules out a
/// tag containing `/` or `..` retargeting the request to a different
/// release or repository path.
fn validate_release_tag(tag: &str) -> CoreResult<()> {
    let valid = !tag.is_empty()
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'));
    if valid {
        Ok(())
    } else {
        Err(Error::config(format!(
            "invalid supervisor_release_tag {tag:?}: expected only letters, digits, '.', '-', \
             '_', or '+'"
        )))
    }
}

async fn download_and_cache_supervisor_bin(tag: &str) -> CoreResult<PathBuf> {
    validate_release_tag(tag)?;
    let triple = supervisor_target_triple()?;
    let cache_path = supervisor_cache_path(tag, triple)?;
    // `symlink_metadata` rather than `is_file()`/`Path::exists` — those
    // follow symlinks, so a symlink planted at the cache path (by another
    // local user, if the cache directory were ever more permissive than
    // the `create_dir_restricted` below makes it) would otherwise be
    // accepted and mounted into every sandbox this driver creates.
    if std::fs::symlink_metadata(&cache_path).is_ok_and(|meta| meta.file_type().is_file()) {
        return Ok(cache_path);
    }

    let asset_name = format!("{SUPERVISOR_BINARY_NAME}-{triple}.tar.gz");
    let base_url = format!("https://github.com/{SUPERVISOR_RELEASE_REPO}/releases/download/{tag}");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|err| Error::config(format!("failed to build HTTP client: {err}")))?;

    let checksums = fetch_text(&client, &format!("{base_url}/{CHECKSUMS_ASSET_NAME}")).await?;
    let expected_digest = find_checksum(&checksums, &asset_name).ok_or_else(|| {
        Error::config(format!(
            "no checksum entry for '{asset_name}' in {CHECKSUMS_ASSET_NAME} (release {tag})"
        ))
    })?;

    let archive_bytes = fetch_bytes(&client, &format!("{base_url}/{asset_name}")).await?;
    verify_sha256(&archive_bytes, &expected_digest, &asset_name)?;

    let binary_bytes = extract_single_file(&archive_bytes, SUPERVISOR_BINARY_NAME)?;

    let cache_dir = cache_path.parent().ok_or_else(|| {
        Error::config(format!(
            "supervisor cache path '{}' has no parent directory",
            cache_path.display()
        ))
    })?;
    openshell_core::paths::create_dir_restricted(cache_dir).map_err(|err| {
        Error::config(format!(
            "failed to create supervisor cache dir '{}': {err}",
            cache_dir.display()
        ))
    })?;
    write_cache_binary_atomic(&cache_path, &binary_bytes)?;
    Ok(cache_path)
}

async fn fetch_bytes(client: &reqwest::Client, url: &str) -> CoreResult<bytes::Bytes> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| Error::config(format!("failed to fetch '{url}': {err}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::config(format!(
            "fetching '{url}' returned HTTP {status}"
        )));
    }
    response
        .bytes()
        .await
        .map_err(|err| Error::config(format!("failed to read response body from '{url}': {err}")))
}

async fn fetch_text(client: &reqwest::Client, url: &str) -> CoreResult<String> {
    let bytes = fetch_bytes(client, url).await?;
    String::from_utf8(bytes.to_vec())
        .map_err(|err| Error::config(format!("'{url}' is not valid UTF-8: {err}")))
}

/// Find the checksum for `asset_name` in a standard `sha256sum`-format
/// manifest (`<hex digest>  <file name>`, one entry per line, optionally
/// prefixed with `*` on the file name for binary mode).
fn find_checksum(checksums: &str, asset_name: &str) -> Option<String> {
    checksums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == asset_name).then(|| digest.to_ascii_lowercase())
    })
}

fn verify_sha256(bytes: &[u8], expected_hex: &str, label: &str) -> CoreResult<()> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let actual = digest.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write;
        let _ = write!(acc, "{byte:02x}");
        acc
    });
    if actual.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(Error::config(format!(
            "checksum mismatch for '{label}': expected {expected_hex}, got {actual}"
        )))
    }
}

/// Extract the single file named `expected_name` from a gzip-compressed tar
/// archive.
fn extract_single_file(archive_bytes: &[u8], expected_name: &str) -> CoreResult<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(archive_bytes);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|err| Error::config(format!("failed to read tar entries: {err}")))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|err| Error::config(format!("failed to read tar entry: {err}")))?;
        let path = entry
            .path()
            .map_err(|err| Error::config(format!("failed to read tar entry path: {err}")))?
            .into_owned();
        if path.file_name().and_then(|name| name.to_str()) == Some(expected_name) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|err| {
                Error::config(format!(
                    "failed to read '{expected_name}' from archive: {err}"
                ))
            })?;
            return Ok(buf);
        }
    }
    Err(Error::config(format!(
        "archive did not contain an entry named '{expected_name}'"
    )))
}

fn supervisor_cache_path(tag: &str, triple: &str) -> CoreResult<PathBuf> {
    let base = openshell_core::paths::xdg_data_dir()
        .map_err(|err| Error::config(format!("failed to resolve XDG data dir: {err}")))?;
    let sanitized_tag: String = tag
        .chars()
        .map(|c| if c == '/' || c == ':' { '-' } else { c })
        .collect();
    Ok(base
        .join("openshell")
        .join("docker-sandboxes-supervisor")
        .join(format!("{sanitized_tag}-{triple}"))
        .join(SUPERVISOR_BINARY_NAME))
}

fn write_cache_binary_atomic(final_path: &Path, bytes: &[u8]) -> CoreResult<()> {
    let dir = final_path.parent().ok_or_else(|| {
        Error::config(format!(
            "supervisor cache path '{}' has no parent directory",
            final_path.display()
        ))
    })?;
    let mut temp = tempfile::Builder::new()
        .prefix(".openshell-sandbox-")
        .tempfile_in(dir)
        .map_err(|err| {
            Error::config(format!(
                "failed to create temp file for supervisor binary in '{}': {err}",
                dir.display()
            ))
        })?;
    std::io::Write::write_all(&mut temp, bytes).map_err(|err| {
        Error::config(format!(
            "failed to write supervisor binary to temp file: {err}"
        ))
    })?;
    temp.as_file().sync_all().map_err(|err| {
        Error::config(format!("failed to sync supervisor binary temp file: {err}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set permissions via the open file descriptor (fchmod), not by
        // path — the latter re-resolves the path and could, in principle,
        // apply to something else if the temp file's name were ever reused
        // between creation and this call.
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|err| {
                Error::config(format!(
                    "failed to chmod supervisor binary temp file: {err}"
                ))
            })?;
    }

    temp.persist(final_path).map_err(|err| {
        Error::config(format!(
            "failed to rename supervisor binary into '{}': {}",
            final_path.display(),
            err.error
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tag_for_version_prefixes_numeric_versions() {
        assert_eq!(release_tag_for_version("0.0.105"), "v0.0.105");
        assert_eq!(release_tag_for_version("1.2.3"), "v1.2.3");
    }

    #[test]
    fn release_tag_for_version_leaves_non_numeric_versions_unprefixed() {
        // The published "dev" pre-release tag carries no `v` prefix, unlike
        // every numbered release tag.
        assert_eq!(release_tag_for_version("dev"), "dev");
    }

    #[test]
    fn validate_release_tag_accepts_typical_tags() {
        validate_release_tag("v0.0.105").expect("numbered tag");
        validate_release_tag("dev").expect("dev tag");
        validate_release_tag("v1.2.3-rc.1+build_2").expect("tag with extra punctuation");
    }

    #[test]
    fn validate_release_tag_rejects_path_traversal_and_empty() {
        assert!(validate_release_tag("").is_err());
        assert!(validate_release_tag("../other-repo").is_err());
        assert!(validate_release_tag("v1/../../x").is_err());
        assert!(validate_release_tag("v1 rm -rf").is_err());
    }

    #[test]
    fn supervisor_cache_path_is_stable_and_keyed_by_tag_and_triple() {
        let a = supervisor_cache_path("v0.0.105", "x86_64-unknown-linux-gnu").expect("resolves");
        let b = supervisor_cache_path("v0.0.105", "x86_64-unknown-linux-gnu").expect("resolves");
        assert_eq!(a, b);
        assert!(a.ends_with(
            "openshell/docker-sandboxes-supervisor/v0.0.105-x86_64-unknown-linux-gnu/openshell-sandbox"
        ));
    }

    #[test]
    fn supervisor_cache_path_differs_by_tag_and_triple() {
        let a = supervisor_cache_path("v0.0.105", "x86_64-unknown-linux-gnu").expect("resolves");
        let b = supervisor_cache_path("v0.0.106", "x86_64-unknown-linux-gnu").expect("resolves");
        let c = supervisor_cache_path("v0.0.105", "aarch64-unknown-linux-gnu").expect("resolves");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn supervisor_cache_path_sanitizes_slashes_and_colons_in_the_tag() {
        let path =
            supervisor_cache_path("refs/tags/v1", "x86_64-unknown-linux-gnu").expect("resolves");
        let tag_component = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .expect("has a tag+triple directory component");
        assert_eq!(tag_component, "refs-tags-v1-x86_64-unknown-linux-gnu");
    }

    #[test]
    fn find_checksum_locates_matching_entry_and_ignores_others() {
        let manifest = "\
            aaaa111  openshell-sandbox-aarch64-unknown-linux-gnu.tar.gz\n\
            bbbb222  openshell-sandbox-x86_64-unknown-linux-gnu.tar.gz\n";
        assert_eq!(
            find_checksum(
                manifest,
                "openshell-sandbox-x86_64-unknown-linux-gnu.tar.gz"
            ),
            Some("bbbb222".to_string())
        );
        assert_eq!(
            find_checksum(manifest, "openshell-sandbox-checksums-sha256.txt"),
            None
        );
    }

    #[test]
    fn find_checksum_strips_binary_mode_asterisk() {
        let manifest = "cccc333 *openshell-sandbox-x86_64-unknown-linux-gnu.tar.gz\n";
        assert_eq!(
            find_checksum(
                manifest,
                "openshell-sandbox-x86_64-unknown-linux-gnu.tar.gz"
            ),
            Some("cccc333".to_string())
        );
    }

    #[test]
    fn verify_sha256_accepts_correct_digest_case_insensitively() {
        let digest = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        verify_sha256(b"hello", digest, "test").expect("matches");
        verify_sha256(b"hello", &digest.to_uppercase(), "test")
            .expect("matches case-insensitively");
    }

    #[test]
    fn verify_sha256_rejects_mismatched_digest() {
        let err = verify_sha256(
            b"hello",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "test",
        )
        .expect_err("mismatch");
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn extract_single_file_finds_entry_by_basename() {
        use std::io::Write;

        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let contents = b"fake-binary-contents";
            let mut header = tar::Header::new_gnu();
            header.set_path("openshell-sandbox").unwrap();
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder.append(&header, &contents[..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz_bytes = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::default());
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }

        let extracted = extract_single_file(&gz_bytes, "openshell-sandbox").expect("found");
        assert_eq!(extracted, b"fake-binary-contents");
    }

    #[test]
    fn extract_single_file_errors_when_absent() {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            builder.finish().unwrap();
        }
        let mut gz_bytes = Vec::new();
        {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::default());
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }

        let err = extract_single_file(&gz_bytes, "openshell-sandbox").expect_err("missing");
        assert!(err.to_string().contains("did not contain an entry"));
    }
}
