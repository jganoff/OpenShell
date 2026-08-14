#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Start a standalone openshell-gateway backed by the Docker Sandboxes compute
# driver (openshell-driver-docker-sandboxes), embedded in-tree, for local
# manual testing.
#
# Invocation:
#   mise run gateway:docker-sandboxes
#
# Defaults:
# - Plaintext HTTP on 127.0.0.1:18082
# - Dedicated CLI gateway "docker-sandboxes-dev"
# - Persistent gateway state (SQLite DB) under .cache/gateway-docker-sandboxes
#
# Common overrides:
#   OPENSHELL_SERVER_PORT=18092 mise run gateway:docker-sandboxes
#   OPENSHELL_DOCKER_SANDBOXES_GATEWAY_NAME=my-gateway mise run gateway:docker-sandboxes
#   OPENSHELL_DOCKER_SANDBOXES_PROFILE=developer mise run gateway:docker-sandboxes
#
# This script also writes ~/.config/openshell/active_gateway so the
# `openshell` CLI automatically targets this gateway in subsequent shells.
# No need to run `openshell gateway select`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${OPENSHELL_SERVER_PORT:-18082}"
GATEWAY_NAME="${OPENSHELL_DOCKER_SANDBOXES_GATEWAY_NAME:-docker-sandboxes-dev}"
STATE_DIR="${OPENSHELL_DOCKER_SANDBOXES_GATEWAY_STATE_DIR:-${ROOT}/.cache/gateway-docker-sandboxes}"
LOG_LEVEL="${OPENSHELL_LOG_LEVEL:-info}"
GATEWAY_BIN="${ROOT}/target/debug/openshell-gateway"

port_is_in_use() {
  local port=$1
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1
    return $?
  fi
  if command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "${port}" >/dev/null 2>&1
    return $?
  fi
  (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1
}

register_gateway_metadata() {
  local name=$1
  local endpoint=$2
  local port=$3
  local config_home gateway_dir

  config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
  gateway_dir="${config_home}/openshell/gateways/${name}"

  mkdir -p "${gateway_dir}"
  cat >"${gateway_dir}/metadata.json" <<EOF
{
  "name": "${name}",
  "gateway_endpoint": "${endpoint}",
  "is_remote": false,
  "gateway_port": ${port},
  "auth_mode": "plaintext"
}
EOF
}

# Mirror what `openshell gateway select <name>` does: write the gateway name
# to $XDG_CONFIG_HOME/openshell/active_gateway. The CLI picks it up as the
# default target when neither --gateway nor OPENSHELL_GATEWAY is set.
save_active_gateway() {
  local name=$1
  local config_home active_gateway_path
  config_home="${XDG_CONFIG_HOME:-${HOME}/.config}"
  active_gateway_path="${config_home}/openshell/active_gateway"
  mkdir -p "$(dirname "${active_gateway_path}")"
  printf '%s' "${name}" >"${active_gateway_path}"
}

if [[ ! "${GATEWAY_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "ERROR: OPENSHELL_DOCKER_SANDBOXES_GATEWAY_NAME must contain only letters, numbers, dots, underscores, or dashes" >&2
  exit 2
fi

if command -v sbx >/dev/null 2>&1; then
  if ! sbx daemon status >/dev/null 2>&1; then
    echo "ERROR: sandboxd is not running (checked via 'sbx daemon status')" >&2
    exit 2
  fi
else
  echo "WARNING: 'sbx' CLI not found on PATH; assuming sandboxd is reachable" >&2
fi

if port_is_in_use "${PORT}"; then
  echo "ERROR: port ${PORT} is already in use; free it or set OPENSHELL_SERVER_PORT" >&2
  exit 2
fi

OPENSHELL_ENDPOINT="${OPENSHELL_GRPC_ENDPOINT:-http://host.docker.internal:${PORT}}"

CARGO_BUILD_JOBS_ARG=()
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  CARGO_BUILD_JOBS_ARG=(-j "${CARGO_BUILD_JOBS}")
fi

echo "==> Building openshell-gateway (docker-sandboxes-in-tree)"
cargo build ${CARGO_BUILD_JOBS_ARG[@]+"${CARGO_BUILD_JOBS_ARG[@]}"} \
  -p openshell-server --bin openshell-gateway --features docker-sandboxes-in-tree

TLS_DIR="${STATE_DIR}/tls"
echo "==> Generating local gateway credentials"
"${GATEWAY_BIN}" generate-certs \
  --output-dir "${TLS_DIR}" \
  --server-san "127.0.0.1" \
  --server-san "localhost" \
  --server-san "host.docker.internal"

mkdir -p "${STATE_DIR}"
CONFIG_PATH="${STATE_DIR}/gateway.toml"
cat >"${CONFIG_PATH}" <<EOF
[openshell]
version = 1

[openshell.gateway]
compute_drivers = ["docker-sandboxes"]
disable_tls = true

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "${TLS_DIR}/jwt/signing.pem"
public_key_path = "${TLS_DIR}/jwt/public.pem"
kid_path = "${TLS_DIR}/jwt/kid"
gateway_id = "${GATEWAY_NAME}"
ttl_secs = 3600

[openshell.drivers.docker-sandboxes]
openshell_endpoint = "${OPENSHELL_ENDPOINT}"
EOF

if [[ -n "${OPENSHELL_DOCKER_SANDBOXES_PROFILE:-}" ]]; then
  cat >>"${CONFIG_PATH}" <<EOF
profile = "${OPENSHELL_DOCKER_SANDBOXES_PROFILE}"
EOF
fi

GATEWAY_ENDPOINT="http://127.0.0.1:${PORT}"
register_gateway_metadata "${GATEWAY_NAME}" "${GATEWAY_ENDPOINT}" "${PORT}"
save_active_gateway "${GATEWAY_NAME}"

echo "Starting standalone Docker Sandboxes gateway..."
echo "  gateway:   ${GATEWAY_NAME}"
echo "  endpoint:  ${GATEWAY_ENDPOINT}"
echo "  state dir: ${STATE_DIR}"
echo "  profile:   ${OPENSHELL_DOCKER_SANDBOXES_PROFILE:-<none>}"
echo
echo "Active gateway set to '${GATEWAY_NAME}'. The CLI now targets this gateway"
echo "by default — just run \`openshell <command>\`. Override with --gateway"
echo "or by setting OPENSHELL_GATEWAY (e.g. in .env)."
echo

exec "${GATEWAY_BIN}" \
  --config "${CONFIG_PATH}" \
  --port "${PORT}" \
  --log-level "${LOG_LEVEL}" \
  --drivers docker-sandboxes \
  --disable-tls \
  --db-url "sqlite:${STATE_DIR}/gateway.db?mode=rwc"
