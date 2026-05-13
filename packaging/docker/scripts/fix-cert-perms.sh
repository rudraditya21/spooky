#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CERTS_DIR="${1:-${ROOT_DIR}/certs}"
TARGET_GID="${2:-10001}"

KEY_FILE="${CERTS_DIR}/proxy-key-pkcs8.pem"
CERT_FILE="${CERTS_DIR}/proxy-cert.pem"

if [[ ! -d "${CERTS_DIR}" ]]; then
  echo "error: cert directory not found: ${CERTS_DIR}" >&2
  exit 1
fi

if [[ ! -f "${KEY_FILE}" ]]; then
  echo "error: key file not found: ${KEY_FILE}" >&2
  exit 1
fi

if [[ ! -f "${CERT_FILE}" ]]; then
  echo "error: cert file not found: ${CERT_FILE}" >&2
  exit 1
fi

echo "Applying least-privilege cert permissions for container gid ${TARGET_GID}"

# Ensure the container group can traverse the cert directory.
chgrp "${TARGET_GID}" "${CERTS_DIR}"
chmod 750 "${CERTS_DIR}"

# Key: group-readable for container group, owner-readable/writable only otherwise.
chgrp "${TARGET_GID}" "${KEY_FILE}"
chmod 640 "${KEY_FILE}"

# Cert: readable by owner/group/world, with container group ownership.
chgrp "${TARGET_GID}" "${CERT_FILE}"
chmod 644 "${CERT_FILE}"

echo "Done."
echo "Directory: ${CERTS_DIR}"
echo "Key:       ${KEY_FILE}"
echo "Cert:      ${CERT_FILE}"
