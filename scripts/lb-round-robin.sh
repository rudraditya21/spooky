#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

ensure_bins

cat > /tmp/spooky-lb-rr.yaml <<'YAML'
listen:
    protocol: http3
    port: 9889
    address: "127.0.0.1"
    tls:
        cert: "certs/proxy-cert.pem"
        key: "certs/proxy-key-pkcs8.pem"

backends:
    -   id: "backend1"
        address: "127.0.0.1:8081"
        weight: 1
        health_check:
            path: "/health"
            interval: 5000
    -   id: "backend2"
        address: "127.0.0.1:8082"
        weight: 1
        health_check:
            path: "/health"
            interval: 5000
    -   id: "backend3"
        address: "127.0.0.1:8083"
        weight: 1
        health_check:
            path: "/health"
            interval: 5000

load_balancing:
    type: round-robin

log:
  level: info
YAML

B1=$(start_backend 8081)
B2=$(start_backend 8082)
B3=$(start_backend 8083)
SPOOKY=$(start_spooky /tmp/spooky-lb-rr.yaml)

sleep 1

for i in {1..6}; do
  run_client "rr-test"
done

sleep 1
print_selection_log

cleanup_pids "${SPOOKY}" "${B1}" "${B2}" "${B3}"
