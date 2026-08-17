#!/usr/bin/env bash
#
# Generate a throwaway CA plus a server cert (Murtaugh console) and a client
# cert (Riggs agent) for exercising the gRPC mTLS path in development.
#
# This is a stand-in for your real PKI. In production you bring your own CA and
# issue agent/server certs from it; Riggs only needs the PEM paths.
#
# Usage:  scripts/gen-dev-certs.sh [output_dir] [server_dns_name]
#   output_dir       defaults to ./dev-certs
#   server_dns_name  defaults to localhost (must match the agent's dial host or
#                    comms.tls.domain_name)
#
set -euo pipefail

OUT="${1:-dev-certs}"
SERVER_CN="${2:-localhost}"
DAYS=825

mkdir -p "$OUT"
cd "$OUT"

echo "==> CA"
openssl genrsa -out ca-key.pem 4096
openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days "$DAYS" \
  -subj "/CN=Riggs Dev CA" -out ca.pem

gen_cert() {
  local name="$1" cn="$2" ext="$3"
  echo "==> $name cert (CN=$cn)"
  openssl genrsa -out "${name}-key.pem" 4096
  openssl req -new -key "${name}-key.pem" -subj "/CN=${cn}" -out "${name}.csr"
  openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "${name}.pem" -days "$DAYS" -sha256 -extfile <(printf '%s' "$ext")
  rm -f "${name}.csr"
}

# Server cert: needs a SAN matching the name the agent dials / verifies.
gen_cert server "$SERVER_CN" \
  "subjectAltName=DNS:${SERVER_CN},DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth"

# Client (agent) cert: CN identifies the agent; used for mutual auth.
gen_cert agent "riggs-agent-dev" \
  "extendedKeyUsage=clientAuth"

rm -f ca.srl
echo
echo "Wrote certs to $(pwd):"
ls -1 *.pem
cat <<EOF

Console (Murtaugh) — start with mTLS:
  MURTAUGH_GRPC_CERT=$(pwd)/server.pem \\
  MURTAUGH_GRPC_KEY=$(pwd)/server-key.pem \\
  MURTAUGH_GRPC_CACERT=$(pwd)/ca.pem \\
  mix phx.server

Agent (config/riggs.toml):
  cloud_endpoint = "https://${SERVER_CN}:4001"
  [comms.tls]
  ca_cert_path     = "$(pwd)/ca.pem"
  client_cert_path = "$(pwd)/agent.pem"
  client_key_path  = "$(pwd)/agent-key.pem"
  domain_name      = "${SERVER_CN}"

Smoke test the handshake (expects a TLS response, not a plaintext reset):
  openssl s_client -connect ${SERVER_CN}:4001 -CAfile $(pwd)/ca.pem \\
    -cert $(pwd)/agent.pem -key $(pwd)/agent-key.pem -alpn h2 </dev/null
EOF
