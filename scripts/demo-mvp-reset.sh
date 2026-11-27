#!/usr/bin/env bash
set -euo pipefail

# Reset and prepare a clean live Docker Compose demo environment for two
# desktop SecureCloud clients (alice@securecloud.local and bob@securecloud.local).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/compose/docker-compose.yml"
PKI_DIR="${REPO_ROOT}/deploy/dev-pki"
CA_CERT="${PKI_DIR}/ca/ca.crt"
GATEWAY_CERT="${PKI_DIR}/services/gateway/gateway.crt"

ALICE_EMAIL="${DEMO_ALICE_EMAIL:-alice@securecloud.local}"
ALICE_PASSWORD="${DEMO_ALICE_PASSWORD:-AliceDemo#2026}"
ALICE_UUID="01930000-0000-7000-8000-000000000001"

BOB_EMAIL="${DEMO_BOB_EMAIL:-bob@securecloud.local}"
BOB_PASSWORD="${DEMO_BOB_PASSWORD:-BobDemo#2026}"
BOB_UUID="01930000-0000-7000-8000-000000000002"

AUTH_DB_NAME="${AUTH_DB_NAME:-securecloud_auth}"
AUTH_DB_USER="${AUTH_DB_USER:-auth_user}"
AUTH_DB_PASSWORD="${AUTH_DB_PASSWORD:-auth_dev_db_secret}"

WIPE_DBS=1
REBUILD=0
for arg in "$@"; do
    case "${arg}" in
        --keep-client-dbs)
            WIPE_DBS=0
            ;;
        --build)
            REBUILD=1
            ;;
        --help|-h)
            cat <<'EOF'
Usage: scripts/demo-mvp-reset.sh [--build] [--keep-client-dbs]

Options:
  --build            Rebuild backend Docker images before starting Compose stack
  --keep-client-dbs  Preserve /tmp/alice.db and /tmp/bob.db instead of removing them
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: ${arg}" >&2
            exit 1
            ;;
    esac
done

resolve_openssl_with_argon2id() {
    local candidates=()
    if [[ -n "${OPENSSL_BIN:-}" ]]; then
        candidates+=("${OPENSSL_BIN}")
    fi
    if [[ -x "/opt/homebrew/opt/openssl@3/bin/openssl" ]]; then
        candidates+=("/opt/homebrew/opt/openssl@3/bin/openssl")
    fi
    if [[ -x "/usr/local/opt/openssl@3/bin/openssl" ]]; then
        candidates+=("/usr/local/opt/openssl@3/bin/openssl")
    fi
    candidates+=("openssl")

    for bin in "${candidates[@]}"; do
        if command -v "${bin}" >/dev/null 2>&1; then
            if "${bin}" kdf -kdfopt pass:probe -kdfopt hexsalt:00112233445566778899aabbccddeeff \
                -kdfopt memcost:1024 -kdfopt iter:1 -kdfopt lanes:1 -kdfopt threads:1 \
                -binary -keylen 16 ARGON2ID >/dev/null 2>&1; then
                echo "${bin}"
                return 0
            fi
        fi
    done
    return 1
}

make_argon2id_phc() {
    local password="$1"
    local openssl_bin="$2"
    local salt_b64_padded salt_b64 salt_hex hash_b64

    if [[ -n "${openssl_bin}" ]]; then
        salt_b64_padded="$(head -c 16 /dev/urandom | "${openssl_bin}" base64 -A)"
        salt_b64="${salt_b64_padded%%=*}"
        salt_hex="$(printf '%s' "${salt_b64_padded}" | "${openssl_bin}" base64 -d -A | od -An -tx1 | tr -d ' \n')"
        hash_b64="$("${openssl_bin}" kdf \
            -kdfopt "pass:${password}" \
            -kdfopt "hexsalt:${salt_hex}" \
            -kdfopt memcost:65536 \
            -kdfopt iter:3 \
            -kdfopt lanes:1 \
            -kdfopt threads:1 \
            -binary -keylen 32 ARGON2ID | "${openssl_bin}" base64 -A | tr -d '=')"
    else
        salt_b64_padded="$(head -c 16 /dev/urandom | base64 | tr -d '\n')"
        salt_b64="${salt_b64_padded%%=*}"
        salt_hex="$(printf '%s' "${salt_b64_padded}" | base64 --decode | od -An -tx1 | tr -d ' \n')"
        hash_b64="$(docker compose -f "${COMPOSE_FILE}" exec -T auth sh -lc \
            "openssl kdf -kdfopt 'pass:${password}' -kdfopt 'hexsalt:${salt_hex}' -kdfopt memcost:65536 -kdfopt iter:3 -kdfopt lanes:1 -kdfopt threads:1 -binary -keylen 32 ARGON2ID | openssl base64 -A | tr -d '='")"
    fi

    printf '$argon2id$v=19$m=65536,t=3,p=1$%s$%s' "${salt_b64}" "${hash_b64}"
}

echo "[demo-mvp-reset] 1/5 Ensuring dev PKI exists with Gateway SAN (DNS:gateway,DNS:localhost,IP:127.0.0.1)..."
if [[ ! -f "${GATEWAY_CERT}" || ! -f "${CA_CERT}" ]] || \
   ! openssl x509 -in "${GATEWAY_CERT}" -noout -text | grep -q "IP Address:127.0.0.1"; then
    "${REPO_ROOT}/scripts/generate-dev-pki.sh" --force
fi
"${REPO_ROOT}/scripts/verify-dev-pki.sh" >/dev/null

echo "[demo-mvp-reset] 2/5 Starting full 5-service Docker Compose MVP stack..."
if [[ "${REBUILD}" -eq 1 ]]; then
    docker compose -f "${COMPOSE_FILE}" up -d --build
else
    docker compose -f "${COMPOSE_FILE}" up -d
fi

echo "[demo-mvp-reset] 3/5 Waiting for Postgres, migrations, and Gateway TLS 1.3 health endpoint..."
for attempt in $(seq 1 60); do
    if docker compose -f "${COMPOSE_FILE}" exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
        break
    fi
    if [[ "${attempt}" -eq 60 ]]; then
        echo "Postgres failed to become ready in time" >&2
        exit 1
    fi
    sleep 2
done

for attempt in $(seq 1 30); do
    if curl --http1.1 -sf --cacert "${CA_CERT}" https://127.0.0.1:8443/health/live >/dev/null 2>&1; then
        break
    fi
    if [[ "${attempt}" -eq 30 ]]; then
        echo "Gateway https://127.0.0.1:8443/health/live did not become ready in time" >&2
        exit 1
    fi
    sleep 2
done

echo "[demo-mvp-reset] 4/5 Seeding demo users (${ALICE_EMAIL}, ${BOB_EMAIL}) in ${AUTH_DB_NAME}..."
OPENSSL_ARGON2_BIN="$(resolve_openssl_with_argon2id || true)"
ALICE_PHC="$(make_argon2id_phc "${ALICE_PASSWORD}" "${OPENSSL_ARGON2_BIN}")"
BOB_PHC="$(make_argon2id_phc "${BOB_PASSWORD}" "${OPENSSL_ARGON2_BIN}")"

docker compose -f "${COMPOSE_FILE}" exec -T -e "PGPASSWORD=${AUTH_DB_PASSWORD}" postgres \
    psql -v ON_ERROR_STOP=1 -U "${AUTH_DB_USER}" -d "${AUTH_DB_NAME}" \
    -v alice_id="${ALICE_UUID}" -v alice_email="${ALICE_EMAIL}" -v alice_hash="${ALICE_PHC}" \
    -v bob_id="${BOB_UUID}" -v bob_email="${BOB_EMAIL}" -v bob_hash="${BOB_PHC}" <<'SQL'
INSERT INTO users (
    user_id, credential_identifier, password_verifier, password_algorithm,
    password_updated_at, account_status, created_at, updated_at, version
) VALUES
    (:'alice_id', :'alice_email', :'alice_hash', 'argon2id', NOW(), 'Active', NOW(), NOW(), 1),
    (:'bob_id', :'bob_email', :'bob_hash', 'argon2id', NOW(), 'Active', NOW(), NOW(), 1)
ON CONFLICT (credential_identifier) DO UPDATE SET
    password_verifier = EXCLUDED.password_verifier,
    password_algorithm = 'argon2id',
    password_updated_at = NOW(),
    account_status = 'Active',
    updated_at = NOW();
SQL

if [[ "${WIPE_DBS}" -eq 1 ]]; then
    echo "[demo-mvp-reset] Resetting clean desktop SQLCipher state in /tmp/alice.db and /tmp/bob.db..."
    rm -f /tmp/alice.db /tmp/alice.db-wal /tmp/alice.db-shm /tmp/bob.db /tmp/bob.db-wal /tmp/bob.db-shm
fi

GATEWAY_SPKI_SHA256="$(openssl x509 -in "${GATEWAY_CERT}" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')"

CLIENT_BIN="./build/dev-release/src/client/securecloud-client"
if [[ ! -x "${REPO_ROOT}/${CLIENT_BIN#./}" && -x "${REPO_ROOT}/build/dev-debug/src/client/securecloud-client" ]]; then
    CLIENT_BIN="./build/dev-debug/src/client/securecloud-client"
fi

echo ""
echo "[demo-mvp-reset] 5/5 MVP Live Demo Environment Ready"
echo "================================================================================"
echo "Gateway HTTPS Endpoint : https://127.0.0.1:8443 (HTTP->HTTPS redirect :8080)"
echo "CA Certificate Bundle  : ${CA_CERT}"
echo "Gateway SPKI SHA-256   : ${GATEWAY_SPKI_SHA256}"
echo ""
echo "Demo Credentials:"
echo "  Alice : ${ALICE_EMAIL} / ${ALICE_PASSWORD} (user_id=${ALICE_UUID})"
echo "  Bob   : ${BOB_EMAIL}   / ${BOB_PASSWORD}   (user_id=${BOB_UUID})"
echo ""
echo "Terminal 1 — Launch Alice Window:"
cat <<EOF
  cd "${REPO_ROOT}" && \\
  SECURECLOUD_USE_LIVE_GATEWAY=1 \\
  SECURECLOUD_GATEWAY_URL=https://127.0.0.1 \\
  SECURECLOUD_GATEWAY_PORT=8443 \\
  SECURECLOUD_TLS_CA_CERT_PATH="${CA_CERT}" \\
  SECURECLOUD_TLS_PIN_SPKI_SHA256="${GATEWAY_SPKI_SHA256}" \\
  SECURECLOUD_TLS_ENFORCE_PINNING=1 \\
  SECURECLOUD_DATABASE_PATH=/tmp/alice.db \\
  SECURECLOUD_KEYCHAIN_SERVICE_ID=securecloud-demo-alice \\
  "${CLIENT_BIN}"
EOF
echo ""
echo "Terminal 2 — Launch Bob Window:"
cat <<EOF
  cd "${REPO_ROOT}" && \\
  SECURECLOUD_USE_LIVE_GATEWAY=1 \\
  SECURECLOUD_GATEWAY_URL=https://127.0.0.1 \\
  SECURECLOUD_GATEWAY_PORT=8443 \\
  SECURECLOUD_TLS_CA_CERT_PATH="${CA_CERT}" \\
  SECURECLOUD_TLS_PIN_SPKI_SHA256="${GATEWAY_SPKI_SHA256}" \\
  SECURECLOUD_TLS_ENFORCE_PINNING=1 \\
  SECURECLOUD_DATABASE_PATH=/tmp/bob.db \\
  SECURECLOUD_KEYCHAIN_SERVICE_ID=securecloud-demo-bob \\
  "${CLIENT_BIN}"
EOF
echo "================================================================================"
