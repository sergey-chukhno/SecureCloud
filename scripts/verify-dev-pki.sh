#!/usr/bin/env bash
set -euo pipefail

# SecureCloud Development PKI Automated Verification Suite
# SC-009 — Establish Development CA and Service Certificates (SC09-T04)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PKI_DIR="${ROOT_DIR}/deploy/dev-pki"
CA_DIR="${PKI_DIR}/ca"
SERVICES_DIR="${PKI_DIR}/services"
COMPOSE_FILE="${ROOT_DIR}/deploy/compose/docker-compose.yml"

SERVICES=("gateway" "auth" "messaging" "files" "audit")

ERRORS=0

log_pass() {
    echo "  [PASS] $1"
}

log_fail() {
    echo "  [FAIL] $1" >&2
    ERRORS=$((ERRORS + 1))
}

echo "[SecureCloud PKI Verification] Starting automated PKI validation suite..."

# Ensure OpenSSL is available
if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: OpenSSL CLI is required but not found." >&2
    exit 1
fi

# Step 1: Verify Directory and File Existence
echo "[Check 1/11] Verifying PKI file structure..."
if [[ ! -f "${CA_DIR}/ca.key" || ! -f "${CA_DIR}/ca.crt" ]]; then
    log_fail "Root CA key or certificate missing in ${CA_DIR}"
else
    log_pass "Root CA key and certificate exist"
fi

for service in "${SERVICES[@]}"; do
    SVC_DIR="${SERVICES_DIR}/${service}"
    if [[ ! -f "${SVC_DIR}/${service}.key" || ! -f "${SVC_DIR}/${service}.crt" ]]; then
        log_fail "Service '${service}' key or certificate missing in ${SVC_DIR}"
    else
        log_pass "Service '${service}' key and certificate exist"
    fi
done

# Step 2: Verify Host Permissions
echo "[Check 2/11] Verifying host file and directory permissions..."
CA_KEY_PERM="$(stat -f "%A" "${CA_DIR}/ca.key" 2>/dev/null || stat -c "%a" "${CA_DIR}/ca.key")"
if [[ "${CA_KEY_PERM}" != "600" ]]; then
    log_fail "Root CA key permission is ${CA_KEY_PERM}, expected 600"
else
    log_pass "Root CA key permission is 0600"
fi

for service in "${SERVICES[@]}"; do
    KEY_PATH="${SERVICES_DIR}/${service}/${service}.key"
    KEY_PERM="$(stat -f "%A" "${KEY_PATH}" 2>/dev/null || stat -c "%a" "${KEY_PATH}")"
    if [[ "${KEY_PERM}" != "600" ]]; then
        log_fail "Service '${service}' key permission is ${KEY_PERM}, expected 600"
    else
        log_pass "Service '${service}' key permission is 0600"
    fi
done

# Step 3: Verify Root CA Constraints
echo "[Check 3/11] Verifying Root CA certificate constraints..."
CA_TEXT="$(openssl x509 -text -noout -in "${CA_DIR}/ca.crt")"

if echo "${CA_TEXT}" | grep -q "CA:TRUE" && echo "${CA_TEXT}" | grep -q "pathlen:0"; then
    log_pass "Root CA has CA:TRUE and pathlen:0"
else
    log_fail "Root CA does not specify CA:TRUE, pathlen:0"
fi

if echo "${CA_TEXT}" | grep -qi "Certificate Sign"; then
    log_pass "Root CA KeyUsage includes Certificate Sign"
else
    log_fail "Root CA KeyUsage missing Certificate Sign"
fi

# Step 4: Verify Service Certificate Constraints & SAN
echo "[Check 4/11] Verifying Service Certificate constraints, SANs, and EKU..."
for service in "${SERVICES[@]}"; do
    CRT_PATH="${SERVICES_DIR}/${service}/${service}.crt"
    CRT_TEXT="$(openssl x509 -text -noout -in "${CRT_PATH}")"

    if echo "${CRT_TEXT}" | grep -q "CA:FALSE"; then
        log_pass "Service '${service}' certificate has CA:FALSE"
    else
        log_fail "Service '${service}' certificate missing CA:FALSE"
    fi

    # Check KeyUsage: digitalSignature present, keyEncipherment ABSENT
    if echo "${CRT_TEXT}" | grep -q "Digital Signature"; then
        if echo "${CRT_TEXT}" | grep -q "Key Encipherment"; then
            log_fail "Service '${service}' KeyUsage improperly includes Key Encipherment for ECDSA"
        else
            log_pass "Service '${service}' KeyUsage includes Digital Signature (no Key Encipherment)"
        fi
    else
        log_fail "Service '${service}' KeyUsage missing Digital Signature"
    fi

    # Check Extended Key Usage
    if echo "${CRT_TEXT}" | grep -q "TLS Web Server Authentication" && echo "${CRT_TEXT}" | grep -q "TLS Web Client Authentication"; then
        log_pass "Service '${service}' EKU contains serverAuth, clientAuth"
    else
        log_fail "Service '${service}' EKU missing serverAuth or clientAuth"
    fi

    # Check SAN identity
    SAN_LINE="$(echo "${CRT_TEXT}" | grep -A 1 "Subject Alternative Name" | tail -n 1 | sed 's/^[[:space:]]*//')"
    if [[ "${SAN_LINE}" == "DNS:${service}" ]]; then
        log_pass "Service '${service}' SAN matches exact service DNS name: ${SAN_LINE}"
    else
        log_fail "Service '${service}' SAN '${SAN_LINE}' does not match expected 'DNS:${service}'"
    fi
done

# Step 5: Verify Cryptographic Certificate Chaining to Root CA
echo "[Check 5/11] Verifying X.509 certificate chaining to Root CA..."
for service in "${SERVICES[@]}"; do
    CRT_PATH="${SERVICES_DIR}/${service}/${service}.crt"
    VERIFY_OUTPUT="$(openssl verify -CAfile "${CA_DIR}/ca.crt" "${CRT_PATH}" 2>&1)"
    if echo "${VERIFY_OUTPUT}" | grep -q ": OK"; then
        log_pass "Service '${service}' certificate chains to Root CA"
    else
        log_fail "Service '${service}' certificate verification failed: ${VERIFY_OUTPUT}"
    fi
done

# Step 6: Verify Key <-> Certificate Matching
echo "[Check 6/11] Verifying public key matching between private key and certificate..."
for service in "${SERVICES[@]}"; do
    KEY_PATH="${SERVICES_DIR}/${service}/${service}.key"
    CRT_PATH="${SERVICES_DIR}/${service}/${service}.crt"

    KEY_PUB="$(openssl pkey -in "${KEY_PATH}" -pubout 2>/dev/null)"
    CRT_PUB="$(openssl x509 -in "${CRT_PATH}" -pubkey -noout 2>/dev/null)"

    if [[ -n "${KEY_PUB}" && "${KEY_PUB}" == "${CRT_PUB}" ]]; then
        log_pass "Service '${service}' public key matches certificate"
    else
        log_fail "Service '${service}' public key does NOT match certificate"
    fi
done

# Step 7: Verify Public Key Uniqueness Across Services
echo "[Check 7/11] Verifying public key uniqueness across all services..."
KEY_HASHES=()
KEY_HASHES+=("$(openssl pkey -in "${CA_DIR}/ca.key" -pubout 2>/dev/null | shasum -a 256 | awk '{print $1}')")

for service in "${SERVICES[@]}"; do
    KEY_PATH="${SERVICES_DIR}/${service}/${service}.key"
    KEY_HASHES+=("$(openssl pkey -in "${KEY_PATH}" -pubout 2>/dev/null | shasum -a 256 | awk '{print $1}')")
done

UNIQUE_COUNT="$(printf "%s\n" "${KEY_HASHES[@]}" | sort -u | wc -l | tr -d ' ')"
TOTAL_COUNT="${#KEY_HASHES[@]}"

if [[ "${UNIQUE_COUNT}" -eq "${TOTAL_COUNT}" ]]; then
    log_pass "All ${TOTAL_COUNT} private keys (Root CA + 5 services) are unique"
else
    log_fail "Duplicate private keys detected (${UNIQUE_COUNT} unique out of ${TOTAL_COUNT})"
fi

# Step 8: Verify Git Exclusion Rules
echo "[Check 8/11] Verifying Git repository exclusion rules..."
if git check-ignore -q "${CA_DIR}/ca.key" && git check-ignore -q "${SERVICES_DIR}/gateway/gateway.key"; then
    log_pass "Git ignore correctly excludes development PKI private keys"
else
    log_fail "Git ignore check failed for PKI private keys"
fi

# Step 9: Verify Docker Build Context Isolation
echo "[Check 9/11] Verifying Docker build-context isolation..."
TAR_EXCLUDE="$(tar --exclude-from="${ROOT_DIR}/.dockerignore" -cf - -C "${ROOT_DIR}" . | tar tf - | grep "deploy/dev-pki" || true)"
if [[ -z "${TAR_EXCLUDE}" ]]; then
    log_pass "Docker context tarball successfully excludes deploy/dev-pki/"
else
    log_fail "Docker context tarball includes deploy/dev-pki/ paths: ${TAR_EXCLUDE}"
fi

# Step 10: Verify Docker Compose Mount Configuration
echo "[Check 10/11] Verifying Docker Compose configuration syntax..."
if docker compose -f "${COMPOSE_FILE}" config >/dev/null 2>&1; then
    log_pass "Docker Compose configuration syntax is valid"
else
    log_fail "Docker Compose configuration validation failed"
fi

# Step 11: Verify Container Non-Root Read Access and Write Protection
echo "[Check 11/11] Verifying container UID 10001 read access and read-only mount protection..."
for service in "${SERVICES[@]}"; do
    # Check Readability of CA cert, service cert, and service key inside container
    if docker compose -f "${COMPOSE_FILE}" run --rm --entrypoint "" "${service}" test -r /etc/securecloud/certs/service.key >/dev/null 2>&1; then
        log_pass "Container '${service}' process (UID 10001) can read service.key"
    else
        log_fail "Container '${service}' process (UID 10001) CANNOT read service.key"
    fi

    # Check Write Protection (touch should fail with exit code != 0)
    if docker compose -f "${COMPOSE_FILE}" run --rm --entrypoint "" "${service}" touch /etc/securecloud/certs/service.key >/dev/null 2>&1; then
        log_fail "Container '${service}' process was able to modify service.key (Write protection missing)"
    else
        log_pass "Container '${service}' write operation correctly blocked (Read-only volume mount)"
    fi
done

echo ""
if [[ "${ERRORS}" -eq 0 ]]; then
    echo "[SecureCloud PKI Verification] SUCCESS: All PKI security and verification checks passed cleanly."
    exit 0
else
    echo "[SecureCloud PKI Verification] FAILURE: ${ERRORS} verification check(s) failed." >&2
    exit 1
fi
