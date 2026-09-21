#!/usr/bin/env bash
set -euo pipefail

# In Git Bash / MSYS2, exempt -subj arguments from automatic POSIX-to-Windows path conversion
export MSYS2_ARG_CONV_EXCL="/CN="

# SecureCloud Development PKI Provisioning Tool
# SC-009 — Establish Development CA and Service Certificates

get_native_path() {
    local target_dir="$1"
    if (cd "${target_dir}" && pwd -W) >/dev/null 2>&1; then
        (cd "${target_dir}" && pwd -W)
    elif command -v cygpath >/dev/null 2>&1; then
        cygpath -m "${target_dir}"
    else
        (cd "${target_dir}" && pwd)
    fi
}

SCRIPT_DIR="$(get_native_path "$(dirname "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(get_native_path "${SCRIPT_DIR}/..")"

PKI_DIR="${ROOT_DIR}/deploy/dev-pki"
CA_DIR="${PKI_DIR}/ca"
SERVICES_DIR="${PKI_DIR}/services"

SERVICES=("gateway" "auth" "messaging" "files" "audit")

FORCE_REGEN=false

for arg in "$@"; do
    case "$arg" in
        --force)
            FORCE_REGEN=true
            ;;
        -h|--help)
            echo "Usage: $0 [--force]"
            echo ""
            echo "Options:"
            echo "  --force    Force regeneration of CA and all service certificates"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            echo "Error: Unknown argument '$arg'" >&2
            echo "Usage: $0 [--force]" >&2
            exit 1
            ;;
    esac
done

# Discover OpenSSL CLI (prefer Homebrew OpenSSL 3 over legacy system LibreSSL on macOS)
OPENSSL_BIN="openssl"
if [[ -x "/opt/homebrew/opt/openssl@3/bin/openssl" ]]; then
    OPENSSL_BIN="/opt/homebrew/opt/openssl@3/bin/openssl"
elif [[ -x "/usr/local/opt/openssl@3/bin/openssl" ]]; then
    OPENSSL_BIN="/usr/local/opt/openssl@3/bin/openssl"
elif ! command -v "${OPENSSL_BIN}" >/dev/null 2>&1; then
    echo "Error: OpenSSL CLI is required but not found in PATH." >&2
    exit 1
fi

OPENSSL_VER="$("${OPENSSL_BIN}" version)"
echo "[SecureCloud PKI] Using OpenSSL tool: ${OPENSSL_VER}"

# Create root PKI and subdirectories with strict permissions (0700)
mkdir -p "${CA_DIR}" "${SERVICES_DIR}"
chmod 700 "${PKI_DIR}" "${CA_DIR}" "${SERVICES_DIR}" 2>/dev/null || true

CA_KEY="${CA_DIR}/ca.key"
CA_CRT="${CA_DIR}/ca.crt"
CA_SRL="${CA_DIR}/ca.srl"

CA_REGENERATED=false

if [[ -f "${CA_KEY}" && -f "${CA_CRT}" && "${FORCE_REGEN}" == "false" ]]; then
    echo "[SecureCloud PKI] Existing Root CA identity found at ${CA_DIR}. Preserving CA (use --force to regenerate)."
else
    echo "[SecureCloud PKI] Generating Root CA (ECDSA P-256)..."
    
    # Generate Root CA key & cert atomically
    "${OPENSSL_BIN}" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -pkeyopt ec_param_enc:named_curve -sha256 \
        -keyout "${CA_KEY}" -out "${CA_CRT}" -nodes -days 365 \
        -subj "/CN=SecureCloud Development Root CA/O=SecureCloud Dev" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,digitalSignature,cRLSign,keyCertSign" \
        -addext "subjectKeyIdentifier=hash" >/dev/null

    chmod 600 "${CA_KEY}" 2>/dev/null || true
    chmod 644 "${CA_CRT}" 2>/dev/null || true
    CA_REGENERATED=true
    echo "[SecureCloud PKI] Root CA created."
fi

# Ensure CA key permissions remain strict 0600
chmod 600 "${CA_KEY}" 2>/dev/null || true
chmod 644 "${CA_CRT}" 2>/dev/null || true

# Provision Service Identities
for service in "${SERVICES[@]}"; do
    SVC_DIR="${SERVICES_DIR}/${service}"
    mkdir -p "${SVC_DIR}"
    chmod 700 "${SVC_DIR}" 2>/dev/null || true

    SVC_KEY="${SVC_DIR}/${service}.key"
    SVC_CRT="${SVC_DIR}/${service}.crt"
    SVC_CSR="${SVC_DIR}/${service}.csr"
    SVC_EXT="${SVC_DIR}/${service}.ext"

    if [[ -f "${SVC_KEY}" && -f "${SVC_CRT}" && "${FORCE_REGEN}" == "false" && "${CA_REGENERATED}" == "false" ]]; then
        echo "[SecureCloud PKI] Service '${service}' certificate already exists. Preserving identity."
        chmod 600 "${SVC_KEY}" 2>/dev/null || true
        chmod 644 "${SVC_CRT}" 2>/dev/null || true
        continue
    fi

    echo "[SecureCloud PKI] Provisioning service identity: ${service}..."

    # Generate unique ECDSA P-256 private key for service with explicit named curve encoding
    "${OPENSSL_BIN}" ecparam -name prime256v1 -genkey -param_enc named_curve -noout -out "${SVC_KEY}" >/dev/null
    chmod 600 "${SVC_KEY}" 2>/dev/null || true

    # Generate CSR for service
    "${OPENSSL_BIN}" req -new -key "${SVC_KEY}" -sha256 -out "${SVC_CSR}" \
        -subj "/CN=${service}.dev.securecloud.local/O=SecureCloud Dev" >/dev/null

    # Create temporary extension configuration for service
    cat << EOF > "${SVC_EXT}"
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:${service}
EOF

    # Sign service certificate against Root CA using SHA-256
    "${OPENSSL_BIN}" x509 -req -sha256 -in "${SVC_CSR}" \
        -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAserial "${CA_SRL}" -CAcreateserial \
        -out "${SVC_CRT}" -days 365 -extfile "${SVC_EXT}" >/dev/null

    chmod 600 "${SVC_KEY}" 2>/dev/null || true
    chmod 644 "${SVC_CRT}" 2>/dev/null || true

    # Cleanup temporary CSR and extension files
    rm -f "${SVC_CSR}" "${SVC_EXT}"

    echo "[SecureCloud PKI] Service '${service}' identity provisioned."
done

echo "[SecureCloud PKI] Development PKI provisioning complete."
