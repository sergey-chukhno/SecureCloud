# SecureCloud MVP Full-Stack Live Demo Runbook

> **Scope (`CLIENT-015-T06`):** End-to-end operator guide for running the 5-service SecureCloud backend stack (`Gateway`, `Auth`, `Messaging`, `Files`, `Audit`) + 4 datastores (`PostgreSQL 17`, `ScyllaDB 6.2`, `ClickHouse`, `MinIO`) via Docker Compose and connecting two isolated `securecloud-client` desktop windows side-by-side over fail-closed TLS 1.3 with SPKI certificate pinning.

---

## 1. Architecture Overview

- **External Edge (Client ↔ Gateway `:8443`):** Desktop clients communicate exclusively over **HTTPS TLS 1.3** (`HTTP/1.1`) against `Gateway` (`https://127.0.0.1:8443`) using the local Dev Root CA (`deploy/dev-pki/ca/ca.crt`) and pinned leaf `SPKI SHA-256` fingerprint. Plaintext port `8080` returns `308 Permanent Redirect` to HTTPS.
- **Internal Mesh (Gateway ↔ Services mTLS gRPC):**
  - `Auth` (`:50052`) — PostgreSQL (`securecloud_auth`) for Argon2id authentication, Ed25519 JWT issuance, TOTP MFA, device lifecycle, X25519/Ed25519 crypto directory & OTPK inventory, and `auth_outbox`.
  - `Messaging` (`:50053`) — ScyllaDB 6.2 (`securecloud_messaging`) for conversations, encrypted message fan-out, per-device delivery queues/ACKs, read receipts, and `messaging_audit_outbox`.
  - `Files` (`:50054`) — PostgreSQL (`securecloud_files`) + MinIO S3 (`:9000`) for chunked ciphertext staging/assembly and `files_outbox`.
  - `Audit` (`:50055`) — ClickHouse (`:8123` / `:9009`) for append-only deduplicated security audit ingestion & internal `AuditQueryService` mTLS queries (`ADR-001` / `ADR-005` / `ADR-011`: decoupled from client UI; zero public `/api/v1/audit` HTTP route).
- **Local Client Storage:** Each desktop instance maintains its own encrypted SQLCipher database (`SECURECLOUD_DATABASE_PATH=/tmp/alice.db`, `/tmp/bob.db`), including `local_audit_log` (Table #9) and secret storage scoped by `SECURECLOUD_KEYCHAIN_SERVICE_ID`.

---

## 2. Prerequisites

1. **Docker & Docker Compose v2** running with at least `6 GiB` RAM allocated to the container engine (for ScyllaDB, ClickHouse, Postgres, MinIO, and 5 C++ services).
2. **Built host desktop binary & unit/integration targets** (built via `-DSECURECLOUD_BUILD_CLIENT=ON`):
   ```bash
   cmake --preset dev-release
   cmake --build build/dev-release --target securecloud-client --parallel
   ```
   *(Or use `./build/dev-debug/src/client/securecloud-client` and `./build/dev-debug/tests/integration/securecloud_client_gateway_backend_integration_test` for debug diagnostics.)*
3. **OpenSSL 3.2+ CLI** (`brew install openssl@3` on macOS; falls back automatically to the `auth` container's OpenSSL 3.5.9 CLI when deriving Argon2id password hashes inside `scripts/demo-mvp-reset.sh`).

---

## 3. One-Command Demo Reset & Provisioning

Run the reset script from the repository root:

```bash
./scripts/demo-mvp-reset.sh
```

Pass `--build` if you modified backend C++ or Dockerfiles:

```bash
./scripts/demo-mvp-reset.sh --build
```

Pass `--keep-client-dbs` to keep `/tmp/alice.db` and `/tmp/bob.db` intact across resets:

```bash
./scripts/demo-mvp-reset.sh --keep-client-dbs
```

### What `demo-mvp-reset.sh` Does

1. Ensures `deploy/dev-pki/` contains `gateway.crt` carrying `DNS:gateway,DNS:localhost,IP:127.0.0.1` (regenerating via `scripts/generate-dev-pki.sh --force` only if missing loopback SAN) and validates PKI permissions (`scripts/verify-dev-pki.sh`).
2. Boots all Compose services + one-shot migration jobs (`postgres-migrate` for `auth_db` `V001`–`V005` & `files_db` `V001`–`V002`; `scylla-init` for `V001`–`V006`; `minio-init` bucket provisioning).
3. Waits for Postgres readiness and `GET https://127.0.0.1:8443/health/live` (`HTTP/1.1 200 {"status":"SERVING"}`).
4. Idempotently upserts demo accounts into `securecloud_auth.users` with OpenSSL 3 Argon2id hashes:
   - **Alice:** `alice@securecloud.local` / `AliceDemo#2026`
   - **Bob:** `bob@securecloud.local` / `BobDemo#2026`
5. Clears stale `/tmp/alice.db*` and `/tmp/bob.db*` (unless `--keep-client-dbs`), computes the live Gateway `SPKI SHA-256` fingerprint, and prints exact copy-paste terminal commands for launching Alice and Bob side-by-side.

---

## 4. Launching Two Live Desktop Clients Side-by-Side

Set the Gateway `SPKI SHA-256` pin printed by `./scripts/demo-mvp-reset.sh` (or evaluate it inline):

```bash
PIN=$(openssl x509 -in deploy/dev-pki/services/gateway/gateway.crt -pubkey -noout \
  | openssl pkey -pubin -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')
```

**Terminal 1 (Alice):**

```bash
SECURECLOUD_USE_LIVE_GATEWAY=1 \
SECURECLOUD_GATEWAY_URL=https://127.0.0.1 \
SECURECLOUD_GATEWAY_PORT=8443 \
SECURECLOUD_TLS_CA_CERT_PATH="$(pwd)/deploy/dev-pki/ca/ca.crt" \
SECURECLOUD_TLS_PIN_SPKI_SHA256="$PIN" \
SECURECLOUD_TLS_ENFORCE_PINNING=1 \
SECURECLOUD_DATABASE_PATH=/tmp/alice.db \
SECURECLOUD_KEYCHAIN_SERVICE_ID=securecloud-demo-alice \
./build/dev-release/src/client/securecloud-client
```

**Terminal 2 (Bob):**

```bash
SECURECLOUD_USE_LIVE_GATEWAY=1 \
SECURECLOUD_GATEWAY_URL=https://127.0.0.1 \
SECURECLOUD_GATEWAY_PORT=8443 \
SECURECLOUD_TLS_CA_CERT_PATH="$(pwd)/deploy/dev-pki/ca/ca.crt" \
SECURECLOUD_TLS_PIN_SPKI_SHA256="$PIN" \
SECURECLOUD_TLS_ENFORCE_PINNING=1 \
SECURECLOUD_DATABASE_PATH=/tmp/bob.db \
SECURECLOUD_KEYCHAIN_SERVICE_ID=securecloud-demo-bob \
./build/dev-release/src/client/securecloud-client
```

*(Note: Passing `--database` on the CLI is not needed; `ClientConfig::from_environment()` reads `SECURECLOUD_DATABASE_PATH` and `SECURECLOUD_KEYCHAIN_SERVICE_ID` cleanly so both desktop instances never collide on SQLCipher vaults or local secrets.)*

---

## 5. Live Presentation Walkthrough

1. **Boot Crypto KATs & Live Login:** Both windows pass the 6 OpenSSL boot self-tests cleanly, then sign in with `alice@securecloud.local` / `AliceDemo#2026` and `bob@securecloud.local` / `BobDemo#2026` over TLS 1.3 `POST /api/v1/auth/login`.
2. **TLS Pin & Diagnostics Inspection (`Ctrl+Shift+D`):** Open `Settings -> Network` to show `Live Gateway Transport = Enabled`, `SPKI SHA-256 Pin` matched, and open `Diagnostics & Troubleshooting` (`Ctrl+Shift+D`) to show live Gateway RTT metrics, RSS memory, normalized CPU load, and hash-chained `local_audit_log`.
3. **E2EE Double Ratchet Chat & Zero-Plaintext Proof:** Create/open a direct conversation (`POST /api/v1/conversations`), send a secret demo message from Alice to Bob, verify Bob decrypts it cleanly, then verify ScyllaDB contains only opaque ciphertext:
   ```bash
   docker compose -f deploy/compose/docker-compose.yml exec -T scylladb \
     cqlsh -e "SELECT conversation_id, message_sequence, message_id, ciphertext_envelope FROM securecloud_messaging.messages_by_conversation LIMIT 5;"
   ```
4. **Encrypted File Transfer & MinIO Zero-Plaintext Proof:** Attach and upload a multi-MB document from Alice (`POST /api/v1/files/upload/{init,chunk,finalize}` + encrypted file key envelope delivered over Double Ratchet); confirm Postgres `encrypted_file_metadata` and MinIO `securecloud-files-encrypted` hold zero plaintext filenames or contents.
5. **Automated Full-Stack 5-Scenario Gate & ClickHouse Audit Continuity:**
   Execute the automated end-to-end suite verifying live auth, E2EE chat, 5 MiB chunked file transfer, offline catch-up sync, MFA device revocation, emergency panic wipe, and internal mTLS `AuditQueryService` continuity across `GATEWAY`, `AUTH`, `MESSAGING`, and `FILES`:
   ```bash
   SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1 QT_QPA_PLATFORM=offscreen \
     ./build/dev-debug/tests/integration/securecloud_client_gateway_backend_integration_test
   ```
   Verify recent ClickHouse audit rows directly:
   ```bash
   docker compose -f deploy/compose/docker-compose.yml exec -T clickhouse \
     clickhouse-client --password clickhouse_dev_admin_secret \
     -q "SELECT producer_service, event_type, severity, occurred_at_ms FROM securecloud_audit.audit_events ORDER BY occurred_at_ms DESC LIMIT 20;"
   ```

---

## 6. Troubleshooting

- **`TLS SPKI fingerprint mismatch` on launch:** Re-run `openssl x509 -in deploy/dev-pki/services/gateway/gateway.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -hex` and verify `SECURECLOUD_TLS_PIN_SPKI_SHA256` matches after any `generate-dev-pki.sh --force`.
- **`curl` fails with HTTP/2 framing error on `:8443`:** Gateway runs HTTP/1.1 over TLS 1.3 (`cpp-httplib`). Always pass `--http1.1` when probing via `curl`. (`QtHttpGatewayClient` disables HTTP/2 automatically via `QNetworkRequest::Http2AllowedAttribute = false`.)
- **Postgres or Scylla schema missing after volume reset:** Verify `docker compose -f deploy/compose/docker-compose.yml ps -a` shows `postgres-migrate`, `scylla-init`, and `minio-init` with `Exited (0)`. Re-run `docker compose -f deploy/compose/docker-compose.yml up -d postgres-migrate scylla-init` if a datastore started cold after interruption.
- **Stop stack cleanly (preserving DB volumes) / Full volume wipe:**
  - Preserve state: `docker compose -f deploy/compose/docker-compose.yml down`
  - Clean reset of all 4 datastores: `docker compose -f deploy/compose/docker-compose.yml down -v`
