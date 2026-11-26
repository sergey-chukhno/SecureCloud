# SecureCloud MVP Live Smoke Test Scenarios (Automated E2E & Desktop UI)

> **Related Docs:**
> - Operator Setup & Launch Commands: [mvp-live-demo-runbook.md](mvp-live-demo-runbook.md)
> - Performance & Live Latency Addendum: [client-performance-benchmark-report.md](../final-reports/client-performance-benchmark-report.md)
> - Automated E2E Test Source: [client_gateway_backend_integration_test.cpp](../../tests/integration/client_gateway_backend_integration_test.cpp)

This guide covers both:
- **Part A — Automated 5-Scenario Full-Stack E2E Smoke Suite** (headless C++ integration binary against the live 5-service Docker Compose stack)
- **Part B — Interactive 2-Client Desktop UI Smoke Scenarios** (two live `securecloud-client` windows side-by-side for `alice@securecloud.local` and `bob@securecloud.local`)
- **Part C — Backend Zero-Plaintext & Audit Continuity Checks** (ScyllaDB & ClickHouse)

---

## 1. Prerequisites & Environment Reset

From the repository root:

```bash
./scripts/demo-mvp-reset.sh
```

- Pass `--build` if backend C++ files or Dockerfiles were modified.
- Pass `--keep-client-dbs` if you want to preserve `/tmp/alice.db` and `/tmp/bob.db` across resets.

Verify all 9 runtime services are healthy/running and all 4 one-shot init jobs exited `0`:

```bash
docker compose -f deploy/compose/docker-compose.yml ps -a
```

Expected init jobs with `Exited (0)`: `postgres-migrate`, `scylla-init`, `clickhouse-init`, `minio-init`.

---

## Part A — Automated 5-Scenario Full-Stack E2E Suite

Run all 5 scenarios end-to-end against the live Docker Compose stack:

```bash
SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1 QT_QPA_PLATFORM=offscreen \
  ./build/dev-debug/tests/integration/securecloud_client_gateway_backend_integration_test
```

To smoke-test a single scenario, append `--gtest_filter`:

```bash
SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1 QT_QPA_PLATFORM=offscreen \
  ./build/dev-debug/tests/integration/securecloud_client_gateway_backend_integration_test \
  --gtest_filter='*Scenario2*'
```

### Scenario 1 — `Scenario1_LiveAuthDeviceEnrollmentAndPrekeyUpload`
- **Tests:** Live Argon2id login (`POST /api/v1/auth/login`), bootstrap device provisioning & in-place E2EE key attachment (`POST /api/v1/devices`), JWT refresh (`refresh_session`), initial OTPK inventory check, `+10` OTPK replenishment, and crypto directory query (`get_device_crypto_directory`).

### Scenario 2 — `Scenario2_TwoClientLiveE2eeDoubleRatchetMessagingAndZeroPlaintextScylla`
- **Tests:** Live direct conversation creation (`POST /api/v1/conversations`), X3DH handshake + Double Ratchet encryption from Alice to Bob, Bob fetching and decrypting the message, delivery ACK + read receipt, and direct ScyllaDB scan (`messages_by_conversation` & `pending_deliveries_by_device`) verifying **zero plaintext** on disk.

### Scenario 3 — `Scenario3_LiveEncryptedChunkedFileTransferAndZeroPlaintextStorage`
- **Tests:** Live `5 MiB` multi-chunk file upload (`4,194,304 B` + `1,048,632 B`) using client-side AES-256-GCM + `FileAttachmentKeyEnvelope` over Double Ratchet, Bob downloading & reassembling with SHA-256 byte-for-byte verification, and direct Postgres (`encrypted_file_metadata`) + MinIO (`securecloud-files-encrypted`) inspection verifying **zero plaintext** filenames or payload bytes.

### Scenario 4 — `Scenario4_OfflineReconnectCatchUpSyncAndMfaDeviceRevocation`
- **Tests:** Switching Alice offline (`set_simulated_offline(true)`), queuing an encrypted outbound message locally (`DeliveryState::LocalPending`), reconnecting (`set_simulated_offline(false)`) to auto-flush the outbox & checkpoint sync cursors, Bob decrypting the caught-up message, enrolling/confirming TOTP MFA on Alice, revoking Alice's companion device, and proving the revoked companion device receives zero new fan-out envelopes and fails closed on re-login.

### Scenario 5 — `Scenario5_EmergencyPanicWipeAuditContinuityAndLiveLatencyMetrics`
- **Tests:** Live message + encrypted file transfer, 20 TLS 1.3 `/health` probes emitting `[LiveComposeBenchmark]`, Alice's emergency panic wipe (shredding SQLCipher DB, keychain secrets, and `local_audit_log`), an invalid-token Gateway probe (`401`), and polling internal mTLS `AuditQueryService` to verify **all 4 producers (`GATEWAY`, `AUTH`, `MESSAGING`, `FILES`)** landed in ClickHouse with zero leaked plaintext sentinels.

---

## Part B — Interactive 2-Client Desktop UI Smoke Scenarios (Alice & Bob)

Launch **Terminal 1 (Alice)** and **Terminal 2 (Bob)** using the exact commands printed at the end of `./scripts/demo-mvp-reset.sh` (see [mvp-live-demo-runbook.md](mvp-live-demo-runbook.md#4-launching-two-live-desktop-clients-side-by-side)).

*(Run Scenario 8 last because it shreds Alice's local SQLCipher database.)*

### 1. Boot Cryptographic Self-Tests & Fail-Closed Live Auth Login
- **Illustrates:** Mandatory OpenSSL boot KATs (`Ed25519`, `X25519`, `AES-256-GCM`, `HKDF-SHA256`, `RAND_status`, `ISecureStorage` canary), Argon2id password verification, and TLS 1.3 SPKI-pinned device bootstrap.
- **Steps:** Sign in as `alice@securecloud.local` / `AliceDemo#2026` in Window 1 and `bob@securecloud.local` / `BobDemo#2026` in Window 2. Confirm both enter the workspace cleanly with `Boot cryptographic self-test passed (6 checks...)` in console output.

### 2. Transport Security & Live Telemetry Inspection
- **Illustrates:** Fail-closed TLS 1.3 + SPKI pinning, live Gateway RTT tracking, host RSS/CPU telemetry, tamper-evident hash-chained `local_audit_log`, and encrypted `.scdiag` diagnostic export.
- **Steps:**
  1. Open **Settings -> Network** on Alice to confirm **Live Gateway Transport** is active and the **SPKI SHA-256 Pin** matches `deploy/dev-pki/services/gateway/gateway.crt`.
  2. Press **`Ctrl+Shift+D`** (or **Settings -> Advanced -> Diagnostics & Troubleshooting**) to inspect live **Gateway RTT**, **RSS**, **CPU**, and hash-chained local audit entries.
  3. *(Optional)* Export a sanitized encrypted **`.scdiag`** diagnostic bundle.

### 3. 1:1 E2EE Double Ratchet Chat & Zero-Plaintext Proof
- **Illustrates:** X3DH session establishment, Double Ratchet forward secrecy, and zero-plaintext ScyllaDB storage.
- **Steps:**
  1. On **Alice**, open/create a direct conversation with **Bob** (`bob@securecloud.local`) and send a distinctive message (e.g. `LIVE_UI_SECRET_HELLO_42`).
  2. Confirm **Bob** receives and decrypts it cleanly, then reply from Bob to Alice to advance the DH ratchet step.
  3. Verify ScyllaDB holds only opaque ciphertext (see Part C).

### 4. Encrypted Chunked File Transfer & Zero-Plaintext Storage Proof
- **Illustrates:** Client-side AES-256-GCM chunked file encryption, `FileAttachmentKeyEnvelope` delivery over Double Ratchet, and zero-plaintext MinIO/Postgres storage.
- **Steps:**
  1. On **Alice**, attach and upload a file (use a `> 4 MiB` file to exercise multi-chunk upload) in the conversation with Bob.
  2. On **Bob**, download and open/verify the decrypted file matches the original byte-for-byte.

### 5. Appearance, Accessibility & Theme Switching
- **Illustrates:** Zero-warning QML theming across accessibility modes and live font scaling.
- **Steps:** Open **Settings -> Appearance**, switch between **Dark**, **Light**, and **High Contrast** themes, adjust **Font Scale**, and verify Workspace, Settings, and Diagnostics (`Ctrl+Shift+D`) render cleanly without layout clipping.

### 6. Offline Queuing & Reconnect Catch-Up Sync
- **Illustrates:** Durable SQLCipher offline outbox queuing (`LocalPending`) and automatic catch-up sync upon reconnect.
- **Steps:**
  1. Pause Gateway (`docker compose -f deploy/compose/docker-compose.yml pause gateway`), send a message from Alice to Bob, and confirm it queues locally as pending.
  2. Unpause Gateway (`docker compose -f deploy/compose/docker-compose.yml unpause gateway`) and wait for reconnect.
  3. Confirm Alice auto-flushes the outbox and **Bob** receives and decrypts the message.

### 7. Cross-Service Security Audit Continuity
- **Illustrates:** Decoupled internal audit trail (`ADR-001` / `ADR-005` / `ADR-011`) across `GATEWAY`, `AUTH`, `MESSAGING`, and `FILES` in ClickHouse.
- **Steps:** After exercising login, chat, and file upload, run the ClickHouse verification query in Part C.

### 8. Emergency Panic Wipe *(Run Last)*
- **Illustrates:** Multi-phase local vault destruction (volatile memory wipe, keychain purge, SQLCipher DB + `local_audit_log` shredding) transitioning immediately to `EmergencyLocked`.
- **Steps:**
  1. Trigger **Emergency Panic Wipe** on Alice.
  2. Confirm Alice's UI transitions immediately to the locked/wiped emergency state and `/tmp/alice.db` is shredded on disk (`ls -la /tmp/alice.db*`).
  3. Re-run `./scripts/demo-mvp-reset.sh` whenever you want to restore a fresh demo state.

---

## Part C — Backend Zero-Plaintext & Audit Verification Queries

- **ScyllaDB (`messages_by_conversation`):**
  ```bash
  docker compose -f deploy/compose/docker-compose.yml exec -T scylladb \
    cqlsh -e "SELECT conversation_id, message_sequence, message_id, ciphertext_envelope FROM securecloud_messaging.messages_by_conversation LIMIT 5;"
  ```
- **ClickHouse (`securecloud_audit.audit_events`):**
  ```bash
  docker compose -f deploy/compose/docker-compose.yml exec -T clickhouse \
    clickhouse-client --user audit_user --password audit_dev_db_secret \
    -q "SELECT producer_service, event_type, severity, occurred_at FROM securecloud_audit.audit_events ORDER BY occurred_at DESC LIMIT 20 FORMAT PrettyCompact"
  ```
