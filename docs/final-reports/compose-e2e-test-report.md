# Full-Stack Live Compose E2E Test Report (`SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1`)

- **Target Binary:** `build/dev-debug/tests/integration/securecloud_client_gateway_backend_integration_test`
- **Environment:** 5 live C++ microservices (`Gateway`, `Auth`, `Messaging`, `Files`, `Audit`) + 4 datastores (`PostgreSQL 17`, `ScyllaDB 6.2`, `ClickHouse`, `MinIO`) over Docker Compose (`127.0.0.1:8443`, TLS 1.3 + SPKI pinning)
- **Overall Result:** **5 / 5 PASSED** in **3,227 ms** (`3.23 s`)
- **Operational Note:** On the initial run, `gateway`'s `/var/spool/securecloud/gateway/audit/spool.wal` held a 5.3 MB backlog from earlier offline-gateway stop/start tests, delaying `PRODUCER_SERVICE_GATEWAY` ingestion beyond Scenario 5's 20 s window. Clearing that stale spool file and restarting `gateway` resolved it immediately (`Scenario 5` completed in `903 ms`).

---

## Scenario 1 — `LiveAuthDeviceEnrollmentAndPrekeyUpload`
- **What it tests:** Seeds fresh Alice & Bob accounts, logs both in over TLS 1.3 + SPKI pinning, registers both devices with X3DH prekey bundles, rotates Alice's access token via `refresh_session()`, replenishes 10 one-time prekeys, and looks up Bob's device crypto directory from Alice.
- **What we expect:** Both users & devices enroll cleanly, the refreshed access token differs from the initial token, prekey count increases by 10, and Bob's device appears as `Authorized` in Alice's directory lookup.
- **How it's measured/verified:** GoogleTest assertions on `is_live_gateway_transport_active()`, token inequality, prekey inventory `after > before`, and `DeviceAuthorizationStatus::Authorized`.
- **Result:** **PASS (`513 ms`)** — Boot KATs passed (`418 us` / `278 us`), both workstations enrolled, token refresh rotated cleanly, 10 OTPKs uploaded, and Bob's directory entry verified `Authorized`.

---

## Scenario 2 — `TwoClientLiveE2eeDoubleRatchetMessagingAndZeroPlaintextScylla`
- **What it tests:** Creates a live direct conversation between Alice & Bob, sends an E2EE message containing a unique sentinel (`SC_E2EE_SENTINEL_MSG_<uuid>`), fetches & decrypts it on Bob, sends delivery ACK + read receipt, and directly scans ScyllaDB (`messages_by_conversation` and `pending_deliveries_by_device`).
- **What we expect:** Alice's send returns `DeliveryState::Accepted`, Bob decrypts the exact sentinel plaintext, ACK/read receipts succeed, and **zero** raw or hex occurrences of the sentinel exist in ScyllaDB.
- **How it's measured/verified:** Exact plaintext match on Bob + direct CQL queries scanning `ciphertext_envelope` and `ciphertext_blob` for zero plaintext leakage.
- **Result:** **PASS (`311 ms`)** — End-to-end Double Ratchet decryption matched the sentinel exactly; direct ScyllaDB scan confirmed zero plaintext in both tables.

---

## Scenario 3 — `LiveEncryptedChunkedFileTransferAndZeroPlaintextStorage`
- **What it tests:** Generates a **5 MiB** binary file with a secret filename (`classified-mvp-dossier-<uuid>.bin`) and embedded sentinels in both chunks, encrypts & uploads it from Alice in **2 chunks** (4 MiB + 1 MiB) using AES-256-GCM, delivers the encrypted file key over Double Ratchet to Bob, downloads & decrypts on Bob, and directly inspects PostgreSQL (`securecloud_files`) and MinIO (S3).
- **What we expect:** Upload finishes with `2/2` chunks, Bob's decrypted file matches Alice's 5 MiB original byte-for-byte and by SHA-256, MinIO object size > 5 MiB, and **zero** occurrences of the secret filename or sentinel appear in Postgres metadata or raw MinIO ciphertext.
- **How it's measured/verified:** Full byte-array & SHA-256 equality check + direct SQL query on `encrypted_file_metadata` + direct S3 `GetObject` byte scan.
- **Result:** **PASS (`969 ms`)** — 5 MiB 2-chunk upload/download round-trip matched byte-for-byte & SHA-256; Postgres metadata and MinIO raw ciphertext passed zero-plaintext verification.

---

## Scenario 4 — `OfflineReconnectCatchUpSyncAndMfaDeviceRevocation`
- **What it tests:**
  1. **Offline catch-up:** Puts Alice offline, queues an encrypted message (`LocalPending`, `pending_outbox_count == 1`), reconnects Alice, runs `execute_catch_up_sync`, and verifies Bob decrypts the flushed message.
  2. **MFA step-up & device revocation:** Enrolls & confirms RFC 6238 TOTP MFA on Alice, upgrades her session to `MFA_VERIFIED`, revokes `alice_companion`, sends a post-revocation message from Bob, and tests login from the revoked device.
- **What we expect:** Outbox drains to `0` and Bob decrypts the queued message; after revocation, `alice_companion` is no longer `Authorized`, receives **zero** new rows in ScyllaDB `pending_deliveries_by_device`, and its login fails closed.
- **How it's measured/verified:** Outbox counter assertions, Bob's decrypted payload match, ScyllaDB row-count comparison before/after revocation, and `revoked_login.is_error()`.
- **Result:** **PASS (`527 ms`)** — Offline outbox flushed cleanly, MFA step-up & device revocation succeeded, zero post-revocation fan-out rows reached the revoked device, and revoked login failed closed (`HTTP 403`).

---

## Scenario 5 — `EmergencyPanicWipeAuditContinuityAndLiveLatencyMetrics`
- **What it tests:**
  1. **Live latency metrics:** Sends a live E2EE message + 4 KiB encrypted file upload, then runs **20 live TLS 1.3 `/health` probes**.
  2. **Emergency Panic Wipe:** Runs `execute_panic_wipe` on Alice and checks SQLCipher DB file removal, empty `ISecureStorage`, and unauthenticated state.
  3. **Cross-service ClickHouse Audit continuity:** Triggers a `401` rejected token on Gateway, then queries `AuditQueryService` (`:50055`) over internal mTLS to confirm events from all **4 producers (`GATEWAY`, `AUTH`, `MESSAGING`, `FILES`)** exist in ClickHouse with **zero sentinel leakage** in actor/target/metadata fields.
- **What we expect:** All panic-wipe critical steps succeed, DB file is shredded, all 4 producers appear in ClickHouse, and zero plaintext sentinels appear in audit metadata.
- **How it's measured/verified:** Filesystem check, secret-key list emptiness, mTLS gRPC `QueryAuditEvents` assertions across all 4 producers, and latency percentile capture.
- **Result:** **PASS (`903 ms`)** — Panic wipe shredded DB & secrets cleanly; all 4 audit producers verified over mTLS with zero plaintext leakage.

### Live Compose Latency Metrics (Scenario 5)
| Metric | Observed Value |
| :--- | :--- |
| TLS 1.3 `/health` Probes | 20 requests |
| Probe Mean Latency | **1.80 ms** |
| Probe p50 Latency | **1.72 ms** |
| Probe p95 / p99 / Max Latency | **2.60 ms** |
| Live E2EE Message Send (`stage_outbound_message`) | **21.27 ms** |
| Live 4 KiB Encrypted File Upload (`start_upload`) | **33.57 ms** |
| Client-Measured Avg Gateway RTT (`34` requests) | **4 ms** |
