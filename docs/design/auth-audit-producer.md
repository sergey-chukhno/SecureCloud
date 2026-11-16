# Auth Audit Producer Specification & Event Catalog (AUDIT-013)

## 1. Context and Architectural Position

Under **ADR-005 (§6)**, **ADR-007 (§18–§23)**, and **RULES.md (§6, §9)**, the Authentication Service (`securecloud-auth`) strictly owns the primary PostgreSQL database (`securecloud_auth`).

Unlike the stateless API Gateway (which relies on a local disk WAL spool under **ADR-011**), the Auth Service performs authoritative business state transitions (credential verification, token issuance, session revocation, device pairing, MFA challenges, key management).

To eliminate dual-write inconsistencies and prevent phantom audit entries or lost events during crashes/outages, **every security audit event emitted by Auth must be written to the `auth_outbox` table**.

---

## 2. Event Durability Categories

### Category A: State-Mutating Business Operations (Atomic Outbox)
Events triggered by successful or failing state-mutating operations (e.g., successful login, session revocation, device pairing, TOTP verification) are inserted into `auth_outbox` using the **same active PostgreSQL transaction (`pqxx::work`)** as the business table updates.
* **Invariant**: If the business transaction rolls back, the audit event is never staged. If it commits, the audit event is durably staged.

### Category B: Non-State-Mutating & Perimeter Rejections (Autonomous Outbox)
Events triggered by non-mutating checks or immediate rejections (e.g., bad password, expired token presentation, disabled account access attempt) do not modify business tables.
* **Invariant**: Staged into `auth_outbox` using a **dedicated autonomous transaction** with immediate commit, guaranteeing durable security tracking without corrupting business state.

---

## 3. Auth Audit Event Catalog (23 Event Types)

| # | `event_type` | Severity | Cat. | Triggering Condition | Actor / Target | Metadata Whitelist |
| :-- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E01** | `auth.login.succeeded` | INFO | A | Password verified, new session issued | `USER=user_id` / `SESSION=session_id` | `credential_identifier`, `device_id`, `client_ip` |
| **E02** | `auth.login.failed` | SECURITY | B | Invalid password or unknown credential | `USER` or `UNKNOWN` / `SERVICE=auth` | `credential_identifier`, `failure_reason`, `client_ip` |
| **E03** | `auth.account.disabled_attempt` | SECURITY | B | Login attempt on disabled/locked account | `USER=user_id` / `USER=user_id` | `credential_identifier`, `failure_reason`, `client_ip` |
| **E04** | `auth.session.revoked` | INFO | A | User logout or explicit admin session revocation | `USER=user_id` / `SESSION=session_id` | `device_id`, `reason`, `client_ip` |
| **E05** | `auth.session.expired_attempt` | WARNING | B | Presentation of an expired session token | `USER=user_id` / `SESSION=session_id` | `device_id`, `client_ip` |
| **E06** | `auth.session.revoked_attempt` | SECURITY | B | Presentation of a previously revoked session | `USER=user_id` / `SESSION=session_id` | `device_id`, `client_ip` |
| **E07** | `auth.token.refreshed` | INFO | A | Refresh token exchange for new access token | `USER=user_id` / `SESSION=session_id` | `device_id`, `client_ip` |
| **E08** | `auth.token.reuse_detected` | CRITICAL | A | Token replay attack (reuse of rotated token) | `USER=user_id` / `DEVICE=device_id` | `session_id`, `client_ip` |
| **E09** | `auth.mfa.enrollment_initiated` | INFO | A | User initiates TOTP secret generation | `USER=user_id` / `USER=user_id` | `mfa_type="totp"`, `client_ip` |
| **E10** | `auth.mfa.enrollment_confirmed` | INFO | A | User verifies first TOTP code | `USER=user_id` / `USER=user_id` | `mfa_type="totp"`, `recovery_codes_count`, `client_ip` |
| **E11** | `auth.mfa.disabled` | SECURITY | A | MFA configuration removed | `USER=user_id` / `USER=user_id` | `client_ip` |
| **E12** | `auth.mfa.challenge_created` | INFO | A | MFA prompt generated during login | `USER=user_id` / `SESSION=session_id` | `challenge_id`, `client_ip` |
| **E13** | `auth.mfa.challenge_succeeded` | INFO | A | Correct TOTP code submitted | `USER=user_id` / `SESSION=session_id` | `challenge_id`, `client_ip` |
| **E14** | `auth.mfa.challenge_failed` | SECURITY | B | Invalid TOTP code or expired challenge | `USER=user_id` / `SESSION=session_id` | `challenge_id`, `failure_reason`, `client_ip` |
| **E15** | `auth.mfa.recovery_code_used` | SECURITY | A | Backup recovery code consumed | `USER=user_id` / `SESSION=session_id` | `remaining_recovery_codes`, `client_ip` |
| **E16** | `auth.device.enrolled` | INFO | A | New device registered with public keys | `USER=user_id` / `DEVICE=device_id` | `is_primary`, `client_ip` |
| **E17** | `auth.device.pairing_initiated` | INFO | A | Secondary device requests authorization | `USER=user_id` / `DEVICE=device_id` | `client_ip` |
| **E18** | `auth.device.authorized` | INFO | A | Primary device approves secondary pairing | `USER=user_id` / `DEVICE=device_id` | `authorizing_device_id`, `client_ip` |
| **E19** | `auth.device.revoked` | SECURITY | A | Device access revoked | `USER=user_id` / `DEVICE=device_id` | `reason`, `client_ip` |
| **E20** | `auth.device.prekeys_updated` | INFO | A | One-time prekey bundle uploaded | `USER=user_id` / `DEVICE=device_id` | `prekey_count` |
| **E21** | `auth.device.signed_prekey_rotated`| INFO | A | Cryptographic signed prekey rotated | `USER=user_id` / `DEVICE=device_id` | `key_id` |
| **E22** | `auth.device.prekey_inventory_low` | WARNING | B | One-time prekey count drops below limit | `USER=user_id` / `DEVICE=device_id` | `remaining_count`, `threshold` |
| **E23** | `auth.device.prekey_inventory_exhausted`| CRITICAL| B | All one-time prekeys consumed | `USER=user_id` / `DEVICE=device_id` | `remaining_count=0` |

---

## 4. Zero-Secret & Privacy Rules

Under **RULES.md (§5)** and **ADR-008**, audit payloads and metadata **must never contain**:
- Plaintext passwords or Argon2id verifiers
- Access tokens, refresh tokens, or bearer token strings
- MFA TOTP secret keys or plaintext recovery codes
- Private cryptographic keys or session keys