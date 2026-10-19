# Walkthrough: FILES-002-T05 — FileAccess Authorization & Transactional Outbox Repositories

## 1. Overview & Architectural Goals
**Ticket ID**: `FILES-002-T05`  
**Card**: `FILES-002` (Establish Files PostgreSQL Persistence)  
**Branch**: `feature/files-002-establish-files-postgresql-persistence`

Card `FILES-002-T05` delivers the access control repository and transactional outbox persistence components for the SecureCloud Files Service (`securecloud-files`). It enforces:
1. **Ownership Access Invariant**: The file creator/owner has implicit full `ADMIN` access without requiring an explicit grant record in `file_access`. Non-owner authorization queries follow the permission hierarchy (`Admin >= Write >= Read`).
2. **Access Control Management**: Granting, checking, listing active grantees, and soft-revoking (`revoked_at` timestamp) access permissions for files.
3. **Transactional Outbox Pattern (ADR-005, Files Design 6.22)**: Staging audit/domain events in `files_outbox` atomically within domain transactions (`pqxx::work`), guaranteeing at-least-once asynchronous event dispatch and eliminating dual-write hazards.
4. **Deterministic Outbox Polling**: Polling pending outbox events ordered by `created_at ASC` with `FOR UPDATE SKIP LOCKED` semantics and retry count increments on failure.
5. **Zero-Plaintext Invariant (ADR-005, ADR-008)**: Outbox events and access grants contain only metadata IDs, permission levels, and JSON audit payloads without cryptographic private keys or plaintext data.

---

## 2. Key Components Delivered

### 2.1 FileAccessRepository (`src/files/repository/file_access_repository.{hpp,cpp}`)
- **Implicit Owner Hierarchy (`check_access`)**:
  Queries the owning user ID from `files`:
  ```sql
  SELECT owner_user_id FROM files WHERE file_id = $1;
  ```
  If `user_id == owner_user_id`, immediately authorizes access for any requested permission level (`Read`, `Write`, `Admin`).
- **Granular Permission Check for Non-Owners**:
  Queries active grants where `revoked_at IS NULL`:
  ```sql
  SELECT access_id, file_id, grantee_user_id, grantee_device_id, permission, granted_by, granted_at, revoked_at
  FROM file_access
  WHERE file_id = $1 AND grantee_user_id = $2 AND revoked_at IS NULL;
  ```
  Evaluates permission hierarchy: `Admin` satisfies all permissions; `Write` satisfies `Write` and `Read`; `Read` satisfies `Read`.
- **Grant Access (`grant_access`)**:
  Inserts or updates access records:
  ```sql
  INSERT INTO file_access (access_id, file_id, grantee_user_id, grantee_device_id, permission, granted_by, granted_at, revoked_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
  ON CONFLICT (file_id, grantee_user_id) DO UPDATE
  SET permission = EXCLUDED.permission,
      grantee_device_id = EXCLUDED.grantee_device_id,
      granted_by = EXCLUDED.granted_by,
      granted_at = EXCLUDED.granted_at,
      revoked_at = NULL;
  ```
- **Soft Revocation (`revoke_access`)**:
  Updates `revoked_at` timestamp:
  ```sql
  UPDATE file_access SET revoked_at = $1 WHERE file_id = $2 AND grantee_user_id = $3 AND revoked_at IS NULL;
  ```
- **List Grantees (`list_grantees`)**:
  Retrieves active grantees for a file ordered by `granted_at ASC`.

### 2.2 FilesOutboxRepository (`src/files/repository/files_outbox_repository.{hpp,cpp}`)
- **Atomic Event Staging (`stage_event`)**:
  Inserts audit event into `files_outbox` within the caller's active `pqxx::work`:
  ```sql
  INSERT INTO files_outbox (event_id, aggregate_type, aggregate_id, event_type, payload_json, status, retry_count, created_at, processed_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
  ```
- **Fetch Pending Events (`fetch_pending_events`)**:
  Retrieves unhandled events up to a configurable batch size:
  ```sql
  SELECT event_id, aggregate_type, aggregate_id, event_type, payload_json, status, retry_count, created_at, processed_at
  FROM files_outbox
  WHERE status = 'PENDING'
  ORDER BY created_at ASC
  LIMIT $1
  FOR UPDATE SKIP LOCKED;
  ```
- **Acknowledge Dispatched Event (`mark_published`)**:
  Transitions status to `PUBLISHED` and sets `processed_at`:
  ```sql
  UPDATE files_outbox SET status = 'PUBLISHED', processed_at = $1 WHERE event_id = $2;
  ```
- **Record Dispatch Failure (`mark_failed`)**:
  Transitions status to `FAILED` and increments `retry_count`:
  ```sql
  UPDATE files_outbox SET status = 'FAILED', retry_count = retry_count + 1 WHERE event_id = $2;
  ```

---

## 3. Testing & Verification

### 3.1 Unit Test Suite (`tests/unit/files/access_outbox_repository_test.cpp`)
16 targeted unit tests covering all authorization rules, transactions, outbox batching, and error handling:
1. `OwnerHasImplicitAdminAccess`: Proves owner gets implicit Admin without `file_access` entry.
2. `NonOwnerWithoutGrantReturnsFalse`: Asserts unauthorized non-owner is rejected.
3. `NonOwnerWithReadGrant`: Verifies Read grant permits Read and denies Write/Admin.
4. `NonOwnerWithWriteGrant`: Verifies Write grant permits Read and Write, denies Admin.
5. `NonOwnerWithAdminGrant`: Verifies Admin grant satisfies all permission checks.
6. `RevokeAccessFailsSubsequentChecks`: Verifies soft revocation denies further access immediately.
7. `UpdateGrantPermissionAndClearRevocation`: Verifies re-granting clears `revoked_at` and updates permission level.
8. `ListGranteesReturnsOnlyActiveOrdered`: Confirms only non-revoked grants are listed, ordered by `granted_at ASC`.
9. `FindGrantById`: Verifies exact grant lookup.
10. `FileAccessValidationFailures`: Asserts empty identifiers throw `RepositoryException`.
11. `StageAndFetchPendingEvents`: Confirms staging and FIFO batch retrieval of outbox events.
12. `MarkPublishedRemovesFromPending`: Verifies published event is excluded from subsequent pending polling.
13. `MarkFailedIncrementsRetryCount`: Verifies status transitions to Failed and retry counter increments.
14. `OutboxTransactionRollbackLeavesNoOrphanEvents`: Confirms aborted transactions produce no persistent outbox records.
15. `OutboxValidationFailures`: Asserts invalid aggregate or event fields are rejected.
16. `AtomicDomainStateAndOutboxPersistence`: Verifies file metadata updates and outbox events commit atomically together in single `pqxx::work`.

### 3.2 Test Results
```
[==========] Running 16 tests from 1 test suite.
[----------] 16 tests from AccessOutboxRepositoryTest
[  PASSED  ] 16 tests.
```
