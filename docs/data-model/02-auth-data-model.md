# 2. Auth Service Data Model — PostgreSQL

## 2.1 Auth Data Ownership

Auth owns the security and authentication records required for:

* SecureCloud account identity;
* credential authentication;
* MFA;
* device registration;
* device authorization/revocation;
* session lifecycle;
* refresh-token lifecycle;
* public cryptographic device identity discovery.

Auth does not own:

* conversations;
* messages;
* message ciphertext persistence;
* delivery state;
* files;
* file ciphertext;
* audit history.

---

## 2.2 Logical Auth Model

The core relationships are:

```text
User
 │
 ├── Devices
 │      │
 │      └── DevicePublicKeys
 │
 ├── Sessions
 │      │
 │      └── RefreshTokens
 │
 └── MFAConfiguration
        │
        └── MFAChallenges
```

A user may have multiple devices.

Each device represents one registered SecureCloud endpoint.

A user can have multiple active sessions.

A revoked device remains historically identifiable.

---

# 2.3 `users`

The `users` table represents the SecureCloud account identity.

```text
users
├── user_id
├── credential_identifier
├── password_verifier
├── password_algorithm
├── password_updated_at
├── account_status
├── created_at
├── updated_at
└── version
```

### Primary key

```text
PRIMARY KEY (user_id)
```

### Fields

| Field                   | Type          | Purpose                            |
| ----------------------- | ------------- | ---------------------------------- |
| `user_id`               | UUID          | Canonical `UserId`                 |
| `credential_identifier` | VARCHAR       | Authentication lookup identifier   |
| `password_verifier`     | BYTEA/VARCHAR | Password verifier/hash             |
| `password_algorithm`    | VARCHAR       | Password hashing algorithm/version |
| `password_updated_at`   | TIMESTAMPTZ   | Last credential update             |
| `account_status`        | ENUM/VARCHAR  | Account lifecycle state            |
| `created_at`            | TIMESTAMPTZ   | Creation time                      |
| `updated_at`            | TIMESTAMPTZ   | Last modification                  |
| `version`               | BIGINT        | Optimistic concurrency version     |

`credential_identifier` is an authentication concern.

It is not propagated as the user's general application identity.

Other services use `UserId`.

### Account states

The MVP uses:

```text
ACTIVE
DISABLED
```

Account deletion is handled through lifecycle policy rather than immediately introducing a third runtime state.

### Constraints

```text
UNIQUE (credential_identifier)
```

The implementation must normalize the credential identifier before uniqueness comparison according to the selected credential format.

---

## 2.4 Password Storage

Passwords are never stored.

Auth stores a password verifier generated using **Argon2id**.

The selected password verifier parameters are stored/configured with algorithm versioning so that stronger parameters can be introduced later.

Conceptually:

```text
password
    │
    ▼
Argon2id
    │
    ▼
password_verifier
```

The verifier is the only password-derived persistent value.

Plaintext passwords must never enter:

* Audit;
* logs;
* API responses;
* database exports;
* error messages.

---

# 2.5 `devices`

The `devices` table represents registered user devices.

```text
devices
├── device_id
├── user_id
├── device_status
├── registered_at
├── revoked_at
├── revocation_reason
├── last_authenticated_at
├── created_at
└── updated_at
```

### Primary key

```text
PRIMARY KEY (device_id)
```

### Foreign key

```text
user_id → users.user_id
```

This is an internal Auth relational relationship and therefore uses a PostgreSQL foreign key.

### Fields

| Field                   | Purpose                               |
| ----------------------- | ------------------------------------- |
| `device_id`             | Canonical `DeviceId`                  |
| `user_id`               | Owning `UserId`                       |
| `device_status`         | `ACTIVE` or `REVOKED`                 |
| `registered_at`         | Successful registration               |
| `revoked_at`            | Revocation timestamp                  |
| `revocation_reason`     | Optional security reason              |
| `last_authenticated_at` | Last successful device authentication |
| `created_at`            | Record creation                       |
| `updated_at`            | Last modification                     |

### Index

```text
INDEX (user_id, device_status)
```

Primary query:

```text
all active devices for UserId
```

---

## 2.6 Device Revocation

A device is never physically reused.

Revocation changes:

```text
ACTIVE
   │
   ▼
REVOKED
```

When revoked:

* `revoked_at` is recorded;
* active sessions for the device are revoked;
* refresh tokens associated with the device are revoked;
* the device cannot authenticate future requests;
* the device cannot receive newly encrypted messages;
* public key records remain historically available with revoked status.

A revoked device may still decrypt messages that were previously encrypted for it.

This is an intentional consequence of cryptographic delivery history.

Revocation prevents future participation; it cannot retroactively erase ciphertext or keys already present on a compromised device.

---

# 2.7 `device_public_keys`

Auth stores public cryptographic material associated with devices.

```text
device_public_keys
├── key_id
├── device_id
├── key_type
├── public_key
├── key_status
├── created_at
├── revoked_at
└── replaced_by_key_id
```

### Primary key

```text
PRIMARY KEY (key_id)
```

### Foreign key

```text
device_id → devices.device_id
```

### Key types

The exact cryptographic key taxonomy is defined by ADR-008 and the cryptographic implementation.

The persistence model supports explicit key types rather than assuming one universal key.

Examples may include:

```text
IDENTITY_SIGNING
IDENTITY_AGREEMENT
PREKEY
```

The concrete cryptographic implementation may introduce additional public-key records where required.

### Key status

```text
ACTIVE
REVOKED
REPLACED
```

Public-key records are versioned.

A replacement does not overwrite the historical record.

---

## 2.8 Device Discovery

Device discovery is performed through Auth.

Conceptually, an authorized lookup can retrieve:

```text
UserId
   │
   ▼
ACTIVE devices
   │
   ▼
public cryptographic material
```

The response contains only the public material required for cryptographic communication.

Private key material is never discoverable.

A Messaging Service operation does not query the Auth PostgreSQL database directly for this information.

Messaging obtains device-related identity information through the approved service API or authenticated context.

---

# 2.9 `sessions`

A session represents an authenticated login/session lifecycle.

```text
sessions
├── session_id
├── user_id
├── device_id
├── session_status
├── authentication_level
├── created_at
├── expires_at
├── revoked_at
└── last_used_at
```

### Primary key

```text
PRIMARY KEY (session_id)
```

### Foreign keys

```text
user_id   → users.user_id
device_id → devices.device_id
```

### Authentication level

The approved levels are:

```text
PRIMARY_ONLY
MFA_VERIFIED
```

`authentication_level` represents the current assurance achieved by the session.

Security-sensitive operations may require:

```text
MFA_VERIFIED
```

### Session states

```text
ACTIVE
REVOKED
EXPIRED
```

Indexes support:

```text
sessions by user
sessions by device
active session lookup
```

---

# 2.10 `refresh_tokens`

Refresh tokens are persisted as verifiers rather than plaintext bearer tokens.

```text
refresh_tokens
├── refresh_token_id
├── session_id
├── device_id
├── token_verifier
├── token_status
├── issued_at
├── expires_at
├── revoked_at
├── rotated_at
└── replaced_by_token_id
```

### Primary key

```text
PRIMARY KEY (refresh_token_id)
```

### Foreign keys

```text
session_id → sessions.session_id
device_id  → devices.device_id
```

### Token states

```text
ACTIVE
ROTATED
REVOKED
EXPIRED
```

The plaintext refresh token is returned only to the authenticated client at issuance.

The database stores only a secure verifier.

---

## 2.11 Refresh Token Rotation

Refresh tokens are single-use for rotation.

The lifecycle is:

```text
ACTIVE
  │
  │ refresh
  ▼
ROTATED
  │
  └── new ACTIVE refresh token
```

The old token references its replacement:

```text
replaced_by_token_id
```

Reuse of a previously rotated refresh token is treated as a potential credential compromise.

The security response is:

1. detect reuse;
2. revoke the affected session;
3. revoke associated active refresh tokens;
4. emit an audit event;
5. require re-authentication.

---

# 2.12 `mfa_configurations`

MFA configuration is owned by the user.

```text
mfa_configurations
├── mfa_configuration_id
├── user_id
├── factor_type
├── encrypted_secret
├── status
├── created_at
├── enabled_at
├── disabled_at
└── version
```

### Primary key

```text
PRIMARY KEY (mfa_configuration_id)
```

### Foreign key

```text
user_id → users.user_id
```

### MVP factor

The MVP supports:

```text
TOTP
```

TOTP is selected as the initial MFA factor because it:

* does not require SMS infrastructure;
* works in constrained connectivity conditions;
* is widely supported;
* can operate offline after enrollment.

Additional factors can be added later without changing the core model.

### MFA secret protection

The TOTP secret is encrypted at rest.

The encryption key is infrastructure-managed and is not an E2E messaging key.

The MFA secret must never appear in:

* API responses;
* Audit events;
* application logs.

### MFA status

```text
PENDING
ENABLED
DISABLED
```

`PENDING` exists during enrollment before successful verification.

---

# 2.13 `mfa_challenges`

An MFA challenge represents an authentication or step-up authentication request.

```text
mfa_challenges
├── mfa_challenge_id
├── user_id
├── session_id
├── challenge_purpose
├── challenge_status
├── created_at
├── expires_at
└── completed_at
```

### Primary key

```text
PRIMARY KEY (mfa_challenge_id)
```

### Challenge purposes

The MVP supports:

```text
LOGIN
STEP_UP
```

`LOGIN` is used during authentication.

`STEP_UP` is used when an existing authenticated session performs a security-sensitive operation.

### Challenge states

```text
PENDING
COMPLETED
EXPIRED
FAILED
```

Challenges are short-lived.

Expired challenges cannot be reused.

---

# 2.14 MFA Flow and Persistence

The persistence flow is:

```text
Login
  │
  ▼
Primary credentials verified
  │
  ▼
Session created
authentication_level = PRIMARY_ONLY
  │
  ▼
MFA challenge created
  │
  ▼
TOTP verified
  │
  ▼
Challenge = COMPLETED
Session.authentication_level = MFA_VERIFIED
```

For step-up authentication:

```text
Authenticated session
PRIMARY_ONLY
       │
       ▼
Sensitive operation
       │
       ▼
STEP_UP challenge
       │
       ▼
MFA verification
       │
       ▼
operation allowed
```

---

# 2.15 Auth Relationship Summary

The concrete relational model is:

```text
users
  │ 1
  │
  ├──────────< devices
  │              │
  │              ├──────< device_public_keys
  │              │
  │              └──────< sessions
  │                       │
  │                       ├──────< refresh_tokens
  │                       │
  │                       └──────< mfa_challenges
  │
  └──────────< mfa_configurations
```

---

# 2.16 Auth Index Strategy

The initial PostgreSQL indexes are:

### Users

```text
PRIMARY KEY (user_id)
UNIQUE (credential_identifier)
```

### Devices

```text
PRIMARY KEY (device_id)

INDEX (user_id, device_status)
```

### Device public keys

```text
PRIMARY KEY (key_id)

INDEX (device_id, key_status)
```

### Sessions

```text
PRIMARY KEY (session_id)

INDEX (user_id, session_status)
INDEX (device_id, session_status)
```

### Refresh tokens

```text
PRIMARY KEY (refresh_token_id)

INDEX (session_id, token_status)
INDEX (device_id, token_status)
```

### MFA configurations

```text
PRIMARY KEY (mfa_configuration_id)

INDEX (user_id, status)
```

### MFA challenges

```text
PRIMARY KEY (mfa_challenge_id)

INDEX (user_id, challenge_status)
INDEX (session_id, challenge_status)
```

These indexes correspond to the initial known access patterns.

---

# 2.17 Auth Data Invariants

The Auth persistence model must preserve the following invariants:

1. `UserId` and `DeviceId` are opaque UUIDv7 identifiers.
2. Other runtime services never directly access Auth's PostgreSQL database.
3. Passwords are never persisted in plaintext.
4. Password verifiers use Argon2id.
5. Refresh tokens are never persisted as plaintext bearer tokens.
6. Refresh tokens are rotated.
7. Reuse of a rotated refresh token is treated as a potential compromise.
8. A revoked device cannot authenticate future requests.
9. Device revocation revokes associated active sessions and refresh tokens.
10. A revoked device can still decrypt messages previously encrypted for it.
11. Auth never stores E2E private keys.
12. Public cryptographic keys are versioned rather than silently overwritten.
13. MFA secrets are encrypted at rest.
14. MFA secrets never appear in logs, APIs or Audit.
15. The MVP MFA factor is TOTP.
16. Security-sensitive operations require the appropriate authentication assurance.
17. Session authentication assurance is explicitly represented by `authentication_level`.
18. Historical security records remain meaningful after revocation.
19. Cross-service relationships use opaque identifiers rather than distributed foreign keys.
20. All authoritative server timestamps are stored in UTC.