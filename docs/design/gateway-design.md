# Section 4 — Authentication Service Design

## 4.1 Purpose

The Authentication Service is the authoritative backend component for:

* application authentication;
* multi-factor authentication (MFA);
* session lifecycle;
* access and refresh token issuance;
* device authorization and revocation;
* authentication-related authorization decisions;
* user/device authentication state;
* the public cryptographic identity directory.

The Auth Service **does not own E2E message/file plaintext or private cryptographic keys**.

Authentication credentials and cryptographic identity are deliberately separated.

---

## 4.2 Responsibilities

The Auth Service is responsible for:

1. verifying user authentication credentials;
2. enforcing MFA when required;
3. creating and managing authenticated sessions;
4. issuing and rotating access/refresh tokens;
5. revoking sessions and devices;
6. maintaining authoritative device authorization state;
7. authorizing sensitive device/security operations;
8. maintaining the public cryptographic directory;
9. managing public prekey material;
10. publishing authentication/security audit events.

It is **not** responsible for:

* decrypting messages or files;
* storing message/file plaintext;
* storing device private keys;
* deciding message delivery;
* managing conversations/groups;
* storing encrypted message history;
* storing file content;
* making business-level messaging authorization decisions.

---

# 4.3 Persistence

The Auth Service uses **PostgreSQL 17**.

It owns its database and is the only service allowed to modify Auth-owned persistent state.

Conceptually, the database contains:

* `User`
* `Session`
* `RefreshTokenState`
* `Device`
* `CryptoIdentity`
* `SignedPrekey`
* `OneTimePrekey`
* MFA-related authentication state

The exact physical schema, indexes, constraints, and migration structure belong in `data-model.md`.

### Database rules

* No other service accesses the Auth database directly.
* No cross-service SQL.
* No cross-service foreign keys.
* All Auth state changes use local PostgreSQL transactions.
* Authentication state required for correctness must be durable.
* Process-local memory may be used only as a cache or bounded optimization.

---

# 4.4 Identity Model

SecureCloud distinguishes three concepts:

### User identity

A logical SecureCloud account identified by an opaque `user_id`.

### Device identity

A physical application installation/device identified by a unique `device_id`.

One user may have multiple authorized devices:

```text
User
 ├── Device A — phone
 ├── Device B — laptop
 └── Device C — tablet
```

### Cryptographic identity

Each device possesses its own E2E cryptographic identity.

Therefore:

```text
User
  └── Device
       ├── Authentication state
       └── E2E cryptographic identity
```

Authentication identity and E2E cryptographic identity are independent.

A valid authentication token does not provide access to the device's private cryptographic keys.

---

# 4.5 Authentication Flow

All external authentication requests pass through the Gateway.

The Gateway does not perform authentication itself; it routes authentication requests to Auth.

For a normal login:

```text
Client
  │
  │ HTTPS / TLS 1.3
  ▼
Gateway
  │
  │ gRPC + Protobuf / mTLS
  ▼
Auth
  │
  ├── Verify primary credential
  │
  ├── Determine MFA requirement
  │
  ├── Verify second factor
  │
  ├── Create authenticated session
  │
  └── Issue tokens
  │
  ▼
Gateway
  │
  ▼
Client
```

Authentication succeeds only when all required authentication factors have been successfully verified.

When MFA is required, Auth **must not issue a fully authenticated session/token after successful primary-factor verification alone**.

---

# 4.6 Multi-Factor Authentication

MFA is a first-class capability of the Auth Service.

The project requirements explicitly include multi-factor authentication as part of centralized authentication.

### MVP mechanism

The initial implementation uses **TOTP** as the second factor.

The design must keep the MFA mechanism behind an abstraction so that stronger factors can be introduced later, such as:

* WebAuthn/FIDO2 security keys;
* platform authenticators;
* other organization-approved authentication factors.

The architecture therefore does not couple the rest of SecureCloud to TOTP-specific behavior.

### Authentication assurance

Authentication state distinguishes the assurance level achieved by the session.

Conceptually:

```text
PRIMARY_ONLY
MFA_VERIFIED
```

A session requiring MFA must reach `MFA_VERIFIED` before it can be used for operations requiring full authentication assurance.

The resulting authentication context may therefore contain:

```text
authentication_level = MFA_VERIFIED
```

This value can be propagated through the Gateway's `AuthenticatedContext`.

---

# 4.7 MFA and Sensitive Operations

MFA is particularly important for operations that could materially change the security identity of an account.

The following operations should require an appropriately strong authentication level, with `MFA_VERIFIED` as the MVP baseline:

* registering a new device;
* revoking a device;
* changing authentication credentials;
* changing MFA configuration;
* changing important security settings;
* other explicitly security-sensitive account operations.

This creates an important security boundary:

```text
Valid access token
        │
        ▼
Authentication established
        │
        ├── Normal operation
        │
        └── Sensitive operation
                 │
                 ▼
          MFA assurance required
```

Consequently, possession of a stolen ordinary access token does not automatically grant unrestricted authority over account security state.

---

# 4.8 Access Tokens

Auth issues short-lived signed access tokens.

The token contains only authentication/authorization information required by downstream components.

Conceptual claims include:

```text
user_id
device_id
session_id
issuer
audience
issued_at
expires_at
jti
scopes
token_version
authentication_level
```

`user_id` and `device_id` are opaque identifiers.

The token contains:

* no message plaintext;
* no file plaintext;
* no private cryptographic keys;
* no sensitive cryptographic session state.

Auth owns the private signing key.

The Gateway receives only the corresponding public verification material and can therefore validate access tokens locally without calling Auth for every request.

---

# 4.9 Refresh Tokens

Refresh tokens are longer-lived and stateful.

Auth:

1. validates the refresh token;
2. validates its associated session/device state;
3. issues a new access token;
4. rotates the refresh token;
5. invalidates the previous refresh token.

The server stores a protected representation of refresh-token state rather than relying on plaintext storage.

Reuse of an already-rotated refresh token is treated as a security event and may result in session revocation according to security policy.

---

# 4.10 Session Management

Sessions are device-specific.

Conceptually:

```text
User
 ├── Session A → Device A
 ├── Session B → Device B
 └── Session C → Device C
```

A session contains authoritative authentication state such as:

* `session_id`;
* `user_id`;
* `device_id`;
* authentication level;
* creation time;
* expiration state;
* revocation state;
* token/version state.

Conceptual session states:

```text
ACTIVE
REVOKED
EXPIRED
```

Session state is durable in PostgreSQL.

The Auth Service remains the authority for session revocation.

---

# 4.11 Device Management

Auth is the authoritative service for device registration, authorization and revocation.

A new device must undergo an explicit authenticated onboarding/pairing process.

A valid access token alone must **not** be sufficient to silently register an attacker-controlled device.

Device registration therefore establishes:

```text
User
  │
  └── explicitly authorizes
          │
          ▼
       New Device
          │
          └── New E2E Crypto Identity
```

Each registered device receives its own:

* `device_id`;
* authentication state;
* E2E identity;
* public identity key;
* signed prekey;
* one-time prekeys.

Private device keys remain exclusively on the device.

---

# 4.12 Device Revocation

Auth can revoke an individual device.

Revocation results in:

* device state becoming `REVOKED`;
* associated authentication sessions being revoked;
* future authentication being rejected;
* future message delivery to that device being prevented;
* relevant cryptographic directory state being updated.

A revoked device may still decrypt encrypted messages that it had already legitimately received before revocation.

Revocation therefore means:

> A revoked device cannot obtain new authorized data, but revocation cannot retroactively erase plaintext that the device already legitimately possessed.

---

# 4.13 Cryptographic Directory

Auth owns the public cryptographic directory required for E2E communication.

For each authorized device, the directory may contain:

```text
user_id
device_id
identity_public_key
signed_prekey
prekey_signature
one_time_prekeys
key_state
revocation_state
```

Private keys are never stored by Auth.

Clients generate their own cryptographic private material and upload only the public components required for other devices to establish E2E sessions.

Auth is therefore a **directory and authorization authority**, not a cryptographic decryption authority.

---

# 4.14 Device Discovery

Device discovery is explicit.

When a client needs to establish or update an E2E communication session, it can obtain the authorized device set and corresponding public cryptographic material from Auth.

For example:

```text
Alice
 ├── Alice-phone
 ├── Alice-laptop
 └── Alice-tablet
```

The logical communication participant remains Alice, while Messaging operates on individual device delivery targets.

This distinction is required for:

* multi-device messaging;
* device-specific encryption;
* device revocation;
* prekey/session establishment;
* synchronization.

Contact discovery and device discovery are separate concepts.

---

# 4.15 Prekey Management

The client generates cryptographic prekeys.

Auth stores and manages their public components:

* signed prekey;
* signature;
* one-time prekeys;
* availability/state.

Auth does not generate or possess device private prekeys.

The Auth Service may track one-time-prekey consumption so that a prekey is not incorrectly allocated multiple times.

---

# 4.16 Identity Verification

Auth provides cryptographic identity information but does not decide whether a human user trusts another user's cryptographic identity.

That decision belongs to the client.

The client detects events such as:

```text
Known identity
      │
      ▼
Identity key changed
      │
      ▼
Contact marked KEY_CHANGED / UNVERIFIED
      │
      ▼
User explicitly verifies identity
```

High-risk deployments should support out-of-band verification of cryptographic fingerprints/safety numbers.

The security distinction is:

> Authentication proves control of an account/device credential; identity verification establishes trust in the cryptographic identity used for E2E communication.

---

# 4.17 Authorization Boundary

Auth authorizes operations over Auth-owned resources.

Examples include:

* session management;
* device registration;
* device revocation;
* authentication state;
* security settings;
* cryptographic directory access.

Gateway performs coarse route/scope enforcement.

Backend services perform their own business/resource authorization.

For example:

```text
Gateway
  └── "Is this request allowed to access this API scope?"
  
Messaging
  └── "Is this user/device allowed to perform this messaging operation?"
  
Files
  └── "Is this user/device allowed to access this file?"
  
Auth
  └── "Is this session/device/account authorized?"
```

No service assumes that the Gateway's authorization check alone is sufficient for sensitive business operations.

---

# 4.18 Internal Interface

Auth communicates internally using:

```text
gRPC
Protocol Buffers
HTTP/2
mTLS
```

Each Auth instance has its own service identity and certificate.

The service-to-service certificate authenticates the Auth service itself.

Application-level authorization determines which RPCs another service may invoke.

Conceptual RPC operations include:

```text
Authenticate
RefreshSession
ValidateSession
RevokeSession

GetUser
GetDevice
ListUserDevices

RegisterDevice
RevokeDevice

GetDeviceCryptoDirectory
GetCryptoIdentity
UpdateCryptoPrekeys
```

MFA-specific operations are exposed through the authentication/session workflow rather than introducing a separate MFA service.

---

# 4.19 Internal Components

The Auth Service is internally divided into focused components:

```text
AuthenticationController
CredentialVerifier
MfaManager
SecondFactorVerifier

SessionManager
AccessTokenIssuer
RefreshTokenManager

DeviceManager
DeviceAuthorizationManager
DeviceRevocationManager

CryptoDirectoryManager
PrekeyManager

AuthorizationPolicy

PostgreSQLRepository
TransactionManager

AuditOutboxPublisher
```

`MfaManager` owns MFA policy/state and coordinates the selected second-factor verifier.

`SecondFactorVerifier` abstracts the actual factor mechanism, allowing TOTP to be replaced or supplemented without redesigning the authentication service.

These are implementation components, **not additional microservices**.

---

# 4.20 Credential Security

If password authentication is used, Auth stores only a strong password-derived verifier using a current vetted password-hashing algorithm.

Auth must enforce:

* bounded authentication attempts;
* appropriate throttling/rate limiting;
* no credential logging;
* protected credential storage;
* secure secret handling;
* explicit failure on credential-verification errors.

MFA secrets must receive equivalent protection and must never appear in logs, tokens, audit payloads, or error messages.

Exact password-hashing parameters and MFA-secret storage details belong to implementation/security configuration, not to a new architectural decision.

---

# 4.21 Failure Behavior

Authentication failures must fail closed.

Examples:

### PostgreSQL unavailable

Auth cannot reliably determine authoritative authentication/session state.

Result:

```text
Authentication operation → explicit failure/unavailable
```

Auth must not fabricate successful authentication.

### Token signing key unavailable

Auth must not:

* issue unsigned tokens;
* use a weaker signing mechanism;
* silently downgrade security.

Token issuance fails explicitly.

### Invalid credentials

Authentication fails without revealing unnecessary information.

### MFA failure

Authentication does not reach `MFA_VERIFIED`.

The client must not receive a fully privileged authentication result.

### Revoked session/device

Authentication or sensitive operations are rejected.

### Gateway cannot reach Auth

Operations requiring Auth authority fail explicitly.

The Gateway must never bypass Auth to authenticate a user.

---

# 4.22 Audit Integration

Auth publishes security and operational events through its transactional outbox.

Examples:

* login success;
* login failure;
* MFA success/failure;
* session creation;
* session revocation;
* refresh-token reuse;
* device registration;
* device revocation;
* cryptographic identity change;
* security-policy violation.

Audit publication is asynchronous.

An Audit outage must not cause an otherwise valid authentication state transaction to become dependent on synchronous Audit availability, unless a specific security policy explicitly requires otherwise.

No passwords, MFA secrets, private keys, access-token plaintext, refresh-token plaintext, or message/file plaintext are included in audit events.

---

# 4.23 Horizontal Scaling

Auth supports multiple service instances.

Durable authentication state remains in PostgreSQL.

Instances must not rely on process-local state for correctness.

Stateless or safely cacheable operations may use local caching, but stale cache data must never bypass:

* device revocation;
* critical authentication state;
* security-sensitive authorization;
* MFA requirements.

The authoritative database remains the source of truth.

---

# 4.24 Security Invariants

The following invariants are mandatory:

1. Auth is the authoritative authentication authority.
2. Gateway cannot bypass Auth to authenticate users.
3. MFA requirements cannot be bypassed by successful primary-factor authentication.
4. Sensitive security operations require the appropriate authentication assurance level.
5. Authentication credentials and E2E cryptographic identity remain separate.
6. Private device cryptographic keys never enter the backend.
7. Auth never decrypts E2E content.
8. Auth stores only public cryptographic directory material.
9. Device registration requires explicit authorization.
10. Revoked devices receive no future authorized data.
11. Previously received encrypted data remains decryptable by the revoked device.
12. Access tokens contain no private cryptographic keys or plaintext content.
13. Token issuance fails closed if signing security cannot be guaranteed.
14. MFA secrets and authentication credentials are never logged.
15. Refresh-token reuse is detectable and treated as a security event.
16. Authentication state required for correctness is durable.
17. No administrator backdoor provides access to E2E plaintext or private keys.
18. No insecure authentication downgrade is permitted.

---

# 4.25 Implementation Boundary

The architecture is now concrete enough to implement.

The following belong in subsequent implementation-oriented documentation:

* PostgreSQL physical schema and indexes;
* exact MFA tables/state;
* exact TOTP enrollment/verification parameters;
* exact protobuf definitions;
* REST authentication contract;
* token serialization;
* cryptographic library/API integration;
* secret/key deployment configuration;
* device-pairing protocol;
* exact authentication error codes;
* migration strategy;
* test cases and security-test vectors.

These details do **not** require additional architectural ADRs unless implementation later reveals a genuine architectural conflict.

---

## 4.26 Design Summary

```text
                    ┌───────────────┐
                    │    Client     │
                    └───────┬───────┘
                            │
                     HTTPS / TLS 1.3
                            │
                    ┌───────▼───────┐
                    │    Gateway    │
                    └───────┬───────┘
                            │
                     gRPC / mTLS
                            │
                    ┌───────▼───────┐
                    │      Auth     │
                    │               │
                    │ Credentials   │
                    │ MFA           │
                    │ Sessions      │
                    │ Tokens        │
                    │ Devices       │
                    │ Crypto Dir.   │
                    └───────┬───────┘
                            │
                       PostgreSQL
```

The Auth Service therefore provides the **authentication and device-security foundation** of SecureCloud while remaining completely outside the E2E decryption boundary.

Its central principle is:

> **Auth proves who is authorized to use the system and which devices are authorized; it never becomes an authority over E2E plaintext or private cryptographic keys.**
