# 3. Gateway Service Design

## 3.1 Purpose

The Gateway is SecureCloud's single external entry point.

Its responsibilities are:

* terminate external TLS connections;
* accept client API requests;
* enforce authentication at the external boundary;
* validate requests;
* enforce coarse-grained route/scope authorization;
* route requests to the appropriate backend service;
* translate external REST/JSON requests into internal gRPC/Protobuf calls;
* enforce request, connection and resource limits;
* propagate deadlines and cancellation;
* provide streaming for large transfers;
* apply controlled retry behavior;
* translate internal failures into appropriate external errors.

The Gateway does **not** own business state and does not become an authority over E2E encrypted content.

It must never possess:

* E2E private keys;
* message plaintext;
* plaintext file contents;
* file-encryption keys;
* cryptographic authority over user/device E2E identities.

The Gateway is therefore a **security and protocol boundary**, not a business-logic service.

---

## 3.2 Architectural Position

The canonical request path is:

```text id="p7g8a1"
Qt/C++ Client
      │
      │ HTTPS + TLS 1.3
      ▼
   Gateway
      │
      ├──────────────► Auth
      │
      ├──────────────► Messaging
      │
      └──────────────► Files
```

Audit is primarily reached through internal asynchronous events rather than direct client access.

The client never connects directly to:

* Auth;
* Messaging;
* Files;
* Audit;
* PostgreSQL;
* ScyllaDB;
* MinIO;
* ClickHouse.

The Gateway hides backend topology from the client.

---

## 3.3 External Transport

Client-to-Gateway communication uses:

* HTTPS;
* TLS 1.3;
* REST/JSON for external APIs.

The Gateway terminates external TLS.

Normal application authentication uses application credentials and tokens rather than requiring client TLS certificates.

Client TLS certificates are therefore not the primary application identity mechanism.

The Gateway validates the external TLS session before processing the HTTP request.

---

## 3.4 Authentication Boundary

The Gateway is the **authentication enforcement point**.

Auth is the **authentication authority**.

This distinction is important.

```text id="3q0w7m"
Client
  │
  │ credentials
  ▼
Gateway
  │
  │ authentication request
  ▼
Auth
  │
  │ authentication result
  ▼
Gateway
  │
  │ response
  ▼
Client
```

For example:

```text
POST /auth/login
```

is sent to the Gateway.

The Gateway routes the request to Auth.

The Gateway does not implement credential verification itself.

Likewise:

```text
POST /auth/refresh
```

is routed to Auth.

The Gateway must not redirect the client to Auth using an HTTP redirect.

The client should remain unaware of internal service addresses.

---

## 3.5 Access Tokens

After successful authentication, Auth issues a short-lived access token.

The access token contains only the information necessary for authorization and request context.

Conceptual claims include:

```text id="h3xj1k"
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

Identifiers are opaque.

The token must not contain:

* E2E private keys;
* message plaintext;
* file plaintext;
* file-encryption keys;
* unnecessary personal information.

The access token is an **application authentication/authorization credential**.

It is not the user's cryptographic identity for E2E communication.

---

## 3.6 Access Token Verification

Auth owns the private signing key used to issue access tokens.

The Gateway possesses only the corresponding public verification material.

Conceptually:

```text id="1k2x8r"
Auth
 ├── private signing key
 │
 └── signs access token
          │
          ▼
       Gateway
          │
          └── verifies signature
```

The Gateway verifies at minimum:

* token signature;
* issuer;
* audience;
* expiration;
* required claims;
* token version;
* applicable authentication level;
* required scopes.

The Gateway must fail closed if token verification cannot be performed reliably.

It must never treat an unverifiable token as authenticated.

---

## 3.7 Request Authentication Context

After successful token verification, the Gateway creates a request-scoped `AuthenticatedContext`.

Conceptually:

```text id="9jv6f2"
AuthenticatedContext
 ├── user_id
 ├── device_id
 ├── session_id
 ├── scopes
 └── authentication_level
```

This context is passed to the appropriate backend service through the internal authenticated request.

The Gateway should not rely on client-supplied identity fields when authoritative identity is already available from the verified token.

For example, a request containing:

```text
user_id = X
```

does not allow the client to impersonate `X`.

The authoritative identity comes from the authenticated context.

---

## 3.8 Authentication Assurance and MFA

Some operations require stronger authentication assurance.

Auth defines the authoritative authentication level.

The MVP uses:

```text id="j6w3zz"
PRIMARY_ONLY
MFA_VERIFIED
```

Sensitive operations requiring stronger assurance include operations such as:

* registering a new device;
* revoking a device;
* changing credentials;
* modifying MFA/security settings.

The Gateway may enforce the required authentication level for the relevant route.

Auth remains authoritative for the underlying authentication state.

The Gateway must never implement an MFA bypass.

---

## 3.9 Authorization

Authorization is deliberately split between Gateway and backend services.

### Gateway

Performs coarse-grained authorization:

* route access;
* required scope;
* authentication level;
* basic request policy.

### Backend service

Performs fine-grained business authorization.

For example:

```text
Gateway
   │
   │ "authenticated user has messaging scope"
   ▼
Messaging
   │
   │ "is this user actually a member of conversation X?"
   ▼
allow / deny
```

The Gateway must not attempt to reproduce all business authorization logic.

This prevents the Gateway from becoming a centralized business-logic monolith.

---

## 3.10 Routing

The Gateway maps external API operations to backend services.

Canonical routing:

| External capability              | Backend   |
| -------------------------------- | --------- |
| Login / MFA / refresh            | Auth      |
| User/device discovery            | Auth      |
| Public cryptographic directory   | Auth      |
| Conversations/groups             | Messaging |
| Send/retrieve messages           | Messaging |
| Synchronization                  | Messaging |
| Delivery/read receipts           | Messaging |
| File metadata                    | Files     |
| File upload/download             | Files     |
| Device/authentication operations | Auth      |

Audit is an internal service and is not directly exposed as a normal client API.

The Gateway must not expose backend addresses or allow arbitrary service selection by clients.

---

## 3.11 Internal Communication

Gateway-to-service communication uses:

* gRPC;
* Protocol Buffers;
* HTTP/2;
* mTLS.

Each backend service has its own service identity.

The Gateway authenticates the target service connection through the service PKI defined in ADR-008.

The Gateway must not use a shared service private key.

---

## 3.12 E2E Encrypted Data Handling

The Gateway treats encrypted message and file payloads as opaque data.

For a message:

```text id="v0m5bp"
Client
   │
   │ ciphertext
   ▼
Gateway
   │
   │ ciphertext
   ▼
Messaging
```

For a file:

```text id="xj0y7k"
Client
   │
   │ encrypted stream
   ▼
Gateway
   │
   │ encrypted stream
   ▼
Files
```

The Gateway may process the routing and transport metadata required for the request.

It must not decrypt application payloads.

The Gateway is therefore not an E2E cryptographic endpoint.

---

## 3.13 Streaming

Streaming is required for large file transfers.

The Gateway must stream data between:

```text
HTTP client
     ↕
Gateway
     ↕
gRPC stream
     ↕
Files
     ↕
MinIO
```

The Gateway must not buffer the complete file in memory.

Buffers are bounded.

Backpressure must propagate through the complete streaming path.

For example:

```text id="i5xk4z"
slow client
    ↓
Gateway output buffer fills
    ↓
gRPC stream slows
    ↓
Files slows
    ↓
MinIO read slows
```

The same principle applies to uploads.

---

## 3.14 Message Synchronization

Messaging synchronization may use:

* bounded batches;
* streaming where appropriate;
* explicit cursors;
* bounded response sizes.

The Gateway must not create unbounded response buffers.

Long-lived streams must have:

* cancellation;
* deadlines or lifecycle limits where appropriate;
* bounded server-side state;
* explicit reconnection behavior.

---

## 3.15 Retry Policy

The Gateway may automatically retry only operations where retry is demonstrably safe.

Automatic retry is appropriate primarily for:

* idempotent reads;
* explicitly idempotent operations;
* transient dependency failures;
* operations where the remaining request deadline permits retry.

Retries use:

* bounded retry count;
* exponential backoff;
* jitter;
* deadline awareness.

The Gateway must not blindly retry operations such as:

* `SendMessage`;
* `CreateConversation`;
* `AddParticipant`;
* `RegisterDevice`;
* `RevokeDevice`;
* `UploadFile`;
* emergency message submission.

Where retries are required for these operations, stable idempotency mechanisms must be used.

---

## 3.16 Idempotency and Unknown Outcomes

The Gateway must account for the possibility that:

```text
request → backend → operation succeeds → response lost
```

The client may therefore retry.

For operations with durable side effects, the backend service's idempotency mechanism is authoritative.

The Gateway must not attempt to infer whether a state-changing operation succeeded merely from a network timeout.

It should return an appropriate unknown/transient failure to the client when the outcome cannot safely be established.

The client can then retry using the operation's stable idempotency identifier.

---

## 3.17 Deadlines and Cancellation

Every internal request has a bounded deadline.

The Gateway propagates the remaining request deadline to backend services.

Conceptually:

```text id="h7e1x4"
Client
   │
   │ request deadline = T
   ▼
Gateway
   │
   │ remaining deadline
   ▼
Messaging/Auth/Files
```

When the client cancels a request, the Gateway should propagate cancellation where supported.

The Gateway must not allow abandoned requests to continue consuming resources indefinitely.

---

## 3.18 Rate and Resource Limiting

The Gateway is the first resource-protection boundary.

It applies limits to:

* request size;
* connection count;
* request concurrency;
* streaming concurrency;
* upload/download size;
* authentication attempts;
* request rates;
* backend connection usage.

Limits should be differentiated where necessary.

For example, authentication endpoints require stronger anti-abuse protection than ordinary message retrieval.

Resource limits must be bounded and explicit.

---

## 3.19 Backpressure

The Gateway must provide backpressure rather than accepting unlimited work.

When resources are exhausted it may:

* reject requests;
* throttle;
* delay work within bounded limits;
* terminate overloaded streams;
* return explicit retryable errors.

It must never silently discard an accepted request.

For durable operations, the distinction between:

```text
not accepted
```

and:

```text
durably accepted
```

must remain clear.

---

## 3.20 Error Translation

Backend services return internal errors.

The Gateway translates them into stable external API errors.

Clients should not receive:

* internal service addresses;
* stack traces;
* database errors;
* internal implementation details;
* sensitive operational information.

Conceptually:

```text
Internal:
SCYLLA_TIMEOUT
```

may become an external error such as:

```text
503 Service Temporarily Unavailable
```

with a stable application error code.

The mapping must preserve enough information for clients to distinguish:

* authentication failure;
* authorization failure;
* validation failure;
* rate limiting;
* temporary unavailability;
* timeout;
* permanent business failure.

---

## 3.21 Failure Behavior

### Auth unavailable

Authentication-dependent operations fail.

The Gateway must not bypass Auth.

### Messaging unavailable

Messaging operations fail explicitly.

The Gateway must not fabricate successful message submission.

### Files unavailable

File operations fail explicitly.

Messaging operations should remain independently available.

### Audit unavailable

The Gateway should not make ordinary successful requests dependent on synchronous Audit availability.

### Internal network failure

The Gateway returns an explicit transient error when the request cannot safely complete.

### Gateway restart

The Gateway should not lose durable business state because it is stateless.

In-flight requests may fail and be retried according to their idempotency semantics.

---

## 3.22 Statelessness

The Gateway is designed to be stateless with respect to business data.

It does not own:

* messages;
* conversations;
* files;
* user credentials;
* device registrations;
* audit history.

It may maintain bounded process-local state for:

* active connections;
* rate limiting;
* in-flight requests;
* connection pools;
* temporary streaming buffers.

Such state must not be required for correctness.

This allows multiple Gateway instances to operate interchangeably:

```text id="q7t3f5"
                  Load Balancer
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
      Gateway-1    Gateway-2    Gateway-3
          │            │            │
          └────────────┼────────────┘
                       ▼
              backend services
```

No sticky sessions are required for correctness.

---

## 3.23 Gateway Components

The Gateway is organized around the following components:

### Transport

* `HttpsServer`
* `TlsHandler`

### Request Processing

* `RequestValidator`
* `AccessTokenMiddleware`
* `RouteScopeAuthorizer`

### Routing

* `Router`
* `GrpcClientLayer`

### Resource Protection

* `RateLimiter`
* `ResourceLimiter`
* `DeadlineCancellationHandler`

### Streaming

* `StreamingProxy`

### Response Handling

* `ErrorMapper`

These are internal Gateway components, not independent services.

---

## 3.24 Security Invariants

The Gateway must preserve these invariants:

1. All external client traffic uses TLS.
2. Authentication is enforced before protected requests reach backend services.
3. Auth remains the authentication authority.
4. The Gateway never bypasses MFA requirements.
5. Access-token verification fails closed.
6. Backend services remain responsible for fine-grained business authorization.
7. E2E ciphertext remains opaque to the Gateway.
8. The Gateway never receives E2E private keys.
9. The Gateway never decrypts messages or files.
10. Backend service addresses are never exposed to clients.
11. Internal service communication is authenticated using service identity/mTLS.
12. Service private keys are never shared.
13. Request and streaming resources are bounded.
14. Retries never create unsafe duplicate side effects.
15. Authentication and authorization failures cannot be bypassed during dependency outages.
16. The Gateway does not become a business-state authority.
17. Process-local Gateway state is never required for durable correctness.

---

## 3.25 Implementation Boundary

The following decisions are fixed for implementation:

* Gateway is the single external entry point.
* Client ↔ Gateway uses HTTPS + TLS 1.3.
* External API uses REST/JSON.
* Gateway → backend uses gRPC/Protobuf.
* Internal service communication uses mTLS.
* Auth is the authentication authority.
* Gateway is the authentication enforcement point.
* Access tokens are short-lived signed tokens.
* Auth owns the token signing private key.
* Gateway verifies tokens using public verification material.
* Refresh tokens are handled by Auth and are not treated as stateless access tokens.
* Gateway creates a request-scoped `AuthenticatedContext`.
* Gateway performs coarse route/scope/authentication-level authorization.
* Backend services perform fine-grained business authorization.
* E2E ciphertext is opaque to the Gateway.
* Gateway is stateless with respect to business state.
* File transfers use streaming.
* Large payloads are never fully buffered by the Gateway.
* Backpressure is mandatory.
* Request/resource limits are mandatory.
* Deadlines and cancellation are propagated.
* Automatic retries are restricted to safe/idempotent operations.
* State-changing operations rely on explicit idempotency semantics.
* Internal errors are translated into stable external errors.
* Gateway instances are horizontally interchangeable.
* Gateway failure must not imply business-data loss.

The detailed REST schema, request/response structures, error codes and gRPC contracts belong in `openapi.yaml` and the corresponding `.proto` files rather than in this section.
