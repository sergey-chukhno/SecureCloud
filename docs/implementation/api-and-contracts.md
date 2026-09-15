# SecureCloud API and Contract Rules

**Status:** Implementation Standard
**Applies to:** Gateway REST API, internal gRPC APIs, Protobuf contracts, client/server integration
**Primary goal:** Stable, explicit and independently implementable service contracts

---

# 1. Purpose

This document defines how SecureCloud APIs and inter-service contracts are designed, implemented, tested and changed.

It covers:

* external REST API;
* internal gRPC APIs;
* Protobuf contracts;
* request/response models;
* authentication context;
* authorization expectations;
* error semantics;
* idempotency;
* deadlines and cancellation;
* streaming;
* compatibility;
* versioning;
* contract ownership;
* generated code;
* contract testing;
* API change workflow.

The document does **not** redefine the business architecture or cryptographic protocol.

The authoritative architecture remains defined by:

1. architectural drivers;
2. system context;
3. trust boundaries;
4. architecture;
5. ADRs;
6. detailed design;
7. data model;
8. API contracts.

---

# 2. Contract Principles

SecureCloud contracts follow these principles:

1. **Contracts are explicit.**
2. **Contracts are owned by the service exposing them.**
3. **Consumers depend on contracts, not implementations.**
4. **Transport models are not automatically domain models.**
5. **Security requirements are part of the contract.**
6. **Failure behavior is part of the contract.**
7. **Idempotency semantics are part of the contract.**
8. **Timeout/deadline behavior is part of the contract.**
9. **Compatibility must be considered before changing a contract.**
10. **Generated code is never the source of truth.**

---

# 3. Contract Sources of Truth

SecureCloud uses two principal contract technologies.

## 3.1 External API

The external client-facing API uses:

* HTTPS/TLS 1.3;
* REST;
* JSON;
* OpenAPI.

Authoritative contract:

```text
openapi/openapi.yaml
```

The Gateway owns the external REST API.

---

## 3.2 Internal APIs

Backend service-to-service communication uses:

* gRPC;
* Protobuf;
* HTTP/2;
* mTLS.

Authoritative contracts:

```text
proto/securecloud/
```

Each service owns the RPC contracts it exposes.

---

# 4. API Ownership

The following ownership model applies:

| API                               | Owner                      | Consumers                                   |
| --------------------------------- | -------------------------- | ------------------------------------------- |
| Client-facing REST API            | Gateway                    | Client                                      |
| Authentication RPC                | Auth                       | Gateway, authorized backend consumers       |
| Messaging RPC                     | Messaging                  | Gateway                                     |
| Files RPC                         | Files                      | Gateway                                     |
| Audit RPC/events                  | Audit / producing services | Internal                                    |
| Auth public crypto-directory APIs | Auth                       | Gateway/client-facing flows through Gateway |

A service owns:

* its API definitions;
* request/response schemas;
* validation rules;
* error semantics;
* compatibility policy;
* implementation.

Consumers must not modify another service's contract.

---

# 5. Repository Contract Layout

Contracts are stored independently from service implementation.

Recommended structure:

```text id="b8dbn5"
openapi/
└── openapi.yaml

proto/
└── securecloud/
    ├── common/
    ├── auth/
    ├── messaging/
    ├── files/
    └── audit/
```

Generated sources must be placed in a generated/build-specific location.

For example:

```text id="7x8zjq"
build/generated/
```

or another explicitly configured generated directory.

Generated files must not be manually edited.

---

# 6. Contract Design Workflow

Before implementing an API:

```text id="zq9b7f"
Requirement
    ↓
Domain/use-case definition
    ↓
API contract
    ↓
Contract review
    ↓
Contract tests
    ↓
Server implementation
    ↓
Client implementation
```

The contract should be sufficiently stable before parallel implementation begins.

For work involving multiple developers, agree on the contract before writing dependent implementation code.

---

# 7. API Contract Contents

Every non-trivial operation should define:

* operation name;
* purpose;
* caller;
* authentication requirements;
* authorization requirements;
* request schema;
* response schema;
* validation rules;
* success semantics;
* error semantics;
* idempotency semantics;
* timeout/deadline expectations;
* retry behavior;
* consistency/durability semantics;
* streaming behavior where applicable.

A contract that only defines the happy-path JSON/Protobuf structure is incomplete.

---

# 8. External REST API

The Gateway is the only external backend entry point.

Clients must not directly connect to:

* Auth;
* Messaging;
* Files;
* Audit.

The Gateway:

1. terminates client TLS;
2. validates HTTP requests;
3. verifies access tokens;
4. establishes `AuthenticatedContext`;
5. performs coarse route/scope authorization;
6. calls the appropriate backend service;
7. maps backend results to the external API contract.

---

# 9. REST Resource Design

Use resource-oriented URLs.

Examples:

```text id="3v8yr3"
/v1/auth/...
/v1/devices/...
/v1/conversations/...
/v1/messages/...
/v1/files/...
/v1/sync/...
```

Exact endpoint names are defined by `openapi.yaml`.

Do not introduce an endpoint merely because it is convenient for a particular UI component if the operation can be represented by an existing domain operation.

Avoid transport-driven business models such as:

```text id="3swy1p"
/doEverything
/processRequest
/executeAction
```

unless the domain operation genuinely requires such semantics.

---

# 10. REST Versioning

External APIs use an explicit major version:

```text id="z2tq2e"
/v1/
```

Breaking changes require a new major API version.

Examples of potentially breaking changes:

* removing a field;
* changing field meaning;
* changing field type;
* changing requiredness in an incompatible direction;
* changing authentication requirements;
* changing success semantics;
* changing error semantics in a way that breaks consumers.

Non-breaking additions should normally remain within the existing major version.

---

# 11. JSON Rules

JSON field names must be consistent across the API.

Use one naming convention throughout the external API.

Do not expose internal database column names as API fields merely because they already exist.

API schemas represent external contracts, not persistence schemas.

---

# 12. Identifiers

API identifiers must use the identifier semantics defined by the domain.

Important identifiers include:

* user ID;
* device ID;
* session ID;
* conversation ID;
* message ID;
* idempotency ID;
* file ID;
* file version ID;
* transfer ID.

Do not substitute database-specific identifiers for domain identifiers without an explicit design reason.

---

# 13. Authentication Context

After successful Gateway authentication, the request should carry an internal `AuthenticatedContext` containing the authenticated principal information required by downstream authorization.

Conceptually:

```text id="2e8flr"
AuthenticatedContext
├── user_id
├── device_id
├── session_id
├── scopes
└── authentication_level
```

The exact transport representation is defined by the internal contract.

Do not trust client-provided equivalents after authentication.

For example, a request body containing:

```text id="w4y0i2"
"user_id": "..."
```

does not establish the authenticated identity.

The authenticated identity comes from the verified authentication context.

---

# 14. Authorization Contract

Each sensitive operation must define:

* who may call it;
* required scope/permission;
* required authentication level;
* resource ownership/membership requirements.

Gateway authorization is coarse.

Backend services perform authoritative resource/business authorization.

Example:

```text id="v8gk5t"
Gateway
  → Is caller allowed to access messaging route?

Messaging
  → Is this authenticated device allowed to send
    to this conversation?
```

Do not assume that passing Gateway authorization means the operation is authorized.

---

# 15. Authentication Levels

Operations requiring elevated authentication must explicitly declare it.

SecureCloud currently uses:

```text id="m9m0ph"
PRIMARY_ONLY
MFA_VERIFIED
```

Sensitive operations include, where defined by the approved design:

* new device registration;
* device revocation;
* credential changes;
* MFA/security settings.

The contract must make this requirement discoverable to implementers.

---

# 16. Request Validation

Every API boundary validates requests.

Validation should include:

* required fields;
* field sizes;
* identifier formats;
* enum values;
* nested structures;
* maximum request size;
* state validity;
* mutually exclusive fields;
* required authentication level;
* resource constraints.

Validation failures must produce a defined client-visible error.

Do not rely on downstream services to discover malformed HTTP requests.

---

# 17. Error Contract

Errors must be structured and stable.

A REST error should contain enough information for a client to understand the category of failure without exposing internal implementation details.

Conceptually:

```text id="f3o7m6"
{
    error_code,
    message,
    request_id
}
```

Additional fields may be defined by the OpenAPI contract.

`message` is safe human-readable information.

`error_code` is the stable machine-readable contract.

`request_id` allows operational correlation.

---

# 18. Error Categories

The implementation should distinguish at least:

```text id="0lupgq"
VALIDATION_ERROR
AUTHENTICATION_ERROR
AUTHORIZATION_ERROR
NOT_FOUND
CONFLICT
RATE_LIMITED
RESOURCE_EXHAUSTED
TIMEOUT
DEPENDENCY_UNAVAILABLE
INTERNAL_ERROR
CRYPTOGRAPHIC_ERROR
```

The exact public error-code set belongs in the API contract.

Do not expose database, filesystem, gRPC or exception implementation details.

---

# 19. Internal gRPC Errors

Internal RPC failures must use consistent gRPC status semantics.

Map application/domain failures to appropriate gRPC statuses.

Do not use:

```text id="4r9p6f"
INTERNAL
```

for every possible failure.

Consumers must be able to distinguish:

* invalid request;
* authentication failure;
* authorization failure;
* not found;
* conflict;
* transient dependency failure;
* timeout;
* resource exhaustion;
* internal failure.

---

# 20. Error Mapping

The Gateway maps internal service errors to external REST semantics.

Conceptually:

```text id="b5i9dj"
Messaging
    ↓
gRPC application error
    ↓
Gateway error mapper
    ↓
HTTP status + stable error_code
    ↓
Client
```

Do not leak internal RPC status codes directly if they expose implementation details or produce an inconsistent public API.

---

# 21. Error Stability

Clients should depend on:

* stable error codes;
* documented HTTP semantics;
* documented retryability.

Clients should **not** depend on:

* human-readable error strings;
* SQL error text;
* exception class names;
* server log messages.

Human-readable messages may evolve without constituting a breaking API change.

---

# 22. Idempotency

Any operation vulnerable to duplicate submission must define its idempotency semantics.

Important operations include:

* message submission;
* conversation creation;
* participant changes;
* device registration;
* device revocation;
* file upload;
* file chunk submission.

An idempotent operation must define:

1. idempotency key;
2. scope of uniqueness;
3. retention/lifetime;
4. behavior for duplicate requests;
5. behavior when the original operation is still in progress;
6. behavior when the original operation succeeded;
7. behavior when the original operation failed.

---

# 23. Message Submission

Message submission is not transparently retried by the Gateway.

The client uses a stable idempotency identifier.

Conceptually:

```text id="0ngyqc"
Client
  ↓
message + client_idempotency_id
  ↓
Gateway
  ↓
Messaging
```

If the client does not know whether the previous submission succeeded, it can safely retry using the same idempotency identifier.

Messaging must return the same logical result rather than creating a second message.

---

# 24. Durable Acceptance

The message API must clearly distinguish:

> request received

from:

> message durably accepted.

The successful acceptance response must correspond to the approved durability invariant:

* message persisted;
* initial delivery state persisted;
* required metadata persisted;
* outbox event persisted atomically.

Only then is the message considered accepted.

A network response must never claim durable acceptance when the durable acceptance transaction failed.

---

# 25. File Upload Idempotency

File uploads use stable transfer identifiers.

Chunk operations use:

```text id="m7q4j2"
transfer_id
chunk_index
```

A repeated chunk submission must not corrupt the transfer or create duplicate logical chunks.

The API must define whether a repeated identical chunk is:

* accepted as already present;
* verified and ignored;
* rejected if its content conflicts.

---

# 26. gRPC Streaming

Streaming APIs must explicitly define:

* stream direction;
* message types;
* termination semantics;
* cancellation;
* deadlines;
* maximum message/chunk size;
* backpressure behavior;
* retry/resume behavior where applicable.

Streaming must not imply unbounded buffering.

---

# 27. File Streaming

Files use streaming rather than loading large objects into memory.

Conceptual flow:

```text id="r4l7dz"
Client
   ↓ HTTPS stream
Gateway
   ↓ gRPC stream
Files
   ↓ storage stream
MinIO
```

The Gateway must preserve backpressure.

A slow downstream consumer must not cause unlimited memory growth upstream.

---

# 28. Resumable Transfers

A resumable transfer contract must expose enough information for the client to recover after:

* network interruption;
* Gateway restart;
* Files restart;
* client restart.

The transfer state remains authoritative on the Files service.

The client must not assume that successful transmission of bytes means the transfer is durably finalized.

Finalization is an explicit state transition.

---

# 29. Synchronization API

Synchronization is authoritative from the server side.

The contract must distinguish:

* initial synchronization;
* incremental synchronization;
* synchronization cursor;
* completion;
* retry/resume behavior.

Conceptually:

```text id="6oqgkv"
Client
  ↓
sync request + cursor
  ↓
Messaging
  ↓
changes + next cursor
```

The client maintains local `SyncState`.

The server remains authoritative for the synchronization cursor.

---

# 30. Presence and Delivery State

API contracts must not confuse:

### Presence

Whether a device/user is currently available.

### SyncState

Where the client is relative to backend synchronization.

### DeliveryState

Whether a message has progressed through delivery/read lifecycle.

### DeviceState

Whether a device is authorized, active or revoked.

These are separate concepts and must remain separate in API models.

---

# 31. Read Receipts

Read receipts are distinct from delivery acknowledgements.

Conceptually:

```text id="0h0h1a"
DELIVERED
    ≠
READ
```

Delivery means the recipient device has durably accepted the encrypted message locally.

Read means the client reports that the message was presented/opened according to the approved UI semantics.

The API must not infer READ merely from DELIVERED.

---

# 32. Device APIs

Device lifecycle operations must define:

* authentication requirements;
* MFA requirements;
* pairing/approval requirements;
* device identity;
* authorization state;
* revocation semantics;
* public cryptographic identity;
* key/prekey registration where applicable.

A valid access token alone must not bypass the approved strong device-registration flow.

---

# 33. Cryptographic API Boundaries

Backend APIs must transport only the cryptographic material explicitly permitted by the architecture.

Never include:

* device private keys;
* message plaintext;
* file plaintext;
* backend decryption keys

in backend API contracts.

The Auth public crypto directory may expose public cryptographic material required for endpoint E2E session establishment.

Private endpoint keys remain local.

---

# 34. Audit Contracts

Audit is asynchronous where defined by the architecture.

Security/business operations may publish audit events through the approved outbox mechanism.

Audit processing must not unnecessarily block durable message acceptance.

Audit events must contain only the metadata required by the approved audit policy.

Do not place plaintext message content into audit events.

---

# 35. Protobuf Design Rules

Protobuf messages must be designed for compatibility.

Rules:

* never reuse a field number for a different semantic meaning;
* reserve removed field numbers where appropriate;
* avoid unnecessary `required` semantics;
* prefer additive evolution;
* document important compatibility constraints;
* use explicit enum values;
* preserve unknown fields according to Protobuf behavior;
* avoid embedding persistence models directly into Protobuf.

---

# 36. Protobuf Field Numbers

Once a field number is published, it must not be reused for a different field.

When removing a field, reserve its number and, where appropriate, its name.

Example:

```text id="rkgp5r"
reserved 7;
reserved "old_field";
```

The exact generated syntax must follow the Protobuf version/toolchain used by the project.

---

# 37. Enum Evolution

Enums must have an explicit zero/default value where appropriate.

Consumers must not assume that an enum can never contain a future value.

When receiving an unknown or unsupported value:

* reject when the value would make processing unsafe or ambiguous;
* otherwise handle it according to forward-compatibility rules.

Never reinterpret an unknown security-sensitive enum as a permissive default.

---

# 38. Backward Compatibility

Prefer additive changes.

Usually safe:

* adding an optional field;
* adding a new RPC where consumers are unaffected;
* adding a new endpoint;
* adding a new response field where clients tolerate it.

Potentially breaking:

* removing fields;
* changing field semantics;
* changing types;
* changing authentication requirements;
* changing idempotency behavior;
* changing error semantics;
* changing ordering guarantees;
* changing durability guarantees.

Breaking changes require explicit review.

---

# 39. Contract Versioning

Do not version every minor contract change.

Use:

* additive evolution for compatible changes;
* major version changes for externally breaking REST changes;
* Protobuf compatibility rules for internal gRPC.

If a breaking internal contract change cannot be rolled out atomically, use a compatibility period where old and new versions coexist.

---

# 40. Rolling Deployment Compatibility

Services may temporarily run different versions during deployment.

Therefore, contract changes must consider:

```text id="2cr5l8"
Old client/service
        ↕
New service/client
```

A deployment must not require every component to upgrade simultaneously unless the deployment architecture explicitly guarantees atomic replacement.

Prefer:

```text id="u9z4z2"
Add new field
      ↓
Deploy producer
      ↓
Deploy consumer
      ↓
Remove obsolete behavior later
```

rather than an immediate incompatible replacement.

---

# 41. Contract Testing

Contract tests verify that implementations conform to published contracts.

At minimum:

### REST

Verify:

* request schema;
* response schema;
* status codes;
* error schema;
* authentication behavior;
* authorization behavior;
* idempotency semantics.

### gRPC

Verify:

* RPC method;
* request/response schema;
* status semantics;
* authorization;
* deadlines;
* cancellation;
* streaming semantics.

---

# 42. Consumer-Driven Testing

For important service integrations, consumers should test the assumptions they depend on.

Examples:

```text id="1rv4d0"
Gateway → Messaging
Gateway → Files
Gateway → Auth
```

A contract change should reveal whether the consumer remains compatible before integration reaches production-like environments.

---

# 43. Mocking

Mocks may be used for unit tests.

However, mocks must not become the only verification of service contracts.

For important integrations, use:

* contract tests;
* integration tests;
* real service instances where practical;
* failure injection.

A mock that simply returns successful responses does not prove distributed correctness.

---

# 44. Generated Code

Generated code must be reproducible from the contract.

Developers must not:

* manually edit generated Protobuf classes;
* manually edit generated gRPC classes;
* add business logic to generated files.

If generated code requires modification, modify the source contract or generation configuration.

---

# 45. Client API Layer

The C++ client should isolate transport details from application/domain logic.

Conceptually:

```text id="f9hlnd"
UI
 ↓
Application manager
 ↓
API client / repository
 ↓
REST transport
 ↓
Gateway
```

Application code should not construct raw HTTP requests throughout the codebase.

Centralize:

* authentication headers;
* serialization;
* error mapping;
* request IDs;
* cancellation;
* timeouts;
* retry rules.

---

# 46. Request IDs and Correlation

Requests should carry a correlation/request identifier where appropriate.

Purpose:

* trace a request across Gateway and backend services;
* correlate client-visible failures with server-side logs;
* diagnose distributed failures.

Request IDs are operational identifiers.

They must not be treated as authentication credentials or authorization proofs.

---

# 47. Deadlines

API calls must define reasonable deadlines.

A downstream service must not wait indefinitely for an upstream request.

Conceptually:

```text id="w2g3or"
Client deadline
      ↓
Gateway remaining deadline
      ↓
Backend RPC deadline
      ↓
Database/storage timeout
```

Each layer should respect the remaining time budget.

A child operation should not receive a deadline later than the parent operation's effective deadline.

---

# 48. Cancellation

Cancellation should propagate when an operation is no longer needed.

Examples:

* client closes a file download;
* client cancels an upload;
* Gateway request is disconnected;
* upstream deadline expires.

Cancellation must not bypass required durability operations.

For example, if a message has already reached the durable acceptance transaction, cancellation cannot retroactively erase the accepted message.

---

# 49. Retryability Contract

Every potentially transient operation should have a defined retry policy.

Conceptually classify operations as:

```text id="l4z8kg"
SAFE_RETRY
IDEMPOTENT_RETRY
NO_AUTOMATIC_RETRY
```

Examples:

| Operation                       | Automatic retry                       |
| ------------------------------- | ------------------------------------- |
| Read-only query                 | Usually allowed                       |
| Explicitly idempotent operation | Allowed within limits                 |
| SendMessage                     | No transparent retry; use idempotency |
| CreateConversation              | No transparent retry; use idempotency |
| RegisterDevice                  | No transparent retry                  |
| RevokeDevice                    | No transparent retry                  |
| UploadFile                      | No transparent whole-operation retry  |
| Chunk upload                    | Idempotent retry allowed              |
| Emergency submission            | No transparent retry                  |

Exact policies must remain aligned with the error/retry design.

---

# 50. Rate Limits and Resource Limits

Contracts must define relevant externally observable limits.

Examples:

* maximum request size;
* maximum message size;
* maximum file size;
* maximum chunk size;
* maximum concurrent streams;
* rate limits;
* synchronization page/batch size.

A resource-limit failure should have a stable error semantic such as `RESOURCE_EXHAUSTED` or `RATE_LIMITED`.

Limits must not be hidden implementation assumptions.

---

# 51. Security of API Schemas

API schemas must never encourage insecure usage.

Do not expose fields that allow callers to:

* bypass authorization;
* select arbitrary users as authenticated principals;
* disable encryption;
* bypass MFA;
* override device state;
* force delivery state;
* mark messages as accepted;
* override audit requirements.

Security invariants must be enforced server-side even if the schema exposes technically valid values.

---

# 52. Contract Change Workflow

Any contract change follows:

```text id="h0q8x4"
Change requested
      ↓
Determine compatibility
      ↓
Update contract
      ↓
Review affected consumers
      ↓
Update contract tests
      ↓
Generate code
      ↓
Implement producer
      ↓
Implement consumers
      ↓
Integration tests
      ↓
Review
```

Do not change the implementation first and update the contract afterward.

---

# 53. Three-Developer Parallel Workflow

The contract system is specifically designed to allow parallel work.

Example:

### Developer 2 — Auth

Owns:

* Auth Protobuf APIs;
* authentication models;
* device APIs;
* MFA APIs;
* Auth contract tests.

### Sergey — Gateway/Messaging

Owns:

* Gateway OpenAPI;
* Messaging Protobuf APIs;
* Gateway↔Auth integration;
* Gateway↔Messaging integration.

### Developer 3 — Files

Owns:

* Files Protobuf APIs;
* file transfer contracts;
* Gateway↔Files integration;
* Files contract tests.

Shared contract changes require review from affected consumers.

---

# 54. Contract-First Parallel Development

When two developers need an interface that is not yet implemented:

```text
Developer A
    ↓
defines contract
    ↓
contract review
    ↓
published contract
    ↙       ↘
Server       Consumer
implementation
```

Both developers can then work independently using:

* generated interfaces;
* test fixtures;
* contract tests;
* agreed example requests/responses.

This prevents implementation details from becoming accidental APIs.

---

# 55. API Examples

Important API operations should have representative examples in the contract documentation.

Examples should demonstrate:

* successful request;
* validation failure;
* authentication failure;
* authorization failure;
* duplicate/idempotent request;
* dependency failure where relevant.

Examples must not contain real secrets, real credentials or sensitive user data.

Use synthetic values.

---

# 56. Contract Review Checklist

Before approving an API contract, verify:

### Domain

* [ ] Operation corresponds to a real domain/use case.
* [ ] Resource ownership is clear.
* [ ] State transitions are defined.

### Security

* [ ] Authentication requirement is defined.
* [ ] Authorization requirement is defined.
* [ ] MFA requirement is defined where necessary.
* [ ] No plaintext/private-key leakage.
* [ ] No security bypass fields.

### Reliability

* [ ] Idempotency behavior is defined.
* [ ] Retryability is defined.
* [ ] Timeout/deadline behavior is defined.
* [ ] Cancellation behavior is defined.
* [ ] Durable acceptance semantics are explicit where relevant.

### Data

* [ ] Request limits are defined.
* [ ] Response limits/pagination are defined.
* [ ] Identifiers are explicit.
* [ ] No persistence schema accidentally exposed.

### Compatibility

* [ ] Change is classified as breaking/non-breaking.
* [ ] Protobuf field numbers are safe.
* [ ] Removed fields are reserved where appropriate.
* [ ] Rolling deployment compatibility is considered.

### Testing

* [ ] Contract tests exist.
* [ ] Negative/error cases exist.
* [ ] Idempotency is tested.
* [ ] Authorization is tested.
* [ ] Relevant streaming/cancellation behavior is tested.

---

# 57. Contract Compliance

An API implementation is contract-compliant when:

* the published schema matches the implementation;
* validation rules are enforced;
* authentication and authorization semantics are preserved;
* errors follow the defined contract;
* idempotency behavior is correct;
* retryability is correctly represented;
* deadlines and cancellation are respected;
* streaming behavior is bounded;
* compatibility rules are respected;
* contract tests pass.

No developer may silently change an API contract to simplify implementation.

If implementation requirements expose a problem with an existing contract, raise the contract change explicitly and update the source of truth before proceeding.

---

# 58. Final Rule

**The contract is an interface between independently evolving components.**

A contract must therefore describe not only:

> what data goes in and out

but also:

> who may call it, what is guaranteed, what can fail, what can be retried, what is durable, and how the interface can evolve safely.

Implementation convenience must never become an undocumented contract.
