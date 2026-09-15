How to read this diagram

The primary execution path is:

Client
  │ HTTPS/TLS
  ▼
GatewayController
  │
  ├── AuthenticationMiddleware
  │         │
  │         ▼
  │    TokenValidator
  │         │
  │         ▼
  │ AuthenticatedRequestContext
  │
  ▼
GatewaySecurityPolicy
  │
  ▼
RequestRouter
  │
  ▼
ServiceProxy
  │
  │ gRPC + mTLS
  ▼
Auth / Messaging / Files

1. GatewayController

This represents the Gateway's incoming HTTP request handling layer.

It should remain thin. Its responsibility is orchestration:

receive the HTTPS request;
invoke authentication enforcement;
apply Gateway-level policy;
route the request;
forward it to the correct downstream service;
stream where necessary;
apply explicitly configured retry behaviour;
emit relevant Gateway application Audit events.

It should not contain Auth, Messaging, or Files business logic.

2. AuthenticationMiddleware

This is the Gateway's authentication enforcement point.

It does not mean that Gateway becomes the owner of authentication.

The distinction we previously approved remains:

Auth Service
    =
authentication authority
credential validation authority
MFA authority
token issuance authority

Gateway
    =
authentication enforcement point

The middleware extracts the credential/token and obtains a validation result through the TokenValidator abstraction.

The concrete implementation shown here is:

AuthServiceGrpcClient
        implements
TokenValidator

This makes the dependency explicit:

Gateway
   │ gRPC + mTLS
   ▼
Auth Service
   │
   ▼
TokenValidationResult

The Gateway then creates an AuthenticatedRequestContext for the remainder of the request.

3. AuthenticatedRequestContext

This is particularly important for SecureCloud.

Once authentication succeeds, downstream requests carry a trusted authenticated context containing, at minimum:

userId
deviceId
credentialId
authenticated
scopes

The Gateway does not simply forward the original JWT and hope every service interprets it independently.

Conceptually:

Client JWT
     │
     ▼
Gateway authentication enforcement
     │
     ▼
AuthenticatedRequestContext
     │
     │ internal gRPC request
     ▼
Downstream service

This gives us a clearer internal trust boundary.

4. GatewaySecurityPolicy

This class represents explicit Gateway-level decisions such as:

Does this route require authentication?

Is this route security-sensitive?

Does this request satisfy Gateway-level policy?

This should not duplicate downstream business authorization.

For example:

Can Alice modify Group X?

belongs to Messaging because Messaging owns conversation membership and group rules.

But:

Does this endpoint require an authenticated device?

is appropriate for Gateway enforcement.

5. RequestRouter and ServiceProxy

These are deliberately separated.

RequestRouter

Answers:

Where should this request go?

For example:

/api/auth/*
        ↓
Auth Service

/api/conversations/*
        ↓
Messaging Service

/api/files/*
        ↓
Files Service
ServiceProxy

Answers:

How is this request forwarded?

The concrete downstream clients implement this abstraction:

AuthServiceGrpcClient
MessagingServiceGrpcClient
FilesServiceGrpcClient

All internal service communication follows the approved direction:

gRPC + mTLS
6. StreamingProxy

This represents the approved Gateway streaming requirement.

The Gateway should not do:

Read complete file into memory
        ↓
Store byte[]
        ↓
Send complete file

Instead:

Client request stream
        ↓
Gateway StreamingProxy
        ↓
Files Service gRPC stream

and similarly in the reverse direction for downloads:

Files Service stream
        ↓
Gateway StreamingProxy
        ↓
Client response stream

The class diagram intentionally models streaming separately because its lifecycle and resource handling differ from ordinary request/response forwarding.

7. Retry model

Retries are represented explicitly rather than being hidden inside every client.

GatewayController
       │
       ▼
RetryPolicy
       │
       ▼
RetryClassifier
       │
       ▼
RetryDecision

The RetryClassifier determines whether a particular operation is safe to retry.

This supports our approved principle:

The Gateway does not blindly retry every request.

In particular, retries must respect:

idempotency;
operation semantics;
whether downstream processing may already have succeeded.
8. Gateway Audit events

GatewayAuditPublisher is deliberately separate from request telemetry.

It publishes only approved application/security-relevant Gateway events.

For example, the Gateway may audit events such as:

AUTHENTICATION_ENFORCEMENT_FAILURE
INVALID_AUTHENTICATION_CREDENTIAL
SECURITY_POLICY_REJECTION

It should not send every HTTP request, latency measurement, or connection event to the Audit Service.

That remains:

Observability / telemetry
≠
Application Audit

The concrete communication path is:

GatewayAuditPublisher
        │
        │ gRPC + mTLS
        ▼
AuditServiceGrpcClient
        │
        ▼
Audit Service

What is deliberately excluded

To avoid turning this into an oversized diagram, I excluded:

DTO classes for every API endpoint;
HTTP framework classes;
gRPC generated classes;
logging classes;
metrics classes;
TLS implementation classes;
configuration classes;
exception classes;
every individual route handler.

Those are implementation details rather than architectural classes.

Important note for implementation

The diagram defines the logical implementation structure, not necessarily the exact C++ implementation structure. For implementation can be organized like this:

gateway/
├── transport/
│   └── GatewayController
│
├── security/
│   ├── AuthenticationMiddleware
│   ├── TokenValidator
│   └── GatewaySecurityPolicy
│
├── routing/
│   ├── RequestRouter
│   └── ServiceProxy
│
├── grpc/
│   ├── AuthServiceGrpcClient
│   ├── MessagingServiceGrpcClient
│   ├── FilesServiceGrpcClient
│   └── AuditServiceGrpcClient
│
├── streaming/
│   └── StreamingProxy
│
├── resilience/
│   ├── RetryPolicy
│   └── RetryClassifier
│
└── audit/
    └── GatewayAuditPublisher