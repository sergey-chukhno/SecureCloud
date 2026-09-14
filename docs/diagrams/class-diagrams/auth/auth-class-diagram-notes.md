Auth Service — UML Class Diagram: Explanatory Notes
1. Purpose

The Auth Service UML Class Diagram describes the implementation-level structure of SecureCloud's authentication and identity service.

It is derived from the approved Auth data model and reflects the separation between:

transport handling;
application services;
domain entities;
security components;
persistence abstractions;
audit publication.

The Auth Service owns:

User accounts
Credentials
Devices
Device public keys
Sessions
Refresh tokens
MFA configurations
MFA challenges

It does not own:

conversations;
messages;
files;
audit storage.

The fundamental structure is:

Client / Gateway
       │
       ▼
Transport Handler
       │
       ▼
Application Service
       │
       ├── Domain / Security Components
       │
       ├── Repository Interfaces
       │
       └── Audit Publisher
2. Transport Boundary

The diagram contains two entry points:

AuthRequestHandler
AuthGrpcHandler
AuthRequestHandler

AuthRequestHandler represents requests arriving at Auth through the external/client-facing path.

Its responsibilities are limited to:

receiving requests;
parsing transport-level input;
invoking the appropriate application service;
returning the application result.

It handles operations such as:

Register
Authenticate
Verify MFA
Refresh token
Logout
Register device
Revoke device

It should remain thin.

For example:

Client request
      │
      ▼
AuthRequestHandler
      │
      ▼
AuthenticationService

The request handler should not contain password verification, TOTP verification, SQL, or token lifecycle logic.

AuthGrpcHandler

This represents Auth's internal gRPC interface.

Other runtime services can call Auth through the approved:

gRPC + mTLS

service-to-service mechanism.

The diagram currently exposes two logical capabilities:

Validate authenticated context
Discover device public keys

These are represented by:

AuthGrpcHandler
        │
        ├── CredentialValidationService
        │
        └── DeviceService

This does not mean that other services gain access to Auth's database.

The rule remains:

Service
   │
   │ gRPC + mTLS
   ▼
Auth Service
   │
   ▼
Auth-owned database

There is no cross-service database access.

3. Application Services

The Auth Service separates major authentication responsibilities into focused application services.

RegistrationService
AuthenticationService
MfaService
SessionService
TokenService
DeviceService
CredentialValidationService

This avoids one large AuthManager or AuthenticationManager containing all authentication logic.

3.1 RegistrationService

Responsible for creating a new account.

Conceptually:

Registration request
       │
       ▼
RegistrationService
       │
       ├── PasswordHasher
       │
       ├── UserRepository
       │
       └── AuthAuditPublisher

Its important responsibilities include:

validating registration input;
creating the user identity;
generating the password verifier;
storing the account;
emitting the relevant application audit event.

The service does not manipulate Argon2id details directly.

Instead:

RegistrationService
        │
        ▼
PasswordHasher
        │
        ▼
Argon2idPasswordHasher
4. AuthenticationService

This coordinates the primary authentication flow.

Conceptually:

Authentication request
        │
        ▼
AuthenticationService
        │
        ├── UserRepository
        │
        ├── PasswordHasher
        │
        ├── DeviceService
        │
        ├── SessionService
        │
        ├── MfaService
        │
        └── TokenService

A typical flow is:

Credential identifier
        +
Password
        │
        ▼
Find UserAccount
        │
        ▼
Verify password
        │
        ▼
Validate / identify device
        │
        ▼
Create Session
        │
        ▼
MFA required?
     │       │
    Yes      No
     │       │
     ▼       ▼
Challenge   Issue tokens

The result of authentication is represented by:

AuthenticationResult

This is an application result/value object, not a database entity.

It can indicate, for example:

MFA required
Session identifier
MFA challenge identifier
5. Password Security

The class diagram uses:

PasswordHasher
       ▲
       │ implements
       │
Argon2idPasswordHasher

This reflects the approved use of Argon2id without coupling the rest of the Auth Service directly to a specific hashing implementation.

The domain/application layer works with:

PasswordHasher

while the concrete infrastructure/security implementation provides:

Argon2idPasswordHasher

The user account stores:

credentialIdentifier
passwordVerifier
passwordAlgorithm

The important conceptual distinction is:

Plaintext password
        ❌ never stored

Password verifier
        ✓ stored
6. SessionService

A Session is a first-class entity in the approved Auth model.

This is one of the important corrections made to the original diagram.

Conceptually:

User
 │
 └── Device
       │
       └── Session

A session represents an authenticated lifecycle associated with:

userId
deviceId
sessionStatus
authenticationLevel
expiresAt

The important authentication levels are conceptually:

PRIMARY_ONLY
MFA_VERIFIED

A typical lifecycle is:

Primary authentication succeeds
        │
        ▼
Session created
authenticationLevel = PRIMARY_ONLY
        │
        ▼
MFA challenge
        │
        ▼
TOTP verification succeeds
        │
        ▼
authenticationLevel = MFA_VERIFIED

SessionService owns session lifecycle operations such as:

Create session
Revoke session
Revoke device sessions
7. MfaService

MFA is owned entirely by Auth.

The Gateway does not:

generate TOTP secrets;
decrypt MFA secrets;
verify TOTP codes;
create MFA challenges;
modify MFA configurations.

The relevant structure is:

MfaService
   │
   ├── MfaConfigurationRepository
   ├── MfaChallengeRepository
   ├── SessionRepository
   ├── TotpService
   └── MfaSecretProtector
7.1 MfaConfiguration

An MFA configuration represents an enrolled authentication factor.

For the MVP, the factor is:

TOTP

A user can have:

one active TOTP configuration
+
zero or more historical disabled configurations

This is why the relationship is:

UserAccount
     │
     │ 1
     │
     └──────── 0..*
              MfaConfiguration

Historical configurations remain useful for lifecycle and audit consistency.

The TOTP secret is represented as:

encryptedSecret

because the server must recover the TOTP secret in order to verify future TOTP codes.

Therefore:

TOTP secret
     │
     ▼
Encrypted at rest
     │
     ▼
encryptedSecret stored in database

The secret is decrypted only inside the Auth Service's MFA security boundary.

8. MfaChallenge

MfaChallenge is fundamentally different from MfaConfiguration.

MfaConfiguration
       =
persistent enrolled factor

MfaChallenge
       =
temporary authentication operation

A challenge contains information such as:

challenge purpose
status
expiration time
completion time

The diagram associates challenges with:

User
Session

A typical login flow is:

Primary credentials verified
        │
        ▼
Session created
        │
        ▼
MFA challenge created
        │
        ▼
User enters TOTP code
        │
        ▼
MfaService verifies code
        │
        ▼
Challenge completed
        │
        ▼
Session becomes MFA_VERIFIED
9. TokenService

TokenService manages token issuance and refresh lifecycle.

The most important distinction is:

Access token
        ≠
persisted Auth entity

Refresh token
        =
persisted lifecycle entity

The class diagram therefore intentionally contains:

TokenPair

as a value/application result:

TokenPair
├── accessToken
└── refreshToken

but does not contain a persisted AccessCredential.

This correction was necessary because the approved Auth data model does not define an access-token persistence entity.

9.1 Refresh tokens

Refresh tokens have explicit server-side lifecycle management.

The relationship is:

Session
   │
   └──── 0..*
          RefreshToken

This supports token rotation and revocation.

The conceptual lifecycle is:

Session
   │
   ▼
Issue refresh token
   │
   ▼
Refresh request
   │
   ▼
Validate stored verifier
   │
   ▼
Rotate refresh token
   │
   ├── old token → no longer active
   │
   └── new token → active

The diagram uses:

RefreshTokenRepository

for persistence operations and keeps token lifecycle rules inside TokenService.

10. DeviceService

A user can have multiple devices.

UserAccount
      │
      ├── Phone
      │
      ├── Laptop
      │
      └── Tablet

Therefore the Auth Service owns device lifecycle independently from sessions.

DeviceService is responsible for operations such as:

Register device
Revoke device
Discover active device keys

The diagram explicitly separates:

Device

from:

DevicePublicKey

because a device's lifecycle and its cryptographic key lifecycle are not identical.

11. DevicePublicKey

A device can have public cryptographic identity material.

The relationship is:

Device
   │
   └──── 0..*
          DevicePublicKey

Multiple records support lifecycle events such as:

key replacement;
key rotation;
revocation;
historical retention.

The important rule remains:

Auth owns registration and discovery
of public cryptographic identity material

Auth does not own private keys

Private keys remain on the client device.

12. Repository Interfaces

The repositories represent persistence boundaries:

UserRepository
DeviceRepository
DevicePublicKeyRepository
SessionRepository
RefreshTokenRepository
MfaConfigurationRepository
MfaChallengeRepository

Application services depend on repository abstractions:

Application Service
        │
        ▼
Repository Interface
        │
        ▼
Concrete PostgreSQL implementation

This allows the PostgreSQL implementation to remain infrastructure-specific.

The class diagram intentionally does not model:

SQL statements;
PostgreSQL connection pooling;
transaction implementation;
ORM details.

Those are implementation details.

13. CredentialValidationService

This service exists for Auth's internal validation responsibilities.

Conceptually:

Internal service request
        │
        │ gRPC + mTLS
        ▼
AuthGrpcHandler
        │
        ▼
CredentialValidationService
        │
        ├── SessionRepository
        └── DeviceRepository
        │
        ▼
CredentialValidationResult

The result provides a validated authentication context rather than exposing Auth's internal persistence model.

For example:

valid
userId
deviceId
sessionId
authenticationLevel
14. Device Public-Key Discovery

The other important internal capability is:

Device discovery
        +
public-key discovery

Conceptually:

Messaging / Client-related flow
        │
        │ gRPC + mTLS
        ▼
AuthGrpcHandler
        │
        ▼
DeviceService
        │
        ├── DeviceRepository
        └── DevicePublicKeyRepository
        │
        ▼
DeviceDiscoveryResult

Auth remains the authority for registered devices and their public keys.

Other services receive the information they need through the Auth service boundary rather than querying Auth's database.

15. Audit Publication

Auth produces application/security-relevant audit events.

The dependency is:

Application Service
        │
        ▼
AuthAuditPublisher
        │
        ▼
AuditServiceClient
        │
        │ gRPC + mTLS
        ▼
Audit Service

Examples can include:

Authentication success
Authentication failure
MFA verification success/failure
Device registration
Device revocation
Session revocation
Refresh token security event

The Auth Service does not write directly into ClickHouse.

The ownership boundary remains:

Auth
   │ produces audit event
   ▼
Audit Service
   │ owns
   ▼
ClickHouse
16. Main Authentication Flow Through the Classes

The most important class interaction can be summarized as:

Client
 │
 ▼
AuthRequestHandler
 │
 ▼
AuthenticationService
 │
 ├── UserRepository
 │
 ├── PasswordHasher
 │
 └── DeviceService
          │
          ▼
      SessionService
          │
          ▼
      Session
          │
          ├── MFA required
          │       │
          │       ▼
          │   MfaService
          │       │
          │       ▼
          │   MfaChallenge
          │
          └── MFA not required
                  │
                  ▼
              TokenService
                  │
                  ▼
               TokenPair
17. Main Architectural Principles Captured by the Diagram

The Auth class diagram deliberately enforces several boundaries.

No Auth database access from other services
Other Service
      │
      │ gRPC + mTLS
      ▼
Auth Service
      │
      ▼
Auth PostgreSQL

Never:

Messaging ───────► Auth PostgreSQL
Credentials are separate from devices
User credentials
       ≠
Registered device
       ≠
Device public key
MFA configuration is separate from MFA authentication attempts
MfaConfiguration
       ≠
MfaChallenge
Session is separate from tokens
Session
   =
server-side authentication lifecycle

Access token
   =
issued authentication artifact

Refresh token
   =
persisted renewable credential lifecycle
Private keys never belong to Auth
Client Device
   └── Private Key

Auth Service
   └── Public Key only
Final implementation view

The Auth Service can therefore be understood as:

                     Auth Service

 ┌─────────────────────────────────────────────┐
 │              Transport Layer                │
 │ AuthRequestHandler / AuthGrpcHandler        │
 └──────────────────────┬──────────────────────┘
                        │
 ┌──────────────────────▼──────────────────────┐
 │             Application Layer               │
 │                                             │
 │ RegistrationService                         │
 │ AuthenticationService                       │
 │ MfaService                                  │
 │ SessionService                              │
 │ TokenService                                │
 │ DeviceService                               │
 │ CredentialValidationService                 │
 └───────────────┬───────────────────┬─────────┘
                 │                   │
 ┌───────────────▼─────────┐  ┌──────▼──────────┐
 │ Security Components     │  │ Persistence      │
 │                         │  │                  │
 │ Argon2id                │  │ PostgreSQL       │
 │ TOTP                    │  │ Repositories     │
 │ MFA Secret Protection   │  │                  │
 └─────────────────────────┘  └─────────────────┘
                 │
                 ▼
          Audit Publisher
                 │
                 ▼
          Audit Service