What this sequence establishes
1. Authentication comes first

The device is registered within an authenticated account context.

User authentication
        ↓
Authenticated session
        ↓
Device registration
        ↓
Device authorized
        ↓
Public cryptographic material available for discovery

The device registration request is therefore not an unauthenticated mechanism for inserting arbitrary public keys into the cryptographic directory.

2. The cryptographic identity is device-specific

The approved client model is:

User
 │
 ├── Device A
 │      └── CryptoIdentity A
 │
 ├── Device B
 │      └── CryptoIdentity B
 │
 └── Device C
        └── CryptoIdentity C

A user's devices do not share one private device identity.

Each device is an independent cryptographic endpoint.

3. Private keys never cross the client boundary

The most important security boundary in this diagram is:

SecureCloud Client
────────────────────────────────
CryptoManager
        │
        ▼
SecureKeyStore
        │
        ▼
Private cryptographic material

              NEVER

              ▼

Gateway
              │
              ▼
Auth

The registration request contains only information that the backend is permitted to store, such as:

device registration information;
the public cryptographic identity material required for discovery;
other approved public cryptographic material required by the selected protocol.

The exact public key/prekey structures remain governed by the vetted Signal Protocol-family implementation selected under ADR-008.

4. Auth owns the authoritative device directory

The ownership model is:

Client
│
├── owns private device cryptographic state
│
└── stores local representation of device state


Auth
│
├── authoritative device identifier
├── device authorization/revocation state
└── public cryptographic directory

This allows another client to later perform identity and device discovery through Auth without ever accessing private key material.

5. Registration does not establish messaging sessions yet

This sequence is intentionally limited to:

Create/load CryptoIdentity
        ↓
Secure private material locally
        ↓
Register device
        ↓
Publish public cryptographic material

It does not establish a cryptographic session with every other SecureCloud user.

For example:

Alice registers Device A
        │
        ▼
Auth stores Alice Device A public material

Bob wants to communicate with Alice
        │
        ▼
Bob discovers Alice's authorized devices
        │
        ▼
Bob obtains required public material
        │
        ▼
Bob's client establishes the required
cryptographic session state locally

That discovery and session establishment naturally appears as part of the Send Encrypted Message sequence diagram, where it is actually required.

6. Important revocation implication

After this flow, Auth can later change:

Device authorization state

AUTHORIZED
     ↓
REVOKED