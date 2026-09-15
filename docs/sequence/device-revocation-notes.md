1. The authoritative revocation decision belongs to Auth

This follows our approved ownership model:

Auth Service
    │
    ├── Device registration
    ├── Device authorization
    ├── Device revocation
    ├── Authentication state
    └── Public cryptographic device directory

Therefore, neither Gateway nor Messaging decides independently whether a device is revoked.

The authoritative operation is:

RevokeDevice(device_id)
        │
        ▼
Auth Service
        │
        ▼
Durably change device state
        │
        ▼
REVOKED

2. Revocation must be durable before its effects propagate

The critical ordering is:

1. Authorize revocation request
        ↓
2. Mark device REVOKED durably
        ↓
3. Invalidate/revoke active authentication state
        ↓
4. Update device public-key directory state
        ↓
5. Publish significant application event
        ↓
6. Propagate revocation consequences

We should not do this:

Send "device revoked" notification
        ↓
Later update database

because a failure could leave different parts of the system with contradictory views.

The authoritative durable state must change first.

3. What happens to the device's authentication

Once revoked:

Old device
    │
    ▼
Attempts authenticated operation
    │
    ▼
Auth validates current device state
    │
    ▼
REVOKED
    │
    ▼
Operation rejected

This applies even if the revoked device still has:

locally stored tokens;
an existing TLS connection;
cached device metadata;
an old public/private cryptographic identity.

Those local artifacts do not override the server-authoritative device authorization state.

4. What Messaging needs to know

Messaging owns device-level delivery targeting.

Therefore it must eventually enforce:

Authorized recipient devices
        ↓
Create future delivery targets

After revocation:

Authorized recipient devices
        ↓
Exclude revoked device
        ↓
Create future delivery targets

Conceptually:

Before:

Alice
 ├── Phone     ✓
 ├── Laptop    ✓
 └── Tablet    ✓


After Laptop revocation:

Alice
 ├── Phone     ✓
 ├── Laptop    ✗ REVOKED
 └── Tablet    ✓

A newly accepted message must therefore not create:

pending_deliveries_by_device

device_id = revoked_laptop
5. Existing delivery records are historical state

We should not rewrite Messaging history when a device is revoked.

For example:

Message M1

Phone   → DELIVERED
Laptop  → DELIVERED
Tablet  → PENDING

If Laptop is later revoked, the historical record:

Laptop → DELIVERED

does not become false.

Likewise, deleting all historical references to the device would destroy meaningful state.

Therefore:

Revocation changes future eligibility; it does not rewrite historical communication facts.
6. The revoked device cannot synchronize future data

A later reconnect behaves as:

Revoked device
       │
       ▼
Connect
       │
       ▼
Authenticate / validate device
       │
       ▼
REVOKED
       │
       ▼
Reject normal synchronization

This is important because simply removing the device from future delivery creation is insufficient.

Otherwise, a revoked device could potentially reconnect and retrieve already-created but not yet delivered server-side data.

Therefore revocation must affect both:

future delivery target creation, and
authorization to access synchronization/delivery operations.

