1. The synchronization flow has three deliberate phases


Phase 1 — Reconcile PendingOperation

The client first checks locally durable operations whose final outcome may be unknown.

For example:

Message submitted
      ↓
Server accepts it
      ↓
Network connection fails
      ↓
Client never receives response

The client must not simply send a new message.

Instead:

PendingOperation
      ↓
Reconnect
      ↓
Reuse stable idempotency identity
      ↓
Messaging checks durable submission state
      ↓
Already accepted?
      │
      ├── Yes → recover existing result
      │
      └── No → operation-specific retry may proceed

This is why PendingOperation is locally durable rather than merely an in-memory retry queue.

2. Phase 2 — Incremental conversation synchronization

The client maintains local synchronization progress.

Conceptually:

Client SQLite

Conversation A → last_synced_sequence = 85
Conversation B → last_synced_sequence = 41

After reconnection:

Conversation A

Client:  1 ... 85
Server:  1 ... 100

Synchronize:
86 → 87 → ... → 100

The client does not download the entire conversation again.

This follows the approved sync_state_by_device model.

3. Local persistence happens before the synchronization cursor advances

This ordering is important:

Receive encrypted item
        ↓
Persist encrypted item in SQLite
        ↓
SQLite durability succeeds
        ↓
Advance local cursor
        ↓
Confirm synchronization progress

We must avoid:

Receive item
    ↓
Advance cursor
    ↓
Crash before persistence

because after restart the client could claim synchronization progress for data it never durably stored.

Therefore:

The synchronization cursor represents durably persisted local progress, not merely data that has passed through memory.

4. Why both local and server-side synchronization state exist

The client has its local representation:

Client SQLite

SyncState

Messaging maintains:

ScyllaDB

sync_state_by_device

These have different purposes.

Local state

Supports:

offline operation;
crash recovery;
determining locally persisted progress.
Server-side state

Supports:

backend knowledge of device synchronization progress;
incremental synchronization behavior;
durable device-level reconciliation.

The two are reconciled rather than assuming process-local memory is authoritative.

5. Pending delivery is device-specific

Suppose Bob has:

Bob
├── Phone
├── Laptop
└── Tablet

A reconnecting Laptop must not infer its state from Bob's Phone.

The backend can independently have:

Phone   → DELIVERED
Laptop  → PENDING
Tablet  → PENDING

Therefore synchronization and delivery retrieval are scoped to:

device_id

rather than only:

user_id

6. DELIVERED still means durable local persistence

The synchronization flow preserves the same semantics established in Sequence Diagram 3:

Backend sends ciphertext
        ≠
DELIVERED

Instead:

Receive ciphertext
        ↓
Persist encrypted representation locally
        ↓
Durability confirmed
        ↓
Acknowledge delivery
        ↓
Messaging:
PENDING → DELIVERED

This prevents the backend from incorrectly reporting delivery merely because a network connection was temporarily available.

7. Device revocation is checked before normal synchronization

The reconnecting device verifies its authorization state.

If:

AUTHORIZED

it may continue synchronization.

If:

REVOKED

the normal synchronization flow stops.

This supports the approved rule:

A revoked device receives no future messages.

However, revocation does not magically remove cryptographic knowledge already present on the endpoint.

Therefore:

Previously received encrypted messages
        +
Previously held cryptographic state

remain subject to the endpoint's existing cryptographic capabilities.

Revocation protects future communication targeting, not historical plaintext that the endpoint may already have decrypted.
8. Why the client returns safely to OFFLINE

A failure can happen during:

CONNECTING
AUTHENTICATING
SYNCING
ONLINE

The system must not rely on a special "graceful disconnect" sequence.

Instead:

Connection failure
       ↓
Stop transient network activity
       ↓
Durable state remains intact
       ↓
Return to OFFLINE
       ↓
Later reconnect
       ↓
Reconcile durable state again

This is particularly important for SecureCloud's intended operating conditions, including unreliable or intermittent connectivity.