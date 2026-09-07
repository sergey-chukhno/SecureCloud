# 3. Messaging Service Data Model — ScyllaDB

## 3.1 Purpose and Ownership

The Messaging Service owns the persistence required for:

* direct conversations;
* group conversations;
* conversation membership;
* encrypted message envelopes;
* per-device delivery state;
* read receipts;
* synchronization progress;
* idempotent message submission.

The Messaging Service does not own:

* human identity;
* passwords;
* MFA;
* device credentials;
* private cryptographic keys;
* file binary objects;
* audit-event persistence.

Messaging references users and devices using opaque identifiers owned by Auth:

```text
UserId
DeviceId
```

The Messaging Service owns:

```text
ConversationId
MessageId
```

---

## 3.2 Why the Messaging Model Is Denormalized

ScyllaDB is not used like PostgreSQL.

The Messaging data model is designed around concrete query patterns rather than normalized entity relationships.

The primary MVP query patterns are:

1. Get a conversation by `ConversationId`.
2. Find an existing direct conversation between two users.
3. List conversations for a user.
4. Get conversation membership.
5. Submit a message to a conversation.
6. Read messages in canonical conversation order.
7. Retrieve pending messages for a specific device.
8. Record and retrieve delivery state per recipient device.
9. Record and retrieve read receipts.
10. Synchronize an individual device.
11. Guarantee idempotent message submission.

The schema therefore contains intentionally denormalized tables.

There are no joins between Messaging tables or between Messaging and other services.

---

# 3.3 Canonical Messaging Concepts

The canonical domain model is:

```text
User
 │
 └── Device

User
 │
 └── Conversation Participant
         │
         ▼
    Conversation
         │
         ├── Direct
         │
         └── Group
                 │
                 └── Membership

Conversation
       │
       └── Message
              │
              └── Delivery State
                      │
                      └── Recipient Device
```

A conversation is the canonical messaging container.

Two conversation types exist:

```text
DIRECT
GROUP
```

Messages belong to conversations.

---

# 3.4 Conversation Metadata

## Table: `conversations_by_id`

Purpose:

Retrieve canonical conversation metadata by `ConversationId`.

```text
conversations_by_id
├── conversation_id
├── conversation_type
├── created_at
├── created_by_user_id
└── metadata_version
```

### Primary key

```text
PRIMARY KEY (conversation_id)
```

### Fields

| Field                | Purpose                   |
| -------------------- | ------------------------- |
| `conversation_id`    | Canonical ConversationId  |
| `conversation_type`  | `DIRECT` or `GROUP`       |
| `created_at`         | Server creation time      |
| `created_by_user_id` | Opaque UserId of creator  |
| `metadata_version`   | Explicit metadata version |

`conversations_by_id` contains only common conversation metadata.

Participants are stored separately.

---

# 3.5 Conversation Lifecycle

Direct and group conversations have different lifecycle semantics.

## Direct conversations

A direct conversation does not have an `ACTIVE` or `CLOSED` lifecycle state.

A direct conversation:

```text
exists
```

or:

```text
is created when required
```

for the canonical pair of users.

Deleting or hiding a direct conversation from a client does not close or destroy the server-side conversation.

Such behavior is a client-side visibility or local storage concern.

---

## Group conversations

Groups have an explicit lifecycle.

For the MVP:

```text
ACTIVE
CLOSED
```

### `ACTIVE`

The group:

* accepts new messages;
* permits membership changes according to authorization rules;
* participates in normal synchronization and delivery.

### `CLOSED`

The group:

* does not accept new messages;
* has frozen membership;
* retains historical messages and membership records according to retention and access rules.

A group is not closed merely because its original creator decides to close it.

The creator is not a permanent privileged identity.

Instead, closing authorization is based on current group membership and role.

For the MVP:

```text
role = ADMIN
```

may close an active group.

---

# 3.6 Direct Conversation Identity

A direct conversation must be unique for its two participating users.

To enforce lookup and reuse without distributed joins, Messaging stores:

## Table: `direct_conversation_by_users`

```text
direct_conversation_by_users
├── user_a_id
├── user_b_id
└── conversation_id
```

The two UserIds are stored in canonical order.

Conceptually:

```text
smaller(UserId) → user_a_id
larger(UserId)  → user_b_id
```

Therefore:

```text
Alice + Bob
```

and:

```text
Bob + Alice
```

resolve to the same canonical pair.

### Primary key

```text
PRIMARY KEY ((user_a_id, user_b_id))
```

If the record exists, the existing `ConversationId` is reused.

If it does not exist, Messaging creates the direct conversation and participant records.

---

# 3.7 Group Conversation Metadata

Group-specific metadata is stored separately.

## Table: `group_metadata_by_conversation`

```text
group_metadata_by_conversation
├── conversation_id
├── group_name
├── group_status
├── created_by_user_id
├── created_at
└── metadata_version
```

### Primary key

```text
PRIMARY KEY (conversation_id)
```

### `group_status`

```text
ACTIVE
CLOSED
```

For the MVP, `ConversationId` is also the canonical group identifier.

A separate `GroupId` is not introduced.

---

# 3.8 Conversation Membership

Membership is required for:

* conversation authorization;
* group participation;
* recipient determination;
* synchronization;
* membership lifecycle.

The canonical membership query is:

```text
Get all participants of ConversationId
```

Therefore:

## Table: `conversation_members_by_conversation`

```text
conversation_members_by_conversation
├── conversation_id
├── user_id
├── membership_status
├── role
├── joined_at
├── left_at
└── membership_version
```

### Primary key

```text
PRIMARY KEY (
    conversation_id,
    user_id
)
```

### Membership status

```text
ACTIVE
LEFT
REMOVED
```

### Roles

The MVP uses:

```text
MEMBER
ADMIN
```

A direct conversation has two `MEMBER` participants.

A group may contain one or more `ADMIN` participants.

Historical membership records are retained after leaving or removal.

---

# 3.9 Conversations by User

The client must efficiently retrieve:

```text
all conversations for UserId
```

Therefore Messaging stores a denormalized query table.

## Table: `conversations_by_user`

```text
conversations_by_user
├── user_id
├── conversation_id
├── conversation_type
├── membership_status
├── last_activity_at
└── unread_state_version
```

### Primary key

```text
PRIMARY KEY (
    user_id,
    last_activity_at,
    conversation_id
)
```

The conceptual query is:

```text
UserId
   │
   ▼
Recent conversations
```

`last_activity_at` supports recent-conversation ordering.

Queries must be paginated.

---

# 3.10 Message Priority

SecureCloud supports three message priorities:

```text
NORMAL
URGENT
EMERGENCY
```

Priority is delivery and notification metadata.

It does not change the fundamental end-to-end confidentiality model.

The backend continues to process encrypted envelopes rather than message plaintext.

## `NORMAL`

Ordinary communication.

## `URGENT`

Communication requiring elevated delivery and notification treatment.

`URGENT` does not bypass:

* conversation membership;
* authorization;
* normal cryptographic protections.

## `EMERGENCY`

An emergency message is routed to the authorized Emergency Unit conversation or group.

The Emergency Unit remains a normal user/group structure with a special operational role.

No separate Emergency Messaging Service is introduced.

---

# 3.11 Canonical Message Record

Messages are immutable after durable acceptance.

## Table: `messages_by_conversation`

```text
messages_by_conversation
├── conversation_id
├── message_bucket
├── message_sequence
├── message_id
├── sender_user_id
├── sender_device_id
├── message_priority
├── accepted_at
├── ciphertext_envelope
├── envelope_version
└── file_reference_ids
```

---

# 3.12 Message Partitioning Strategy

A long-lived or highly active conversation must not accumulate an unlimited number of messages in one ScyllaDB partition.

Therefore the logical conversation history is divided into bounded physical storage partitions.

The MVP uses:

> **Monthly UTC time buckets.**

```text
message_bucket = YYYYMM
```

Example:

```text
ConversationId = C123
message_bucket = 202609
```

means:

> Messages accepted for conversation `C123` during September 2026.

The partition key is:

```text
(conversation_id, message_bucket)
```

Conceptually:

```text
Logical Conversation C123
│
├── Physical Partition: C123 + 202609
│
├── Physical Partition: C123 + 202610
│
└── Physical Partition: C123 + 202611
```

Time bucketing does not create a new logical conversation.

The canonical conversation remains:

```text
ConversationId = C123
```

The bucket exists only to bound physical ScyllaDB partition growth.

---

# 3.13 Message Ordering and Clustering

Within each ScyllaDB partition, messages are stored using clustering columns.

The primary key is:

```text
PRIMARY KEY (
    (conversation_id, message_bucket),
    message_sequence,
    message_id
)
```

The clustering order is:

```text
message_sequence ASC
```

The partition key determines:

> Which physical partition contains the message.

The clustering order determines:

> How messages are ordered inside that partition.

Example:

```text
Conversation C123 + 202609

message_sequence = 1001
message_sequence = 1002
message_sequence = 1003
message_sequence = 1004
```

The canonical message order is therefore sequence order.

Client timestamps never determine canonical conversation ordering.

---

# 3.14 Canonical Message Sequence

Each message receives a monotonically increasing sequence within its conversation.

Example:

```text
Conversation A

1
2
3
4
```

Another conversation independently has:

```text
Conversation B

1
2
3
```

There is:

```text
NO GLOBAL MESSAGE SEQUENCE
```

The sequence scope is:

```text
ConversationId
```

---

# 3.15 Conversation-Affine Sequence Allocation

Canonical message ordering is assigned through a **conversation-affine single logical writer** implemented inside the Messaging Service.

The Messaging Service deterministically routes message acceptance for the same `ConversationId` to the same active logical owner.

Conceptually:

```text
hash(ConversationId)
        │
        ▼
Messaging Service logical partition
        │
        ▼
Active conversation owner
```

Example:

```text
Conversation A → Messaging Instance 1
Conversation B → Messaging Instance 3
Conversation C → Messaging Instance 2
```

The logical owner serializes acceptance operations for its assigned conversation only.

Conceptually:

```text
Conversation A
       │
       ▼
Single logical acceptance stream
       │
       ├── assign sequence 101
       ├── assign sequence 102
       └── assign sequence 103
```

Other conversations continue processing concurrently.

Therefore:

```text
Conversation A ─┐
Conversation B ─┼── processed concurrently
Conversation C ─┘
```

while only operations belonging to the same conversation are serialized.

---

## 3.16 Durable Sequence State and Failover

Conversation ownership is logical and recoverable.

It is not permanently bound to a process.

Sequence state is durably persisted.

Conceptually:

```text
ConversationId
       │
       ▼
Durable last assigned sequence
```

If a Messaging Service instance fails:

```text
Conversation A
      │
      ▼
Owner instance fails
      │
      ▼
Conversation ownership recovered
      │
      ▼
New active owner
      │
      ▼
Read durable sequence state
      │
      ▼
Continue sequence allocation
```

Example:

```text
Last durable sequence = 1000

Next accepted message = 1001
```

No dedicated infrastructure component is introduced for sequence generation.

Conversation ownership and sequence allocation remain internal Messaging Service responsibilities.

---

# 3.17 Hot Conversation Trade-Off

The design avoids a global bottleneck.

However, a single extremely active conversation remains serialized at message acceptance because strict canonical ordering is required.

For the SecureCloud MVP, this is an explicit trade-off:

```text
Correct per-conversation ordering
+
Predictable behavior
+
Durability
```

are prioritized over unlimited parallel writes inside one individual conversation.

Different conversations remain independently scalable.

---

# 3.18 Message Envelope

The Messaging Service stores an encrypted envelope.

Conceptually:

```text
ciphertext_envelope
```

contains cryptographically protected application content.

The Messaging Service does not decrypt message plaintext.

The envelope may contain encrypted components required for multi-device delivery.

Conceptually:

```text
Message Envelope
├── ciphertext
│
├── recipient device envelopes
│      ├── Device A
│      ├── Device B
│      └── Device C
│
└── cryptographic metadata
```

The exact cryptographic construction is governed by ADR-008.

The data model treats the envelope as opaque encrypted data.

---

# 3.19 Sender and Recipient Privacy

Messaging has a hard confidentiality objective to minimize knowledge of sender and recipient identity.

The database nevertheless requires opaque routing information.

Therefore:

```text
sender_user_id
sender_device_id
recipient_user_id
recipient_device_id
```

are opaque identifiers.

Messaging must not store:

* names;
* email addresses;
* phone numbers;
* contact labels;
* other human-readable identity data.

---

# 3.20 File References

Messages may reference files owned by the Files Service.

`file_reference_ids` contains opaque `FileId` references.

The Messaging Service does not store file binary content.

Conceptually:

```text
Message
   │
   │ FileId
   ▼
Files Service
```

No distributed foreign key exists.

---

# 3.21 Per-Device Delivery State

Messages are delivered to devices rather than abstract users.

A user may have:

```text
Phone
Laptop
Tablet
```

Each eligible device receives independent delivery tracking.

The canonical delivery query is:

```text
What messages are pending for DeviceId?
```

Therefore:

## Table: `pending_deliveries_by_device`

```text
pending_deliveries_by_device
├── device_id
├── delivery_bucket
├── accepted_at
├── message_id
├── conversation_id
├── message_sequence
├── message_priority
└── delivery_state
```

### Partition key

```text
(device_id, delivery_bucket)
```

The MVP uses:

```text
delivery_bucket = YYYYMM
```

### Primary key

```text
PRIMARY KEY (
    (device_id, delivery_bucket),
    accepted_at,
    message_id
)
```

---

# 3.22 Delivery Acknowledgement

Delivery acknowledgement is an application-level protocol operation.

A device does not acknowledge a message merely because bytes arrived over the network.

The required sequence is:

```text
Messaging Service
       │
       │ encrypted message envelope
       ▼
Recipient Device
       │
       ▼
Receive message
       │
       ▼
Persist locally
       │
       ├── Failure
       │      │
       │      └── No acknowledgement
       │
       └── Success
              │
              ▼
       Send DELIVERY acknowledgement
              │
              ▼
       Messaging Service
```

The acknowledgement contains at minimum:

```text
DeviceId
MessageId
```

Messaging transitions the device delivery state:

```text
PENDING → DELIVERED
```

only after receiving this acknowledgement.

Therefore network receipt alone never constitutes durable delivery.

---

# 3.23 Delivery States

The canonical device-level lifecycle is:

```text
PENDING
   │
   ▼
DELIVERED
   │
   ▼
READ
```

### `PENDING`

The message was durably accepted but the recipient device has not confirmed local persistence.

### `DELIVERED`

The recipient device confirmed that the message was durably persisted locally.

### `READ`

The recipient device reported that the message was read according to the client read-receipt policy.

---

# 3.24 Delivery History

`pending_deliveries_by_device` is optimized for active delivery.

It is not the only historical delivery representation.

Therefore:

## Table: `delivery_state_by_message`

```text
delivery_state_by_message
├── message_id
├── recipient_device_id
├── delivery_state
├── delivered_at
└── read_at
```

### Primary key

```text
PRIMARY KEY (
    message_id,
    recipient_device_id
)
```

This provides delivery and read state for all recipient devices.

---

# 3.25 Read Receipts

Read receipts are recorded per device.

Example:

```text
Bob
├── Phone  → READ
└── Laptop → DELIVERED
```

For the MVP, the user-level rule is:

> A recipient user is considered to have read a message when at least one active recipient device reports `READ`.

Device-level delivery and read state remain preserved.

---

# 3.26 Offline Delivery

Offline delivery does not require a separate authoritative queueing technology.

The ScyllaDB delivery model is the durable source of pending delivery work.

Conceptually:

```text
Message accepted
       │
       ▼
Create PENDING delivery
for each eligible recipient device
       │
       ▼
Device offline
       │
       ▼
Delivery remains PENDING
       │
       ▼
Device reconnects
       │
       ▼
Messaging synchronization/delivery
       │
       ▼
Message delivered
```

In-memory workers may optimize active delivery.

They are never authoritative for durability.

---

# 3.27 Synchronization State

Each device maintains independent synchronization progress.

## Table: `sync_state_by_device`

```text
sync_state_by_device
├── device_id
├── conversation_id
├── last_synced_sequence
├── last_sync_at
└── sync_version
```

### Primary key

```text
PRIMARY KEY (
    device_id,
    conversation_id
)
```

Example:

```text
User
├── Phone
│     └── last sequence = 100
│
└── Laptop
      └── last sequence = 85
```

Each device synchronizes independently.

---

# 3.28 Initial Synchronization

Initial synchronization occurs when a device has no local synchronization state.

Examples include:

* newly registered device;
* fresh application installation;
* local database reset.

Synchronization is:

```text
paginated
bounded
resumable
```

The device does not request the entire account history in one unbounded operation.

The client persists received data locally before advancing its synchronization state.

---

# 3.29 Incremental Synchronization

Incremental synchronization occurs when the device already has synchronization state.

Example:

```text
Device cursor = sequence 100
        │
        ▼
Messaging Service
        │
        ▼
Return messages after sequence 100
```

The synchronization cursor advances only after successful local persistence.

---

# 3.30 Idempotent Message Submission

A unique `MessageId` and an idempotency key represent different concepts.

```text
MessageId
    │
    └── Identity of the message

IdempotencyKey
    │
    └── Identity of the message-submission operation
```

Network failures may leave the client uncertain whether a request was accepted.

Example:

```text
Client
  │
  │ Submit message
  ▼
Messaging Service
  │
  │ Message accepted
  ▼
Response lost
```

The client must be able to retry without creating another message.

The client therefore generates one `IdempotencyKey` for one logical submission operation and reuses it for every retry.

---

## Table: `message_submission_by_idempotency_key`

```text
message_submission_by_idempotency_key
├── sender_device_id
├── idempotency_key
├── message_id
├── submission_status
└── created_at
```

### Primary key

```text
PRIMARY KEY (
    sender_device_id,
    idempotency_key
)
```

Example:

```text
Attempt 1

DeviceId = AlicePhone
IdempotencyKey = X
```

The service accepts:

```text
MessageId = M100
```

If the response is lost:

```text
Attempt 2

DeviceId = AlicePhone
IdempotencyKey = X
```

Messaging finds the existing submission result and returns:

```text
MessageId = M100
```

No duplicate message is created.

---

# 3.31 Emergency Routing

Emergency routing uses the same underlying Messaging model.

An emergency message has:

```text
message_priority = EMERGENCY
```

and is routed to the configured Emergency Unit conversation or group.

The Emergency Unit is represented through:

```text
Conversation
+
Membership
+
Special operational role
```

No separate Emergency Messaging microservice exists.

Where emergency location sharing is authorized, location is handled only in the approved emergency context.

Normal and urgent messaging does not inherit this privilege.

---

# 3.32 Messaging Table Summary

| Table                                   | Primary query                         |
| --------------------------------------- | ------------------------------------- |
| `conversations_by_id`                   | Get conversation metadata             |
| `direct_conversation_by_users`          | Find direct conversation              |
| `group_metadata_by_conversation`        | Get group metadata and status         |
| `conversation_members_by_conversation`  | List conversation participants        |
| `conversations_by_user`                 | List user's conversations             |
| `messages_by_conversation`              | Read messages in canonical order      |
| `pending_deliveries_by_device`          | Retrieve pending device messages      |
| `delivery_state_by_message`             | Retrieve delivery/read status         |
| `sync_state_by_device`                  | Retrieve device synchronization state |
| `message_submission_by_idempotency_key` | Deduplicate message submission        |

---

# 3.33 Messaging Data Invariants

The Messaging persistence model must preserve the following invariants:

1. Messaging stores only opaque user and device identifiers.
2. Messaging never stores human-readable identity information.
3. Messaging does not store E2E private keys.
4. Message content is persisted as encrypted ciphertext envelopes.
5. Messages are immutable after durable acceptance.
6. Every message belongs to exactly one conversation.
7. Conversations are either `DIRECT` or `GROUP`.
8. Direct conversations do not have an `ACTIVE/CLOSED` lifecycle.
9. A direct conversation is uniquely identified by its canonical pair of users.
10. Group conversations have `ACTIVE` and `CLOSED` states.
11. Only currently authorized group administrators may close a group.
12. Closed groups do not accept new messages.
13. Membership is explicit and versioned.
14. Historical membership records are retained.
15. Message order is determined by a server-assigned per-conversation sequence.
16. There is no global message sequence generator.
17. Sequence allocation is performed by a conversation-affine logical owner inside Messaging Service.
18. Different conversations may be processed concurrently.
19. Conversation ownership is recoverable after Messaging Service instance failure.
20. Sequence state is durably persisted.
21. Client timestamps do not determine canonical message order.
22. Physical ScyllaDB partitions are bounded using monthly UTC buckets.
23. A time bucket is a physical storage mechanism and does not create a new logical conversation.
24. Multi-device delivery is device-specific.
25. Every eligible recipient device has independent delivery state.
26. Delivery acknowledgement occurs only after successful local device persistence.
27. Network receipt alone does not constitute `DELIVERED`.
28. Offline delivery state is durable.
29. No in-memory queue is authoritative for message durability.
30. Read receipts are recorded per device.
31. A recipient user is considered to have read a message when at least one active recipient device reports `READ`.
32. Each device maintains independent synchronization progress.
33. Initial synchronization is bounded, paginated, and resumable.
34. Incremental synchronization is cursor-based.
35. Synchronization cursors advance only after successful local persistence.
36. `MessageId` identifies a message.
37. `IdempotencyKey` identifies a logical submission operation.
38. Message submission is idempotent per sender device and idempotency key.
39. `URGENT` does not bypass normal conversation authorization.
40. `EMERGENCY` routes through an authorized Emergency Unit conversation or group.
41. The Emergency Unit is a normal user/group structure with a special operational role.
42. File attachments are represented through opaque `FileId` references.
43. Messaging does not store file binary objects.
