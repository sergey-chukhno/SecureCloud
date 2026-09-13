Messaging Service MPD — Explanatory Notes
1. Purpose

The Messaging Service uses ScyllaDB as a query-driven, denormalized physical data model.

Unlike a relational database, the physical tables are not designed around normalization and foreign-key relationships. Each table exists primarily to support one or more concrete access patterns.

The Messaging MPD contains twelve tables:

Conversation and membership
├── conversations_by_id
├── direct_conversation_by_users
├── group_metadata_by_conversation
├── conversation_members_by_conversation
└── conversations_by_user
Message ordering and storage
├── conversation_sequence_state
└── messages_by_conversation
Delivery and synchronization
├── pending_deliveries_by_device
├── delivery_state_by_message
└── sync_state_by_device
Reliability
├── message_submission_by_idempotency_key
└── messaging_outbox_events

The same logical information may appear in more than one physical table. This is intentional denormalization for efficient ScyllaDB reads.

2. conversations_by_id
Purpose

Stores the canonical common metadata of a conversation.

Primary access pattern
Given conversation_id
→ retrieve conversation metadata
Key
Partition key:
conversation_id
Stored information
conversation_id
conversation_type
created_at
created_by_user_id
metadata_version
Why this table exists

This is the canonical starting point when the Messaging Service needs to determine what conversation is being addressed.

For example:

conversation_id
      ↓
conversation_type = GROUP

The service can then retrieve group-specific metadata separately if necessary.

Participants are deliberately not embedded here because membership has its own lifecycle and access patterns.

3. direct_conversation_by_users
Purpose

Find the direct conversation between two users.

Primary access pattern
Given User A and User B
→ find their direct conversation
Key
Partition key:
(user_a_id, user_b_id)

The user IDs are stored in canonical order.

Conceptually:

min(UserA, UserB) → user_a_id
max(UserA, UserB) → user_b_id
Why this matters

Without canonical ordering:

Alice + Bob

and:

Bob + Alice

could produce two different lookups.

Canonical ordering guarantees one deterministic lookup key.

Main use

Before creating a direct conversation:

User A requests direct conversation with User B
        ↓
Lookup direct_conversation_by_users
        ↓
Exists?
├── Yes → return existing conversation_id
└── No  → create conversation

This supports the invariant that the same pair of users does not accidentally create multiple direct conversations.

4. group_metadata_by_conversation
Purpose

Stores metadata specific to group conversations.

Primary access pattern
Given group conversation_id
→ retrieve group metadata
Key
Partition key:
conversation_id
Stored information
group_name
group_status
created_by_user_id
created_at
metadata_version
group_status

The approved group lifecycle is:

ACTIVE
CLOSED
ACTIVE

The group accepts new conversation items.

CLOSED

The group remains historically available, but new conversation items are not accepted.

This is particularly useful for temporary or mission-specific groups.

Why this is separate from conversations_by_id

Only groups require group-specific metadata and lifecycle.

Direct conversations do not need:

group_name
group_status

Separating this data avoids mixing two different conversation models into one physical structure.

5. conversation_members_by_conversation
Purpose

Stores the membership of a conversation.

Primary access pattern
Given conversation_id
→ retrieve participants and membership state
Key
Partition key:
conversation_id

Clustering key:
user_id
Stored information
user_id
membership_status
role
joined_at
left_at
membership_version
Membership states
ACTIVE
LEFT
REMOVED

Historical membership is retained.

This is important because a Messaging Service may need to understand historical membership while processing synchronization, delivery, or conversation history according to the approved rules.

Roles
MEMBER
ADMIN

The role supports group administration.

Why users are not stored as Messaging entities

user_id is an opaque identifier.

The Auth Service owns the actual user identity.

Therefore:

Messaging Service
      │
      └── stores UserId

Auth Service
      │
      └── owns User

There is no cross-service database foreign key.

6. conversations_by_user
Purpose

Provides the user's conversation list.

Primary access pattern
Given user_id
→ retrieve that user's conversations
→ ordered by recent activity
Key
Partition key:
user_id

Clustering keys:
last_activity_at
conversation_id
Stored information
conversation_id
conversation_type
membership_status
last_activity_at
unread_state_version
Why this table is necessary

The canonical conversation table is optimized for:

conversation_id
→ conversation

But the client frequently needs:

user_id
→ all relevant conversations

Scanning all conversations would be unacceptable.

Therefore this table provides a separate query-oriented representation.

This is intentional ScyllaDB denormalization.

7. conversation_sequence_state
Purpose

Durably stores the latest message sequence allocated for each conversation.

Primary access pattern
Given conversation_id
→ retrieve latest assigned sequence
Key
Partition key:
conversation_id
Stored information
last_assigned_sequence
updated_at
Why it exists

Each conversation has its own strictly increasing logical sequence:

Conversation A
1 → 2 → 3 → 4

Conversation B
1 → 2 → 3 → 4

There is no global sequence.

The Messaging Service's conversation-affine logical owner allocates sequences for its conversation.

For example:

last_assigned_sequence = 1042
        ↓
accept next item
        ↓
assign sequence = 1043
        ↓
persist state = 1043
Why durable storage is necessary

Suppose the Messaging Service instance handling a conversation fails:

Instance A
last known sequence = 1042
        ↓
failure
        ↓
Instance B becomes logical owner
        ↓
reads durable state
        ↓
continues from 1043

This prevents sequence reuse after ownership changes or failures.

8. messages_by_conversation
Purpose

Stores conversation items in canonical conversation order.

This is the primary message-history table.

Primary access pattern
Given conversation_id and bucket
→ retrieve conversation items
→ ordered by message_sequence
Key
Partition key:
conversation_id
message_bucket

Clustering keys:
message_sequence ASC
message_id
Stored information
message_sequence
message_id
sender_user_id
sender_device_id
message_priority
accepted_at
ciphertext_envelope
envelope_version
file_reference_ids
Message bucket

The approved bucket is:

YYYYMM

For example:

202609

means September 2026.

A physical partition therefore looks conceptually like:

(conversation_id, 202609)
Why time buckets are necessary

Without bucketing, an extremely active long-lived conversation could grow indefinitely within one ScyllaDB partition.

Time bucketing bounds partition growth.

Importantly:

message_bucket

does not create a new logical conversation.

The logical conversation remains:

conversation_id

The bucket is purely a physical storage decision.

9. pending_deliveries_by_device
Purpose

Retrieves messages waiting to be delivered to a specific device.

Primary access pattern
Given device_id
→ retrieve pending deliveries
Key
Partition key:
device_id
delivery_bucket

Clustering keys:
accepted_at
message_id
Stored information
conversation_id
message_sequence
message_priority
delivery_state
Why delivery is device-specific

A user can have multiple devices.

For example:

Bob
├── Phone
├── Laptop
└── Tablet

Each device may be at a different delivery state.

For example:

Phone  → DELIVERED
Laptop → PENDING
Tablet → offline / PENDING

Therefore, delivery cannot be modeled simply as:

Message → User

It must be:

Message → Target Device
Why this table is separate from message storage

messages_by_conversation supports conversation-history reads.

This table supports:

device_id
→ pending work for this device

These are different access patterns and therefore different ScyllaDB tables.

10. delivery_state_by_message
Purpose

Stores delivery state for each recipient device.

Primary access pattern
Given message_id
→ retrieve delivery state for recipient devices
Key
Partition key:
message_id

Clustering key:
recipient_device_id
Delivery lifecycle
PENDING
   ↓
DELIVERED
   ↓
READ
PENDING

The target device has not yet confirmed successful delivery.

DELIVERED

The target device confirms successful local persistence.

This is an important distinction:

Network transmission complete
≠
DELIVERED

The message becomes DELIVERED only after the device confirms that it has persisted the item according to the client architecture.

READ

The device sends a read receipt when the user displays the message according to the approved read-receipt policy.

Why this table exists separately

The system must answer:

For this message,
which devices have received it
and which have read it?

This is a different query from:

What messages are waiting for Device X?

Therefore both delivery_state_by_message and pending_deliveries_by_device are required.

11. sync_state_by_device
Purpose

Stores synchronization progress independently for each device and conversation.

Primary access pattern
Given device_id
→ determine synchronization progress

with state scoped by:

conversation_id
Key
Partition key:
device_id

Clustering key:
conversation_id
Stored information
last_synced_sequence
last_sync_at
sync_version
Why synchronization is per device

Consider:

Conversation X

with sequence:

1 → 2 → 3 → ... → 100

A user's devices may be at different positions:

Phone  → 100
Laptop → 85
Tablet → 62

Each device therefore needs an independent synchronization cursor.

Incremental synchronization

The device can effectively say:

I have synchronized through sequence 85.

The service can retrieve subsequent conversation items:

86 → 87 → ... → 100

This avoids repeatedly transferring the entire conversation history.

The synchronization cursor advances only after successful local persistence on the client.

12. message_submission_by_idempotency_key
Purpose

Prevents duplicate messages when a client retries a submission.

Primary access pattern
Given:
sender_device_id
+
idempotency_key

→ determine whether this logical submission
  was already processed
Key
Partition key:
sender_device_id

Clustering key:
idempotency_key
Stored information
message_id
submission_status
created_at
Why MessageId is not sufficient

message_id identifies the resulting message.

The idempotency_key identifies the logical submission operation.

Example:

Client submits message
        ↓
Server accepts message
        ↓
Network response is lost
        ↓
Client does not know whether submission succeeded
        ↓
Client retries

The retry uses the same:

sender_device_id
+
idempotency_key

The service detects the previous submission and returns the already-created result instead of creating another message.

Conceptually:

IdempotencyKey
       ↓
Logical submission

MessageId
       ↓
Resulting message
13. messaging_outbox_events
Purpose

Stores Messaging Service application events that must be published reliably after durable Messaging state has been accepted.

The Outbox exists to avoid treating cross-service event publication as an unreliable best-effort side effect.

For example:

Messaging state accepted
        ↓
service crashes
        ↓
required application event is never published

The Outbox provides durable event records that can later be processed by the Messaging event publisher.

Primary access pattern
Given:
producer_shard
+
event_bucket

→ retrieve unpublished events
→ process them in creation order
→ mark successfully published events
Key
Partition keys:
producer_shard
event_bucket

Clustering keys:
created_at
event_id
Stored information
event_id
aggregate_type
aggregate_id
event_type
payload
created_at
publication_status
published_at

The full physical identity of an event row is therefore determined by:

producer_shard
+
event_bucket
+
created_at
+
event_id
Why producer_shard exists

The Messaging Service must not create a single globally contended Outbox partition.

A single partition such as:

ALL_MESSAGING_EVENTS

would eventually become a hotspot.

Instead, events are distributed across a bounded number of producer shards.

Conceptually:

event
  ↓
deterministic shard selection
  ↓
producer_shard

For example:

producer_shard = 7
event_bucket   = 202609

identifies one physical partition containing events assigned to producer shard 7 during September 2026.

This allows event production and publishing to scale across multiple partitions.

Why event_bucket exists

Like message_bucket and delivery_bucket, event_bucket bounds partition growth.

The approved format is:

YYYYMM

For example:

202609

represents events created during September 2026.

A physical partition is therefore conceptually:

(producer_shard, event_bucket)

No logical event semantics depend on the bucket. It is purely a physical ScyllaDB partitioning decision.

Ordering

Within one physical Outbox partition, events are ordered by:

created_at
event_id

created_at provides chronological ordering.

event_id provides deterministic ordering when two events have the same timestamp.

This ordering is partition-local.

There is deliberately no globally ordered Messaging Outbox, because global ordering would introduce unnecessary coordination and potential bottlenecks.

Aggregate examples

For a message event:

aggregate_type = MESSAGE
aggregate_id   = message_id

For a conversation event:

aggregate_type = CONVERSATION
aggregate_id   = conversation_id

The Outbox therefore supports application events originating from different Messaging aggregates without requiring a separate Outbox table per aggregate.

MVP event types

The initial Messaging Service Outbox publishes the following application events:

MESSAGE_ACCEPTED
CONVERSATION_CREATED
GROUP_CREATED
MEMBER_ADDED
MEMBER_REMOVED
GROUP_CLOSED

These events are meaningful application events that may need to be consumed by another runtime service, particularly the Audit Service.

Events intentionally not emitted for every delivery transition

The MVP does not create a separate Outbox event for every:

MESSAGE_DELIVERED
MESSAGE_READ

Delivery and read transitions already have durable state in:

delivery_state_by_message

Publishing every normal delivery or read transition as an Audit event would substantially increase event volume and would turn Audit into a high-volume replica of Messaging operational state.

Therefore, for the MVP:

delivery_state_by_message

remains the authoritative Messaging state for normal delivery and read receipts.

The Audit Service receives significant Messaging application events rather than every operational delivery transition.

Important difference from the Files Service Outbox

The Files Service uses PostgreSQL.

Therefore, it can perform:

PostgreSQL transaction

UPDATE files
+
INSERT INTO outbox_events

COMMIT atomically

The Messaging Service uses ScyllaDB.

Therefore, the Messaging Outbox must not be described as relying on the same PostgreSQL multi-row transaction model.

The design goal remains:

A successfully accepted Messaging operation must not result in a permanently lost required application event.

The implementation must achieve this using the Messaging Service's conversation-affine processing path and ScyllaDB-compatible durability strategy.

The Outbox is therefore conceptually the same reliability pattern, but its physical consistency mechanism is specific to the Messaging persistence technology.

14. How the tables work together
Message submission

A simplified message submission looks like:

Client
  │
  │ Submit item
  ▼
message_submission_by_idempotency_key
  │
  │ New submission?
  ▼
conversation_sequence_state
  │
  │ Allocate next sequence
  ▼
messages_by_conversation
  │
  │ Persist ciphertext envelope
  ▼
delivery_state_by_message
  │
  │ Create per-device delivery state
  ▼
pending_deliveries_by_device

The conversation and membership tables are consulted to validate the operation:

conversations_by_id
        +
conversation_members_by_conversation

When the accepted operation requires a published application event, the operation also creates a durable Outbox record:

Accepted Messaging operation
        ↓
messaging_outbox_events
        ↓
Messaging Event Publisher
        ↓
publish application event
        ↓
mark event as published

The event publisher processes unpublished Outbox records asynchronously.

Device synchronization

When a device synchronizes:

sync_state_by_device
        ↓
Determine last synchronized sequence
        ↓
messages_by_conversation
        ↓
Retrieve subsequent items
        ↓
Update sync_state_by_device

The synchronization cursor advances only after successful local persistence on the client.

15. Key architectural principle

The Messaging MPD is deliberately not a normalized entity model.

The same logical concept may be represented in multiple tables because each table supports a concrete operation.

For example:

ConversationItem
       │
       ├── messages_by_conversation
       │       → conversation history
       │
       ├── pending_deliveries_by_device
       │       → device delivery work
       │
       └── delivery_state_by_message
               → delivery/read tracking

Similarly, significant Messaging application operations can be represented through:

Messaging Aggregate
       │
       ├── canonical Messaging state
       │
       └── messaging_outbox_events
               → reliable asynchronous
                 application-event publication

This duplication is intentional.

The objective is:

Predictable, bounded, high-throughput reads and writes for the known Messaging Service access patterns, reliable publication of significant application events, no cross-service database joins, and no single globally contended message-processing or Outbox structure.

