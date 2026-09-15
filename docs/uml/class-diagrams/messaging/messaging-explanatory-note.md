1. Purpose of this diagram

This diagram represents the principal implementation-level classes and responsibilities of the Messaging Service.

It is deliberately different from the Messaging MCD and MPD.

The:

MCD describes logical data concepts;
MPD describes the 12 concrete ScyllaDB tables and query patterns;
UML Class Diagram describes how the C++ Messaging Service can organize responsibilities around those approved persistence models.

The diagram does not convert ScyllaDB into a relational object model.

That distinction is important.

For example:

ConversationMessage

is represented in several physical query-oriented forms through:

messages_by_conversation
pending_deliveries_by_device
delivery_state_by_message

These are different persistence representations supporting different access patterns.

2. The 12 approved persistence models

The UML contains one explicit repository boundary for each approved physical table.

#	MPD table	UML model	Repository
1	conversations_by_id	Conversation	ConversationRepository
2	direct_conversation_by_users	DirectConversationMapping	DirectConversationRepository
3	group_metadata_by_conversation	GroupMetadata	GroupMetadataRepository
4	conversation_members_by_conversation	ConversationMember	ConversationMemberRepository
5	conversations_by_user	UserConversation	UserConversationRepository
6	conversation_sequence_state	ConversationSequenceState	ConversationSequenceStateRepository
7	messages_by_conversation	ConversationMessage	ConversationMessageRepository
8	pending_deliveries_by_device	PendingDelivery	PendingDeliveryRepository
9	delivery_state_by_message	MessageDeliveryState	MessageDeliveryStateRepository
10	sync_state_by_device	DeviceSyncState	DeviceSyncStateRepository
11	message_submission_by_idempotency_key	MessageSubmission	MessageSubmissionRepository
12	messaging_outbox_events	MessagingOutboxEvent	MessagingOutboxEventRepository

This one-to-one representation is intentional: no approved table is silently omitted.

3. Transport boundary
MessagingRequestHandler

This represents the Messaging Service's incoming API boundary.

Its responsibility is orchestration at the transport edge:

Client / Gateway
       ↓
MessagingRequestHandler
       ↓
Application services

It should not contain:

sequence allocation logic;
ScyllaDB query logic;
delivery state transitions;
idempotency implementation;
Outbox scanning.

Those responsibilities belong to dedicated application components.

4. Conversation management
ConversationService

Responsible for:

creating direct conversations;
creating group conversations;
retrieving conversation metadata;
retrieving a user's conversation list.

For direct conversations, the important operation is:

User A + User B
        ↓
DirectConversationRepository
        ↓
Existing mapping?
   ┌────┴────┐
  Yes       No
   │         │
return     create
existing   conversation

The canonical ordering of:

user_a_id
user_b_id

belongs to the direct conversation lookup logic.

This prevents:

Alice + Bob

and:

Bob + Alice

from producing separate conversation identities.

GroupMetadata

Groups have their own metadata because direct conversations do not need:

group_name;
group_status.

The approved lifecycle is:

ACTIVE
   ↓
CLOSED

CLOSED means the group remains historically available, but new conversation items are not accepted.

5. Membership
ConversationMember

Membership is independent from the canonical Conversation.

This is important because membership has its own lifecycle:

ACTIVE
LEFT
REMOVED

and historical membership is retained.

The Messaging Service stores opaque:

UserId

rather than User entities.

The Auth Service remains the owner of actual user identity.

MembershipService

This service centralizes membership checks such as:

Can User X submit
to Conversation Y?

It is used by message submission and group-related operations.

This prevents submission code from independently reimplementing membership rules.

6. Conversation-affine ordering

This is the most important internal concurrency part of the Messaging design.

The model explicitly avoids:

One global sequence
        ↓
global lock / bottleneck

Instead:

Conversation A → independent sequence
Conversation B → independent sequence
Conversation C → independent sequence

The relevant implementation path is:

MessageSubmissionService
        ↓
ConversationOwnerRouter
        ↓
ConversationOwner
        ↓
ConversationExecutionContext
        ↓
ConversationSequenceService

Different conversations can therefore be processed concurrently.

Operations affecting the same conversation are serialized through its conversation-affine execution path.

ConversationSequenceState

The durable state contains:

conversationId
lastAssignedSequence
updatedAt

Conceptually:

lastAssignedSequence = 1042
        ↓
next accepted message
        ↓
assign 1043
        ↓
persist new state

After failure or ownership movement:

new owner
    ↓
read durable state
    ↓
continue from last assigned sequence

There is no globally increasing message sequence.

7. Message storage
ConversationMessage

This model represents the canonical message-history record.

Important fields include:

conversationId
messageBucket
messageSequence
messageId
senderUserId
senderDeviceId
ciphertextEnvelope
fileReferenceIds

The service stores the encrypted:

ciphertextEnvelope

It does not need plaintext message content.

messageBucket

The approved format is:

YYYYMM

For example:

202609

The physical partition is conceptually:

(conversation_id, message_bucket)

The bucket is purely a ScyllaDB physical partitioning mechanism.

It does not create another logical conversation.

8. Idempotency
MessageSubmission

This is separate from the resulting message.

The identity is:

senderDeviceId
+
idempotencyKey

The distinction is:

IdempotencyKey
        ↓
one logical submission attempt

MessageId
        ↓
the resulting accepted message

Example:

Client submits message
        ↓
Server accepts message
        ↓
response is lost
        ↓
Client retries
        ↓
same idempotency key
        ↓
existing result returned

No duplicate message is created.

9. Device-specific delivery

A user can own multiple devices.

Therefore delivery state is not:

Message → User

but:

Message → Recipient Device

The model uses two separate persistence representations.

PendingDelivery

Answers:

What work is waiting
for Device X?

Its physical partition is device-oriented.

MessageDeliveryState

Answers:

For Message Y,
what is the state
of every recipient device?

The lifecycle is:

PENDING
   ↓
DELIVERED
   ↓
READ

DELIVERED means the recipient device has confirmed successful local persistence.

It does not merely mean:

server sent bytes

or:

network transmission completed
10. Synchronization
DeviceSyncState

Synchronization progress belongs to:

Device
   +
Conversation

For example:

Phone  → sequence 100
Laptop → sequence 85
Tablet → sequence 62

Each device therefore has an independent cursor.

The synchronization flow is:

DeviceSyncState
        ↓
lastSyncedSequence
        ↓
ConversationMessageRepository
        ↓
retrieve later messages
        ↓
successful local persistence
        ↓
advance DeviceSyncState

The cursor advances only after successful local persistence.

11. Messaging Outbox

This is the major correction compared with the previous UML version.

MessagingOutboxEvent

It is an explicit approved ScyllaDB persistence model.

Its full physical identity is:

producerShard
+
eventBucket
+
createdAt
+
eventId

The physical partition is:

(producer_shard, event_bucket)

and ordering within that partition is:

created_at
event_id

There is deliberately no globally ordered Outbox.

That would introduce unnecessary coordination and could create a bottleneck.

MessagingOutboxService

Its responsibility is to create durable event records for significant Messaging operations.

Examples include:

MESSAGE_ACCEPTED
CONVERSATION_CREATED
GROUP_CREATED
MEMBER_ADDED
MEMBER_REMOVED
GROUP_CLOSED

The approved MVP deliberately does not create an Outbox event for every:

MESSAGE_DELIVERED
MESSAGE_READ

Those transitions already have authoritative durable state in:

delivery_state_by_message

Publishing every delivery/read transition would unnecessarily turn Audit into a high-volume operational replica of Messaging.

12. MessagingEventPublisher

The publisher operates asynchronously:

messaging_outbox_events
        ↓
find unpublished events
        ↓
ApplicationEventPublisher
        ↓
successful publication
        ↓
mark published

The publisher processes events partition-by-partition.

There is no requirement for global event ordering across:

producerShard = 1
producerShard = 2
producerShard = 3

Ordering is only meaningful inside an individual physical Outbox partition.

13. ApplicationEventPublisher

This is intentionally an interface.

The Messaging Service should not conceptually contain a hard-coded class named:

AuditPublisher

The Messaging Service produces application events.

Another runtime service—particularly Audit in the current MVP—may consume them.

This gives the Messaging implementation a clean boundary:

Messaging domain
      │
      │ produces
      ▼
Messaging application event
      │
      ▼
ApplicationEventPublisher

rather than embedding the Audit Service directly into Messaging domain logic.

14. Important design principle: the UML is not a relational schema

Some classes in this diagram correspond closely to physical ScyllaDB rows.

Others represent application responsibilities.

For example:

ConversationMessage

is one application concept, but message-related information appears in several physical representations:

ConversationMessage
        │
        ├── messages_by_conversation
        │
        ├── pending_deliveries_by_device
        │
        └── delivery_state_by_message

That duplication is intentional.

The class diagram therefore should not be interpreted as saying that:

PendingDelivery

is a child entity of ConversationMessage in the relational ORM sense.

It represents a logical relationship while the actual ScyllaDB model remains query-driven and denormalized.

15. Overall main submission flow

The principal message path represented by the UML is:

MessagingRequestHandler
        ↓
MessageSubmissionService
        │
        ├── IdempotencyService
        │
        ├── MembershipService
        │
        └── ConversationOwnerRouter
                    ↓
             ConversationOwner
                    ↓
          ConversationExecutionContext
                    ↓
        ConversationSequenceService
                    ↓
       ConversationSequenceState
                    ↓
          ConversationMessage
                    ↓
             DeliveryService
                    ├── PendingDelivery
                    └── MessageDeliveryState
                    │
                    └── MessagingOutboxService
                              ↓
                       MessagingOutboxEvent

