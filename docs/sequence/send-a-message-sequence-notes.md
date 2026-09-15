Main sequence: 

1. user composes plaintext locally;
2. recipient identity/device discovery occurs through Auth;
3. cryptographic sessions are established or reused locally;
4. the client encrypts before transmission;
5. the client durably persists its encrypted outgoing state;
6. Gateway forwards the request to Messaging;
7. Messaging validates membership and idempotency;
8. Messaging allocates the next conversation sequence;
9. Messaging durably persists the ciphertext and delivery state;
10. Messaging creates the required Audit application event through its Outbox;
11. the recipient device synchronizes and durably persists ciphertext;
12. only then does the recipient acknowledge delivery.

Explanation of the important parts
1. MessagingManager creates both message_id and idempotency_key

These represent different concepts.

message_id
    ↓
Identity of the resulting logical message

idempotency_key
    ↓
Identity of the submission operation

For example:

Client submits message
       ↓
Messaging accepts message
       ↓
Network response disappears
       ↓
Client does not know whether operation succeeded
       ↓
Retry using SAME idempotency_key
       ↓
Messaging detects previous submission
       ↓
Returns existing accepted message

This prevents a network failure from creating:

Hello
Hello
Hello

three times.

2. Encryption happens before backend transmission

The security boundary is:

Plaintext
    ↓
MessagingManager
    ↓
CryptoManager
    ↓
Encrypt locally
    ↓
MessageEnvelope / Ciphertext
    ↓
Gateway
    ↓
Messaging
    ↓
ScyllaDB

Neither Gateway nor Messaging needs message plaintext.

3. Why device discovery is shown as conditional

The client does not necessarily contact Auth before every message.

If the necessary cryptographic state is already valid locally:

Existing valid session
        ↓
Encrypt immediately

Otherwise:

No session / changed device state
        ↓
Discover authorized devices
        ↓
Retrieve public crypto material
        ↓
Verify identity/key state
        ↓
Establish/update local session
        ↓
Encrypt

This is important for performance and offline behavior.

The Auth Service remains authoritative for device authorization and public cryptographic directory information, but clients may maintain local cryptographic session state.

4. Conversation ordering is independent of global ordering

The Messaging Service allocates:

Conversation A

1 → 2 → 3 → 4

independently from:

Conversation B

1 → 2 → 3 → 4

There is deliberately no:

SecureCloud global message sequence

The operation is routed through the conversation-affine processing path, which allows the conversation's logical owner to allocate the next sequence without introducing a system-wide sequencing bottleneck.

5. Why the message is persisted in several ScyllaDB tables

One accepted message supports several different queries.

Conversation history
messages_by_conversation

conversation_id + bucket
        ↓
ordered message history
Duplicate submission detection
message_submission_by_idempotency_key

sender_device_id + idempotency_key
        ↓
previous submission result
Per-device delivery status
delivery_state_by_message

message_id
        ↓
recipient devices + state
Pending work for a device
pending_deliveries_by_device

device_id
        ↓
messages waiting for delivery

This is intentional ScyllaDB denormalization.

6. MESSAGE_ACCEPTED is an application event, not message content

The Messaging Outbox produces:

MESSAGE_ACCEPTED

for Audit.

The Audit event does not contain plaintext.

The purpose is to record a significant application event such as:

A Messaging operation was durably accepted

This is different from telemetry.

Also, as approved earlier, we do not publish a separate Audit event for every:

MESSAGE_DELIVERED
MESSAGE_READ

because that would turn Audit into a high-volume copy of Messaging operational state.

7. Why Audit publication is asynchronous

The critical Messaging path is:

Validate
    ↓
Allocate sequence
    ↓
Persist ciphertext
    ↓
Create delivery state
    ↓
Create durable Outbox record
    ↓
Return ACCEPTED

The client does not need to wait for Audit ingestion.

Later:

Messaging Event Publisher
        ↓
Reads durable Outbox
        ↓
Publishes MESSAGE_ACCEPTED
        ↓
Audit
        ↓
Marks event published

Therefore a temporary Audit outage does not prevent secure message acceptance.

8. The recipient does not acknowledge delivery immediately

This distinction remains fundamental:

Gateway transmitted ciphertext
        ≠
Message delivered

The approved flow is:

Receive ciphertext
        ↓
Persist encrypted message locally
        ↓
Durable local persistence succeeds
        ↓
Send acknowledgement
        ↓
Messaging updates:
PENDING → DELIVERED

This gives DELIVERED a concrete meaning:

The recipient device confirmed successful durable local persistence of the encrypted message.

9. Decryption occurs only after encrypted local persistence

For incoming messages:

Backend ciphertext
        ↓
Recipient client receives ciphertext
        ↓
Persist encrypted representation
        ↓
Local durability confirmed
        ↓
Acknowledge delivery
        ↓
Decrypt
        ↓
Display plaintext

This follows the approved client architecture and avoids acknowledging a message that has not yet been durably persisted.

Important scope clarification: direct vs group messages

The sequence above intentionally uses the generic term:

recipient devices

because the Messaging Service's server-side delivery model operates at the device level.

The client-side cryptographic preparation differs according to whether:

DIRECT

or:

GROUP

but both cases ultimately produce an encrypted MessageEnvelope that Messaging stores and routes without decrypting.