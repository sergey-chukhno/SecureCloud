Audit Service MPD summary

The approved Audit Service MPD contains one physical table:

audit_events

with the following concrete physical decisions:

Decision	Approved implementation
Database	ClickHouse
Storage engine	MergeTree
Primary table	audit_events
Event identity	UUIDv7
Partitioning	Monthly by occurred_at
Ordering	occurred_at, producer_service, event_type, event_id
Persistence model	Append-only
Ingestion	Asynchronous
Queue	Globally bounded
Validation workers	4
Insert workers	2
Maximum queue	10,000 events
Batch size	1,000 events
Maximum batch delay	100 ms
Delivery semantics	At-least-once
Retry identity	event_id
Deduplication	100,000 IDs / 10-minute TTL
Retention	36 months
Retention mechanism	ClickHouse TTL
Per-event hash chain	Not in MVP
Cryptographic checkpoints	Future enhancement