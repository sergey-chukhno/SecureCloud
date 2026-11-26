#pragma once

#include "domain/audit_event.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "securecloud/audit/v1/audit.pb.h"

#include <optional>
#include <string_view>

namespace securecloud::messaging::audit {

/**
 * Maps an internal outbox record whose payload_proto_bin holds JSON metadata into the
 * canonical AUDIT-002 Protobuf representation.
 * Enforces UUIDv7 event_id, known severity, and ZeroPlaintextGuard checks, returning
 * std::nullopt if the event is malformed or unsafe.
 */
[[nodiscard]] std::optional<securecloud::audit::v1::AuditEventProto>
map_outbox_record_to_canonical_proto(const repository::AuditOutboxRecord& record,
                                     std::string_view producer_instance = "messaging");

/**
 * Validates `event` (RFC 9562 UUIDv7 + ZeroPlaintextGuard), serializes its canonical
 * AUDIT-002 AuditEventProto into wire bytes, and returns a populated AuditOutboxRecord
 * tagged with hourly UTC bucket (`YYYYMMDDHH`) and deterministic 16-way shard ID.
 */
[[nodiscard]] repository::AuditOutboxRecord
build_canonical_outbox_record(const domain::MessagingAuditEvent& event, std::string_view routing_key,
                              std::string_view producer_instance = "messaging");

/**
 * Validates, builds canonical serialized protobuf payload, enqueues into `audit_repo`,
 * and records producer staged metrics. No-ops safely when `audit_repo` is null.
 */
void stage_canonical_audit_event(repository::IMessagingAuditOutboxRepository* audit_repo,
                                 const domain::MessagingAuditEvent& event, std::string_view routing_key,
                                 std::string_view producer_instance = "messaging");

} // namespace securecloud::messaging::audit
