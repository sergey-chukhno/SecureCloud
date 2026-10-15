#pragma once

#include "domain/conversation_types.hpp"
#include "domain/outbox_event.hpp"

#include <chrono>
#include <compare>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::repository {

/// Operational status of an outbox event.
enum class OutboxPublishStatus : uint8_t {
    Pending = 1,
    Published = 2,
    Failed = 3,
};

[[nodiscard]] inline std::string to_string(OutboxPublishStatus status) {
    switch (status) {
    case OutboxPublishStatus::Pending:
        return "PENDING";
    case OutboxPublishStatus::Published:
        return "PUBLISHED";
    case OutboxPublishStatus::Failed:
        return "FAILED";
    }
    return "PENDING";
}

[[nodiscard]] inline std::optional<OutboxPublishStatus>
outbox_publish_status_from_string(std::string_view sv) noexcept {
    if (sv == "PENDING") {
        return OutboxPublishStatus::Pending;
    }
    if (sv == "PUBLISHED") {
        return OutboxPublishStatus::Published;
    }
    if (sv == "FAILED") {
        return OutboxPublishStatus::Failed;
    }
    return std::nullopt;
}

/// Computes hourly UTC outbox bucket string (YYYYMMDDHH) from a timestamp.
[[nodiscard]] inline std::string outbox_bucket_from_time_point(std::chrono::system_clock::time_point tp) {
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &tt);
#else
    gmtime_r(&tt, &tm_utc);
#endif
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(4) << (tm_utc.tm_year + 1900) << std::setw(2) << (tm_utc.tm_mon + 1)
        << std::setw(2) << tm_utc.tm_mday << std::setw(2) << tm_utc.tm_hour;
    return oss.str();
}

/// Durable outbox record as stored in securecloud_messaging.messaging_outbox_events.
struct OutboxEventRecord {
    std::string outbox_bucket;
    std::chrono::system_clock::time_point created_at;
    std::string event_id;
    domain::ConversationId conversation_id;
    std::string event_type;
    std::string payload_json;
    std::optional<std::chrono::system_clock::time_point> published_at{std::nullopt};
    OutboxPublishStatus publish_status{OutboxPublishStatus::Pending};

    auto operator<=>(const OutboxEventRecord& other) const noexcept = default;
    bool operator==(const OutboxEventRecord& other) const noexcept = default;
};

/// Abstract repository contract for Transactional Outbox persistence.
/// Conforms to ADR-005 and 03-messaging-data-model.md:
/// - Table: securecloud_messaging.messaging_outbox_events
/// - Partition Key: outbox_bucket (e.g. YYYYMMDDHH or shard key)
/// - Clustering Key: created_at ASC, event_id ASC
class IOutboxRepository {
  public:
    virtual ~IOutboxRepository() = default;

    /// Enqueues an outbox event. If outbox_bucket is empty, it is automatically derived from event.created_at.
    virtual void enqueue_event(const domain::ConversationOutboxEvent& event, const std::string& outbox_bucket = "") = 0;

    /// Fetches pending outbox events for a given outbox bucket ordered by created_at ASC.
    [[nodiscard]] virtual std::vector<OutboxEventRecord> fetch_pending_events(const std::string& outbox_bucket,
                                                                              size_t limit) = 0;

    /// Marks an event as published with its publication timestamp.
    virtual void mark_event_published(const std::string& outbox_bucket,
                                      std::chrono::system_clock::time_point created_at, const std::string& event_id,
                                      std::chrono::system_clock::time_point published_at) = 0;
};

} // namespace securecloud::messaging::repository
