#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Processing lifecycle status of a client message submission.
enum class SubmissionStatus : uint8_t {
    Processing = 1,
    Committed = 2,
    Failed = 3,
};

[[nodiscard]] inline std::string to_string(SubmissionStatus status) {
    switch (status) {
    case SubmissionStatus::Processing:
        return "PROCESSING";
    case SubmissionStatus::Committed:
        return "COMMITTED";
    case SubmissionStatus::Failed:
        return "FAILED";
    }
    return "PROCESSING";
}

[[nodiscard]] inline std::optional<SubmissionStatus> submission_status_from_string(std::string_view sv) noexcept {
    if (sv == "PROCESSING") {
        return SubmissionStatus::Processing;
    }
    if (sv == "COMMITTED") {
        return SubmissionStatus::Committed;
    }
    if (sv == "FAILED") {
        return SubmissionStatus::Failed;
    }
    return std::nullopt;
}

/// Durable deduplication record for idempotent client message submission.
/// Matches schema of securecloud_messaging.message_submission_by_idempotency_key:
/// - Partition Key: ((sender_device_id))
/// - Clustering Key: idempotency_key
struct IdempotencyRecord {
    DeviceId sender_device_id;
    std::string idempotency_key;
    MessageId message_id;
    ConversationId conversation_id;
    MessageSequence message_sequence{0};
    SubmissionStatus submission_status{SubmissionStatus::Processing};
    std::chrono::system_clock::time_point created_at;
    std::string request_fingerprint{};

    auto operator<=>(const IdempotencyRecord& other) const noexcept = default;
    bool operator==(const IdempotencyRecord& other) const noexcept = default;
};

} // namespace securecloud::messaging::domain
