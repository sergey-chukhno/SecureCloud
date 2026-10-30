#include "query/audit_query_validator.hpp"

#include <algorithm>
#include <regex>

namespace securecloud::audit::query {

namespace {

bool matches_event_type_pattern(std::string_view sv) {
    static const std::regex kEventTypeRegex(R"(^[a-z0-9_]+(\.[a-z0-9_]+)+$)", std::regex::optimize);
    return std::regex_match(sv.begin(), sv.end(), kEventTypeRegex);
}

} // namespace

grpc::Status AuditQueryValidator::validate_and_normalize(
    AuditQueryFilter& filter,
    const QueryConfig& config,
    std::chrono::system_clock::time_point now) {

    // 1. Time Window Validation
    if (!filter.start_occurred_at.has_value() && !filter.end_occurred_at.has_value()) {
        filter.start_occurred_at = now - std::chrono::hours(config.default_time_window_hours);
        filter.end_occurred_at = now + std::chrono::minutes(5);
    } else if (!filter.start_occurred_at.has_value() || !filter.end_occurred_at.has_value()) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "MissingTimeRangeBound: Both start_occurred_at and end_occurred_at must be provided together");
    }

    if (*filter.start_occurred_at >= *filter.end_occurred_at) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "InvalidTimeRangeOrder: start_occurred_at must be strictly less than end_occurred_at");
    }

    auto window_duration = std::chrono::duration_cast<std::chrono::hours>(*filter.end_occurred_at - *filter.start_occurred_at);
    if (window_duration.count() > static_cast<int64_t>(config.max_time_window_hours)) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "TimeWindowExceeded: Requested time window exceeds maximum allowed duration");
    }

    // 2. Pagination Limit Validation
    if (filter.page_size == 0) {
        filter.page_size = config.default_page_limit;
    } else if (filter.page_size > config.max_page_limit) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "PageSizeExceeded: Requested page_size exceeds maximum allowed limit");
    }

    // 3. Filter Field Sanity & Injection Defense
    if (filter.event_types.size() > 20) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "TooManyEventTypes: Maximum allowed event_types filter count is 20");
    }

    for (const auto& et : filter.event_types) {
        if (!is_valid_event_type(et)) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidEventType: Event type format mismatch or exceeds 64 characters");
        }
    }

    // Actor validation
    if (filter.actor_id.has_value()) {
        if (!filter.actor_type.has_value() || static_cast<int>(*filter.actor_type) == 0) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidActorTargetRequirement: actor_type must be specified when actor_id is present");
        }
        if (!is_safe_identifier(*filter.actor_id, 128)) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidCharacterInIdentifier: actor_id contains forbidden control, quote, or null characters");
        }
    }

    // Target validation
    if (filter.target_id.has_value()) {
        if (!filter.target_type.has_value() || static_cast<int>(*filter.target_type) == 0) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidActorTargetRequirement: target_type must be specified when target_id is present");
        }
        if (!is_safe_identifier(*filter.target_id, 128)) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidCharacterInIdentifier: target_id contains forbidden control, quote, or null characters");
        }
    }

    // Correlation ID validation
    if (filter.correlation_id.has_value() && !is_valid_correlation_id(*filter.correlation_id)) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "InvalidCorrelationId: correlation_id length must be <= 64 and contain printable ASCII");
    }

    // Page token validation
    if (!filter.page_token.empty()) {
        auto expected_hash = AuditPageCursorCodec::compute_filter_hash(filter);
        auto cursor_opt = AuditPageCursorCodec::decode(filter.page_token, expected_hash);
        if (!cursor_opt.has_value()) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "InvalidPageToken: Decoded cursor fingerprint does not match canonical filter hash");
        }
    }

    return grpc::Status::OK;
}

bool AuditQueryValidator::is_valid_event_type(std::string_view event_type) {
    if (event_type.empty() || event_type.size() > 64) {
        return false;
    }
    return matches_event_type_pattern(event_type);
}

bool AuditQueryValidator::is_safe_identifier(std::string_view id, size_t max_len) {
    if (id.empty() || id.size() > max_len) {
        return false;
    }
    for (char c : id) {
        if (c < 0x20 || c > 0x7E || c == '\'' || c == '"' || c == '`' || c == '\0') {
            return false;
        }
    }
    return true;
}

bool AuditQueryValidator::is_valid_correlation_id(std::string_view token) {
    return is_safe_identifier(token, 64);
}

} // namespace securecloud::audit::query