#pragma once

#include "domain/audit_event.hpp"
#include "domain/enums.hpp"
#include "domain/event_id.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::audit::query {

enum class SortOrder : uint8_t {
    Descending = 0, // Default: newest occurred_at first
    Ascending = 1   // Oldest occurred_at first
};

struct AuditQueryFilter {
    std::optional<std::chrono::system_clock::time_point> start_occurred_at;
    std::optional<std::chrono::system_clock::time_point> end_occurred_at;
    std::vector<domain::ProducerService> producer_services;
    std::vector<std::string> event_types;
    std::vector<domain::Severity> severities;
    std::optional<domain::ActorType> actor_type;
    std::optional<std::string> actor_id;
    std::optional<domain::TargetType> target_type;
    std::optional<std::string> target_id;
    std::optional<std::string> correlation_id;
    uint32_t page_size{100};
    std::string page_token;
    SortOrder sort_order{SortOrder::Descending};
};

struct AuditPageCursor {
    int64_t last_occurred_at_ms{0};
    std::string last_producer_service;
    std::string last_event_type;
    domain::EventId last_event_id;
    SortOrder sort_order{SortOrder::Descending};
    std::array<uint8_t, 16> filter_hash{};
};

struct AuditQueryPageResult {
    std::vector<domain::AuditEvent> events;
    std::string next_page_token;
    bool has_more{false};
    uint32_t effective_page_size{0};
};

} // namespace securecloud::audit::query