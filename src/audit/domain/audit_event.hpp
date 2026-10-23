#pragma once

#include "enums.hpp"
#include "event_id.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>

namespace securecloud::audit::domain {

struct AuditEvent {
    EventId event_id{};
    std::chrono::system_clock::time_point occurred_at{};
    std::optional<std::chrono::system_clock::time_point> received_at{std::nullopt};
    std::string event_type;
    Severity severity{Severity::Info};
    ProducerService producer_service{ProducerService::Audit};
    std::string producer_instance;
    ActorType actor_type{ActorType::Unknown};
    std::string actor_id;
    TargetType target_type{TargetType::Unknown};
    std::string target_id;
    std::string correlation_id;
    std::optional<std::string> causation_id{std::nullopt};
    std::unordered_map<std::string, std::string> metadata;
};

} // namespace securecloud::audit::domain