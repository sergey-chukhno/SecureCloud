#pragma once

#include <string_view>

namespace securecloud::audit::lifecycle {

enum class DetailedServiceState {
    Uninitialized,
    Configured,
    Starting,
    Ready,
    Degraded,
    NotReady,
    Draining,
    Stopped,
    Failed
};

enum class StateTransitionReason {
    None,
    ServiceStartup,
    ClickHousePingTimeout,
    ClickHouseRecovered,
    QueueSaturated,
    QueueDrained,
    ClickHouseAndQueueFailure,
    ShutdownRequested,
    Unknown
};

[[nodiscard]] constexpr std::string_view to_string(DetailedServiceState state) noexcept {
    switch (state) {
    case DetailedServiceState::Uninitialized:
        return "Uninitialized";
    case DetailedServiceState::Configured:
        return "Configured";
    case DetailedServiceState::Starting:
        return "Starting";
    case DetailedServiceState::Ready:
        return "Ready";
    case DetailedServiceState::Degraded:
        return "Degraded";
    case DetailedServiceState::NotReady:
        return "NotReady";
    case DetailedServiceState::Draining:
        return "Draining";
    case DetailedServiceState::Stopped:
        return "Stopped";
    case DetailedServiceState::Failed:
        return "Failed";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view to_string(StateTransitionReason reason) noexcept {
    switch (reason) {
    case StateTransitionReason::None:
        return "None";
    case StateTransitionReason::ServiceStartup:
        return "ServiceStartup";
    case StateTransitionReason::ClickHousePingTimeout:
        return "ClickHousePingTimeout";
    case StateTransitionReason::ClickHouseRecovered:
        return "ClickHouseRecovered";
    case StateTransitionReason::QueueSaturated:
        return "QueueSaturated";
    case StateTransitionReason::QueueDrained:
        return "QueueDrained";
    case StateTransitionReason::ClickHouseAndQueueFailure:
        return "ClickHouseAndQueueFailure";
    case StateTransitionReason::ShutdownRequested:
        return "ShutdownRequested";
    case StateTransitionReason::Unknown:
        return "Unknown";
    }
    return "Unknown";
}

} // namespace securecloud::audit::lifecycle
