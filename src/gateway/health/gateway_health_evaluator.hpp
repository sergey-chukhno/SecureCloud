#pragma once

#include "grpc/channel_manager.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <unordered_map>

namespace securecloud::gateway::audit {
    class AuditProducerMetrics; // Forward declaration
}

namespace securecloud::gateway::health {

    class GatewayHealthEvaluator {
    public:
        explicit GatewayHealthEvaluator(grpc::GrpcChannelManager& channel_manager,
                                        std::shared_ptr<securecloud::gateway::audit::AuditProducerMetrics> audit_metrics = nullptr,
                                        std::chrono::milliseconds probe_timeout = std::chrono::milliseconds(500));

        /// Evaluates system readiness. Does NOT factor in Audit Producer health.
        [[nodiscard]] bool evaluate_readiness() noexcept;

        /// Generates detailed internal health status for internal diagnostic endpoints.
        [[nodiscard]] std::unordered_map<std::string, std::string> evaluate_detailed_health() noexcept;

    private:
        grpc::GrpcChannelManager& channel_manager_;
        std::shared_ptr<securecloud::gateway::audit::AuditProducerMetrics> audit_metrics_;
        std::chrono::milliseconds probe_timeout_;
    };

} // namespace securecloud::gateway::health
