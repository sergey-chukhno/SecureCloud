#include "health/gateway_health_evaluator.hpp"
#include "audit/audit_producer_metrics.hpp"

namespace securecloud::gateway::health {

    GatewayHealthEvaluator::GatewayHealthEvaluator(grpc::GrpcChannelManager& channel_manager,
                                                   std::shared_ptr<audit::AuditProducerMetrics> audit_metrics,
                                                   std::chrono::milliseconds probe_timeout)
        : channel_manager_(channel_manager), audit_metrics_(std::move(audit_metrics)), probe_timeout_(probe_timeout) {}

    bool GatewayHealthEvaluator::evaluate_readiness() noexcept {
        try {
            // Check critical downstream dependency: Auth service.
            // Note: Audit service health deliberately does not affect Gateway readiness.
            return channel_manager_.check_connectivity(grpc::GrpcChannelManager::k_service_auth, probe_timeout_);
        } catch (...) {
            return false;
        }
    }

    std::unordered_map<std::string, std::string> GatewayHealthEvaluator::evaluate_detailed_health() noexcept {
        std::unordered_map<std::string, std::string> health_details;

        // Auth Service Health
        bool auth_ready = false;
        try {
            auth_ready = channel_manager_.check_connectivity(grpc::GrpcChannelManager::k_service_auth, probe_timeout_);
        } catch (...) {}

        health_details["auth_service"] = auth_ready ? "HEALTHY" : "UNAVAILABLE";

        // Audit Producer Health
        if (audit_metrics_) {
            health_details["audit_producer"] = audit::to_string(audit_metrics_->health_state());
        } else {
            health_details["audit_producer"] = "NOT_CONFIGURED";
        }

        return health_details;
    }

} // namespace securecloud::gateway::health
