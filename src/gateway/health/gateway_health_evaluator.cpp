#include "health/gateway_health_evaluator.hpp"

namespace securecloud::gateway::health {

GatewayHealthEvaluator::GatewayHealthEvaluator(grpc::GrpcChannelManager& channel_manager,
                                               std::chrono::milliseconds probe_timeout)
    : channel_manager_(channel_manager), probe_timeout_(probe_timeout) {}

bool GatewayHealthEvaluator::evaluate_readiness() noexcept {
    try {
        // Check critical downstream dependency: Auth service
        return channel_manager_.check_connectivity(grpc::GrpcChannelManager::k_service_auth, probe_timeout_);
    } catch (...) {
        return false;
    }
}

} // namespace securecloud::gateway::health
