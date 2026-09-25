#pragma once

#include "grpc/channel_manager.hpp"

#include <chrono>

namespace securecloud::gateway::health {

class GatewayHealthEvaluator {
  public:
    explicit GatewayHealthEvaluator(grpc::GrpcChannelManager& channel_manager,
                                    std::chrono::milliseconds probe_timeout = std::chrono::milliseconds(500));

    [[nodiscard]] bool evaluate_readiness() noexcept;

  private:
    grpc::GrpcChannelManager& channel_manager_;
    std::chrono::milliseconds probe_timeout_;
};

} // namespace securecloud::gateway::health
