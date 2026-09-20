#pragma once

#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/health/health_status_manager.hpp"

#include <grpcpp/grpcpp.h>
#include <string>

namespace securecloud::common::health {

class HealthServiceImpl final : public securecloud::common::v1::HealthService::Service {
  public:
    explicit HealthServiceImpl(std::string service_name, HealthStatusManager& status_manager,
                               std::string expected_client_identity = "");
    ~HealthServiceImpl() override = default;

    HealthServiceImpl(const HealthServiceImpl&) = delete;
    HealthServiceImpl& operator=(const HealthServiceImpl&) = delete;
    HealthServiceImpl(HealthServiceImpl&&) = delete;
    HealthServiceImpl& operator=(HealthServiceImpl&&) = delete;

    [[nodiscard]] const std::string& service_name() const noexcept;
    [[nodiscard]] const std::string& expected_client_identity() const noexcept;
    void set_expected_client_identity(std::string expected_client_identity);

    grpc::Status Check(grpc::ServerContext* context, const securecloud::common::v1::HealthCheckRequest* request,
                       securecloud::common::v1::HealthCheckResponse* response) override;

    grpc::Status Check(const grpc::AuthContext* auth_ctx, const securecloud::common::v1::HealthCheckRequest* request,
                       securecloud::common::v1::HealthCheckResponse* response);

  private:
    std::string service_name_;
    HealthStatusManager& status_manager_;
    std::string expected_client_identity_;
};

} // namespace securecloud::common::health
