#pragma once

#include "query/audit_query_application_service.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::audit::service {

/// Implémentation gRPC de transport pour le service Read-Only AuditQueryService.
class AuditQueryServiceImpl final : public securecloud::audit::v1::AuditQueryService::Service {
  public:
    explicit AuditQueryServiceImpl(std::shared_ptr<query::AuditQueryApplicationService> app_service);

    ~AuditQueryServiceImpl() override = default;

    grpc::Status QueryAuditEvents(grpc::ServerContext* context,
                                  const securecloud::audit::v1::QueryAuditEventsRequest* request,
                                  securecloud::audit::v1::QueryAuditEventsResponse* response) override;

    grpc::Status GetAuditEventById(grpc::ServerContext* context,
                                   const securecloud::audit::v1::GetAuditEventByIdRequest* request,
                                   securecloud::audit::v1::GetAuditEventByIdResponse* response) override;

  private:
    std::shared_ptr<query::AuditQueryApplicationService> app_service_;
};

} // namespace securecloud::audit::service