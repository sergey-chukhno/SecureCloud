#pragma once

#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "security/grpc_producer_identity_validator.hpp"
#include "service/audit_ingestion_service.hpp"
#include "service/audit_proto_mapper.hpp"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::audit::service {

class AuditServiceImpl final : public v1::AuditIngestionService::Service {
  public:
    explicit AuditServiceImpl(std::shared_ptr<AuditIngestionService> ingestion_service);

    grpc::Status SubmitAuditEvent(grpc::ServerContext* context, const v1::SubmitAuditEventRequest* request,
                                  v1::SubmitAuditEventResponse* response) override;

    grpc::Status BatchSubmitAuditEvents(grpc::ServerContext* context, const v1::BatchSubmitAuditEventsRequest* request,
                                        v1::BatchSubmitAuditEventsResponse* response) override;

  private:
    std::shared_ptr<AuditIngestionService> ingestion_service_;

    static grpc::Status map_error_to_grpc_status(const IngestionResult& result);
};

} // namespace securecloud::audit::service