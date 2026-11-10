#pragma once

#include "grpc/client_call_context.hpp"
#include "grpc/dependency_error.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <memory>

namespace securecloud::gateway::grpc {

class IAuditIngestionClient {
  public:
    virtual ~IAuditIngestionClient() = default;

    virtual Result<securecloud::audit::v1::SubmitAuditEventResponse>
    submit_event(const securecloud::audit::v1::SubmitAuditEventRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::audit::v1::BatchSubmitAuditEventsResponse>
    batch_submit_events(const securecloud::audit::v1::BatchSubmitAuditEventsRequest& req, ClientCallContext& ctx) = 0;
};

} // namespace securecloud::gateway::grpc
