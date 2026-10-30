#include "service/audit_service_impl.hpp"

#include <chrono>

namespace securecloud::audit::service {

AuditServiceImpl::AuditServiceImpl(std::shared_ptr<AuditIngestionService> ingestion_service)
    : ingestion_service_(std::move(ingestion_service)) {}

grpc::Status AuditServiceImpl::SubmitAuditEvent(grpc::ServerContext* context,
                                                const v1::SubmitAuditEventRequest* request,
                                                v1::SubmitAuditEventResponse* response) {

    if (context->IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Client cancelled request");
    }

    if (!request || !request->has_event()) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Missing event payload");
    }

    const auto& proto_event = request->event();

    auto auth_status = security::GrpcProducerIdentityValidator::validate_peer_context(
        *context, v1::ProducerServiceProto_Name(proto_event.producer_service()));
    if (!auth_status.ok()) {
        return auth_status;
    }

    auto domain_event = AuditProtoMapper::to_domain(proto_event);
    auto result = ingestion_service_->ingest_single(domain_event);

    if (!result.success) {
        return map_error_to_grpc_status(result);
    }

    response->set_success(true);
    response->set_event_id(domain_event.event_id.to_string());

    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(result.received_at.time_since_epoch()).count();
    response->set_received_at_ms(millis);

    return grpc::Status::OK;
}

grpc::Status AuditServiceImpl::BatchSubmitAuditEvents(grpc::ServerContext* context,
                                                      const v1::BatchSubmitAuditEventsRequest* request,
                                                      v1::BatchSubmitAuditEventsResponse* response) {

    if (context->IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Client cancelled request");
    }

    if (!request) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Null request batch");
    }

    for (const auto& event_proto : request->events()) {
        auto auth_status = security::GrpcProducerIdentityValidator::validate_peer_context(
            *context, v1::ProducerServiceProto_Name(event_proto.producer_service()));
        if (!auth_status.ok()) {
            return auth_status;
        }
    }

    std::vector<domain::AuditEvent> domain_events;
    domain_events.reserve(static_cast<size_t>(request->events_size()));
    for (const auto& event_proto : request->events()) {
        domain_events.push_back(AuditProtoMapper::to_domain(event_proto));
    }

    auto batch_res = ingestion_service_->ingest_batch(domain_events);

    response->set_accepted_count(batch_res.accepted_count);
    response->set_rejected_count(batch_res.rejected_count);

    for (const auto& [event_id, item_res] : batch_res.item_results) {
        if (!item_res.success) {
            response->add_rejected_event_ids(event_id.to_string());
        }
    }

    return grpc::Status::OK;
}

grpc::Status AuditServiceImpl::map_error_to_grpc_status(const IngestionResult& result) {
    if (result.error_code == "BATCH_SIZE_EXCEEDED") {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, result.error_message);
    }
    if (result.error_code == "UNAUTHORIZED" || result.error_code == "UNAUTHENTICATED") {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, result.error_message);
    }
    if (result.error_code == "PERMISSION_DENIED") {
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, result.error_message);
    }
    if (result.error_code == "REPOSITORY_ERROR") {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, result.error_message);
    }
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, result.error_message);
}

} // namespace securecloud::audit::service