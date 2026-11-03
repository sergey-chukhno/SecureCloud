#include "service/audit_service_impl.hpp"

#include "domain/audit_event_validator.hpp"

#include <chrono>

namespace securecloud::audit::service {

namespace {

security::SecurityEventContext make_event_context(grpc::ServerContext* context, std::string_view rpc_method) {
    security::SecurityEventContext ctx;
    ctx.rpc_method = std::string(rpc_method);
    if (context) {
        ctx.peer_socket_address = context->peer();
        auto identity = security::GrpcProducerIdentityValidator::extract_peer_identity(*context);
        if (identity.is_authenticated && !identity.common_name.empty()) {
            ctx.verified_peer_identity = identity.common_name;
        }
    }
    return ctx;
}

} // namespace

AuditServiceImpl::AuditServiceImpl(std::shared_ptr<AuditIngestionService> ingestion_service,
                                   std::shared_ptr<security::InternalSecurityEventRecorder> security_recorder)
    : ingestion_service_(std::move(ingestion_service)), security_recorder_(std::move(security_recorder)) {}

void AuditServiceImpl::set_draining(bool draining) noexcept {
    draining_.store(draining, std::memory_order_release);
}

bool AuditServiceImpl::is_draining() const noexcept {
    return draining_.load(std::memory_order_acquire);
}

grpc::Status AuditServiceImpl::SubmitAuditEvent(grpc::ServerContext* context,
                                                const v1::SubmitAuditEventRequest* request,
                                                v1::SubmitAuditEventResponse* response) {

    if (draining_.load(std::memory_order_acquire)) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service is draining; retry via outbox buffer");
    }

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
        if (security_recorder_) {
            auto ctx = make_event_context(context, "SubmitAuditEvent");
            if (auth_status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
                security_recorder_->record_event(security::InternalSecurityEventType::UnauthenticatedConnection, ctx);
            } else if (auth_status.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
                ctx.metadata["declared_producer"] = v1::ProducerServiceProto_Name(proto_event.producer_service());
                security_recorder_->record_event(security::InternalSecurityEventType::ProducerIdentityMismatch, ctx);
            }
        }
        return auth_status;
    }

    auto domain_event = AuditProtoMapper::to_domain(proto_event);
    auto result = ingestion_service_->ingest_single(domain_event);

    if (!result.success) {
        if (security_recorder_) {
            auto val_res = domain::AuditEventValidator::validate(domain_event);
            for (const auto& err : val_res.errors()) {
                if (err.code == domain::AuditValidationErrorCode::SensitiveDataDetected) {
                    auto ctx = make_event_context(context, "SubmitAuditEvent");
                    if (!domain_event.correlation_id.empty()) {
                        ctx.correlation_id = domain_event.correlation_id;
                    }
                    ctx.metadata["field"] = err.field;
                    security_recorder_->record_event(security::InternalSecurityEventType::SensitiveDataDetected, ctx);
                } else if (err.code == domain::AuditValidationErrorCode::ClockSkewFuture ||
                           err.code == domain::AuditValidationErrorCode::ClockSkewTooOld) {
                    auto ctx = make_event_context(context, "SubmitAuditEvent");
                    if (!domain_event.correlation_id.empty()) {
                        ctx.correlation_id = domain_event.correlation_id;
                    }
                    ctx.metadata["error_code"] = std::string(domain::to_string(err.code));
                    security_recorder_->record_event(security::InternalSecurityEventType::ExcessiveClockSkew, ctx);
                }
            }
        }
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

    if (draining_.load(std::memory_order_acquire)) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service is draining; retry via outbox buffer");
    }

    if (context->IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Client cancelled request");
    }

    if (!request) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Null request batch");
    }

    if (request->events_size() > 100) {
        if (security_recorder_) {
            auto ctx = make_event_context(context, "BatchSubmitAuditEvents");
            ctx.metadata["batch_size"] = std::to_string(request->events_size());
            security_recorder_->record_event(security::InternalSecurityEventType::OversizedBatchRejected, ctx);
        }
    }

    for (const auto& event_proto : request->events()) {
        auto auth_status = security::GrpcProducerIdentityValidator::validate_peer_context(
            *context, v1::ProducerServiceProto_Name(event_proto.producer_service()));
        if (!auth_status.ok()) {
            if (security_recorder_) {
                auto ctx = make_event_context(context, "BatchSubmitAuditEvents");
                if (auth_status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
                    security_recorder_->record_event(security::InternalSecurityEventType::UnauthenticatedConnection,
                                                     ctx);
                } else if (auth_status.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
                    ctx.metadata["declared_producer"] = v1::ProducerServiceProto_Name(event_proto.producer_service());
                    security_recorder_->record_event(security::InternalSecurityEventType::ProducerIdentityMismatch,
                                                     ctx);
                }
            }
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

    if (security_recorder_) {
        for (const auto& evt : domain_events) {
            auto val_res = domain::AuditEventValidator::validate(evt);
            for (const auto& err : val_res.errors()) {
                if (err.code == domain::AuditValidationErrorCode::SensitiveDataDetected) {
                    auto ctx = make_event_context(context, "BatchSubmitAuditEvents");
                    if (!evt.correlation_id.empty()) {
                        ctx.correlation_id = evt.correlation_id;
                    }
                    ctx.metadata["field"] = err.field;
                    security_recorder_->record_event(security::InternalSecurityEventType::SensitiveDataDetected, ctx);
                } else if (err.code == domain::AuditValidationErrorCode::ClockSkewFuture ||
                           err.code == domain::AuditValidationErrorCode::ClockSkewTooOld) {
                    auto ctx = make_event_context(context, "BatchSubmitAuditEvents");
                    if (!evt.correlation_id.empty()) {
                        ctx.correlation_id = evt.correlation_id;
                    }
                    ctx.metadata["error_code"] = std::string(domain::to_string(err.code));
                    security_recorder_->record_event(security::InternalSecurityEventType::ExcessiveClockSkew, ctx);
                }
            }
        }
    }

    return grpc::Status::OK;
}

grpc::Status AuditServiceImpl::map_error_to_grpc_status(const IngestionResult& result) {
    if (result.outcome_status == ingestion::IngestionOutcomeStatus::IdempotencyConflict ||
        result.error_code == "ALREADY_EXISTS") {
        return grpc::Status(grpc::StatusCode::ALREADY_EXISTS, result.error_message);
    }
    if (result.outcome_status == ingestion::IngestionOutcomeStatus::QueueOverloaded ||
        result.error_code == "BATCH_SIZE_EXCEEDED" || result.error_code == "RESOURCE_EXHAUSTED") {
        return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, result.error_message);
    }
    if (result.outcome_status == ingestion::IngestionOutcomeStatus::PersistenceAmbiguous ||
        result.error_code == "DEADLINE_EXCEEDED") {
        return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, result.error_message);
    }
    if (result.outcome_status == ingestion::IngestionOutcomeStatus::PersistenceFailed ||
        result.error_code == "REPOSITORY_ERROR" || result.error_code == "CLICKHOUSE_ERROR" ||
        result.error_code == "DATABASE_ERROR" || result.error_code == "PERSISTENCE_FAILED" ||
        result.error_code == "UNAVAILABLE") {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, result.error_message);
    }
    if (result.outcome_status == ingestion::IngestionOutcomeStatus::UnauthorizedProducer ||
        result.error_code == "UNAUTHORIZED" || result.error_code == "UNAUTHENTICATED") {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, result.error_message);
    }
    if (result.error_code == "PERMISSION_DENIED") {
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, result.error_message);
    }
    return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, result.error_message);
}

} // namespace securecloud::audit::service
