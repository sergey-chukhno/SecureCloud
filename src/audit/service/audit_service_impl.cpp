#include "service/audit_service_impl.hpp"

#include "domain/audit_event_validator.hpp"
#include "telemetry/audit_metrics.hpp"

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

telemetry::ProducerLabel map_producer_label(domain::ProducerService producer) noexcept {
    switch (producer) {
    case domain::ProducerService::Gateway:
        return telemetry::ProducerLabel::Gateway;
    case domain::ProducerService::Auth:
        return telemetry::ProducerLabel::Auth;
    case domain::ProducerService::Messaging:
        return telemetry::ProducerLabel::Messaging;
    case domain::ProducerService::Files:
        return telemetry::ProducerLabel::Files;
    case domain::ProducerService::Audit:
        return telemetry::ProducerLabel::Audit;
    default:
        return telemetry::ProducerLabel::Unknown;
    }
}

telemetry::SeverityLabel map_severity_label(domain::Severity severity) noexcept {
    switch (severity) {
    case domain::Severity::Info:
        return telemetry::SeverityLabel::Info;
    case domain::Severity::Warning:
        return telemetry::SeverityLabel::Warning;
    case domain::Severity::Security:
        return telemetry::SeverityLabel::Security;
    case domain::Severity::Critical:
        return telemetry::SeverityLabel::Critical;
    default:
        return telemetry::SeverityLabel::Info;
    }
}

void record_rejection_reason_metric(telemetry::AuditMetrics& metrics, domain::AuditValidationErrorCode code) noexcept {
    switch (code) {
    case domain::AuditValidationErrorCode::SensitiveDataDetected:
        metrics.record_rejected_event(telemetry::RejectionReason::SensitiveData);
        break;
    case domain::AuditValidationErrorCode::ClockSkewFuture:
    case domain::AuditValidationErrorCode::ClockSkewTooOld:
        metrics.record_rejected_event(telemetry::RejectionReason::ClockSkew);
        break;
    case domain::AuditValidationErrorCode::InvalidEventId:
    case domain::AuditValidationErrorCode::EventIdNotUuidV7:
        metrics.record_rejected_event(telemetry::RejectionReason::MalformedUuid);
        break;
    case domain::AuditValidationErrorCode::PayloadOversized:
    case domain::AuditValidationErrorCode::ActorIdOversized:
    case domain::AuditValidationErrorCode::TargetIdOversized:
        metrics.record_rejected_event(telemetry::RejectionReason::OversizedPayload);
        break;
    default:
        break;
    }
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

    auto& metrics = telemetry::AuditMetrics::instance();

    if (draining_.load(std::memory_order_acquire)) {
        metrics.record_ingestion_request(telemetry::RpcType::SubmitAuditEvent, telemetry::RequestStatus::Rejected);
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service is draining; retry via outbox buffer");
    }

    if (context->IsCancelled()) {
        metrics.record_ingestion_request(telemetry::RpcType::SubmitAuditEvent, telemetry::RequestStatus::Error);
        return grpc::Status(grpc::StatusCode::CANCELLED, "Client cancelled request");
    }

    if (!request || !request->has_event()) {
        metrics.record_ingestion_request(telemetry::RpcType::SubmitAuditEvent, telemetry::RequestStatus::Rejected);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Missing event payload");
    }

    const auto& proto_event = request->event();

    auto auth_status = security::GrpcProducerIdentityValidator::validate_peer_context(
        *context, v1::ProducerServiceProto_Name(proto_event.producer_service()));
    if (!auth_status.ok()) {
        metrics.record_ingestion_request(telemetry::RpcType::SubmitAuditEvent, telemetry::RequestStatus::Rejected);
        if (auth_status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
            metrics.record_rejected_event(telemetry::RejectionReason::Unauthenticated);
        } else if (auth_status.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
            metrics.record_rejected_event(telemetry::RejectionReason::ProducerMismatch);
        }

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
    auto producer_lbl = map_producer_label(domain_event.producer_service);
    auto severity_lbl = map_severity_label(domain_event.severity);

    metrics.record_ingested_event(producer_lbl, severity_lbl);

    auto result = ingestion_service_->ingest_single(domain_event);

    if (!result.success) {
        if (result.outcome_status == ingestion::IngestionOutcomeStatus::IdempotencyConflict ||
            result.error_code == "ALREADY_EXISTS") {
            metrics.record_duplicate_event(producer_lbl);
        }
        if (result.outcome_status == ingestion::IngestionOutcomeStatus::QueueOverloaded) {
            metrics.record_rejected_event(telemetry::RejectionReason::QueueSaturated);
        }

        auto val_res = domain::AuditEventValidator::validate(domain_event);
        for (const auto& err : val_res.errors()) {
            record_rejection_reason_metric(metrics, err.code);
            if (security_recorder_) {
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

        auto status = map_error_to_grpc_status(result);
        metrics.record_ingestion_request(telemetry::RpcType::SubmitAuditEvent,
                                         status.error_code() == grpc::StatusCode::INVALID_ARGUMENT ||
                                                 status.error_code() == grpc::StatusCode::ALREADY_EXISTS
                                             ? telemetry::RequestStatus::Rejected
                                             : telemetry::RequestStatus::Error);
        return status;
    }

    metrics.record_ingestion_request(telemetry::RpcType::SubmitAuditEvent, telemetry::RequestStatus::Success);

    response->set_success(true);
    response->set_event_id(domain_event.event_id.to_string());

    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(result.received_at.time_since_epoch()).count();
    response->set_received_at_ms(millis);

    return grpc::Status::OK;
}

grpc::Status AuditServiceImpl::BatchSubmitAuditEvents(grpc::ServerContext* context,
                                                      const v1::BatchSubmitAuditEventsRequest* request,
                                                      v1::BatchSubmitAuditEventsResponse* response) {

    auto& metrics = telemetry::AuditMetrics::instance();

    if (draining_.load(std::memory_order_acquire)) {
        metrics.record_ingestion_request(telemetry::RpcType::BatchSubmitAuditEvents,
                                         telemetry::RequestStatus::Rejected);
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit service is draining; retry via outbox buffer");
    }

    if (context->IsCancelled()) {
        metrics.record_ingestion_request(telemetry::RpcType::BatchSubmitAuditEvents, telemetry::RequestStatus::Error);
        return grpc::Status(grpc::StatusCode::CANCELLED, "Client cancelled request");
    }

    if (!request) {
        metrics.record_ingestion_request(telemetry::RpcType::BatchSubmitAuditEvents,
                                         telemetry::RequestStatus::Rejected);
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Null request batch");
    }

    if (request->events_size() > 100) {
        metrics.record_rejected_event(telemetry::RejectionReason::OversizedBatch);
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
            metrics.record_ingestion_request(telemetry::RpcType::BatchSubmitAuditEvents,
                                             telemetry::RequestStatus::Rejected);
            if (auth_status.error_code() == grpc::StatusCode::UNAUTHENTICATED) {
                metrics.record_rejected_event(telemetry::RejectionReason::Unauthenticated);
            } else if (auth_status.error_code() == grpc::StatusCode::PERMISSION_DENIED) {
                metrics.record_rejected_event(telemetry::RejectionReason::ProducerMismatch);
            }
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
        auto devt = AuditProtoMapper::to_domain(event_proto);
        auto p_lbl = map_producer_label(devt.producer_service);
        auto s_lbl = map_severity_label(devt.severity);
        metrics.record_ingested_event(p_lbl, s_lbl);
        domain_events.push_back(std::move(devt));
    }

    auto batch_res = ingestion_service_->ingest_batch(domain_events);

    response->set_accepted_count(batch_res.accepted_count);
    response->set_rejected_count(batch_res.rejected_count);

    for (const auto& [event_id, item_res] : batch_res.item_results) {
        if (!item_res.success) {
            response->add_rejected_event_ids(event_id.to_string());
            if (item_res.outcome_status == ingestion::IngestionOutcomeStatus::IdempotencyConflict ||
                item_res.error_code == "ALREADY_EXISTS") {
                telemetry::ProducerLabel p_lbl = telemetry::ProducerLabel::Unknown;
                for (const auto& devt : domain_events) {
                    if (devt.event_id == event_id) {
                        p_lbl = map_producer_label(devt.producer_service);
                        break;
                    }
                }
                metrics.record_duplicate_event(p_lbl);
            }
            if (item_res.outcome_status == ingestion::IngestionOutcomeStatus::QueueOverloaded) {
                metrics.record_rejected_event(telemetry::RejectionReason::QueueSaturated);
            }
        }
    }

    if (security_recorder_) {
        for (const auto& evt : domain_events) {
            auto val_res = domain::AuditEventValidator::validate(evt);
            for (const auto& err : val_res.errors()) {
                record_rejection_reason_metric(metrics, err.code);
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

    metrics.record_ingestion_request(telemetry::RpcType::BatchSubmitAuditEvents,
                                     batch_res.rejected_count > 0 ? telemetry::RequestStatus::Rejected
                                                                  : telemetry::RequestStatus::Success);

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
