#include "service/audit_query_service_impl.hpp"

#include "domain/audit_event_mapper.hpp"
#include "repository/audit_repository_exceptions.hpp"
#include "security/grpc_producer_identity_validator.hpp"

#include <chrono>

namespace securecloud::audit::service {

namespace {

domain::ProducerService from_proto_producer(securecloud::audit::v1::ProducerServiceProto proto) {
    switch (proto) {
    case securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY:
        return domain::ProducerService::Gateway;
    case securecloud::audit::v1::PRODUCER_SERVICE_AUTH:
        return domain::ProducerService::Auth;
    case securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING:
        return domain::ProducerService::Messaging;
    case securecloud::audit::v1::PRODUCER_SERVICE_FILES:
        return domain::ProducerService::Files;
    case securecloud::audit::v1::PRODUCER_SERVICE_AUDIT:
        return domain::ProducerService::Audit;
    default:
        return domain::ProducerService::Audit;
    }
}

domain::Severity from_proto_severity(securecloud::audit::v1::SeverityProto proto) {
    switch (proto) {
    case securecloud::audit::v1::SEVERITY_INFO:
        return domain::Severity::Info;
    case securecloud::audit::v1::SEVERITY_WARNING:
        return domain::Severity::Warning;
    case securecloud::audit::v1::SEVERITY_SECURITY:
        return domain::Severity::Security;
    case securecloud::audit::v1::SEVERITY_CRITICAL:
        return domain::Severity::Critical;
    default:
        return domain::Severity::Info;
    }
}

domain::ActorType from_proto_actor_type(securecloud::audit::v1::ActorTypeProto proto) {
    switch (proto) {
    case securecloud::audit::v1::ACTOR_TYPE_USER:
        return domain::ActorType::User;
    case securecloud::audit::v1::ACTOR_TYPE_DEVICE:
        return domain::ActorType::Device;
    case securecloud::audit::v1::ACTOR_TYPE_SERVICE:
        return domain::ActorType::Service;
    case securecloud::audit::v1::ACTOR_TYPE_SYSTEM:
        return domain::ActorType::System;
    default:
        return domain::ActorType::Unknown;
    }
}

domain::TargetType from_proto_target_type(securecloud::audit::v1::TargetTypeProto proto) {
    switch (proto) {
    case securecloud::audit::v1::TARGET_TYPE_USER:
        return domain::TargetType::User;
    case securecloud::audit::v1::TARGET_TYPE_DEVICE:
        return domain::TargetType::Device;
    case securecloud::audit::v1::TARGET_TYPE_CONVERSATION:
        return domain::TargetType::Conversation;
    case securecloud::audit::v1::TARGET_TYPE_FILE:
        return domain::TargetType::File;
    case securecloud::audit::v1::TARGET_TYPE_SERVICE:
        return domain::TargetType::Service;
    default:
        return domain::TargetType::Unknown;
    }
}

query::SortOrder from_proto_sort_order(securecloud::audit::v1::SortOrderProto proto) {
    switch (proto) {
    case securecloud::audit::v1::SORT_ORDER_ASC:
        return query::SortOrder::Ascending;
    case securecloud::audit::v1::SORT_ORDER_DESC:
    default:
        return query::SortOrder::Descending;
    }
}

} // namespace

AuditQueryServiceImpl::AuditQueryServiceImpl(std::shared_ptr<query::AuditQueryApplicationService> app_service)
    : app_service_(std::move(app_service)) {}

grpc::Status AuditQueryServiceImpl::QueryAuditEvents(grpc::ServerContext* context,
                                                     const securecloud::audit::v1::QueryAuditEventsRequest* request,
                                                     securecloud::audit::v1::QueryAuditEventsResponse* response) {

    if (!context || !request || !response) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Context, request, or response pointer is null");
    }

    if (context->IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Query request was cancelled by client");
    }

    auto caller_identity = security::GrpcProducerIdentityValidator::extract_peer_identity(*context);

    // Context / Proto Request -> QueryFilter
    query::AuditQueryFilter filter;

    if (request->has_start_occurred_at_ms()) {
        filter.start_occurred_at =
            std::chrono::system_clock::time_point(std::chrono::milliseconds(request->start_occurred_at_ms()));
    }
    if (request->has_end_occurred_at_ms()) {
        filter.end_occurred_at =
            std::chrono::system_clock::time_point(std::chrono::milliseconds(request->end_occurred_at_ms()));
    }

    for (int i = 0; i < request->producer_services_size(); ++i) {
        filter.producer_services.push_back(from_proto_producer(request->producer_services(i)));
    }

    for (int i = 0; i < request->event_types_size(); ++i) {
        filter.event_types.push_back(request->event_types(i));
    }

    for (int i = 0; i < request->severities_size(); ++i) {
        filter.severities.push_back(from_proto_severity(request->severities(i)));
    }

    if (request->has_actor_type()) {
        filter.actor_type = from_proto_actor_type(request->actor_type());
    }
    if (request->has_actor_id()) {
        filter.actor_id = request->actor_id();
    }

    if (request->has_target_type()) {
        filter.target_type = from_proto_target_type(request->target_type());
    }
    if (request->has_target_id()) {
        filter.target_id = request->target_id();
    }

    if (request->has_correlation_id()) {
        filter.correlation_id = request->correlation_id();
    }

    filter.page_size = request->page_size();
    filter.page_token = request->page_token();
    filter.sort_order = from_proto_sort_order(request->sort_order());

    query::AuditQueryPageResult domain_result;
    grpc::Status status;

    try {
        status = app_service_->execute_query(caller_identity, filter, domain_result);
    } catch (const repository::ClickHouseTimeoutException&) {
        return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "ClickHouse query execution deadline exceeded");
    } catch (const repository::ClickHouseConnectionException&) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit storage temporarily unavailable");
    } catch (const repository::ClickHouseQueryException&) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit storage temporarily unavailable");
    } catch (...) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "Internal error occurred during query execution");
    }

    if (!status.ok()) {
        return status;
    }

    // Domain Result -> Proto Response
    for (const auto& ev : domain_result.events) {
        *response->add_events() = domain::AuditEventMapper::to_persisted_proto(ev);
    }

    response->set_next_page_token(domain_result.next_page_token);
    response->set_has_more(domain_result.has_more);
    response->set_effective_page_size(domain_result.effective_page_size);

    return grpc::Status::OK;
}

grpc::Status AuditQueryServiceImpl::GetAuditEventById(grpc::ServerContext* context,
                                                      const securecloud::audit::v1::GetAuditEventByIdRequest* request,
                                                      securecloud::audit::v1::GetAuditEventByIdResponse* response) {

    if (!context || !request || !response) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Context, request, or response pointer is null");
    }

    if (context->IsCancelled()) {
        return grpc::Status(grpc::StatusCode::CANCELLED, "Lookup request was cancelled by client");
    }

    auto caller_identity = security::GrpcProducerIdentityValidator::extract_peer_identity(*context);
    std::optional<domain::AuditEvent> domain_event;
    grpc::Status status;

    try {
        status = app_service_->get_event_by_id(caller_identity, request->event_id(), domain_event);
    } catch (const repository::ClickHouseTimeoutException&) {
        return grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "ClickHouse lookup execution deadline exceeded");
    } catch (const repository::ClickHouseConnectionException&) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit storage temporarily unavailable");
    } catch (const repository::ClickHouseQueryException&) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Audit storage temporarily unavailable");
    } catch (...) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "Internal error occurred during lookup execution");
    }

    if (!status.ok()) {
        return status;
    }

    if (domain_event.has_value()) {
        *response->mutable_event() = domain::AuditEventMapper::to_persisted_proto(*domain_event);
    }

    return grpc::Status::OK;
}

} // namespace securecloud::audit::service