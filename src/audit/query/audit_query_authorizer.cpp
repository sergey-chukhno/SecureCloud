#include "query/audit_query_authorizer.hpp"

#include <algorithm>
#include <optional>

namespace securecloud::audit::query {

namespace {

std::optional<domain::ProducerService> producer_service_from_cn(std::string_view cn) {
    if (cn == "auth.securecloud.internal") return domain::ProducerService::Auth;
    if (cn == "messaging.securecloud.internal") return domain::ProducerService::Messaging;
    if (cn == "files.securecloud.internal") return domain::ProducerService::Files;
    if (cn == "gateway.securecloud.internal") return domain::ProducerService::Gateway;
    if (cn == "audit.securecloud.internal") return domain::ProducerService::Audit;
    return std::nullopt;
}

} // namespace

grpc::Status AuditQueryAuthorizer::authorize_query(const domain::PeerIdentity& peer,
                                                   const AuditQueryFilter& filter) {
    if (!peer.is_authenticated) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                            "Unauthenticated: Valid mTLS peer certificate required");
    }

    // 1. Global audit service authority
    if (peer.common_name == "audit.securecloud.internal") {
        return grpc::Status::OK;
    }

    // 2. Gateway restriction (operator contract disabled)
    if (peer.common_name == "gateway.securecloud.internal") {
        bool is_gateway_self_scope = (filter.producer_services.size() == 1 &&
                                      filter.producer_services[0] == domain::ProducerService::Gateway);
        if (!is_gateway_self_scope) {
            return grpc::Status(
                grpc::StatusCode::PERMISSION_DENIED,
                "ForbiddenOperatorContractNotEnabled: Human operator cross-service access contract not enabled");
        }
        return grpc::Status::OK;
    }

    // 3. Producer-scoped authority (Auth, Messaging, Files)
    auto caller_service_opt = producer_service_from_cn(peer.common_name);
    if (caller_service_opt.has_value() &&
        (*caller_service_opt == domain::ProducerService::Auth ||
         *caller_service_opt == domain::ProducerService::Messaging ||
         *caller_service_opt == domain::ProducerService::Files)) {

        const auto caller_service = *caller_service_opt;

        if (filter.producer_services.empty()) {
            return grpc::Status(
                grpc::StatusCode::PERMISSION_DENIED,
                "ForbiddenScope: Scoped caller must explicitly filter by its own producer_service");
        }

        bool contains_only_self = std::all_of(
            filter.producer_services.begin(), filter.producer_services.end(),
            [caller_service](domain::ProducerService ps) { return ps == caller_service; });

        if (!contains_only_self) {
            return grpc::Status(
                grpc::StatusCode::PERMISSION_DENIED,
                "ForbiddenScope: Caller is unauthorized to query audit logs outside its own producer scope");
        }

        return grpc::Status::OK;
    }

    return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                        "ForbiddenScope: Peer identity is not authorized to query audit service");
}

} // namespace securecloud::audit::query