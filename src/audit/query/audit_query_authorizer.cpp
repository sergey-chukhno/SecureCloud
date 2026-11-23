#include "query/audit_query_authorizer.hpp"

namespace securecloud::audit::query {

namespace {} // namespace

grpc::Status AuditQueryAuthorizer::authorize_query(const domain::PeerIdentity& peer, const AuditQueryFilter& filter) {
    if (!peer.is_authenticated) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Unauthenticated: Valid mTLS peer certificate required");
    }

    // 1. Global audit service authority
    if (domain::ProducerIdentityValidator::matches_peer_identity(domain::ProducerService::Audit, peer)) {
        return grpc::Status::OK;
    }

    // 2. Gateway restriction (operator contract disabled)
    if (domain::ProducerIdentityValidator::matches_peer_identity(domain::ProducerService::Gateway, peer)) {
        bool is_gateway_self_scope =
            (filter.producer_services.size() == 1 && filter.producer_services[0] == domain::ProducerService::Gateway);
        if (!is_gateway_self_scope) {
            return grpc::Status(
                grpc::StatusCode::PERMISSION_DENIED,
                "ForbiddenOperatorContractNotEnabled: Human operator cross-service access contract not enabled");
        }
        return grpc::Status::OK;
    }

    // 3. Producer-scoped authority (Auth, Messaging, Files)
    for (const auto caller_service :
         {domain::ProducerService::Auth, domain::ProducerService::Messaging, domain::ProducerService::Files}) {
        if (!domain::ProducerIdentityValidator::matches_peer_identity(caller_service, peer)) {
            continue;
        }

        if (filter.producer_services.empty()) {
            return grpc::Status(grpc::StatusCode::PERMISSION_DENIED,
                                "ForbiddenScope: Scoped caller must explicitly filter by its own producer_service");
        }

        bool contains_only_self =
            std::all_of(filter.producer_services.begin(), filter.producer_services.end(),
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
