#pragma once

#include "domain/producer_identity_validator.hpp"
#include "query/audit_query_types.hpp"

#include <grpcpp/support/status.h>

namespace securecloud::audit::query {

enum class QueryAuthStatus {
    AuthorizedGlobal = 0,
    AuthorizedProducerScoped,
    Unauthenticated,
    ForbiddenScope,
    ForbiddenOperatorContractNotEnabled
};

class AuditQueryAuthorizer {
  public:
    /// Evaluates peer identity (from mTLS SAN/CN) against requested query filter scopes.
    [[nodiscard]] static grpc::Status authorize_query(const domain::PeerIdentity& peer, const AuditQueryFilter& filter);
};

} // namespace securecloud::audit::query