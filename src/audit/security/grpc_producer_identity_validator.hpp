#pragma once

#include "domain/enums.hpp"
#include "domain/producer_identity_validator.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <string>

namespace securecloud::audit::security {

class GrpcProducerIdentityValidator {
  public:
    /// Controls whether peer verification is bypassed (for unit testing in non-TLS environments).
    static void set_bypass_peer_verification_for_testing(bool bypass) noexcept;

    /// Extracts mTLS peer credentials from gRPC ServerContext into domain PeerIdentity.
    [[nodiscard]] static domain::PeerIdentity extract_peer_identity(const grpc::ServerContext& context);

    /// Validates gRPC peer context against the declared producer service enum.
    [[nodiscard]] static grpc::Status validate_peer_context(const grpc::ServerContext& context,
                                                            domain::ProducerService declared_producer);

    /// Validates gRPC peer context against the declared producer service string.
    [[nodiscard]] static grpc::Status validate_peer_context(const grpc::ServerContext& context,
                                                            const std::string& declared_producer);
};

} // namespace securecloud::audit::security
