#pragma once

#include "domain/enums.hpp"

#include <grpcpp/server_context.hpp>
#include <grpcpp/support/status.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace securecloud::audit::security {

    class ProducerIdentityValidator {
    public:
        // Extracts client certificate identity (SAN or CN) from gRPC ServerContext
        [[nodiscard]] static std::optional<std::string> extract_peer_identity(
            const grpc::ServerContext& context);

        // Maps an FQDN (e.g., auth.securecloud.internal) to a canonical service name (e.g., auth)
        [[nodiscard]] static std::optional<std::string> map_san_to_producer_service(
            std::string_view san_identity);

        // Validates whether the certificate identity matches the declared producer_service
        [[nodiscard]] static bool validate_producer_identity(
            const std::string& cert_identity,
            const std::string& declared_producer);

        // Performs full gRPC verification and returns appropriate status (OK, UNAUTHENTICATED, PERMISSION_DENIED)
        [[nodiscard]] static grpc::Status validate_peer_context(
            const grpc::ServerContext& context,
            const std::string& declared_producer);
    };

} // namespace securecloud::audit::security