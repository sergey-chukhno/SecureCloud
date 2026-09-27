#pragma once

#include "http/auth/authenticated_context.hpp"
#include "http/auth/token_validation_result.hpp"

#include <string>

namespace securecloud::gateway::http {

/**
 * @brief Abstract interface defining perimeter token validation semantics.
 *
 * Decouples the HTTP layer and AuthenticationMiddleware from the concrete
 * transport mechanisms (e.g. gRPC calls to AuthService, local cryptographic validation,
 * or caching layers).
 */
class ITokenValidator {
  public:
    virtual ~ITokenValidator() = default;

    /**
     * @brief Validates an access token and optional session identifier.
     *
     * @param token Bearer token extracted from HTTP authorization header.
     * @param session_id Optional session identifier (if provided via cookie or header).
     * @param request_id Optional correlation ID propagated for distributed tracing.
     * @return AuthenticatedResult containing AuthenticatedContext on success, or TokenValidationError.
     */
    virtual AuthenticatedResult validate(const std::string& token, const std::string& session_id = "",
                                         const std::string& request_id = "") = 0;
};

} // namespace securecloud::gateway::http
