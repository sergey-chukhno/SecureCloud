#pragma once

#include "http/auth/authenticated_context.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/auth/token_validator_interface.hpp"
#include "http/middleware/middleware.hpp"

#include <memory>
#include <optional>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/**
 * @brief Perimeter authentication middleware enforcing token verification and route authorization.
 *
 * Intercepts incoming requests:
 * 1. Checks route authorization via GatewaySecurityPolicy.
 * 2. Allows public routes to bypass token extraction.
 * 3. Extracts and validates Bearer access tokens via BearerTokenExtractor and ITokenValidator.
 * 4. Enforces assurance levels (MFA) and required OAuth scopes.
 * 5. Binds verified AuthenticatedContext to the request execution scope for downstream handlers.
 * 6. Returns standard RFC 7807 problem details on authorization failures.
 */
class AuthenticationMiddleware : public Middleware {
  public:
    AuthenticationMiddleware(std::shared_ptr<GatewaySecurityPolicy> security_policy,
                             std::shared_ptr<ITokenValidator> token_validator);

    ~AuthenticationMiddleware() override = default;

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;

    /// Retrieves the verified AuthenticatedContext bound to the current request execution scope
    [[nodiscard]] static std::optional<AuthenticatedContext> get_context(const httplib::Request& req);

  private:
    std::shared_ptr<GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<ITokenValidator> token_validator_;
};

} // namespace securecloud::gateway::http
