#pragma once

#include "http/auth/authenticated_context.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/middleware/middleware.hpp"

#include <memory>
#include <string>
#include <vector>

namespace securecloud::gateway::http {

/**
 * @brief Perimeter authorization middleware enforcing coarse scope and assurance levels.
 *
 * Sits downstream of AuthenticationMiddleware in the Router pipeline:
 * 1. Allows Public routes to pass immediately.
 * 2. Requires AuthenticatedContext for Protected and Sensitive routes (fail-closed 401).
 * 3. Enforces MFA verification and minimum authentication assurance levels (403 MFA_REQUIRED).
 * 4. Enforces attested device binding requirements (403 DEVICE_BINDING_REQUIRED).
 * 5. Evaluates exact, wildcard, and alternative scopes (403 INSUFFICIENT_SCOPE with missing_scopes).
 */
class AuthorizationMiddleware : public Middleware {
  public:
    explicit AuthorizationMiddleware(std::shared_ptr<GatewaySecurityPolicy> security_policy);
    ~AuthorizationMiddleware() override = default;

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;

  private:
    std::shared_ptr<GatewaySecurityPolicy> security_policy_;

    static void write_problem_details(httplib::Response& res, int http_status, const std::string& code,
                                      const std::string& type_suffix, const std::string& title,
                                      const std::string& detail, const std::string& request_id,
                                      const std::vector<std::string>& missing_scopes = {});
};

} // namespace securecloud::gateway::http
