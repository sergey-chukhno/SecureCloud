#include "http/auth/authorization_middleware.hpp"

#include "http/auth/authentication_middleware.hpp"
#include "http/auth/request_context.hpp"
#include "http/auth/scope_matcher.hpp"
#include "http/errors/error_mapper.hpp"
#include "http/routing/router.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace securecloud::gateway::http {

AuthorizationMiddleware::AuthorizationMiddleware(std::shared_ptr<GatewaySecurityPolicy> security_policy)
    : security_policy_(std::move(security_policy)) {
    if (!security_policy_) {
        throw std::invalid_argument("AuthorizationMiddleware requires a non-null GatewaySecurityPolicy instance");
    }
}

void AuthorizationMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    // 1. Resolve request ID for tracing and error reporting
    std::string request_id;
    if (req.has_header("x-request-id")) {
        request_id = req.get_header_value("x-request-id");
    } else if (res.has_header("x-request-id")) {
        request_id = res.get_header_value("x-request-id");
    } else if (const auto* req_ctx = Router::current_request_context()) {
        request_id = req_ctx->request_id();
    }

    // 2. Query declarative route security rule
    const auto rule = security_policy_->evaluate(req.method, req.path);

    // 3. Public endpoints bypass all authorization checks
    if (rule.is_public()) {
        next(req, res);
        return;
    }

    // 4. Resolve authenticated caller context (fail-closed if missing)
    std::optional<AuthenticatedContext> ctx_opt = Router::current_authenticated_context();
    if (!ctx_opt.has_value()) {
        ctx_opt = AuthenticationMiddleware::get_context(req);
    }
    if (!ctx_opt.has_value()) {
        if (const auto* req_ctx = Router::current_request_context()) {
            if (req_ctx->authenticated_context().has_value()) {
                ctx_opt = req_ctx->authenticated_context();
            }
        }
    }

    if (!ctx_opt.has_value()) {
        res.set_header("WWW-Authenticate",
                       "Bearer error=\"unauthorized\", error_description=\"Authentication required\"");
        write_problem_details(res, 401, "UNAUTHENTICATED", "unauthenticated", "Unauthorized",
                              "Authentication required for this route", request_id);
        return;
    }

    const auto& ctx = ctx_opt.value();

    // 5. Evaluate Multi-Factor Authentication (MFA) requirement
    if (rule.requires_mfa() && !ctx.is_mfa_verified()) {
        write_problem_details(res, 403, "MFA_REQUIRED", "mfa-required", "MFA Required",
                              "Operation requires multi-factor authentication", request_id);
        return;
    }

    // 6. Evaluate minimum authentication assurance level
    if (static_cast<int>(ctx.authentication_level()) < static_cast<int>(rule.min_auth_level)) {
        write_problem_details(res, 403, "INSUFFICIENT_ASSURANCE", "insufficient-assurance", "Forbidden",
                              "Authentication assurance level is insufficient", request_id);
        return;
    }

    // 7. Evaluate attested device binding requirement
    if (rule.requires_device_bound() && ctx.device_id().empty()) {
        write_problem_details(res, 403, "DEVICE_BINDING_REQUIRED", "device-binding-required", "Device Binding Required",
                              "Endpoint requires an attested device binding", request_id);
        return;
    }

    // 8. Evaluate required and alternative permission scopes via ScopeMatcher
    bool scopes_satisfied = true;
    std::vector<std::string> missing_scopes;

    if (!rule.required_scopes.empty()) {
        scopes_satisfied = ScopeMatcher::has_all_scopes(ctx.scopes(), rule.required_scopes);
        if (!scopes_satisfied) {
            missing_scopes = ScopeMatcher::find_missing_scopes(ctx.scopes(), rule.required_scopes);
        }
    } else if (!rule.alternative_scopes.empty()) {
        scopes_satisfied = false;
    }

    if (!scopes_satisfied && !rule.alternative_scopes.empty()) {
        if (ScopeMatcher::has_any_scope(ctx.scopes(), rule.alternative_scopes)) {
            scopes_satisfied = true;
            missing_scopes.clear();
        }
    }

    if (!scopes_satisfied) {
        std::string detail = "Token lacks required authorization scope";
        if (!missing_scopes.empty()) {
            detail += ": " + missing_scopes[0];
        }
        write_problem_details(res, 403, "INSUFFICIENT_SCOPE", "insufficient-scope", "Forbidden", detail, request_id,
                              missing_scopes);
        return;
    }

    // 9. All authorization gates satisfied — dispatch downstream
    next(req, res);
}

void AuthorizationMiddleware::write_problem_details(httplib::Response& res, int http_status, const std::string& code,
                                                    const std::string& type_suffix, const std::string& title,
                                                    const std::string& detail, const std::string& request_id,
                                                    const std::vector<std::string>& missing_scopes) {
    res.status = http_status;

    nlohmann::json j;
    j["type"] = "https://securecloud.internal/errors/" + type_suffix;
    j["title"] = title;
    j["status"] = http_status;
    j["detail"] = detail;
    if (!request_id.empty()) {
        j["request_id"] = request_id;
    }
    if (!missing_scopes.empty()) {
        j["missing_scopes"] = missing_scopes;
    }

    // Canonical nested error object for ErrorMapper client compatibility
    nlohmann::json err_obj = nlohmann::json::object();
    err_obj["code"] = code;
    err_obj["message"] = detail;
    if (code == "MFA_REQUIRED") {
        err_obj["assurance_error"] = "INSUFFICIENT_AUTHENTICATION_ASSURANCE";
        j["assurance_error"] = "INSUFFICIENT_AUTHENTICATION_ASSURANCE";
    }
    if (!request_id.empty()) {
        err_obj["request_id"] = request_id;
    }
    j["error"] = std::move(err_obj);

    res.set_content(j.dump(), "application/json");
}

} // namespace securecloud::gateway::http
