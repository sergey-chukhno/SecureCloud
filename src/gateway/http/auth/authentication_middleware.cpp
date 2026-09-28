#include "http/auth/authentication_middleware.hpp"

#include "http/auth/bearer_token_extractor.hpp"
#include "http/auth/header_sanitizer.hpp"
#include "http/error_mapper.hpp"

#include <httplib.h>
#include <stdexcept>
#include <utility>

namespace securecloud::gateway::http {
namespace {

thread_local const AuthenticatedContext* tl_current_authenticated_context = nullptr;

struct ScopedContextBinding {
    explicit ScopedContextBinding(const AuthenticatedContext* ctx) noexcept { tl_current_authenticated_context = ctx; }
    ~ScopedContextBinding() noexcept { tl_current_authenticated_context = nullptr; }

    ScopedContextBinding(const ScopedContextBinding&) = delete;
    ScopedContextBinding& operator=(const ScopedContextBinding&) = delete;
    ScopedContextBinding(ScopedContextBinding&&) = delete;
    ScopedContextBinding& operator=(ScopedContextBinding&&) = delete;
};

} // namespace

AuthenticationMiddleware::AuthenticationMiddleware(std::shared_ptr<GatewaySecurityPolicy> security_policy,
                                                   std::shared_ptr<ITokenValidator> token_validator)
    : security_policy_(std::move(security_policy)), token_validator_(std::move(token_validator)) {
    if (!security_policy_) {
        throw std::invalid_argument("AuthenticationMiddleware requires a non-null GatewaySecurityPolicy instance");
    }
    if (!token_validator_) {
        throw std::invalid_argument("AuthenticationMiddleware requires a non-null ITokenValidator instance");
    }
}

void AuthenticationMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    // 0. Extract optional session ID hint before perimeter sanitization
    std::string session_id;
    if (req.has_header("x-session-id")) {
        session_id = req.get_header_value("x-session-id");
    }

    // 1. Sanitize untrusted perimeter identity headers in-place
    HeaderSanitizer::sanitize(const_cast<httplib::Request&>(req));

    std::string request_id;
    if (req.has_header("x-request-id")) {
        request_id = req.get_header_value("x-request-id");
    } else if (res.has_header("x-request-id")) {
        request_id = res.get_header_value("x-request-id");
    }

    // 2. Evaluate route access rule
    const auto rule = security_policy_->evaluate(req.method, req.path);

    // 3. Public bypass
    if (rule.is_public()) {
        next(req, res);
        return;
    }

    // 3. Extract Bearer token
    auto token_opt = BearerTokenExtractor::extract(req);
    if (!token_opt.has_value()) {
        res.set_header(
            "WWW-Authenticate",
            "Bearer error=\"invalid_token\", error_description=\"Missing or malformed Authorization header\"");
        ErrorMapper::write_error(res, 401, "UNAUTHENTICATED", "Missing or malformed Authorization header", request_id);
        return;
    }
    const std::string& token = token_opt.value();

    // 4. Validate token against authority
    auto val_res = token_validator_->validate(token, session_id, request_id);
    if (!val_res.has_value()) {
        const auto& err = val_res.error();
        switch (err.kind) {
        case TokenValidationErrorKind::TokenExpired:
            res.set_header("WWW-Authenticate",
                           "Bearer error=\"invalid_token\", error_description=\"The access token expired\"");
            ErrorMapper::write_error(res, 401, "TOKEN_EXPIRED",
                                     err.message.empty() ? "Access token has expired" : err.message, request_id);
            return;
        case TokenValidationErrorKind::SessionRevoked:
            res.set_header("WWW-Authenticate",
                           "Bearer error=\"invalid_token\", error_description=\"The session was revoked\"");
            ErrorMapper::write_error(
                res, 401, "SESSION_REVOKED",
                err.message.empty() ? "Session has been revoked or is no longer active" : err.message, request_id);
            return;
        case TokenValidationErrorKind::ServiceUnavailable:
            res.set_header("Retry-After", "5");
            ErrorMapper::write_error(res, 503, "SERVICE_UNAVAILABLE",
                                     err.message.empty() ? "Authentication authority unavailable" : err.message,
                                     request_id);
            return;
        case TokenValidationErrorKind::InvalidSignature:
        case TokenValidationErrorKind::MalformedToken:
            res.set_header(
                "WWW-Authenticate",
                "Bearer error=\"invalid_token\", error_description=\"Invalid token signature or structure\"");
            ErrorMapper::write_error(res, 401, "INVALID_TOKEN",
                                     err.message.empty() ? "Invalid access token" : err.message, request_id);
            return;
        case TokenValidationErrorKind::MfaRequired:
            ErrorMapper::write_error(res, 403, "MFA_REQUIRED",
                                     err.message.empty() ? "Multi-factor authentication (MFA) required" : err.message,
                                     request_id);
            return;
        case TokenValidationErrorKind::InsufficientScope:
            ErrorMapper::write_error(res, 403, "INSUFFICIENT_SCOPE",
                                     err.message.empty() ? "Token lacks required authorization scope" : err.message,
                                     request_id);
            return;
        case TokenValidationErrorKind::InternalError:
        default:
            ErrorMapper::write_error(res, 500, "INTERNAL_ERROR", "Internal authentication failure", request_id);
            return;
        }
    }

    const auto& ctx = val_res.value();

    // 5. Enforce route assurance level (MFA)
    if (rule.requires_mfa() && !ctx.is_mfa_verified()) {
        ErrorMapper::write_error(res, 403, "MFA_REQUIRED",
                                 "Endpoint requires verified multi-factor authentication (MFA)", request_id);
        return;
    }

    // 6. Enforce mandatory route scopes
    for (const auto& scope : rule.required_scopes) {
        if (!ctx.has_scope(scope)) {
            ErrorMapper::write_error(res, 403, "INSUFFICIENT_SCOPE",
                                     "Token lacks required authorization scope: " + scope, request_id);
            return;
        }
    }

    // 7. Bind verified context to execution scope and proceed downstream
    ScopedContextBinding binding(&ctx);
    next(req, res);
}

std::optional<AuthenticatedContext> AuthenticationMiddleware::get_context(const httplib::Request& /*req*/) {
    if (tl_current_authenticated_context != nullptr) {
        return *tl_current_authenticated_context;
    }
    return std::nullopt;
}

} // namespace securecloud::gateway::http
