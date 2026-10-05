#include "http/auth/authentication_middleware.hpp"

#include "http/auth/bearer_token_extractor.hpp"
#include "http/auth/header_sanitizer.hpp"
#include "http/auth/request_context.hpp"
#include "http/auth/scope_matcher.hpp"
#include "http/errors/error_mapper.hpp"

#include <chrono>
#include <httplib.h>
#include <nlohmann/json.hpp>
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

    int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    std::string client_ip = req.remote_addr;

    // 2. Evaluate route access rule
    const auto rule = security_policy_->evaluate(req.method, req.path);

    // 3. Public bypass
    if (rule.is_public()) {
        RequestContext req_ctx(request_id, client_ip, now_ms, std::nullopt);
        ScopedRequestContext scoped_req_ctx(req_ctx);
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

    // 5. Evaluate Multi-Factor Authentication (MFA) requirement
    if (rule.requires_mfa() && !ctx.is_mfa_verified()) {
        res.status = 403;
        nlohmann::json j;
        j["type"] = "https://securecloud.internal/errors/mfa-required";
        j["title"] = "MFA Required";
        j["status"] = 403;
        j["detail"] = "Endpoint requires verified multi-factor authentication (MFA)";
        if (!request_id.empty()) {
            j["request_id"] = request_id;
        }
        nlohmann::json err_obj = nlohmann::json::object();
        err_obj["code"] = "MFA_REQUIRED";
        err_obj["message"] = "Endpoint requires verified multi-factor authentication (MFA)";
        if (!request_id.empty()) {
            err_obj["request_id"] = request_id;
        }
        j["error"] = std::move(err_obj);
        res.set_content(j.dump(), "application/json");
        return;
    }

    // 6. Evaluate minimum authentication assurance level
    if (static_cast<int>(ctx.authentication_level()) < static_cast<int>(rule.min_auth_level)) {
        res.status = 403;
        nlohmann::json j;
        j["type"] = "https://securecloud.internal/errors/insufficient-assurance";
        j["title"] = "Forbidden";
        j["status"] = 403;
        j["detail"] = "Authentication assurance level is insufficient";
        if (!request_id.empty()) {
            j["request_id"] = request_id;
        }
        nlohmann::json err_obj = nlohmann::json::object();
        err_obj["code"] = "INSUFFICIENT_ASSURANCE";
        err_obj["message"] = "Authentication assurance level is insufficient";
        if (!request_id.empty()) {
            err_obj["request_id"] = request_id;
        }
        j["error"] = std::move(err_obj);
        res.set_content(j.dump(), "application/json");
        return;
    }

    // 7. Evaluate attested device binding requirement
    if (rule.requires_device_bound() && ctx.device_id().empty()) {
        res.status = 403;
        nlohmann::json j;
        j["type"] = "https://securecloud.internal/errors/device-binding-required";
        j["title"] = "Device Binding Required";
        j["status"] = 403;
        j["detail"] = "Endpoint requires an attested device binding";
        if (!request_id.empty()) {
            j["request_id"] = request_id;
        }
        nlohmann::json err_obj = nlohmann::json::object();
        err_obj["code"] = "DEVICE_BINDING_REQUIRED";
        err_obj["message"] = "Endpoint requires an attested device binding";
        if (!request_id.empty()) {
            err_obj["request_id"] = request_id;
        }
        j["error"] = std::move(err_obj);
        res.set_content(j.dump(), "application/json");
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
        res.status = 403;
        std::string detail = "Token lacks required authorization scope";
        if (!missing_scopes.empty()) {
            detail += ": " + missing_scopes[0];
        }
        nlohmann::json j;
        j["type"] = "https://securecloud.internal/errors/insufficient-scope";
        j["title"] = "Forbidden";
        j["status"] = 403;
        j["detail"] = detail;
        if (!request_id.empty()) {
            j["request_id"] = request_id;
        }
        if (!missing_scopes.empty()) {
            j["missing_scopes"] = missing_scopes;
        }
        nlohmann::json err_obj = nlohmann::json::object();
        err_obj["code"] = "INSUFFICIENT_SCOPE";
        err_obj["message"] = detail;
        if (!request_id.empty()) {
            err_obj["request_id"] = request_id;
        }
        j["error"] = std::move(err_obj);
        res.set_content(j.dump(), "application/json");
        return;
    }

    // 7. Bind verified context to execution scope and proceed downstream
    RequestContext req_ctx(request_id, client_ip, now_ms, ctx);
    ScopedRequestContext scoped_req_ctx(req_ctx);
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
