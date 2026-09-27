#include "http/auth/auth_service_token_validator.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

namespace securecloud::gateway::http {

AuthServiceTokenValidator::AuthServiceTokenValidator(
    std::shared_ptr<securecloud::gateway::grpc::IAuthClient> auth_client, TokenValidatorOptions options)
    : auth_client_(std::move(auth_client)), options_(options) {
    if (!auth_client_) {
        throw std::invalid_argument("AuthServiceTokenValidator requires a non-null IAuthClient instance");
    }
}

AuthenticatedResult AuthServiceTokenValidator::validate(const std::string& token, const std::string& session_id,
                                                        const std::string& request_id) {
    if (token.empty()) {
        return TokenValidationError{TokenValidationErrorKind::InvalidSignature, "Bearer token must not be empty"};
    }

    const auto now = std::chrono::system_clock::now();
    const std::string cache_key = build_cache_key(token, session_id);

    // Fast-path: Consult short-lived in-memory cache
    if (options_.cache_ttl.count() > 0) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = cache_.find(cache_key);
        if (it != cache_.end()) {
            if (now < it->second.valid_until) {
                return it->second.context;
            }
            cache_.erase(it);
        }
    }

    // Prepare gRPC ValidateSessionRequest
    securecloud::auth::v1::ValidateSessionRequest req;
    req.set_access_token(token);
    if (!session_id.empty()) {
        req.set_session_id(session_id);
    }

    securecloud::gateway::grpc::CallContextOptions call_options{
        .timeout = options_.rpc_timeout,
        .request_id = request_id,
        .client_service = "gateway",
    };
    securecloud::gateway::grpc::ClientCallContext call_ctx(call_options);

    auto rpc_result = auth_client_->validate_session(req, call_ctx);
    if (!rpc_result.has_value()) {
        const auto& err = rpc_result.error();
        switch (err.kind) {
        case securecloud::gateway::grpc::DependencyErrorKind::Timeout:
        case securecloud::gateway::grpc::DependencyErrorKind::ServiceUnavailable:
            return TokenValidationError{TokenValidationErrorKind::ServiceUnavailable, err.message};
        case securecloud::gateway::grpc::DependencyErrorKind::Unauthenticated:
        case securecloud::gateway::grpc::DependencyErrorKind::InvalidArgument:
            return TokenValidationError{TokenValidationErrorKind::InvalidSignature, err.message};
        case securecloud::gateway::grpc::DependencyErrorKind::NotFound:
            return TokenValidationError{TokenValidationErrorKind::SessionRevoked, err.message};
        default:
            return TokenValidationError{TokenValidationErrorKind::InternalError, err.message};
        }
    }

    const auto& resp = rpc_result.value();
    if (!resp.is_valid()) {
        return TokenValidationError{TokenValidationErrorKind::SessionRevoked,
                                    "Session or token is revoked or no longer active"};
    }

    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (resp.expires_at_epoch_ms() > 0 && resp.expires_at_epoch_ms() <= now_ms) {
        return TokenValidationError{TokenValidationErrorKind::TokenExpired, "Access token has expired"};
    }

    std::vector<std::string> scopes{"access"};
    AuthenticatedContext context(resp.user_id(), resp.device_id(), session_id, resp.authentication_level(),
                                 std::move(scopes), resp.expires_at_epoch_ms());

    // Update in-memory cache if caching is active
    if (options_.cache_ttl.count() > 0) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        evict_expired_or_overflow_locked(now);

        auto token_expiry_tp =
            resp.expires_at_epoch_ms() > 0
                ? std::chrono::system_clock::time_point(std::chrono::milliseconds(resp.expires_at_epoch_ms()))
                : now + options_.cache_ttl;
        auto valid_until = std::min(now + options_.cache_ttl, token_expiry_tp);
        cache_[cache_key] = CacheEntry{context, valid_until};
    }

    return context;
}

void AuthServiceTokenValidator::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_.clear();
}

size_t AuthServiceTokenValidator::cache_size() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_.size();
}

std::string AuthServiceTokenValidator::build_cache_key(const std::string& token, const std::string& session_id) const {
    std::string key;
    key.reserve(token.size() + session_id.size() + 1);
    key.append(token);
    key.push_back('\x1f');
    key.append(session_id);
    return key;
}

void AuthServiceTokenValidator::evict_expired_or_overflow_locked(std::chrono::system_clock::time_point now) {
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (it->second.valid_until <= now) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }

    while (cache_.size() >= options_.max_cache_entries && !cache_.empty()) {
        cache_.erase(cache_.begin());
    }
}

} // namespace securecloud::gateway::http
