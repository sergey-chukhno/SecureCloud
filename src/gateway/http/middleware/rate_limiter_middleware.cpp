#include "http/middleware/rate_limiter_middleware.hpp"

#include "http/auth/authenticated_context.hpp"
#include "http/auth/authentication_middleware.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>

namespace securecloud::gateway::http {

RateLimiterMiddleware::RateLimiterMiddleware(GatewayRateLimitingConfig config,
                                               std::shared_ptr<audit::IGatewayAuditProducer> audit_producer,
                                               ClockFn clock_fn)
    : config_(config),
      audit_producer_(std::move(audit_producer)),
      clock_fn_(std::move(clock_fn)) {}

RateLimiterMiddleware::RateLimiterMiddleware(const GatewayConfig& config,
                                               std::shared_ptr<audit::IGatewayAuditProducer> audit_producer,
                                               ClockFn clock_fn)
    : RateLimiterMiddleware(config.rate_limiting, std::move(audit_producer), std::move(clock_fn)) {}

void RateLimiterMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    if (!config_.enabled) {
        next(req, res);
        return;
    }

    const std::string key = resolve_client_key(req);
    const auto acquire_res = acquire(key);

    res.set_header("X-RateLimit-Limit", std::to_string(acquire_res.limit));
    res.set_header("X-RateLimit-Remaining", std::to_string(acquire_res.remaining));
    res.set_header("X-RateLimit-Reset", std::to_string(acquire_res.reset_sec));

    if (!acquire_res.allowed) {
        res.set_header("Retry-After", std::to_string(acquire_res.retry_after_sec));

        const std::string req_id = extract_request_id(req, res);

        if (audit_producer_) {
            audit::GatewayAuditObservation obs;
            obs.type = audit::GatewayAuditEventType::RateLimitExceeded;
            obs.client_ip = req.remote_addr;
            obs.route_class = req.path;
            obs.http_method = req.method;
            obs.client_request_id = req_id;

            if (auto auth_ctx = AuthenticationMiddleware::get_context(req)) {
                obs.actor_id = auth_ctx->user_id();
                obs.device_id = auth_ctx->device_id();
                obs.session_id = auth_ctx->session_id();
            }

            obs.metadata["limit"] = std::to_string(acquire_res.limit);
            obs.metadata["key"] = key;

            audit_producer_->record_observation(obs);
        }

        nlohmann::json problem = {
            {"type", "https://securecloud.local/errors/rate-limit-exceeded"},
            {"title", "Rate Limit Exceeded"},
            {"status", 429},
            {"detail", "Too many requests from identity/IP key within the rate limit window."},
            {"instance", "/requests/" + req_id}
        };
        res.status = 429;
        res.set_content(problem.dump(), "application/problem+json");
        return;
    }

    next(req, res);
}

RateLimiterMiddleware::AcquireResult RateLimiterMiddleware::acquire(const std::string& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto now_tp = clock_fn_ ? clock_fn_() : std::chrono::steady_clock::now();
    const auto epoch_sec = std::chrono::duration_cast<std::chrono::seconds>(now_tp.time_since_epoch()).count();

    auto it = client_map_.find(key);

    if (it == client_map_.end()) {
        if (client_map_.size() >= config_.max_tracked_clients && !lru_list_.empty()) {
            const std::string oldest_key = lru_list_.back();
            client_map_.erase(oldest_key);
            lru_list_.pop_back();
        }

        lru_list_.push_front(key);
        ClientEntry entry{
            .tokens = static_cast<double>(config_.burst_capacity) - 1.0,
            .last_refill = now_tp,
            .lru_iter = lru_list_.begin()
        };
        client_map_.emplace(key, entry);

        return AcquireResult{
            .allowed = true,
            .remaining = config_.burst_capacity > 0 ? config_.burst_capacity - 1 : 0,
            .limit = config_.burst_capacity,
            .retry_after_sec = 0,
            .reset_sec = static_cast<uint32_t>(epoch_sec + 1)
        };
    }

    lru_list_.erase(it->second.lru_iter);
    lru_list_.push_front(key);
    it->second.lru_iter = lru_list_.begin();

    auto& entry = it->second;
    const auto elapsed_sec = std::chrono::duration_cast<std::chrono::duration<double>>(now_tp - entry.last_refill).count();
    entry.last_refill = now_tp;

    entry.tokens = std::min(static_cast<double>(config_.burst_capacity),
                            entry.tokens + (elapsed_sec * config_.refill_rate_per_sec));

    if (entry.tokens >= 1.0) {
        entry.tokens -= 1.0;
        const uint32_t remaining = static_cast<uint32_t>(std::floor(entry.tokens));

        return AcquireResult{
            .allowed = true,
            .remaining = remaining,
            .limit = config_.burst_capacity,
            .retry_after_sec = 0,
            .reset_sec = static_cast<uint32_t>(epoch_sec + 1)
        };
    }

    const double missing_tokens = 1.0 - entry.tokens;
    const uint32_t retry_after = static_cast<uint32_t>(std::ceil(missing_tokens / config_.refill_rate_per_sec));

    return AcquireResult{
        .allowed = false,
        .remaining = 0,
        .limit = config_.burst_capacity,
        .retry_after_sec = std::max(1u, retry_after),
        .reset_sec = static_cast<uint32_t>(epoch_sec + retry_after)
    };
}

std::string RateLimiterMiddleware::resolve_client_key(const httplib::Request& req) {
    if (auto auth_ctx = AuthenticationMiddleware::get_context(req)) {
        if (!auth_ctx->user_id().empty()) {
            return "usr:" + auth_ctx->user_id();
        }
    }
    if (!req.remote_addr.empty()) {
        return "ip:" + req.remote_addr;
    }
    return "ip:127.0.0.1";
}

size_t RateLimiterMiddleware::tracked_client_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return client_map_.size();
}

size_t RateLimiterMiddleware::prune_expired() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now_tp = clock_fn_ ? clock_fn_() : std::chrono::steady_clock::now();
    size_t pruned_count = 0;

    for (auto it = client_map_.begin(); it != client_map_.end();) {
        if (now_tp - it->second.last_refill > config_.client_ttl) {
            lru_list_.erase(it->second.lru_iter);
            it = client_map_.erase(it);
            ++pruned_count;
        } else {
            ++it;
        }
    }

    return pruned_count;
}

void RateLimiterMiddleware::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    client_map_.clear();
    lru_list_.clear();
}

std::string RateLimiterMiddleware::extract_request_id(const httplib::Request& req, const httplib::Response& res) {
    if (req.has_header("X-Request-ID")) {
        return req.get_header_value("X-Request-ID");
    }
    if (res.has_header("X-Request-ID")) {
        return res.get_header_value("X-Request-ID");
    }
    return "unknown";
}

} // namespace securecloud::gateway::http
