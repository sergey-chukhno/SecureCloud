#include "http/middleware/rate_limiter_middleware.hpp"

#include "http/auth/request_context.hpp"
#include "http/errors/error_mapper.hpp"

#include <algorithm>
#include <cmath>
#include <httplib.h>

namespace securecloud::gateway::http {

RateLimiterMiddleware::RateLimiterMiddleware(GatewayRateLimitingConfig config, ClockFn clock_fn)
    : config_(config), clock_fn_(std::move(clock_fn)) {
    if (!clock_fn_) {
        clock_fn_ = [] { return std::chrono::steady_clock::now(); };
    }
}

RateLimiterMiddleware::RateLimiterMiddleware(const GatewayConfig& config, ClockFn clock_fn)
    : RateLimiterMiddleware(config.rate_limiting, std::move(clock_fn)) {}

std::string RateLimiterMiddleware::resolve_client_key(const httplib::Request& req) {
    if (const auto* rc = RequestContext::current()) {
        if (rc->is_authenticated() && rc->authenticated_context().has_value() &&
            !rc->authenticated_context()->user_id().empty()) {
            return "user:" + rc->authenticated_context()->user_id();
        }
    }

    if (req.has_header("X-Forwarded-For")) {
        auto xff = req.get_header_value("X-Forwarded-For");
        auto comma_pos = xff.find(',');
        std::string first_ip = (comma_pos != std::string::npos) ? xff.substr(0, comma_pos) : xff;
        size_t start = first_ip.find_first_not_of(" \t\r\n");
        size_t end = first_ip.find_last_not_of(" \t\r\n");
        if (start != std::string::npos && end != std::string::npos) {
            return "ip:" + first_ip.substr(start, end - start + 1);
        }
    }

    if (!req.remote_addr.empty()) {
        return "ip:" + req.remote_addr;
    }

    return "ip:anonymous";
}

RateLimiterMiddleware::AcquireResult RateLimiterMiddleware::acquire(const std::string& key) {
    if (!config_.enabled) {
        return AcquireResult{
            .allowed = true,
            .remaining = config_.burst_capacity,
            .limit = config_.burst_capacity,
            .retry_after_sec = 0,
            .reset_sec = 0,
        };
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = clock_fn_();

    auto it = client_map_.find(key);
    if (it != client_map_.end()) {
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_iter);
        it->second.lru_iter = lru_list_.begin();

        double elapsed_sec = std::chrono::duration<double>(now - it->second.last_refill).count();
        if (elapsed_sec < 0.0) {
            elapsed_sec = 0.0;
        }

        if (elapsed_sec >= static_cast<double>(config_.client_ttl.count())) {
            it->second.tokens = static_cast<double>(config_.burst_capacity);
        } else {
            it->second.tokens = std::min(static_cast<double>(config_.burst_capacity),
                                         it->second.tokens + elapsed_sec * config_.refill_rate_per_sec);
        }
        it->second.last_refill = now;
    } else {
        while (client_map_.size() >= config_.max_tracked_clients && !lru_list_.empty()) {
            const auto& oldest_key = lru_list_.back();
            client_map_.erase(oldest_key);
            lru_list_.pop_back();
        }

        lru_list_.push_front(key);
        ClientEntry entry;
        entry.tokens = static_cast<double>(config_.burst_capacity);
        entry.last_refill = now;
        entry.lru_iter = lru_list_.begin();
        it = client_map_.emplace(key, entry).first;
    }

    AcquireResult result;
    result.limit = config_.burst_capacity;

    if (it->second.tokens >= 1.0) {
        it->second.tokens -= 1.0;
        result.allowed = true;
        result.remaining = static_cast<uint32_t>(std::floor(it->second.tokens));
        result.retry_after_sec = 0;

        double missing_for_full = static_cast<double>(config_.burst_capacity) - it->second.tokens;
        if (missing_for_full <= 0.0 || config_.refill_rate_per_sec <= 0.0) {
            result.reset_sec = 0;
        } else {
            result.reset_sec = static_cast<uint32_t>(std::ceil(missing_for_full / config_.refill_rate_per_sec));
        }
    } else {
        result.allowed = false;
        result.remaining = 0;

        double missing_for_one = 1.0 - it->second.tokens;
        if (config_.refill_rate_per_sec > 0.0) {
            result.retry_after_sec = static_cast<uint32_t>(std::ceil(missing_for_one / config_.refill_rate_per_sec));
            double missing_for_full = static_cast<double>(config_.burst_capacity) - it->second.tokens;
            result.reset_sec = static_cast<uint32_t>(std::ceil(missing_for_full / config_.refill_rate_per_sec));
        } else {
            result.retry_after_sec = 1;
            result.reset_sec = 1;
        }
        if (result.retry_after_sec == 0) {
            result.retry_after_sec = 1;
        }
        if (result.reset_sec == 0) {
            result.reset_sec = 1;
        }
    }

    return result;
}

size_t RateLimiterMiddleware::tracked_client_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return client_map_.size();
}

size_t RateLimiterMiddleware::prune_expired() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto now = clock_fn_();
    size_t pruned = 0;

    auto it = lru_list_.rbegin();
    while (it != lru_list_.rend()) {
        auto map_it = client_map_.find(*it);
        if (map_it != client_map_.end()) {
            double elapsed_sec = std::chrono::duration<double>(now - map_it->second.last_refill).count();
            if (elapsed_sec >= static_cast<double>(config_.client_ttl.count())) {
                client_map_.erase(map_it);
                auto erase_iter = std::next(it).base();
                it = decltype(it)(lru_list_.erase(erase_iter));
                ++pruned;
                continue;
            }
        }
        ++it;
    }
    return pruned;
}

void RateLimiterMiddleware::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    client_map_.clear();
    lru_list_.clear();
}

std::string RateLimiterMiddleware::extract_request_id(const httplib::Request& req, const httplib::Response& res) {
    if (const auto* rc = RequestContext::current()) {
        if (!rc->request_id().empty()) {
            return rc->request_id();
        }
    }
    if (res.has_header("X-Request-ID")) {
        return res.get_header_value("X-Request-ID");
    }
    if (res.has_header("X-Request-Id")) {
        return res.get_header_value("X-Request-Id");
    }
    if (req.has_header("X-Request-ID")) {
        return req.get_header_value("X-Request-ID");
    }
    if (req.has_header("X-Request-Id")) {
        return req.get_header_value("X-Request-Id");
    }
    return "";
}

void RateLimiterMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    if (!config_.enabled) {
        next(req, res);
        return;
    }

    std::string key = resolve_client_key(req);
    auto result = acquire(key);

    if (result.allowed) {
        res.set_header("X-RateLimit-Limit", std::to_string(result.limit));
        res.set_header("X-RateLimit-Remaining", std::to_string(result.remaining));
        next(req, res);
        return;
    }

    std::string request_id = extract_request_id(req, res);

    res.status = 429;
    res.set_header("Content-Type", "application/problem+json");
    res.set_header("Retry-After", std::to_string(result.retry_after_sec));
    res.set_header("X-RateLimit-Limit", std::to_string(result.limit));
    res.set_header("X-RateLimit-Remaining", "0");
    res.set_header("X-RateLimit-Reset", std::to_string(result.reset_sec));

    res.body = ErrorMapper::format_problem_details(
        429, "https://securecloud.internal/errors/rate-limit-exceeded", "Too Many Requests",
        "Client rate limit exceeded; retry after backoff", "RATE_LIMIT_EXCEEDED", request_id);
}

} // namespace securecloud::gateway::http
