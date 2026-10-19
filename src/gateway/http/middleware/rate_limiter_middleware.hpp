#pragma once

#include "gateway_config.hpp"
#include "http/middleware/middleware.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace httplib {
struct Request;
struct Response;
} // namespace httplib

namespace securecloud::gateway::http {

/// Token-bucket rate limiter middleware enforcing per-identity or per-IP throttling
/// with strictly bounded LRU memory tracking (ADR-009, ADR-010, GW-009-T02).
class RateLimiterMiddleware : public Middleware {
  public:
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    struct AcquireResult {
        bool allowed{false};
        uint32_t remaining{0};
        uint32_t limit{0};
        uint32_t retry_after_sec{0};
        uint32_t reset_sec{0};
    };

    explicit RateLimiterMiddleware(GatewayRateLimitingConfig config, ClockFn clock_fn = nullptr);
    explicit RateLimiterMiddleware(const GatewayConfig& config, ClockFn clock_fn = nullptr);
    ~RateLimiterMiddleware() override = default;

    RateLimiterMiddleware(const RateLimiterMiddleware&) = delete;
    RateLimiterMiddleware& operator=(const RateLimiterMiddleware&) = delete;
    RateLimiterMiddleware(RateLimiterMiddleware&&) noexcept = delete;
    RateLimiterMiddleware& operator=(RateLimiterMiddleware&&) noexcept = delete;

    void process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) override;

    /// Attempts token acquisition for a given identity key.
    [[nodiscard]] AcquireResult acquire(const std::string& key);

    /// Resolves client key: extracts authenticated user_id if present; falls back to client IP.
    [[nodiscard]] static std::string resolve_client_key(const httplib::Request& req);

    /// Returns current number of tracked clients in LRU memory cache.
    [[nodiscard]] size_t tracked_client_count() const;

    /// Prunes idle client entries exceeding client_ttl. Returns count of pruned entries.
    size_t prune_expired();

    /// Clears all tracked clients (primarily for test resets).
    void clear();

    [[nodiscard]] const GatewayRateLimitingConfig& config() const noexcept { return config_; }

  private:
    struct ClientEntry {
        double tokens{0.0};
        std::chrono::steady_clock::time_point last_refill;
        std::list<std::string>::iterator lru_iter;
    };

    static std::string extract_request_id(const httplib::Request& req, const httplib::Response& res);

    GatewayRateLimitingConfig config_;
    ClockFn clock_fn_;
    mutable std::mutex mutex_;
    std::list<std::string> lru_list_;
    std::unordered_map<std::string, ClientEntry> client_map_;
};

} // namespace securecloud::gateway::http
