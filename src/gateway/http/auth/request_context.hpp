#pragma once

#include "http/auth/authenticated_context.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace securecloud::gateway::http {

/**
 * @brief Request-scoped execution context managing correlation metadata and authenticated identity.
 *
 * RequestContext provides unified access to request-scoped metadata (correlation ID, client IP,
 * request timestamp) and the optional authenticated identity context established at the Gateway perimeter.
 *
 * Context lifecycle is strictly managed via RAII using ScopedRequestContext, ensuring deterministic
 * cleanup across thread pools and exception unwinding.
 */
class RequestContext {
  public:
    RequestContext(std::string request_id, std::string client_ip, int64_t request_timestamp_ms,
                   std::optional<AuthenticatedContext> auth_context = std::nullopt);

    [[nodiscard]] const std::string& request_id() const noexcept { return request_id_; }
    [[nodiscard]] const std::string& client_ip() const noexcept { return client_ip_; }
    [[nodiscard]] int64_t request_timestamp_ms() const noexcept { return request_timestamp_ms_; }
    [[nodiscard]] bool is_authenticated() const noexcept { return auth_context_.has_value(); }
    [[nodiscard]] const std::optional<AuthenticatedContext>& authenticated_context() const noexcept {
        return auth_context_;
    }

    /// Access the active RequestContext bound to the current executing thread, or nullptr if none
    [[nodiscard]] static const RequestContext* current() noexcept;

    /// Sets the active thread-local RequestContext (internal to ScopedRequestContext)
    static void set_current(const RequestContext* ctx) noexcept;

  private:
    std::string request_id_;
    std::string client_ip_;
    int64_t request_timestamp_ms_{0};
    std::optional<AuthenticatedContext> auth_context_;
};

/**
 * @brief RAII guard binding a RequestContext to the current thread for the duration of a scope.
 *
 * Guarantees exception-safe and deterministic cleanup of thread-local execution context,
 * preventing cross-request identity leakage across thread pool workers.
 */
class ScopedRequestContext {
  public:
    explicit ScopedRequestContext(const RequestContext& ctx) noexcept;
    ~ScopedRequestContext() noexcept;

    ScopedRequestContext(const ScopedRequestContext&) = delete;
    ScopedRequestContext& operator=(const ScopedRequestContext&) = delete;
    ScopedRequestContext(ScopedRequestContext&&) = delete;
    ScopedRequestContext& operator=(ScopedRequestContext&&) = delete;

  private:
    const RequestContext* previous_ctx_{nullptr};
};

} // namespace securecloud::gateway::http
