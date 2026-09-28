#include "http/auth/request_context.hpp"

#include <utility>

namespace securecloud::gateway::http {
namespace {

thread_local const RequestContext* tl_current_request_context = nullptr;

} // namespace

RequestContext::RequestContext(std::string request_id, std::string client_ip, int64_t request_timestamp_ms,
                               std::optional<AuthenticatedContext> auth_context)
    : request_id_(std::move(request_id)), client_ip_(std::move(client_ip)), request_timestamp_ms_(request_timestamp_ms),
      auth_context_(std::move(auth_context)) {}

const RequestContext* RequestContext::current() noexcept {
    return tl_current_request_context;
}

void RequestContext::set_current(const RequestContext* ctx) noexcept {
    tl_current_request_context = ctx;
}

ScopedRequestContext::ScopedRequestContext(const RequestContext& ctx) noexcept
    : previous_ctx_(RequestContext::current()) {
    RequestContext::set_current(&ctx);
}

ScopedRequestContext::~ScopedRequestContext() noexcept {
    RequestContext::set_current(previous_ctx_);
}

} // namespace securecloud::gateway::http
