#include "http/middleware/drain_middleware.hpp"

#include "http/auth/request_context.hpp"
#include "http/middleware/request_id_middleware.hpp"

#include <httplib.h>
#include <stdexcept>
#include <utility>

namespace securecloud::gateway::http {

DrainMiddleware::DrainMiddleware(std::shared_ptr<DrainManager> drain_manager)
    : drain_manager_(std::move(drain_manager)) {
    if (!drain_manager_) {
        throw std::invalid_argument("DrainMiddleware: drain_manager must not be null");
    }
}

void DrainMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    // Diagnostic and health endpoints are always allowed to pass through so orchestrators
    // and probes can observe NOT_SERVING / SERVING status without being blocked by drain rejection.
    if (req.path == "/health/live" || req.path == "/health/ready") {
        next(req, res);
        return;
    }

    DrainLease lease;
    if (!drain_manager_->try_acquire(lease)) {
        std::string request_id;
        if (const auto* rc = RequestContext::current()) {
            request_id = rc->request_id();
        }
        if (request_id.empty() && res.has_header(RequestIdMiddleware::k_request_id_header)) {
            request_id = res.get_header_value(RequestIdMiddleware::k_request_id_header);
        }
        if (request_id.empty() && req.has_header(RequestIdMiddleware::k_request_id_header)) {
            request_id = req.get_header_value(RequestIdMiddleware::k_request_id_header);
        }

        DrainManager::write_rejection(res, request_id);
        return;
    }

    next(req, res);
}

} // namespace securecloud::gateway::http
