#include "http/middleware.hpp"

#include <httplib.h>
#include <ranges>
#include <utility>

namespace securecloud::gateway::http {

void MiddlewarePipeline::use(std::shared_ptr<Middleware> middleware) {
    if (middleware) {
        middlewares_.push_back(std::move(middleware));
    }
}

void MiddlewarePipeline::execute(const httplib::Request& req, httplib::Response& res,
                                 const NextHandler& terminal_handler) const {
    NextHandler current = terminal_handler;
    for (const auto& mw : std::views::reverse(middlewares_)) {
        auto next = current;
        current = [mw, next](const httplib::Request& r, httplib::Response& s) { mw->process(r, s, next); };
    }
    current(req, res);
}

} // namespace securecloud::gateway::http
