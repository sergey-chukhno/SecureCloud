#include "http/resilience/deadline_manager.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <httplib.h>
#include <string>
#include <string_view>

namespace securecloud::gateway::http {
namespace {

std::string_view trim_whitespace(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

bool iequals(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

} // namespace

DeadlineManager::DeadlineManager(GatewayServiceDeadlinesConfig config, ClockFn clock_fn) noexcept
    : config_(config), clock_fn_(std::move(clock_fn)) {}

std::chrono::steady_clock::time_point DeadlineManager::now() const noexcept {
    if (clock_fn_) {
        return clock_fn_();
    }
    return std::chrono::steady_clock::now();
}

std::optional<std::chrono::milliseconds> DeadlineManager::parse_duration_string(std::string_view str) noexcept {
    std::string_view s = trim_whitespace(str);
    if (s.empty()) {
        return std::nullopt;
    }

    // Check for "ms" suffix
    if (s.size() > 2 && iequals(s.substr(s.size() - 2), "ms")) {
        std::string_view num_str = trim_whitespace(s.substr(0, s.size() - 2));
        uint64_t val = 0;
        auto [ptr, ec] = std::from_chars(num_str.data(), num_str.data() + num_str.size(), val);
        if (ec == std::errc{} && ptr == num_str.data() + num_str.size() && val > 0) {
            return std::chrono::milliseconds(val);
        }
        return std::nullopt;
    }

    // Check for "s" suffix (e.g. "2s", "1.5s")
    if (s.size() > 1 && (s.back() == 's' || s.back() == 'S')) {
        std::string_view num_str = trim_whitespace(s.substr(0, s.size() - 1));
        std::string null_terminated(num_str);
        char* end_ptr = nullptr;
        double val = std::strtod(null_terminated.c_str(), &end_ptr);
        if (end_ptr == null_terminated.c_str() + null_terminated.size() && val > 0.0) {
            auto ms = static_cast<uint64_t>(val * 1000.0);
            return std::chrono::milliseconds(std::max<uint64_t>(1, ms));
        }
        return std::nullopt;
    }

    // Default: plain integer milliseconds
    uint64_t val = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), val);
    if (ec == std::errc{} && ptr == s.data() + s.size() && val > 0) {
        return std::chrono::milliseconds(val);
    }

    return std::nullopt;
}

std::optional<std::chrono::milliseconds> DeadlineManager::extract_client_timeout(const httplib::Request& req) noexcept {
    if (req.has_header("X-Request-Timeout")) {
        auto val = parse_duration_string(req.get_header_value("X-Request-Timeout"));
        if (val.has_value()) {
            return val;
        }
    }
    if (req.has_header("Request-Timeout")) {
        auto val = parse_duration_string(req.get_header_value("Request-Timeout"));
        if (val.has_value()) {
            return val;
        }
    }
    return std::nullopt;
}

std::chrono::milliseconds
DeadlineManager::compute_effective_deadline(const httplib::Request& req,
                                            std::chrono::milliseconds default_timeout) const noexcept {
    auto client_timeout = extract_client_timeout(req);
    if (!client_timeout.has_value()) {
        return default_timeout;
    }

    const auto min_floor = std::chrono::milliseconds(config_.min_request_deadline_ms);
    const auto max_ceiling = std::chrono::milliseconds(config_.max_request_deadline_ms);

    return std::clamp(*client_timeout, min_floor, max_ceiling);
}

std::chrono::milliseconds
DeadlineManager::compute_downstream_budget(std::chrono::steady_clock::time_point start_tp,
                                           std::chrono::milliseconds effective_deadline,
                                           std::chrono::milliseconds service_timeout) const noexcept {
    const auto current_tp = now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_tp - start_tp);

    if (elapsed >= effective_deadline) {
        return std::chrono::milliseconds{0};
    }

    const auto remaining = effective_deadline - elapsed;
    return std::min(service_timeout, remaining);
}

bool DeadlineManager::has_sufficient_budget(std::chrono::steady_clock::time_point start_tp,
                                            std::chrono::milliseconds effective_deadline,
                                            std::chrono::milliseconds minimum_required) const noexcept {
    const auto current_tp = now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_tp - start_tp);

    if (elapsed >= effective_deadline) {
        return false;
    }

    const auto remaining = effective_deadline - elapsed;
    return remaining >= minimum_required;
}

} // namespace securecloud::gateway::http
