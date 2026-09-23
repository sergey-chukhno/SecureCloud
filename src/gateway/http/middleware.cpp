#include "http/middleware.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <httplib.h>
#include <iostream>
#include <openssl/rand.h>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr size_t k_uuid_byte_count = 16;
constexpr size_t k_uuid_string_buffer_size = 36;
constexpr unsigned int k_uuid_version_mask = 0x0FU;
constexpr unsigned int k_uuid_version_4 = 0x40U;
constexpr unsigned int k_uuid_variant_mask = 0x3FU;
constexpr unsigned int k_uuid_variant_rfc4122 = 0x80U;
constexpr size_t k_uuid_version_byte_index = 6;
constexpr size_t k_uuid_variant_byte_index = 8;

constexpr size_t k_uuid_hyphen_pos_1 = 4;
constexpr size_t k_uuid_hyphen_pos_2 = 6;
constexpr size_t k_uuid_hyphen_pos_3 = 8;
constexpr size_t k_uuid_hyphen_pos_4 = 10;
constexpr unsigned int k_nibble_shift = 4U;
constexpr unsigned int k_nibble_mask = 0x0FU;

constexpr std::string_view k_hex_digits = "0123456789abcdef";

} // namespace

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

std::string RequestIdMiddleware::generate_uuid_v4() {
    std::array<uint8_t, k_uuid_byte_count> bytes{};
    RAND_bytes(bytes.data(), static_cast<int>(bytes.size()));

    auto v_masked = static_cast<unsigned int>(bytes[k_uuid_version_byte_index]) & k_uuid_version_mask;
    bytes[k_uuid_version_byte_index] = static_cast<uint8_t>(v_masked | k_uuid_version_4);

    auto var_masked = static_cast<unsigned int>(bytes[k_uuid_variant_byte_index]) & k_uuid_variant_mask;
    bytes[k_uuid_variant_byte_index] = static_cast<uint8_t>(var_masked | k_uuid_variant_rfc4122);

    std::string result;
    result.reserve(k_uuid_string_buffer_size);

    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i == k_uuid_hyphen_pos_1 || i == k_uuid_hyphen_pos_2 || i == k_uuid_hyphen_pos_3 ||
            i == k_uuid_hyphen_pos_4) {
            result.push_back('-');
        }
        auto high = (static_cast<unsigned int>(bytes[i]) >> k_nibble_shift) & k_nibble_mask;
        auto low = static_cast<unsigned int>(bytes[i]) & k_nibble_mask;
        result.push_back(k_hex_digits[high]);
        result.push_back(k_hex_digits[low]);
    }

    return result;
}

void RequestIdMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    std::string req_id;
    if (req.has_header(k_request_id_header)) {
        req_id = req.get_header_value(k_request_id_header);
    }
    if (req_id.empty()) {
        req_id = generate_uuid_v4();
    }

    res.set_header(k_request_id_header, req_id);
    next(req, res);
    if (!res.has_header(k_request_id_header)) {
        res.set_header(k_request_id_header, req_id);
    }
}

LoggingMiddleware::LoggingMiddleware(LogSink sink) : sink_(std::move(sink)) {}

bool LoggingMiddleware::is_sensitive_auth_route(const std::string& path) noexcept {
    return path.starts_with("/auth") || path.starts_with("/api/v1/auth");
}

void LoggingMiddleware::process(const httplib::Request& req, httplib::Response& res, const NextHandler& next) {
    auto start_time = std::chrono::steady_clock::now();

    next(req, res);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_time);

    std::string req_id;
    if (res.has_header(RequestIdMiddleware::k_request_id_header)) {
        req_id = res.get_header_value(RequestIdMiddleware::k_request_id_header);
    }

    std::string line = "[HTTP] " + req.method + " " + req.path + " -> " + std::to_string(res.status) + " (" +
                       std::to_string(elapsed.count()) + "ms)";
    if (!req_id.empty()) {
        line += " [" + req_id + "]";
    }

    if (sink_) {
        sink_(line);
    } else {
        std::cout << line << "\n";
    }
}

} // namespace securecloud::gateway::http
