#pragma once

#include <httplib.h>
#include <string_view>

namespace securecloud::gateway::http {

/**
 * @brief Perimeter security utility for sanitizing untrusted client identity headers.
 *
 * Ensures that incoming HTTP requests from external clients cannot inject spoofed
 * identity headers (e.g., X-User-Id, X-Device-Id, X-Auth-Level, X-Scopes, X-Authenticated-*).
 * This guarantees that downstream middleware and route handlers rely exclusively on
 * authoritative AuthenticatedContext objects produced by cryptographic token validation.
 */
class HeaderSanitizer {
  public:
    /// Checks whether a header name matches perimeter-reserved untrusted identity headers (case-insensitive)
    [[nodiscard]] static bool is_identity_header(std::string_view header_name) noexcept;

    /// Strips all untrusted identity headers from the incoming request in-place.
    static void sanitize(httplib::Request& req);
};

} // namespace securecloud::gateway::http
