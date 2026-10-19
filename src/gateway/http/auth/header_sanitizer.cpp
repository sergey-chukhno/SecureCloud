#include "http/auth/header_sanitizer.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace securecloud::gateway::http {
namespace {

std::string to_lower_copy(std::string_view sv) {
    std::string s(sv);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool starts_with(std::string_view str, std::string_view prefix) noexcept {
    return str.size() >= prefix.size() && str.substr(0, prefix.size()) == prefix;
}

} // namespace

bool HeaderSanitizer::is_identity_header(std::string_view header_name) noexcept {
    std::string lower = to_lower_copy(header_name);

    if (lower == "x-user-id" || lower == "x-device-id" || lower == "x-auth-level" || lower == "x-scopes" ||
        lower == "x-session-id" || lower == "x-authenticated-user" || lower == "x-authenticated-device" ||
        lower == "x-authenticated-scope" || lower == "x-authenticated-scopes" || lower == "x-authenticated-level") {
        return true;
    }

    if (starts_with(lower, "x-authenticated-") || starts_with(lower, "x-securecloud-identity-")) {
        return true;
    }

    return false;
}

void HeaderSanitizer::sanitize(httplib::Request& req) {
    for (auto it = req.headers.begin(); it != req.headers.end();) {
        if (is_identity_header(it->first)) {
            it = req.headers.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace securecloud::gateway::http
