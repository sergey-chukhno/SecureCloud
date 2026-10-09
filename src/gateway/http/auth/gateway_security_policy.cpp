#include "http/auth/gateway_security_policy.hpp"

#include "http/auth/scope_matcher.hpp"

#include <algorithm>
#include <mutex>
#include <string>

namespace securecloud::gateway::http {

bool RouteSecurityRule::satisfies(const AuthenticatedContext& ctx) const {
    if (is_public()) {
        return true;
    }

    if (requires_mfa() && !ctx.is_mfa_verified()) {
        return false;
    }

    if (static_cast<int>(ctx.authentication_level()) < static_cast<int>(min_auth_level)) {
        return false;
    }

    if (require_device_bound && ctx.device_id().empty()) {
        return false;
    }

    bool scopes_satisfied = true;
    if (!required_scopes.empty()) {
        scopes_satisfied = ScopeMatcher::has_all_scopes(ctx.scopes(), required_scopes);
    } else if (!alternative_scopes.empty()) {
        scopes_satisfied = false;
    }

    if (!scopes_satisfied && !alternative_scopes.empty()) {
        scopes_satisfied = ScopeMatcher::has_any_scope(ctx.scopes(), alternative_scopes);
    }

    if (!scopes_satisfied) {
        return false;
    }

    return true;
}

GatewaySecurityPolicy::GatewaySecurityPolicy() : mutex_(std::make_unique<std::shared_mutex>()) {}

GatewaySecurityPolicy::GatewaySecurityPolicy(GatewaySecurityPolicy&&) noexcept = default;
GatewaySecurityPolicy& GatewaySecurityPolicy::operator=(GatewaySecurityPolicy&&) noexcept = default;

GatewaySecurityPolicy GatewaySecurityPolicy::create_default() {
    GatewaySecurityPolicy policy;

    // Public perimeter routes: Health & Initial Auth Handshake
    policy.add_rule("GET", "/health/live", RouteAccess::Public);
    policy.add_rule("GET", "/health/ready", RouteAccess::Public);
    policy.add_rule("POST", "/api/v1/auth/register", RouteAccess::Public);
    policy.add_rule("POST", "/api/v1/auth/login", RouteAccess::Public);
    policy.add_rule("POST", "/api/v1/auth/refresh", RouteAccess::Public);

    // Sensitive perimeter routes: MFA Verification Required & Device Binding
    policy.add_rule("POST", "/api/v1/auth/device/register", RouteAccess::Sensitive, {"device:manage"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED,
                    {"auth:device:register"}, /*require_device_bound=*/true);
    policy.add_rule("*", "/api/v1/auth/security/*", RouteAccess::Sensitive, {"auth:keys:rotate"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("POST", "/api/v1/auth/mfa/disable", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("POST", "/api/v1/auth/devices/revoke", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("DELETE", "/api/v1/user/delete", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("*", "/api/v1/admin/*", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    // Device lifecycle perimeter routes (AUTH-007-T05)
    policy.add_rule("POST", "/api/v1/devices/register", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("POST", "/api/v1/devices/authorize", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("POST", "/api/v1/devices/revoke", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("GET", "/api/v1/devices", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    policy.add_rule("GET", "/api/v1/devices/*", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    // Auth service aliases for device lifecycle
    policy.add_rule("POST", "/api/v1/auth/devices/register", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("POST", "/api/v1/auth/devices/authorize", RouteAccess::Sensitive, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("GET", "/api/v1/auth/devices", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    policy.add_rule("GET", "/api/v1/auth/devices/*", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    // Cryptographic identity & prekey directory routes (AUTH-008-T04)
    policy.add_rule("GET", "/api/v1/users/:user_id/devices/crypto-directory", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    policy.add_rule("GET", "/api/v1/devices/:device_id/crypto-identity", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);
    policy.add_rule("POST", "/api/v1/devices/:device_id/prekeys", RouteAccess::Protected, {},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY);

    // Auth microservice protected routes
    policy.add_rule("POST", "/api/v1/auth/revoke", RouteAccess::Protected, {"auth:revoke"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"access"});
    policy.add_rule("GET", "/api/v1/auth/me", RouteAccess::Protected, {"user:profile"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"auth:profile"});

    // Messaging microservice protected routes
    policy.add_rule("POST", "/api/v1/messages/send", RouteAccess::Protected, {"messages:send"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"messages:write"});
    policy.add_rule("GET", "/api/v1/messages/inbox", RouteAccess::Protected, {"messages:read"});
    policy.add_rule("GET", "/api/v1/messages/history", RouteAccess::Protected, {"messages:read"});
    policy.add_rule("GET", "/api/v1/messages/*", RouteAccess::Protected, {"messages:read"});
    policy.add_rule("*", "/api/v1/messages/*", RouteAccess::Protected, {"messages:read"});

    // Files microservice protected routes
    policy.add_rule("POST", "/api/v1/files/upload", RouteAccess::Protected, {"files:upload"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"files:write"});
    policy.add_rule("GET", "/api/v1/files/download", RouteAccess::Protected, {"files:read"});
    policy.add_rule("DELETE", "/api/v1/files/delete", RouteAccess::Protected, {"files:delete"});
    policy.add_rule("GET", "/api/v1/files/*", RouteAccess::Protected, {"files:read"});
    policy.add_rule("*", "/api/v1/files/*", RouteAccess::Protected, {"files:read"});

    // Audit microservice sensitive routes
    policy.add_rule("GET", "/api/v1/audit/logs", RouteAccess::Sensitive, {"audit:read"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
    policy.add_rule("*", "/api/v1/audit/*", RouteAccess::Sensitive, {"audit:read"},
                    securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);

    return policy;
}

void GatewaySecurityPolicy::add_rule(std::string method, std::string path_pattern, RouteAccess access,
                                     std::vector<std::string> required_scopes,
                                     securecloud::auth::v1::AuthenticationLevel min_auth_level,
                                     std::vector<std::string> alternative_scopes, bool require_device_bound) {
    // Resolve default authentication level if unspecified
    if (min_auth_level == securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED) {
        switch (access) {
        case RouteAccess::Public:
            min_auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED;
            break;
        case RouteAccess::Sensitive:
            min_auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED;
            break;
        case RouteAccess::Protected:
            min_auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY;
            break;
        }
    }

    RouteSecurityRule rule{
        .access = access,
        .min_auth_level = min_auth_level,
        .required_scopes = std::move(required_scopes),
        .alternative_scopes = std::move(alternative_scopes),
        .require_device_bound = require_device_bound,
    };

    add_rule(std::move(method), std::move(path_pattern), std::move(rule));
}

void GatewaySecurityPolicy::add_rule(std::string method, std::string path_pattern, RouteSecurityRule rule) {
    std::unique_lock<std::shared_mutex> lock(*mutex_);

    if (path_pattern.ends_with("/*")) {
        std::string prefix = path_pattern.substr(0, path_pattern.size() - 1); // keep trailing '/'
        prefix_rules_.push_back(PrefixRule{
            .method = std::move(method),
            .prefix = std::move(prefix),
            .rule = std::move(rule),
        });

        // Maintain prefix rules sorted by prefix length descending (longest prefix match first)
        std::stable_sort(prefix_rules_.begin(), prefix_rules_.end(), [](const PrefixRule& a, const PrefixRule& b) {
            return a.prefix.length() > b.prefix.length();
        });
    } else if (is_parameterized_pattern(path_pattern)) {
        std::regex re = compile_pattern_regex(path_pattern);
        parameterized_rules_.push_back(ParameterizedRule{
            .method = std::move(method),
            .pattern = std::move(path_pattern),
            .regex = std::move(re),
            .rule = std::move(rule),
        });
    } else {
        std::string normalized = normalize_path(path_pattern);
        exact_rules_[make_exact_key(method, normalized)] = std::move(rule);
    }
}

RouteSecurityRule GatewaySecurityPolicy::evaluate(std::string_view method, std::string_view raw_path) const {
    std::shared_lock<std::shared_mutex> lock(*mutex_);

    const std::string normalized = normalize_path(raw_path);

    // 1. Exact match with method (e.g. "POST /api/v1/auth/login")
    if (auto it = exact_rules_.find(make_exact_key(method, normalized)); it != exact_rules_.end()) {
        return it->second;
    }

    // 2. Exact match with wildcard method (e.g. "* /health/live")
    if (auto it = exact_rules_.find(make_exact_key("*", normalized)); it != exact_rules_.end()) {
        return it->second;
    }

    // 3. Parameterized pattern matching
    for (const auto& p_rule : parameterized_rules_) {
        if (p_rule.method != "*" && p_rule.method != method) {
            continue;
        }
        if (std::regex_match(normalized, p_rule.regex)) {
            return p_rule.rule;
        }
    }

    // 4. Prefix matching: longest prefix first
    for (const auto& p_rule : prefix_rules_) {
        if (p_rule.method != "*" && p_rule.method != method) {
            continue;
        }

        // Match if path starts with prefix (e.g. "/api/v1/messages/123" starts with "/api/v1/messages/")
        if (normalized.starts_with(p_rule.prefix)) {
            return p_rule.rule;
        }

        // Match base collection route without trailing slash (e.g. "/api/v1/messages" matches "/api/v1/messages/*")
        if (p_rule.prefix.ends_with('/') && p_rule.prefix.size() > 1) {
            std::string_view prefix_without_slash(p_rule.prefix.data(), p_rule.prefix.size() - 1);
            if (normalized == prefix_without_slash) {
                return p_rule.rule;
            }
        }
    }

    // 5. Fail-closed default: any unmapped route is strictly Protected
    return RouteSecurityRule{
        .access = RouteAccess::Protected,
        .min_auth_level = securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY,
        .required_scopes = {},
        .alternative_scopes = {},
        .require_device_bound = false,
    };
}

bool GatewaySecurityPolicy::is_parameterized_pattern(std::string_view path) {
    return path.find(':') != std::string_view::npos || path.find('{') != std::string_view::npos;
}

std::regex GatewaySecurityPolicy::compile_pattern_regex(std::string_view path) {
    std::string regex_str = "^";
    size_t i = 0;
    while (i < path.size()) {
        if (path[i] == ':' && i + 1 < path.size() &&
            (std::isalnum(static_cast<unsigned char>(path[i + 1])) || path[i + 1] == '_')) {
            size_t start = i + 1;
            size_t end = start;
            while (end < path.size() && (std::isalnum(static_cast<unsigned char>(path[end])) || path[end] == '_')) {
                ++end;
            }
            regex_str += "([^/]+)";
            i = end;
        } else if (path[i] == '{') {
            size_t end = path.find('}', i);
            if (end != std::string_view::npos) {
                regex_str += "([^/]+)";
                i = end + 1;
            } else {
                regex_str += "\\{";
                ++i;
            }
        } else {
            char c = path[i];
            if (c == '.' || c == '+' || c == '?' || c == '*' || c == '^' || c == '$' || c == '(' || c == ')' ||
                c == '[' || c == ']' || c == '\\') {
                regex_str += '\\';
            }
            regex_str += c;
            ++i;
        }
    }
    regex_str += "$";
    return std::regex(regex_str);
}

std::string GatewaySecurityPolicy::normalize_path(std::string_view raw_path) {
    if (raw_path.empty()) {
        return "/";
    }

    // Strip query parameters if present
    auto query_pos = raw_path.find('?');
    if (query_pos != std::string_view::npos) {
        raw_path = raw_path.substr(0, query_pos);
    }

    std::string normalized(raw_path);

    // Ensure leading slash
    if (normalized.empty() || normalized.front() != '/') {
        normalized.insert(normalized.begin(), '/');
    }

    // Strip trailing slash unless root path
    if (normalized.size() > 1 && normalized.back() == '/') {
        normalized.pop_back();
    }

    return normalized;
}

std::string GatewaySecurityPolicy::make_exact_key(std::string_view method, std::string_view path) {
    std::string key;
    key.reserve(method.size() + 1 + path.size());
    key.append(method);
    key.push_back(' ');
    key.append(path);
    return key;
}

} // namespace securecloud::gateway::http
