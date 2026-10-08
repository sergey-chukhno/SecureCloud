#pragma once

#include "http/auth/authenticated_context.hpp"
#include "securecloud/auth/v1/auth.pb.h"

#include <regex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace securecloud::gateway::http {

/**
 * @brief Authorization classification for HTTP routes at the Gateway perimeter.
 */
enum class RouteAccess {
    Public,    ///< Anonymous access permitted; no credentials or token required
    Protected, ///< Requires valid AuthenticatedContext (minimum PRIMARY assurance)
    Sensitive  ///< Requires valid AuthenticatedContext with MFA_VERIFIED assurance
};

/**
 * @brief Detailed authorization requirements evaluated for a given route.
 */
struct RouteSecurityRule {
    RouteAccess access{RouteAccess::Protected};
    securecloud::auth::v1::AuthenticationLevel min_auth_level{
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY};
    std::vector<std::string> required_scopes;
    std::vector<std::string> alternative_scopes;
    bool require_device_bound{false};

    [[nodiscard]] bool is_public() const noexcept { return access == RouteAccess::Public; }
    [[nodiscard]] bool requires_mfa() const noexcept {
        return access == RouteAccess::Sensitive ||
               min_auth_level == securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED;
    }
    [[nodiscard]] bool requires_device_bound() const noexcept { return require_device_bound; }

    /**
     * @brief Verifies whether an authenticated caller context satisfies this security rule.
     * Evaluates MFA requirement, assurance level, device binding, and scopes via ScopeMatcher.
     */
    [[nodiscard]] bool satisfies(const AuthenticatedContext& ctx) const;
};

/**
 * @brief Declaratively registers an authorization rule.
 *
 * Implements deterministic route authorization evaluation with:
 * - Precedence: Exact route match > Parameterized pattern match > Longest prefix match > Fail-closed default.
 * - Wildcard HTTP verbs ('*') supported for prefix, parameterized, and exact rules.
 * - Thread-safe concurrent evaluation via shared mutex.
 * - Fail-closed: Any unmapped path automatically defaults to RouteAccess::Protected.
 */
class GatewaySecurityPolicy {
  public:
    GatewaySecurityPolicy();
    ~GatewaySecurityPolicy() = default;

    GatewaySecurityPolicy(GatewaySecurityPolicy&&) noexcept;
    GatewaySecurityPolicy& operator=(GatewaySecurityPolicy&&) noexcept;
    GatewaySecurityPolicy(const GatewaySecurityPolicy&) = delete;
    GatewaySecurityPolicy& operator=(const GatewaySecurityPolicy&) = delete;

    /// Factory configuring the canonical SecureCloud route security ruleset
    static GatewaySecurityPolicy create_default();

    /**
     * @brief Declaratively registers an authorization rule.
     *
     * @param method HTTP method (e.g. "GET", "POST", or "*" for any method).
     * @param path_pattern Exact route path, parameterized pattern (:param or {param}), or wildcard prefix.
     * @param access Access category (Public, Protected, Sensitive).
     * @param required_scopes Optional list of required scopes (e.g. {"messages:write"}).
     * @param min_auth_level Minimum authentication assurance level.
     * @param alternative_scopes Optional list of alternative scopes (caller needs at least one).
     * @param require_device_bound Whether the route requires an attested device binding in context.
     */
    void add_rule(std::string method, std::string path_pattern, RouteAccess access,
                  std::vector<std::string> required_scopes = {},
                  securecloud::auth::v1::AuthenticationLevel min_auth_level =
                      securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_UNSPECIFIED,
                  std::vector<std::string> alternative_scopes = {}, bool require_device_bound = false);

    /**
     * @brief Declaratively registers a pre-constructed RouteSecurityRule.
     */
    void add_rule(std::string method, std::string path_pattern, RouteSecurityRule rule);

    /**
     * @brief Evaluates the security rule governing the given HTTP method and path.
     *
     * @param method HTTP verb (e.g. "GET", "POST").
     * @param path Request URI path (query string stripped).
     * @return Authoritative RouteSecurityRule. Defaults to Protected if unmapped.
     */
    [[nodiscard]] RouteSecurityRule evaluate(std::string_view method, std::string_view path) const;

  private:
    struct PrefixRule {
        std::string method;
        std::string prefix;
        RouteSecurityRule rule;
    };

    struct ParameterizedRule {
        std::string method;
        std::string pattern;
        std::regex regex;
        RouteSecurityRule rule;
    };

    mutable std::unique_ptr<std::shared_mutex> mutex_;
    std::unordered_map<std::string, RouteSecurityRule> exact_rules_;
    std::vector<PrefixRule> prefix_rules_;
    std::vector<ParameterizedRule> parameterized_rules_;

    [[nodiscard]] static bool is_parameterized_pattern(std::string_view path);
    [[nodiscard]] static std::regex compile_pattern_regex(std::string_view path);
    [[nodiscard]] static std::string normalize_path(std::string_view raw_path);
    [[nodiscard]] static std::string make_exact_key(std::string_view method, std::string_view path);
};

} // namespace securecloud::gateway::http
