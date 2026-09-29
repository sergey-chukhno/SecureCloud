#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace securecloud::gateway::http {

/**
 * @brief High-performance, in-memory evaluator for hierarchical and wildcard authorization scopes.
 *
 * Scope Syntax:
 * - Specific Action: `<domain>:<action>` (e.g., "messages:send", "files:upload", "auth:revoke")
 * - Domain Wildcard: `<domain>:*` matches any action within the specified domain (e.g., "messages:*"
 *   satisfies "messages:read", "messages:send", "messages:delete").
 * - Global Wildcard: `*` matches any non-empty required scope.
 *
 * Invariants:
 * - Scopes are case-sensitive.
 * - Empty scopes or malformed domain wildcards (e.g., ":*") evaluate to false.
 * - Operates without dynamic heap allocations during single scope comparisons.
 */
class ScopeMatcher {
  public:
    /**
     * @brief Evaluates whether a single granted scope satisfies a required scope.
     *
     * @param granted_scope Scope granted in token/context.
     * @param required_scope Scope demanded by the route policy.
     * @return true if granted_scope satisfies required_scope, false otherwise.
     */
    [[nodiscard]] static bool matches(std::string_view granted_scope, std::string_view required_scope) noexcept;

    /**
     * @brief Checks if a collection of granted scopes satisfies a required scope.
     *
     * @param granted_scopes Scopes granted to the caller.
     * @param required_scope Scope demanded by the route policy.
     * @return true if any granted scope satisfies required_scope, false otherwise.
     */
    [[nodiscard]] static bool has_scope(const std::vector<std::string>& granted_scopes,
                                        std::string_view required_scope) noexcept;

    /**
     * @brief Verifies whether all required scopes are satisfied (AND conjunction).
     *
     * @param granted_scopes Scopes granted to the caller.
     * @param required_scopes Set of all scopes demanded by the route policy.
     * @return true if every required scope is satisfied, or if required_scopes is empty.
     */
    [[nodiscard]] static bool has_all_scopes(const std::vector<std::string>& granted_scopes,
                                             const std::vector<std::string>& required_scopes) noexcept;

    /**
     * @brief Verifies whether at least one alternative scope is satisfied (OR disjunction).
     *
     * @param granted_scopes Scopes granted to the caller.
     * @param alternative_scopes Set of alternative scopes accepted by the route policy.
     * @return true if at least one alternative scope is satisfied, or if alternative_scopes is empty.
     */
    [[nodiscard]] static bool has_any_scope(const std::vector<std::string>& granted_scopes,
                                            const std::vector<std::string>& alternative_scopes) noexcept;

    /**
     * @brief Computes the subset of required scopes that are NOT satisfied by granted scopes.
     *
     * Useful for building structured RFC 7807 problem details in 403 Forbidden responses.
     *
     * @param granted_scopes Scopes granted to the caller.
     * @param required_scopes Set of all scopes demanded by the route policy.
     * @return List of unsatisfied required scopes.
     */
    [[nodiscard]] static std::vector<std::string> find_missing_scopes(const std::vector<std::string>& granted_scopes,
                                                                      const std::vector<std::string>& required_scopes);
};

} // namespace securecloud::gateway::http
