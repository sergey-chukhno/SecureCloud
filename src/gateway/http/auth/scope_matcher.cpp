#include "http/auth/scope_matcher.hpp"

#include <algorithm>

namespace securecloud::gateway::http {

bool ScopeMatcher::matches(std::string_view granted_scope, std::string_view required_scope) noexcept {
    if (granted_scope.empty() || required_scope.empty()) {
        return false;
    }

    // 1. Global superuser wildcard matches any non-empty required scope
    if (granted_scope == "*") {
        return true;
    }

    // 2. Exact match
    if (granted_scope == required_scope) {
        return true;
    }

    // 3. Hierarchical domain wildcard matching: "<domain>:*"
    if (granted_scope.size() >= 3 && granted_scope.substr(granted_scope.size() - 2) == ":*") {
        const std::string_view granted_domain = granted_scope.substr(0, granted_scope.size() - 2);

        // Ensure domain is non-empty and does not contain embedded wildcards
        if (granted_domain.empty() || granted_domain.find('*') != std::string_view::npos) {
            return false;
        }

        // Required scope must start with "<domain>:" followed by a non-empty action
        if (required_scope.size() > granted_domain.size() + 1 &&
            required_scope.substr(0, granted_domain.size()) == granted_domain &&
            required_scope[granted_domain.size()] == ':') {
            return true;
        }
    }

    return false;
}

bool ScopeMatcher::has_scope(const std::vector<std::string>& granted_scopes, std::string_view required_scope) noexcept {
    if (required_scope.empty()) {
        return false;
    }

    return std::any_of(granted_scopes.begin(), granted_scopes.end(),
                       [required_scope](const std::string& granted) { return matches(granted, required_scope); });
}

bool ScopeMatcher::has_all_scopes(const std::vector<std::string>& granted_scopes,
                                  const std::vector<std::string>& required_scopes) noexcept {
    return std::all_of(required_scopes.begin(), required_scopes.end(),
                       [&granted_scopes](const std::string& required) { return has_scope(granted_scopes, required); });
}

bool ScopeMatcher::has_any_scope(const std::vector<std::string>& granted_scopes,
                                 const std::vector<std::string>& alternative_scopes) noexcept {
    if (alternative_scopes.empty()) {
        return true;
    }

    return std::any_of(
        alternative_scopes.begin(), alternative_scopes.end(),
        [&granted_scopes](const std::string& alternative) { return has_scope(granted_scopes, alternative); });
}

std::vector<std::string> ScopeMatcher::find_missing_scopes(const std::vector<std::string>& granted_scopes,
                                                           const std::vector<std::string>& required_scopes) {
    std::vector<std::string> missing;
    for (const auto& required : required_scopes) {
        if (!has_scope(granted_scopes, required)) {
            missing.push_back(required);
        }
    }
    return missing;
}

} // namespace securecloud::gateway::http
