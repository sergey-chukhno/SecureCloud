#pragma once

#include "domain/entities.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

/// Result status of primary credential authentication.
/// Notice: To prevent user enumeration attacks, InvalidCredentials is used uniformly
/// for both non-existent users and invalid passwords in client-facing interactions.
enum class AuthenticationStatus { Success, InvalidCredentials, AccountDisabled, InternalError };

[[nodiscard]] inline constexpr std::string_view to_string(AuthenticationStatus status) noexcept {
    switch (status) {
    case AuthenticationStatus::Success:
        return "Success";
    case AuthenticationStatus::InvalidCredentials:
        return "InvalidCredentials";
    case AuthenticationStatus::AccountDisabled:
        return "AccountDisabled";
    case AuthenticationStatus::InternalError:
        return "InternalError";
    }
    return "Unknown";
}

/// Comprehensive outcome of credential verification.
/// Contains the internal diagnostic description for auditing/logging purposes
/// which must never be exposed directly to unauthenticated external clients.
struct AuthenticationResult {
    AuthenticationStatus status{AuthenticationStatus::InvalidCredentials};
    std::optional<UserEntity> user{std::nullopt};
    std::string internal_diagnostic{};

    [[nodiscard]] bool is_success() const noexcept { return status == AuthenticationStatus::Success; }

    static AuthenticationResult success(UserEntity user_entity) {
        AuthenticationResult res;
        res.status = AuthenticationStatus::Success;
        res.user = std::move(user_entity);
        res.internal_diagnostic = "Authenticated successfully";
        return res;
    }

    static AuthenticationResult invalid_credentials(std::string diagnostic) {
        AuthenticationResult res;
        res.status = AuthenticationStatus::InvalidCredentials;
        res.user = std::nullopt;
        res.internal_diagnostic = std::move(diagnostic);
        return res;
    }

    static AuthenticationResult account_disabled(std::string diagnostic) {
        AuthenticationResult res;
        res.status = AuthenticationStatus::AccountDisabled;
        res.user = std::nullopt;
        res.internal_diagnostic = std::move(diagnostic);
        return res;
    }

    static AuthenticationResult internal_error(std::string diagnostic) {
        AuthenticationResult res;
        res.status = AuthenticationStatus::InternalError;
        res.user = std::nullopt;
        res.internal_diagnostic = std::move(diagnostic);
        return res;
    }
};

} // namespace securecloud::auth::domain
