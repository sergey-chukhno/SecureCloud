#pragma once

#include "crypto/password_hasher.hpp"
#include "domain/auth_result.hpp"
#include "domain/credentials.hpp"
#include "repository/user_repository.hpp"

#include <memory>

namespace securecloud::auth::service {

/// Abstract interface for verifying primary user credentials.
class ICredentialVerifier {
  public:
    virtual ~ICredentialVerifier() = default;

    /// Verifies the given credential identifier and candidate password.
    ///
    /// @param identifier Strongly validated and normalized credential identifier.
    /// @param password Strongly validated candidate password container.
    /// @return AuthenticationResult indicating success or failure status.
    virtual domain::AuthenticationResult verify(const domain::CredentialIdentifier& identifier,
                                                const domain::PasswordCredential& password) = 0;
};

/// Core domain service executing primary credential verification.
///
/// Invariants & Security Guarantees:
/// 1. Zero information disclosure: missing user and incorrect password both produce
///    AuthenticationStatus::InvalidCredentials.
/// 2. User enumeration defense: non-existent users trigger execute_dummy_verification()
///    with equal computational hardness to defeat timing attacks.
/// 3. Account state enforcement: accounts with status != Active fail with AccountDisabled.
/// 4. Fail-closed: database or hasher exceptions are caught and return InternalError.
class CredentialVerifier final : public ICredentialVerifier {
  public:
    CredentialVerifier(std::shared_ptr<repository::IUserRepository> user_repository,
                       std::shared_ptr<crypto::IPasswordHasher> password_hasher);
    ~CredentialVerifier() override = default;

    CredentialVerifier(const CredentialVerifier&) = delete;
    CredentialVerifier& operator=(const CredentialVerifier&) = delete;
    CredentialVerifier(CredentialVerifier&&) noexcept = default;
    CredentialVerifier& operator=(CredentialVerifier&&) noexcept = default;

    domain::AuthenticationResult verify(const domain::CredentialIdentifier& identifier,
                                        const domain::PasswordCredential& password) override;

  private:
    std::shared_ptr<repository::IUserRepository> user_repo_;
    std::shared_ptr<crypto::IPasswordHasher> password_hasher_;
};

} // namespace securecloud::auth::service
