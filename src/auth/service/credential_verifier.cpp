#include "service/credential_verifier.hpp"

#include <stdexcept>

namespace securecloud::auth::service {

CredentialVerifier::CredentialVerifier(std::shared_ptr<repository::IUserRepository> user_repository,
                                       std::shared_ptr<crypto::IPasswordHasher> password_hasher)
    : user_repo_(std::move(user_repository)), password_hasher_(std::move(password_hasher)) {
    if (!user_repo_) {
        throw std::invalid_argument("CredentialVerifier: user_repository cannot be null");
    }
    if (!password_hasher_) {
        throw std::invalid_argument("CredentialVerifier: password_hasher cannot be null");
    }
}

domain::AuthenticationResult CredentialVerifier::verify(const domain::CredentialIdentifier& identifier,
                                                        const domain::PasswordCredential& password) {

    std::optional<domain::UserEntity> user_opt;
    try {
        user_opt = user_repo_->find_by_credential_identifier(identifier.value());
    } catch (const std::exception& ex) {
        return domain::AuthenticationResult::internal_error(std::string("Database error during credential lookup: ") +
                                                            ex.what());
    } catch (...) {
        return domain::AuthenticationResult::internal_error("Unknown database error during credential lookup");
    }

    // User enumeration defense: run dummy Argon2id verification with equal computational latency
    if (!user_opt.has_value()) {
        try {
            password_hasher_->execute_dummy_verification(password.secret());
        } catch (...) {
            // Fail-closed continues to return InvalidCredentials
        }
        return domain::AuthenticationResult::invalid_credentials("User not found");
    }

    // Account lifecycle status check: fail immediately if not Active
    if (user_opt->account_status != domain::AccountStatus::Active) {
        return domain::AuthenticationResult::account_disabled(
            "Account is not active (status: " + std::string(domain::to_string(user_opt->account_status)) + ")");
    }

    // Cryptographic Argon2id password verification
    bool password_valid = false;
    try {
        password_valid = password_hasher_->verify_password(password.secret(), user_opt->password_verifier);
    } catch (const std::exception& ex) {
        return domain::AuthenticationResult::internal_error(std::string("Password hasher failure: ") + ex.what());
    } catch (...) {
        return domain::AuthenticationResult::internal_error("Unknown error during password verification");
    }

    if (!password_valid) {
        return domain::AuthenticationResult::invalid_credentials("Password verification failed");
    }

    return domain::AuthenticationResult::success(std::move(*user_opt));
}

} // namespace securecloud::auth::service
