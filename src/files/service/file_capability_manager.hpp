#pragma once

#include "auth/crypto/token_crypto.hpp"
#include "files/db/files_connection_pool.hpp"
#include "files/domain/capability_validator.hpp"
#include "files/domain/file_capability_entity.hpp"
#include "files/domain/file_capability_serializer.hpp"
#include "files/repository/device_revocation_provider.hpp"
#include "files/repository/file_access_repository.hpp"
#include "files/service/file_lifecycle_service.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <string_view>

namespace securecloud::files {

class InvalidCapabilityException : public FileServiceException {
    using FileServiceException::FileServiceException;
};

/**
 * @brief Abstract interface contract for File Capability Management.
 */
class IFileCapabilityManager {
  public:
    virtual ~IFileCapabilityManager() = default;

    /// Generates a signed capability token for an authorized user and device.
    virtual std::string issue_capability(const std::string& grantee_user_id, const std::string& grantee_device_id,
                                         const std::string& file_id, FileCapabilityOperation operation,
                                         int32_t file_version = 0,
                                         std::chrono::seconds ttl = std::chrono::minutes(15)) = 0;

    /// Validates an incoming capability presented by caller and enforces authorization.
    virtual FileAccessCapabilityClaims authorize_capability(std::string_view token, const std::string& caller_user_id,
                                                            const std::string& caller_device_id,
                                                            const std::string& target_file_id,
                                                            FileCapabilityOperation requested_operation,
                                                            int32_t requested_version = 0) = 0;
};

/**
 * @brief Authoritative production implementation of IFileCapabilityManager.
 */
class FileCapabilityManager : public IFileCapabilityManager {
  public:
    FileCapabilityManager(std::shared_ptr<db::FilesDbConnectionPool> pool,
                          std::shared_ptr<auth::crypto::ITokenSigner> signer,
                          std::shared_ptr<auth::crypto::ITokenVerifier> verifier,
                          std::shared_ptr<IDeviceRevocationProvider> revocation_provider = nullptr,
                          std::shared_ptr<FileAccessRepository> access_repo = nullptr);

    std::string issue_capability(const std::string& grantee_user_id, const std::string& grantee_device_id,
                                 const std::string& file_id, FileCapabilityOperation operation,
                                 int32_t file_version = 0,
                                 std::chrono::seconds ttl = std::chrono::minutes(15)) override;

    FileAccessCapabilityClaims authorize_capability(std::string_view token, const std::string& caller_user_id,
                                                    const std::string& caller_device_id,
                                                    const std::string& target_file_id,
                                                    FileCapabilityOperation requested_operation,
                                                    int32_t requested_version = 0) override;

    [[nodiscard]] std::shared_ptr<IDeviceRevocationProvider> revocation_provider() const noexcept {
        return revocation_provider_;
    }

  private:
    std::shared_ptr<db::FilesDbConnectionPool> pool_;
    std::shared_ptr<auth::crypto::ITokenSigner> signer_;
    std::shared_ptr<auth::crypto::ITokenVerifier> verifier_;
    std::shared_ptr<IDeviceRevocationProvider> revocation_provider_;
    std::shared_ptr<FileAccessRepository> access_repo_;
    std::unique_ptr<CapabilityValidator> validator_;
};

} // namespace securecloud::files
