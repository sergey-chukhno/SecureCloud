#pragma once

#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace securecloud::auth::service {

/// Result returned from enrolling a device.
struct DeviceEnrollmentResult {
    bool success{false};
    domain::Uuid device_id{};
    domain::DeviceStatus status{domain::DeviceStatus::PendingAuthorization};
    std::string pairing_code{};
    std::chrono::system_clock::time_point pairing_code_expires_at{};
    std::string error_message{};
};

/// In-flight challenge for cross-device pairing.
struct DevicePairingChallenge {
    domain::Uuid device_id{};
    domain::Uuid user_id{};
    std::string pairing_code{};
    std::chrono::system_clock::time_point created_at{};
    std::chrono::system_clock::time_point expires_at{};
    uint32_t failed_attempts{0};
    bool is_consumed{false};
    bool is_locked_out{false};
};

/// Result returned from attempting device authorization.
struct DeviceAuthorizationResult {
    bool success{false};
    domain::Uuid device_id{};
    domain::DeviceStatus status{domain::DeviceStatus::PendingAuthorization};
    std::string error_message{};
    bool is_locked_out{false};
};

/// Abstract interface contract for Device lifecycle and pairing orchestration.
class IDeviceManager {
  public:
    virtual ~IDeviceManager() = default;

    /// Enrolls a new device endpoint, enforcing cryptographic bundle verification
    /// and assigning PendingAuthorization (for PrimaryOnly) or Active (for MfaVerified).
    virtual DeviceEnrollmentResult enroll_device(const domain::Uuid& user_id, std::span<const uint8_t> identity_key,
                                                 std::span<const uint8_t> signed_prekey,
                                                 std::span<const uint8_t> signature,
                                                 const std::vector<std::vector<uint8_t>>& one_time_prekeys,
                                                 domain::AuthenticationLevel caller_auth_level,
                                                 std::string_view client_ip = "unknown") = 0;

    /// Initiates or refreshes a pairing challenge for a pending device.
    virtual std::optional<DevicePairingChallenge> initiate_device_pairing(const domain::Uuid& user_id,
                                                                          const domain::Uuid& pending_device_id,
                                                                          std::string_view client_ip = "unknown") = 0;

    /// Authorizes a pending device via approved stronger authentication (MfaVerified)
    /// or by submitting the valid pairing challenge PIN.
    virtual DeviceAuthorizationResult authorize_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                                       std::string_view pairing_code,
                                                       domain::AuthenticationLevel caller_auth_level,
                                                       std::string_view client_ip = "unknown") = 0;

    /// Looks up a device by ID.
    [[nodiscard]] virtual std::optional<domain::DeviceEntity> get_device(const domain::Uuid& device_id) = 0;

    /// Lists devices for a user, optionally including revoked devices.
    [[nodiscard]] virtual std::vector<domain::DeviceEntity> list_user_devices(const domain::Uuid& user_id,
                                                                              bool include_revoked = false) = 0;
};

/// Concrete thread-safe implementation of IDeviceManager.
class DeviceManager : public IDeviceManager {
  public:
    static constexpr std::chrono::seconds kDefaultPairingTtl{600}; // 10 minutes
    static constexpr uint32_t kMaxFailedPairingAttempts{3};

    DeviceManager(std::shared_ptr<repository::IDeviceRepository> device_repo,
                  std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo,
                  std::shared_ptr<IAuditEventPublisher> audit_publisher,
                  std::chrono::seconds pairing_ttl = kDefaultPairingTtl);

    DeviceEnrollmentResult enroll_device(const domain::Uuid& user_id, std::span<const uint8_t> identity_key,
                                         std::span<const uint8_t> signed_prekey, std::span<const uint8_t> signature,
                                         const std::vector<std::vector<uint8_t>>& one_time_prekeys,
                                         domain::AuthenticationLevel caller_auth_level,
                                         std::string_view client_ip = "unknown") override;

    std::optional<DevicePairingChallenge> initiate_device_pairing(const domain::Uuid& user_id,
                                                                  const domain::Uuid& pending_device_id,
                                                                  std::string_view client_ip = "unknown") override;

    DeviceAuthorizationResult authorize_device(const domain::Uuid& user_id, const domain::Uuid& device_id,
                                               std::string_view pairing_code,
                                               domain::AuthenticationLevel caller_auth_level,
                                               std::string_view client_ip = "unknown") override;

    [[nodiscard]] std::optional<domain::DeviceEntity> get_device(const domain::Uuid& device_id) override;

    [[nodiscard]] std::vector<domain::DeviceEntity> list_user_devices(const domain::Uuid& user_id,
                                                                      bool include_revoked = false) override;

  private:
    std::shared_ptr<repository::IDeviceRepository> device_repo_;
    std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo_;
    std::shared_ptr<IAuditEventPublisher> audit_publisher_;
    std::chrono::seconds pairing_ttl_;

    std::mutex challenge_mutex_;
    std::unordered_map<domain::Uuid, DevicePairingChallenge> pairing_challenges_;

    [[nodiscard]] std::string generate_pairing_code_internal();
    [[nodiscard]] static std::string normalize_code(std::string_view code);
};

} // namespace securecloud::auth::service
