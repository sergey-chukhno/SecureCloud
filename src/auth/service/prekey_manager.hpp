#pragma once

#include "auth/domain/entities.hpp"
#include "auth/domain/enums.hpp"
#include "auth/domain/uuid.hpp"
#include "auth/repository/device_public_key_repository.hpp"
#include "auth/repository/device_repository.hpp"
#include "auth/service/audit_event_publisher.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::auth::service {

/// Result returned when inspecting prekey inventory health and rotation status.
struct PrekeyInventoryStatusResult {
    enum class Status { Success, NotFound, DeviceRevoked, InternalError };

    Status status{Status::NotFound};
    domain::PrekeyInventoryStatus inventory_status{};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }
    [[nodiscard]] bool is_device_revoked() const noexcept { return status == Status::DeviceRevoked; }

    static PrekeyInventoryStatusResult success(domain::PrekeyInventoryStatus inv) {
        PrekeyInventoryStatusResult r;
        r.status = Status::Success;
        r.inventory_status = std::move(inv);
        return r;
    }

    static PrekeyInventoryStatusResult not_found(std::string_view msg = "Device not found") {
        PrekeyInventoryStatusResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static PrekeyInventoryStatusResult device_revoked(std::string_view msg = "Device is revoked") {
        PrekeyInventoryStatusResult r;
        r.status = Status::DeviceRevoked;
        r.error_message = std::string(msg);
        return r;
    }

    static PrekeyInventoryStatusResult internal_error(std::string_view msg) {
        PrekeyInventoryStatusResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Result returned when claiming an atomic prekey bundle for a single target device.
struct ClaimPrekeyBundleResult {
    enum class Status { Success, NotFound, DeviceRevoked, DeviceNotActive, InternalError };

    Status status{Status::NotFound};
    domain::Uuid device_id{};
    std::vector<uint8_t> identity_key{};
    std::string identity_key_fingerprint{};
    std::vector<uint8_t> signed_prekey{};
    std::vector<uint8_t> signed_prekey_signature{};
    std::chrono::system_clock::time_point signed_prekey_created_at{};
    std::optional<std::vector<uint8_t>> one_time_prekey{std::nullopt};
    std::optional<domain::Uuid> one_time_prekey_id{std::nullopt};
    domain::PrekeyExhaustionState exhaustion_state{domain::PrekeyExhaustionState::InventoryHealthy};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }
    [[nodiscard]] bool is_device_revoked() const noexcept { return status == Status::DeviceRevoked; }
    [[nodiscard]] bool is_device_not_active() const noexcept { return status == Status::DeviceNotActive; }

    static ClaimPrekeyBundleResult success(const domain::Uuid& dev_id, std::vector<uint8_t> id_key,
                                           std::string id_fingerprint, std::vector<uint8_t> spk,
                                           std::vector<uint8_t> spk_sig,
                                           std::chrono::system_clock::time_point spk_created,
                                           std::optional<std::vector<uint8_t>> otk, std::optional<domain::Uuid> otk_id,
                                           domain::PrekeyExhaustionState state) {
        ClaimPrekeyBundleResult r;
        r.status = Status::Success;
        r.device_id = dev_id;
        r.identity_key = std::move(id_key);
        r.identity_key_fingerprint = std::move(id_fingerprint);
        r.signed_prekey = std::move(spk);
        r.signed_prekey_signature = std::move(spk_sig);
        r.signed_prekey_created_at = spk_created;
        r.one_time_prekey = std::move(otk);
        r.one_time_prekey_id = otk_id;
        r.exhaustion_state = state;
        return r;
    }

    static ClaimPrekeyBundleResult not_found(std::string_view msg = "Target device not found") {
        ClaimPrekeyBundleResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static ClaimPrekeyBundleResult device_revoked(std::string_view msg = "Device is revoked") {
        ClaimPrekeyBundleResult r;
        r.status = Status::DeviceRevoked;
        r.error_message = std::string(msg);
        return r;
    }

    static ClaimPrekeyBundleResult device_not_active(std::string_view msg = "Device is not active") {
        ClaimPrekeyBundleResult r;
        r.status = Status::DeviceNotActive;
        r.error_message = std::string(msg);
        return r;
    }

    static ClaimPrekeyBundleResult internal_error(std::string_view msg) {
        ClaimPrekeyBundleResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Result returned when replenishing one-time prekeys.
struct ReplenishPrekeysResult {
    enum class Status {
        Success,
        NotFound,
        DeviceRevoked,
        DeviceNotActive,
        PermissionDenied,
        InvalidArgument,
        Conflict,
        InternalError
    };

    Status status{Status::NotFound};
    int32_t active_count{0};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }
    [[nodiscard]] bool is_device_revoked() const noexcept { return status == Status::DeviceRevoked; }
    [[nodiscard]] bool is_permission_denied() const noexcept { return status == Status::PermissionDenied; }
    [[nodiscard]] bool is_invalid_argument() const noexcept { return status == Status::InvalidArgument; }
    [[nodiscard]] bool is_conflict() const noexcept { return status == Status::Conflict; }

    static ReplenishPrekeysResult success(int32_t count) {
        ReplenishPrekeysResult r;
        r.status = Status::Success;
        r.active_count = count;
        return r;
    }

    static ReplenishPrekeysResult not_found(std::string_view msg = "Target device not found") {
        ReplenishPrekeysResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static ReplenishPrekeysResult device_revoked(std::string_view msg = "Device is revoked") {
        ReplenishPrekeysResult r;
        r.status = Status::DeviceRevoked;
        r.error_message = std::string(msg);
        return r;
    }

    static ReplenishPrekeysResult device_not_active(std::string_view msg = "Device is not active") {
        ReplenishPrekeysResult r;
        r.status = Status::DeviceNotActive;
        r.error_message = std::string(msg);
        return r;
    }

    static ReplenishPrekeysResult permission_denied(std::string_view msg) {
        ReplenishPrekeysResult r;
        r.status = Status::PermissionDenied;
        r.error_message = std::string(msg);
        return r;
    }

    static ReplenishPrekeysResult invalid_argument(std::string_view msg) {
        ReplenishPrekeysResult r;
        r.status = Status::InvalidArgument;
        r.error_message = std::string(msg);
        return r;
    }

    static ReplenishPrekeysResult conflict(std::string_view msg) {
        ReplenishPrekeysResult r;
        r.status = Status::Conflict;
        r.error_message = std::string(msg);
        return r;
    }

    static ReplenishPrekeysResult internal_error(std::string_view msg) {
        ReplenishPrekeysResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Result returned when rotating a device's signed prekey.
struct RotateSignedPrekeyResult {
    enum class Status {
        Success,
        NotFound,
        DeviceRevoked,
        DeviceNotActive,
        PermissionDenied,
        InvalidArgument,
        InternalError
    };

    Status status{Status::NotFound};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }
    [[nodiscard]] bool is_device_revoked() const noexcept { return status == Status::DeviceRevoked; }
    [[nodiscard]] bool is_permission_denied() const noexcept { return status == Status::PermissionDenied; }
    [[nodiscard]] bool is_invalid_argument() const noexcept { return status == Status::InvalidArgument; }

    static RotateSignedPrekeyResult success() {
        RotateSignedPrekeyResult r;
        r.status = Status::Success;
        return r;
    }

    static RotateSignedPrekeyResult not_found(std::string_view msg = "Target device not found") {
        RotateSignedPrekeyResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static RotateSignedPrekeyResult device_revoked(std::string_view msg = "Device is revoked") {
        RotateSignedPrekeyResult r;
        r.status = Status::DeviceRevoked;
        r.error_message = std::string(msg);
        return r;
    }

    static RotateSignedPrekeyResult device_not_active(std::string_view msg = "Device is not active") {
        RotateSignedPrekeyResult r;
        r.status = Status::DeviceNotActive;
        r.error_message = std::string(msg);
        return r;
    }

    static RotateSignedPrekeyResult permission_denied(std::string_view msg) {
        RotateSignedPrekeyResult r;
        r.status = Status::PermissionDenied;
        r.error_message = std::string(msg);
        return r;
    }

    static RotateSignedPrekeyResult invalid_argument(std::string_view msg) {
        RotateSignedPrekeyResult r;
        r.status = Status::InvalidArgument;
        r.error_message = std::string(msg);
        return r;
    }

    static RotateSignedPrekeyResult internal_error(std::string_view msg) {
        RotateSignedPrekeyResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Abstract interface contract for Prekey Management & Inventory Orchestration.
class IPrekeyManager {
  public:
    virtual ~IPrekeyManager() = default;

    /// Evaluates prekey inventory status, exhaustion state, and signed prekey age.
    [[nodiscard]] virtual PrekeyInventoryStatusResult get_inventory_status(const domain::Uuid& device_id) = 0;

    /// Atomically claims a prekey bundle for a single target device with explicit exhaustion state reporting.
    [[nodiscard]] virtual ClaimPrekeyBundleResult claim_device_prekey_bundle(const domain::Uuid& device_id) = 0;

    /// Replenishes one-time prekeys for a target device after cryptographic validation and duplicate checks.
    virtual ReplenishPrekeysResult replenish_one_time_prekeys(const domain::Uuid& caller_user_id,
                                                              const domain::Uuid& caller_device_id,
                                                              const domain::Uuid& target_device_id,
                                                              const std::vector<std::vector<uint8_t>>& new_otks,
                                                              std::string_view client_ip = "unknown") = 0;

    /// Rotates signed prekey for a device after Ed25519 signature verification against Identity Key.
    virtual RotateSignedPrekeyResult
    rotate_signed_prekey(const domain::Uuid& caller_user_id, const domain::Uuid& caller_device_id,
                         const domain::Uuid& target_device_id, std::span<const uint8_t> new_signed_prekey,
                         std::span<const uint8_t> new_signature, std::string_view client_ip = "unknown") = 0;
};

/// Concrete thread-safe implementation of IPrekeyManager.
class PrekeyManager : public IPrekeyManager {
  public:
    static constexpr int32_t kDefaultLowInventoryThreshold = 20;
    static constexpr std::chrono::seconds kDefaultMaxSignedPrekeyAge = std::chrono::hours(24 * 7); // 7 days

    PrekeyManager(std::shared_ptr<repository::IDeviceRepository> device_repo,
                  std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo,
                  std::shared_ptr<IAuditEventPublisher> audit_publisher = nullptr,
                  int32_t low_inventory_threshold = kDefaultLowInventoryThreshold,
                  std::chrono::seconds max_signed_prekey_age = kDefaultMaxSignedPrekeyAge);

    [[nodiscard]] PrekeyInventoryStatusResult get_inventory_status(const domain::Uuid& device_id) override;

    [[nodiscard]] ClaimPrekeyBundleResult claim_device_prekey_bundle(const domain::Uuid& device_id) override;

    ReplenishPrekeysResult replenish_one_time_prekeys(const domain::Uuid& caller_user_id,
                                                      const domain::Uuid& caller_device_id,
                                                      const domain::Uuid& target_device_id,
                                                      const std::vector<std::vector<uint8_t>>& new_otks,
                                                      std::string_view client_ip = "unknown") override;

    RotateSignedPrekeyResult
    rotate_signed_prekey(const domain::Uuid& caller_user_id, const domain::Uuid& caller_device_id,
                         const domain::Uuid& target_device_id, std::span<const uint8_t> new_signed_prekey,
                         std::span<const uint8_t> new_signature, std::string_view client_ip = "unknown") override;

  private:
    std::shared_ptr<repository::IDeviceRepository> device_repo_;
    std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo_;
    std::shared_ptr<IAuditEventPublisher> audit_publisher_;
    int32_t low_inventory_threshold_;
    std::chrono::seconds max_signed_prekey_age_;
};

} // namespace securecloud::auth::service
