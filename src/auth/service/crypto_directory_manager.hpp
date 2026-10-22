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

/// Result returned when querying cryptographic identity of a single device.
struct CryptoIdentityResult {
    enum class Status { Success, NotFound, Revoked, PendingAuthorization, InternalError };

    Status status{Status::NotFound};
    domain::Uuid device_id{};
    domain::DeviceStatus device_status{domain::DeviceStatus::Active};
    std::vector<uint8_t> identity_key{};
    std::string identity_key_fingerprint{};
    std::optional<std::vector<uint8_t>> signed_prekey{std::nullopt};
    std::optional<std::vector<uint8_t>> signed_prekey_signature{std::nullopt};
    std::chrono::system_clock::time_point signed_prekey_created_at{};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }
    [[nodiscard]] bool is_revoked() const noexcept { return status == Status::Revoked; }
    [[nodiscard]] bool is_pending_authorization() const noexcept { return status == Status::PendingAuthorization; }

    static CryptoIdentityResult success(const domain::Uuid& dev_id, domain::DeviceStatus dev_status,
                                        std::vector<uint8_t> id_key, std::string fingerprint, std::vector<uint8_t> spk,
                                        std::vector<uint8_t> sig,
                                        std::chrono::system_clock::time_point spk_created_at) {
        CryptoIdentityResult r;
        r.status = Status::Success;
        r.device_id = dev_id;
        r.device_status = dev_status;
        r.identity_key = std::move(id_key);
        r.identity_key_fingerprint = std::move(fingerprint);
        r.signed_prekey = std::move(spk);
        r.signed_prekey_signature = std::move(sig);
        r.signed_prekey_created_at = spk_created_at;
        return r;
    }

    static CryptoIdentityResult revoked(const domain::Uuid& dev_id) {
        CryptoIdentityResult r;
        r.status = Status::Revoked;
        r.device_id = dev_id;
        r.device_status = domain::DeviceStatus::Revoked;
        r.error_message = "Device is revoked";
        return r;
    }

    static CryptoIdentityResult pending_authorization(const domain::Uuid& dev_id) {
        CryptoIdentityResult r;
        r.status = Status::PendingAuthorization;
        r.device_id = dev_id;
        r.device_status = domain::DeviceStatus::PendingAuthorization;
        r.error_message = "Device is pending authorization";
        return r;
    }

    static CryptoIdentityResult not_found(std::string_view msg = "Device not found") {
        CryptoIdentityResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static CryptoIdentityResult internal_error(std::string_view msg) {
        CryptoIdentityResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Result returned when querying device crypto directory prekey bundles for a user.
struct DeviceCryptoDirectoryResult {
    enum class Status { Success, NotFound, InternalError };

    Status status{Status::Success};
    domain::Uuid user_id{};
    std::vector<domain::PrekeyBundle> bundles{};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }

    static DeviceCryptoDirectoryResult success(const domain::Uuid& uid, std::vector<domain::PrekeyBundle> b) {
        DeviceCryptoDirectoryResult r;
        r.status = Status::Success;
        r.user_id = uid;
        r.bundles = std::move(b);
        return r;
    }

    static DeviceCryptoDirectoryResult not_found(std::string_view msg = "User not found") {
        DeviceCryptoDirectoryResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static DeviceCryptoDirectoryResult internal_error(std::string_view msg) {
        DeviceCryptoDirectoryResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Result returned when rotating signed prekey and/or replenishing one-time prekeys.
struct UpdateCryptoPrekeysResult {
    enum class Status { Success, NotFound, PermissionDenied, InvalidArgument, InternalError };

    Status status{Status::NotFound};
    domain::Uuid device_id{};
    bool signed_prekey_rotated{false};
    int32_t one_time_prekeys_added{0};
    int32_t total_active_one_time_prekeys{0};
    std::string error_message{};

    [[nodiscard]] bool is_success() const noexcept { return status == Status::Success; }
    [[nodiscard]] bool is_not_found() const noexcept { return status == Status::NotFound; }
    [[nodiscard]] bool is_permission_denied() const noexcept { return status == Status::PermissionDenied; }
    [[nodiscard]] bool is_invalid_argument() const noexcept { return status == Status::InvalidArgument; }

    static UpdateCryptoPrekeysResult success(const domain::Uuid& dev_id, bool spk_rotated, int32_t otk_added,
                                             int32_t total_active_otk) {
        UpdateCryptoPrekeysResult r;
        r.status = Status::Success;
        r.device_id = dev_id;
        r.signed_prekey_rotated = spk_rotated;
        r.one_time_prekeys_added = otk_added;
        r.total_active_one_time_prekeys = total_active_otk;
        return r;
    }

    static UpdateCryptoPrekeysResult not_found(std::string_view msg = "Target device not found") {
        UpdateCryptoPrekeysResult r;
        r.status = Status::NotFound;
        r.error_message = std::string(msg);
        return r;
    }

    static UpdateCryptoPrekeysResult permission_denied(std::string_view msg) {
        UpdateCryptoPrekeysResult r;
        r.status = Status::PermissionDenied;
        r.error_message = std::string(msg);
        return r;
    }

    static UpdateCryptoPrekeysResult invalid_argument(std::string_view msg) {
        UpdateCryptoPrekeysResult r;
        r.status = Status::InvalidArgument;
        r.error_message = std::string(msg);
        return r;
    }

    static UpdateCryptoPrekeysResult internal_error(std::string_view msg) {
        UpdateCryptoPrekeysResult r;
        r.status = Status::InternalError;
        r.error_message = std::string(msg);
        return r;
    }
};

/// Abstract interface contract for Public Cryptographic Identity & Directory operations.
class ICryptoDirectoryManager {
  public:
    virtual ~ICryptoDirectoryManager() = default;

    /// Queries cryptographic identity public keys and fingerprint for a device.
    /// Invariant: Strictly omits active prekey material if device is Revoked or PendingAuthorization.
    [[nodiscard]] virtual CryptoIdentityResult get_crypto_identity(const domain::Uuid& device_id) = 0;

    /// Dispatches end-to-end prekey bundles for all active devices of a user.
    /// Atomically claims one OTK per device (falling back gracefully to SPK-only if exhausted).
    /// Devices matching filter_device_ids (or all active devices if filter is empty) are returned.
    /// Non-active or revoked devices are strictly omitted.
    [[nodiscard]] virtual DeviceCryptoDirectoryResult
    get_device_crypto_directory(const domain::Uuid& user_id,
                                const std::vector<domain::Uuid>& filter_device_ids = {}) = 0;

    /// Rotates signed prekey and/or replenishes one-time prekeys for an active device.
    /// Enforces caller device ownership, Active status, and verifies Ed25519 signature
    /// against registered Identity Key when rotating signed prekey.
    virtual UpdateCryptoPrekeysResult update_crypto_prekeys(
        const domain::Uuid& caller_user_id, const domain::Uuid& caller_device_id, const domain::Uuid& target_device_id,
        std::span<const uint8_t> new_signed_prekey, std::span<const uint8_t> new_signature,
        const std::vector<std::vector<uint8_t>>& new_one_time_prekeys, std::string_view client_ip = "unknown") = 0;
};

/// Concrete thread-safe implementation of ICryptoDirectoryManager.
class CryptoDirectoryManager : public ICryptoDirectoryManager {
  public:
    CryptoDirectoryManager(std::shared_ptr<repository::IDeviceRepository> device_repo,
                           std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo,
                           std::shared_ptr<IAuditEventPublisher> audit_publisher = nullptr);

    [[nodiscard]] CryptoIdentityResult get_crypto_identity(const domain::Uuid& device_id) override;

    [[nodiscard]] DeviceCryptoDirectoryResult
    get_device_crypto_directory(const domain::Uuid& user_id,
                                const std::vector<domain::Uuid>& filter_device_ids = {}) override;

    UpdateCryptoPrekeysResult update_crypto_prekeys(
        const domain::Uuid& caller_user_id, const domain::Uuid& caller_device_id, const domain::Uuid& target_device_id,
        std::span<const uint8_t> new_signed_prekey, std::span<const uint8_t> new_signature,
        const std::vector<std::vector<uint8_t>>& new_one_time_prekeys, std::string_view client_ip = "unknown") override;

  private:
    std::shared_ptr<repository::IDeviceRepository> device_repo_;
    std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo_;
    std::shared_ptr<IAuditEventPublisher> audit_publisher_;
};

} // namespace securecloud::auth::service
