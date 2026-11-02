#pragma once

#include "client/auth_crypto_directory_client_interface.hpp"
#include "domain/conversation_types.hpp"
#include "domain/envelope_types.hpp"
#include "domain/message_types.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <chrono>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::service {

/**
 * @brief Thread-safe in-memory LRU Cache with Time-To-Live (TTL) for device crypto records.
 *
 * Eliminates the Auth directory "thundering herd" problem by serving conversational
 * bursts from memory within the configured TTL (default: 30 seconds).
 */
class DeviceDirectoryCache {
  public:
    explicit DeviceDirectoryCache(size_t capacity = 10000,
                                  std::chrono::milliseconds ttl = std::chrono::milliseconds(30000));

    /**
     * @brief Looks up cached records for a user.
     * @return Stored device records if present and unexpired; std::nullopt otherwise.
     */
    [[nodiscard]] std::optional<std::vector<client::DeviceCryptoRecord>> get(const domain::UserId& user_id);

    /**
     * @brief Inserts or updates cached records for a user, evicting the LRU tail if capacity is reached.
     */
    void put(const domain::UserId& user_id, std::vector<client::DeviceCryptoRecord> records);

    /**
     * @brief Explicitly invalidates cache entry for a given user.
     */
    void invalidate(const domain::UserId& user_id);

    /**
     * @brief Explicitly invalidates cached records containing a specific device ID.
     */
    void invalidate_device(const domain::DeviceId& device_id);

    /**
     * @brief Flushes all cached entries.
     */
    void clear();

    /**
     * @brief Returns current number of active entries in cache.
     */
    [[nodiscard]] size_t size() const;

  private:
    struct Entry {
        std::vector<client::DeviceCryptoRecord> records;
        std::chrono::steady_clock::time_point cached_at;
        std::list<domain::UserId>::iterator lru_it;
    };

    size_t capacity_;
    std::chrono::milliseconds ttl_;
    mutable std::mutex mutex_;
    std::list<domain::UserId> lru_order_;
    std::unordered_map<domain::UserId, Entry> entries_;
};

/**
 * @brief Detailed outcome of recipient device target validation.
 */
struct TargetDeviceValidationResult {
    bool is_valid{false};
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    std::string error_message{};
    std::vector<domain::DeviceId> omitted_device_ids{};

    auto operator<=>(const TargetDeviceValidationResult& other) const noexcept = default;
    bool operator==(const TargetDeviceValidationResult& other) const noexcept = default;
};

/**
 * @brief Authoritative Recipient Device Resolution & Target Validation Service.
 *
 * Coordinates between the Messaging submission pipeline and the Auth public crypto directory:
 * - Resolves all active enrolled devices for conversation participants.
 * - Validates device ownership, participant membership, and active lifecycle status.
 * - Enforces fail-closed rejection of revoked or pending devices.
 * - Detects and flags selective device omission attacks.
 */
class RecipientDeviceResolutionService {
  public:
    explicit RecipientDeviceResolutionService(std::shared_ptr<client::IAuthCryptoDirectoryClient> auth_client,
                                              size_t cache_capacity = 10000,
                                              std::chrono::milliseconds cache_ttl = std::chrono::milliseconds(30000));

    /**
     * @brief Resolves device crypto records for a single user (cached read-through).
     */
    client::Result<std::vector<client::DeviceCryptoRecord>, client::CryptoDirectoryError>
    resolve_devices_for_user(const domain::UserId& user_id);

    /**
     * @brief Resolves device crypto records for multiple users concurrently.
     */
    client::Result<std::unordered_map<domain::UserId, std::vector<client::DeviceCryptoRecord>>,
                   client::CryptoDirectoryError>
    resolve_devices_for_users(const std::vector<domain::UserId>& user_ids);

    /**
     * @brief Validates that delivery targets in a message submission comply with security rules:
     * 1. Every recipient user is an authorized conversation participant.
     * 2. Every target device belongs to the declared recipient user.
     * 3. Target devices are in DEVICE_STATUS_ACTIVE (revoked/pending are rejected).
     * 4. Optional completeness enforcement (no active devices omitted).
     */
    TargetDeviceValidationResult
    validate_submission_targets(const std::vector<domain::UserId>& conversation_participant_ids,
                                const std::vector<domain::PerDeviceEnvelope>& target_envelopes,
                                const domain::DeviceId& sender_device_id = domain::DeviceId{},
                                const domain::UserId& sender_user_id = domain::UserId{},
                                bool enforce_completeness = false);

    /**
     * @brief Explicitly invalidates the cache for a specific user.
     */
    void invalidate_user_cache(const domain::UserId& user_id);

    /**
     * @brief Explicitly invalidates the cache for any user possessing the specified device ID.
     */
    void invalidate_device(const domain::DeviceId& device_id);

    /**
     * @brief Resolves and returns current device lifecycle status if found.
     */
    [[nodiscard]] std::optional<securecloud::auth::v1::DeviceStatus>
    get_device_status(const domain::UserId& user_id, const domain::DeviceId& device_id);

    /**
     * @brief Clears the entire in-memory cache.
     */
    void clear_cache();

    /**
     * @brief Returns the number of cached user entries.
     */
    [[nodiscard]] size_t cache_size() const;

  private:
    std::shared_ptr<client::IAuthCryptoDirectoryClient> auth_client_;
    DeviceDirectoryCache cache_;
};

} // namespace securecloud::messaging::service
