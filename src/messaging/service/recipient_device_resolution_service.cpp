#include "service/recipient_device_resolution_service.hpp"

#include <algorithm>
#include <unordered_set>

namespace securecloud::messaging::service {

// ============================================================================
// DeviceDirectoryCache Implementation
// ============================================================================

DeviceDirectoryCache::DeviceDirectoryCache(size_t capacity, std::chrono::milliseconds ttl)
    : capacity_(capacity > 0 ? capacity : 1), ttl_(ttl) {}

std::optional<std::vector<client::DeviceCryptoRecord>> DeviceDirectoryCache::get(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(user_id);
    if (it == entries_.end()) {
        return std::nullopt;
    }

    const auto now = std::chrono::steady_clock::now();
    if (now - it->second.cached_at > ttl_) {
        // Expired entry -> purge
        lru_order_.erase(it->second.lru_it);
        entries_.erase(it);
        return std::nullopt;
    }

    // Move to front of LRU list (most recently used)
    lru_order_.erase(it->second.lru_it);
    lru_order_.push_front(user_id);
    it->second.lru_it = lru_order_.begin();

    return it->second.records;
}

void DeviceDirectoryCache::put(const domain::UserId& user_id, std::vector<client::DeviceCryptoRecord> records) {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto now = std::chrono::steady_clock::now();
    auto it = entries_.find(user_id);
    if (it != entries_.end()) {
        // Update existing entry
        it->second.records = std::move(records);
        it->second.cached_at = now;
        lru_order_.erase(it->second.lru_it);
        lru_order_.push_front(user_id);
        it->second.lru_it = lru_order_.begin();
        return;
    }

    // Evict oldest if at capacity
    if (entries_.size() >= capacity_ && !lru_order_.empty()) {
        const auto& oldest_user = lru_order_.back();
        entries_.erase(oldest_user);
        lru_order_.pop_back();
    }

    // Insert new entry at front
    lru_order_.push_front(user_id);
    entries_[user_id] = Entry{
        .records = std::move(records),
        .cached_at = now,
        .lru_it = lru_order_.begin(),
    };
}

void DeviceDirectoryCache::invalidate(const domain::UserId& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(user_id);
    if (it != entries_.end()) {
        lru_order_.erase(it->second.lru_it);
        entries_.erase(it);
    }
}

void DeviceDirectoryCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    lru_order_.clear();
}

size_t DeviceDirectoryCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

// ============================================================================
// RecipientDeviceResolutionService Implementation
// ============================================================================

RecipientDeviceResolutionService::RecipientDeviceResolutionService(
    std::shared_ptr<client::IAuthCryptoDirectoryClient> auth_client, size_t cache_capacity,
    std::chrono::milliseconds cache_ttl)
    : auth_client_(std::move(auth_client)), cache_(cache_capacity, cache_ttl) {}

client::Result<std::vector<client::DeviceCryptoRecord>, client::CryptoDirectoryError>
RecipientDeviceResolutionService::resolve_devices_for_user(const domain::UserId& user_id) {
    auto cached = cache_.get(user_id);
    if (cached.has_value()) {
        return cached.value();
    }

    if (!auth_client_) {
        return client::CryptoDirectoryError{
            .kind = client::CryptoDirectoryErrorKind::ServiceUnavailable,
            .message = "Auth crypto directory client is uninitialized",
            .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
        };
    }

    auto result = auth_client_->get_user_device_crypto_records(user_id);
    if (!result.has_value()) {
        return result.error();
    }

    cache_.put(user_id, result.value());
    return result.value();
}

client::Result<std::unordered_map<domain::UserId, std::vector<client::DeviceCryptoRecord>>,
               client::CryptoDirectoryError>
RecipientDeviceResolutionService::resolve_devices_for_users(const std::vector<domain::UserId>& user_ids) {
    std::unordered_map<domain::UserId, std::vector<client::DeviceCryptoRecord>> directory_map;

    for (const auto& uid : user_ids) {
        if (directory_map.find(uid) != directory_map.end()) {
            continue;
        }

        auto res = resolve_devices_for_user(uid);
        if (!res.has_value()) {
            return res.error();
        }

        directory_map[uid] = std::move(res.value());
    }

    return directory_map;
}

TargetDeviceValidationResult RecipientDeviceResolutionService::validate_submission_targets(
    const std::vector<domain::UserId>& conversation_participant_ids,
    const std::vector<domain::PerDeviceEnvelope>& target_envelopes, const domain::DeviceId& sender_device_id,
    const domain::UserId& sender_user_id, bool enforce_completeness) {
    if (target_envelopes.empty()) {
        return TargetDeviceValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
            .error_message = "Message submission contains no delivery targets",
            .omitted_device_ids = {},
        };
    }

    std::unordered_set<domain::UserId> participant_set(conversation_participant_ids.begin(),
                                                       conversation_participant_ids.end());

    // 1. Participant membership check
    for (const auto& env : target_envelopes) {
        if (!participant_set.contains(env.recipient_user_id)) {
            return TargetDeviceValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                .error_message =
                    "Recipient user is not a participant in the conversation: " + env.recipient_user_id.str(),
                .omitted_device_ids = {},
            };
        }
    }

    // 2. Resolve device directories for all participants
    auto dir_res = resolve_devices_for_users(conversation_participant_ids);
    if (!dir_res.has_value()) {
        return TargetDeviceValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
            .error_message = "Failed to query Auth device directory: " + dir_res.error().message,
            .omitted_device_ids = {},
        };
    }
    const auto& dir_map = dir_res.value();

    // 3. Target device ownership and active lifecycle validation
    for (const auto& env : target_envelopes) {
        auto it = dir_map.find(env.recipient_user_id);
        if (it == dir_map.end()) {
            return TargetDeviceValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
                .error_message = "No device directory entry found for recipient: " + env.recipient_user_id.str(),
                .omitted_device_ids = {},
            };
        }

        const auto& user_devices = it->second;
        auto dev_it = std::find_if(user_devices.begin(), user_devices.end(), [&](const client::DeviceCryptoRecord& r) {
            return r.device_id == env.recipient_device_id;
        });

        if (dev_it == user_devices.end()) {
            return TargetDeviceValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
                .error_message = "Target device " + env.recipient_device_id.str() + " does not belong to recipient " +
                                 env.recipient_user_id.str(),
                .omitted_device_ids = {},
            };
        }

        if (dev_it->status == securecloud::auth::v1::DEVICE_STATUS_REVOKED) {
            return TargetDeviceValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                .error_message = "Target device " + env.recipient_device_id.str() + " has been revoked",
                .omitted_device_ids = {},
            };
        }

        if (dev_it->status != securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
            return TargetDeviceValidationResult{
                .is_valid = false,
                .error_code = v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                .error_message = "Target device " + env.recipient_device_id.str() +
                                 " is not active (status=" + std::to_string(dev_it->status) + ")",
                .omitted_device_ids = {},
            };
        }
    }

    // 4. Sender device validation (if specified)
    if (!sender_device_id.empty() && !sender_user_id.empty()) {
        auto s_it = dir_map.find(sender_user_id);
        if (s_it != dir_map.end()) {
            auto s_dev =
                std::find_if(s_it->second.begin(), s_it->second.end(),
                             [&](const client::DeviceCryptoRecord& r) { return r.device_id == sender_device_id; });
            if (s_dev != s_it->second.end() && s_dev->status == securecloud::auth::v1::DEVICE_STATUS_REVOKED) {
                return TargetDeviceValidationResult{
                    .is_valid = false,
                    .error_code = v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
                    .error_message = "Sender device " + sender_device_id.str() + " has been revoked",
                    .omitted_device_ids = {},
                };
            }
        }
    }

    // 5. Completeness / Selective Omission detection
    std::vector<domain::DeviceId> omitted;
    for (const auto& participant_id : conversation_participant_ids) {
        if (participant_id == sender_user_id) {
            continue;
        }

        auto it = dir_map.find(participant_id);
        if (it != dir_map.end()) {
            for (const auto& dev : it->second) {
                if (dev.status == securecloud::auth::v1::DEVICE_STATUS_ACTIVE) {
                    bool targeted = false;
                    for (const auto& env : target_envelopes) {
                        if (env.recipient_user_id == participant_id && env.recipient_device_id == dev.device_id) {
                            targeted = true;
                            break;
                        }
                    }
                    if (!targeted) {
                        omitted.push_back(dev.device_id);
                    }
                }
            }
        }
    }

    if (enforce_completeness && !omitted.empty()) {
        return TargetDeviceValidationResult{
            .is_valid = false,
            .error_code = v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
            .error_message = "Incomplete delivery targets: active recipient devices were omitted",
            .omitted_device_ids = std::move(omitted),
        };
    }

    return TargetDeviceValidationResult{
        .is_valid = true,
        .error_code = v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
        .error_message = {},
        .omitted_device_ids = std::move(omitted),
    };
}

void RecipientDeviceResolutionService::invalidate_user_cache(const domain::UserId& user_id) {
    cache_.invalidate(user_id);
}

void RecipientDeviceResolutionService::clear_cache() {
    cache_.clear();
}

size_t RecipientDeviceResolutionService::cache_size() const {
    return cache_.size();
}

} // namespace securecloud::messaging::service
