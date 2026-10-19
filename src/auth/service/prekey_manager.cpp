#include "auth/service/prekey_manager.hpp"

#include "auth/crypto/key_fingerprint.hpp"
#include "auth/crypto/prekey_signature_verifier.hpp"
#include "auth/crypto/prekey_validator.hpp"

#include <chrono>
#include <stdexcept>
#include <utility>

namespace securecloud::auth::service {

PrekeyManager::PrekeyManager(std::shared_ptr<repository::IDeviceRepository> device_repo,
                             std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo,
                             std::shared_ptr<IAuditEventPublisher> audit_publisher, int32_t low_inventory_threshold,
                             std::chrono::seconds max_signed_prekey_age)
    : device_repo_(std::move(device_repo)), public_key_repo_(std::move(public_key_repo)),
      audit_publisher_(std::move(audit_publisher)), low_inventory_threshold_(low_inventory_threshold),
      max_signed_prekey_age_(max_signed_prekey_age) {
    if (!device_repo_) {
        throw std::invalid_argument("PrekeyManager: device_repo must not be null");
    }
    if (!public_key_repo_) {
        throw std::invalid_argument("PrekeyManager: public_key_repo must not be null");
    }
}

PrekeyInventoryStatusResult PrekeyManager::get_inventory_status(const domain::Uuid& device_id) {
    std::optional<domain::DeviceEntity> dev_opt;
    try {
        dev_opt = device_repo_->find_by_id(device_id);
    } catch (const std::exception& ex) {
        return PrekeyInventoryStatusResult::internal_error(std::string("Repository error looking up device: ") +
                                                           ex.what());
    }

    if (!dev_opt) {
        return PrekeyInventoryStatusResult::not_found("Target device not found");
    }

    if (dev_opt->device_status == domain::DeviceStatus::Revoked) {
        return PrekeyInventoryStatusResult::device_revoked("Device is revoked");
    }

    int32_t active_count = 0;
    int32_t claimed_count = 0;
    std::optional<domain::DevicePublicKeyEntity> spk_opt;
    try {
        active_count = public_key_repo_->count_active_one_time_prekeys(device_id);
        claimed_count = public_key_repo_->count_claimed_one_time_prekeys(device_id);
        spk_opt = public_key_repo_->find_active_signed_prekey(device_id);
    } catch (const std::exception& ex) {
        return PrekeyInventoryStatusResult::internal_error(std::string("Repository error querying prekeys: ") +
                                                           ex.what());
    }

    domain::PrekeyInventoryStatus inv;
    inv.device_id = device_id;
    inv.active_one_time_prekeys = active_count;
    inv.claimed_one_time_prekeys = claimed_count;
    inv.low_inventory_threshold = low_inventory_threshold_;
    inv.is_low_inventory = (active_count <= low_inventory_threshold_);
    inv.is_exhausted = (active_count == 0);

    if (spk_opt) {
        inv.signed_prekey_created_at = spk_opt->created_at;
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - spk_opt->created_at).count();
        inv.signed_prekey_age_seconds = age > 0 ? age : 0;
        inv.signed_prekey_needs_rotation = (inv.signed_prekey_age_seconds >= max_signed_prekey_age_.count());
    } else {
        inv.signed_prekey_needs_rotation = true;
    }

    return PrekeyInventoryStatusResult::success(std::move(inv));
}

ClaimPrekeyBundleResult PrekeyManager::claim_device_prekey_bundle(const domain::Uuid& device_id) {
    std::optional<domain::DeviceEntity> dev_opt;
    try {
        dev_opt = device_repo_->find_by_id(device_id);
    } catch (const std::exception& ex) {
        return ClaimPrekeyBundleResult::internal_error(std::string("Repository error looking up device: ") + ex.what());
    }

    if (!dev_opt) {
        return ClaimPrekeyBundleResult::not_found("Target device not found");
    }

    if (dev_opt->device_status == domain::DeviceStatus::Revoked) {
        return ClaimPrekeyBundleResult::device_revoked("Device is revoked");
    }

    if (dev_opt->device_status != domain::DeviceStatus::Active) {
        return ClaimPrekeyBundleResult::device_not_active("Device is not active");
    }

    std::optional<domain::DevicePublicKeyEntity> id_key_opt;
    std::optional<domain::DevicePublicKeyEntity> spk_opt;
    std::optional<domain::DevicePublicKeyEntity> otk_opt;
    int32_t remaining_otk = 0;

    try {
        id_key_opt = public_key_repo_->find_active_identity_key(device_id);
        spk_opt = public_key_repo_->find_active_signed_prekey(device_id);

        if (!id_key_opt) {
            return ClaimPrekeyBundleResult::internal_error("Active identity key not found for device");
        }
        if (!spk_opt) {
            return ClaimPrekeyBundleResult::internal_error("Active signed prekey not found for device");
        }

        otk_opt = public_key_repo_->claim_one_time_prekey(device_id);
        remaining_otk = public_key_repo_->count_active_one_time_prekeys(device_id);
    } catch (const std::exception& ex) {
        return ClaimPrekeyBundleResult::internal_error(std::string("Repository error claiming bundle: ") + ex.what());
    }

    domain::PrekeyExhaustionState state = domain::PrekeyExhaustionState::InventoryHealthy;
    if (!otk_opt) {
        state = domain::PrekeyExhaustionState::InventoryExhausted;
        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::prekey_inventory_exhausted(dev_opt->user_id, device_id));
        }
    } else {
        if (remaining_otk <= low_inventory_threshold_) {
            state = domain::PrekeyExhaustionState::InventoryLow;
            if (audit_publisher_) {
                audit_publisher_->publish(
                    domain::AuditEvent::prekey_inventory_low(dev_opt->user_id, device_id, remaining_otk));
            }
        }
    }

    std::string fingerprint = crypto::KeyFingerprint::compute_sha256(id_key_opt->public_key);
    std::vector<uint8_t> spk_sig = spk_opt->signature.value_or(std::vector<uint8_t>{});

    std::optional<std::vector<uint8_t>> otk_bytes = std::nullopt;
    std::optional<domain::Uuid> otk_id = std::nullopt;
    if (otk_opt) {
        otk_bytes = std::move(otk_opt->public_key);
        otk_id = otk_opt->key_id;
    }

    return ClaimPrekeyBundleResult::success(device_id, std::move(id_key_opt->public_key), std::move(fingerprint),
                                            std::move(spk_opt->public_key), std::move(spk_sig), spk_opt->created_at,
                                            std::move(otk_bytes), otk_id, state);
}

ReplenishPrekeysResult PrekeyManager::replenish_one_time_prekeys(const domain::Uuid& caller_user_id,
                                                                 const domain::Uuid& caller_device_id,
                                                                 const domain::Uuid& target_device_id,
                                                                 const std::vector<std::vector<uint8_t>>& new_otks,
                                                                 std::string_view client_ip) {
    std::optional<domain::DeviceEntity> dev_opt;
    try {
        dev_opt = device_repo_->find_by_id(target_device_id);
    } catch (const std::exception& ex) {
        return ReplenishPrekeysResult::internal_error(std::string("Repository error looking up device: ") + ex.what());
    }

    if (!dev_opt) {
        return ReplenishPrekeysResult::not_found("Target device not found");
    }

    if (dev_opt->device_status == domain::DeviceStatus::Revoked) {
        return ReplenishPrekeysResult::device_revoked("Device is revoked");
    }

    if (caller_user_id != dev_opt->user_id) {
        return ReplenishPrekeysResult::permission_denied("Caller does not own target device");
    }

    if (caller_device_id != target_device_id) {
        return ReplenishPrekeysResult::permission_denied("Caller can only replenish prekeys for their own device");
    }

    if (dev_opt->device_status != domain::DeviceStatus::Active) {
        return ReplenishPrekeysResult::device_not_active("Device is not active");
    }

    std::string val_err;
    if (!crypto::PrekeyValidator::validate_prekey_batch(new_otks, &val_err)) {
        return ReplenishPrekeysResult::invalid_argument(val_err);
    }

    try {
        for (const auto& key : new_otks) {
            if (public_key_repo_->has_active_key_conflict(target_device_id, key)) {
                return ReplenishPrekeysResult::conflict("One or more one-time prekeys are already registered");
            }
        }

        public_key_repo_->store_one_time_prekeys(target_device_id, new_otks);
        int32_t active_count = public_key_repo_->count_active_one_time_prekeys(target_device_id);

        if (audit_publisher_) {
            audit_publisher_->publish(
                domain::AuditEvent::prekeys_updated(dev_opt->user_id, target_device_id, active_count, client_ip));
        }

        return ReplenishPrekeysResult::success(active_count);
    } catch (const std::exception& ex) {
        return ReplenishPrekeysResult::internal_error(std::string("Repository error storing prekeys: ") + ex.what());
    }
}

RotateSignedPrekeyResult
PrekeyManager::rotate_signed_prekey(const domain::Uuid& caller_user_id, const domain::Uuid& caller_device_id,
                                    const domain::Uuid& target_device_id, std::span<const uint8_t> new_signed_prekey,
                                    std::span<const uint8_t> new_signature, std::string_view client_ip) {
    std::optional<domain::DeviceEntity> dev_opt;
    try {
        dev_opt = device_repo_->find_by_id(target_device_id);
    } catch (const std::exception& ex) {
        return RotateSignedPrekeyResult::internal_error(std::string("Repository error looking up device: ") +
                                                        ex.what());
    }

    if (!dev_opt) {
        return RotateSignedPrekeyResult::not_found("Target device not found");
    }

    if (dev_opt->device_status == domain::DeviceStatus::Revoked) {
        return RotateSignedPrekeyResult::device_revoked("Device is revoked");
    }

    if (caller_user_id != dev_opt->user_id) {
        return RotateSignedPrekeyResult::permission_denied("Caller does not own target device");
    }

    if (caller_device_id != target_device_id) {
        return RotateSignedPrekeyResult::permission_denied("Caller can only rotate prekeys for their own device");
    }

    if (dev_opt->device_status != domain::DeviceStatus::Active) {
        return RotateSignedPrekeyResult::device_not_active("Device is not active");
    }

    std::string val_err;
    if (!crypto::PrekeyValidator::validate_single_prekey(new_signed_prekey, &val_err)) {
        return RotateSignedPrekeyResult::invalid_argument("Invalid signed prekey: " + val_err);
    }

    if (new_signature.size() != 64) {
        return RotateSignedPrekeyResult::invalid_argument("Signed prekey signature must be exactly 64 bytes");
    }

    std::optional<domain::DevicePublicKeyEntity> id_key_opt;
    try {
        id_key_opt = public_key_repo_->find_active_identity_key(target_device_id);
    } catch (const std::exception& ex) {
        return RotateSignedPrekeyResult::internal_error(std::string("Repository error looking up identity key: ") +
                                                        ex.what());
    }

    if (!id_key_opt) {
        return RotateSignedPrekeyResult::internal_error("Active identity key not found for device");
    }

    std::string sig_err;
    if (!crypto::PrekeySignatureVerifier::verify(id_key_opt->public_key, new_signed_prekey, new_signature, &sig_err)) {
        return RotateSignedPrekeyResult::invalid_argument("Signed prekey signature verification failed: " + sig_err);
    }

    auto now = std::chrono::system_clock::now();
    domain::DevicePublicKeyEntity new_spk_entity{
        .key_id = domain::Uuid::generate_v7(),
        .device_id = target_device_id,
        .key_type = domain::KeyType::SignedPrekey,
        .public_key = std::vector<uint8_t>(new_signed_prekey.begin(), new_signed_prekey.end()),
        .key_status = domain::KeyStatus::Active,
        .created_at = now,
        .revoked_at = std::nullopt,
        .replaced_by_key_id = std::nullopt,
        .signature = std::vector<uint8_t>(new_signature.begin(), new_signature.end()),
    };

    try {
        auto current_spk_opt = public_key_repo_->find_active_signed_prekey(target_device_id);
        if (current_spk_opt) {
            public_key_repo_->replace_key(current_spk_opt->key_id, new_spk_entity);
        } else {
            public_key_repo_->store_public_key(new_spk_entity);
        }

        if (audit_publisher_) {
            audit_publisher_->publish(
                domain::AuditEvent::signed_prekey_rotated(dev_opt->user_id, target_device_id, client_ip));
        }

        return RotateSignedPrekeyResult::success();
    } catch (const std::exception& ex) {
        return RotateSignedPrekeyResult::internal_error(std::string("Repository error storing signed prekey: ") +
                                                        ex.what());
    }
}

} // namespace securecloud::auth::service
