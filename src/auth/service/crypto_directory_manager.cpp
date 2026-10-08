#include "auth/service/crypto_directory_manager.hpp"

#include "auth/crypto/device_key_validator.hpp"
#include "auth/crypto/key_fingerprint.hpp"
#include "auth/crypto/prekey_signature_verifier.hpp"
#include "auth/domain/audit_event.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace securecloud::auth::service {

CryptoDirectoryManager::CryptoDirectoryManager(std::shared_ptr<repository::IDeviceRepository> device_repo,
                                               std::shared_ptr<repository::IDevicePublicKeyRepository> public_key_repo,
                                               std::shared_ptr<IAuditEventPublisher> audit_publisher)
    : device_repo_(std::move(device_repo)), public_key_repo_(std::move(public_key_repo)),
      audit_publisher_(std::move(audit_publisher)) {
    if (!device_repo_) {
        throw std::invalid_argument("CryptoDirectoryManager requires non-null IDeviceRepository");
    }
    if (!public_key_repo_) {
        throw std::invalid_argument("CryptoDirectoryManager requires non-null IDevicePublicKeyRepository");
    }
}

CryptoIdentityResult CryptoDirectoryManager::get_crypto_identity(const domain::Uuid& device_id) {
    std::optional<domain::DeviceEntity> dev_opt;
    try {
        dev_opt = device_repo_->find_by_id(device_id);
    } catch (const std::exception& ex) {
        return CryptoIdentityResult::internal_error(std::string("Repository error looking up device: ") + ex.what());
    }

    if (!dev_opt) {
        return CryptoIdentityResult::not_found("Device not found");
    }

    const auto& dev = *dev_opt;
    if (dev.device_status == domain::DeviceStatus::Revoked) {
        return CryptoIdentityResult::revoked(device_id);
    }
    if (dev.device_status == domain::DeviceStatus::PendingAuthorization) {
        return CryptoIdentityResult::pending_authorization(device_id);
    }
    if (dev.device_status != domain::DeviceStatus::Active) {
        return CryptoIdentityResult::not_found("Device is not active");
    }

    std::optional<domain::DevicePublicKeyEntity> id_key_opt;
    std::optional<domain::DevicePublicKeyEntity> spk_opt;
    try {
        id_key_opt = public_key_repo_->find_active_identity_key(device_id);
        spk_opt = public_key_repo_->find_active_signed_prekey(device_id);
    } catch (const std::exception& ex) {
        return CryptoIdentityResult::internal_error(std::string("Repository error looking up public keys: ") +
                                                    ex.what());
    }

    if (!id_key_opt) {
        return CryptoIdentityResult::internal_error("Active identity key not found for device");
    }
    if (!spk_opt) {
        return CryptoIdentityResult::internal_error("Active signed prekey not found for device");
    }

    std::string fingerprint = crypto::KeyFingerprint::compute_sha256(id_key_opt->public_key);

    return CryptoIdentityResult::success(device_id, dev.device_status, std::move(id_key_opt->public_key),
                                         std::move(fingerprint), std::move(spk_opt->public_key),
                                         spk_opt->signature.value_or(std::vector<uint8_t>{}), spk_opt->created_at);
}

DeviceCryptoDirectoryResult
CryptoDirectoryManager::get_device_crypto_directory(const domain::Uuid& user_id,
                                                    const std::vector<domain::Uuid>& filter_device_ids) {
    std::vector<domain::DeviceEntity> active_devices;
    try {
        active_devices = device_repo_->list_active_by_user_id(user_id);
    } catch (const std::exception& ex) {
        return DeviceCryptoDirectoryResult::internal_error(std::string("Repository error listing active devices: ") +
                                                           ex.what());
    }

    std::vector<domain::PrekeyBundle> bundles;
    bundles.reserve(active_devices.size());

    const bool has_filter = !filter_device_ids.empty();

    for (const auto& dev : active_devices) {
        if (dev.device_status != domain::DeviceStatus::Active) {
            continue;
        }

        if (has_filter) {
            bool matches = false;
            for (const auto& fid : filter_device_ids) {
                if (fid == dev.device_id) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                continue;
            }
        }

        std::optional<domain::DevicePublicKeyEntity> id_key_opt;
        std::optional<domain::DevicePublicKeyEntity> spk_opt;
        std::optional<domain::DevicePublicKeyEntity> otk_opt;
        int32_t remaining_otk = 0;

        try {
            id_key_opt = public_key_repo_->find_active_identity_key(dev.device_id);
            spk_opt = public_key_repo_->find_active_signed_prekey(dev.device_id);
            if (!id_key_opt || !spk_opt) {
                continue;
            }

            otk_opt = public_key_repo_->claim_one_time_prekey(dev.device_id);
            remaining_otk = public_key_repo_->count_active_one_time_prekeys(dev.device_id);
        } catch (const std::exception& ex) {
            return DeviceCryptoDirectoryResult::internal_error(std::string("Repository error assembling bundle: ") +
                                                               ex.what());
        }

        domain::PrekeyBundle bundle;
        bundle.device_id = dev.device_id;
        bundle.identity_key = std::move(id_key_opt->public_key);
        bundle.identity_key_fingerprint = crypto::KeyFingerprint::compute_sha256(bundle.identity_key);
        bundle.signed_prekey = std::move(spk_opt->public_key);
        bundle.signed_prekey_signature = spk_opt->signature.value_or(std::vector<uint8_t>{});
        bundle.signed_prekey_created_at = spk_opt->created_at;

        if (otk_opt) {
            bundle.one_time_prekey = std::move(otk_opt->public_key);
            bundle.one_time_prekey_id = otk_opt->key_id;
        } else {
            bundle.one_time_prekey = std::nullopt;
            bundle.one_time_prekey_id = std::nullopt;
        }

        bundle.device_status = dev.device_status;
        bundle.remaining_one_time_prekeys = remaining_otk;

        bundles.push_back(std::move(bundle));
    }

    return DeviceCryptoDirectoryResult::success(user_id, std::move(bundles));
}

UpdateCryptoPrekeysResult CryptoDirectoryManager::update_crypto_prekeys(
    const domain::Uuid& caller_user_id, const domain::Uuid& caller_device_id, const domain::Uuid& target_device_id,
    std::span<const uint8_t> new_signed_prekey, std::span<const uint8_t> new_signature,
    const std::vector<std::vector<uint8_t>>& new_one_time_prekeys, std::string_view client_ip) {

    if (new_signed_prekey.empty() && new_one_time_prekeys.empty()) {
        return UpdateCryptoPrekeysResult::invalid_argument("No prekey material provided for update");
    }

    std::optional<domain::DeviceEntity> target_dev_opt;
    try {
        target_dev_opt = device_repo_->find_by_id(target_device_id);
    } catch (const std::exception& ex) {
        return UpdateCryptoPrekeysResult::internal_error(std::string("Repository error looking up device: ") +
                                                         ex.what());
    }

    if (!target_dev_opt) {
        return UpdateCryptoPrekeysResult::not_found("Target device not found");
    }

    const auto& target_dev = *target_dev_opt;
    if (caller_user_id != target_dev.user_id) {
        return UpdateCryptoPrekeysResult::permission_denied("Caller does not own target device");
    }
    if (caller_device_id != target_dev.device_id) {
        return UpdateCryptoPrekeysResult::permission_denied("Caller can only update prekeys for their own device");
    }
    if (target_dev.device_status != domain::DeviceStatus::Active) {
        return UpdateCryptoPrekeysResult::permission_denied("Device is not active");
    }

    bool signed_prekey_rotated = false;
    int32_t one_time_prekeys_added = 0;

    // Handle Signed Prekey rotation
    if (!new_signed_prekey.empty()) {
        if (new_signature.empty()) {
            return UpdateCryptoPrekeysResult::invalid_argument("Signed prekey requires accompanying signature");
        }

        std::string val_err;
        if (!crypto::DeviceKeyValidator::validate_signed_prekey(new_signed_prekey, &val_err)) {
            return UpdateCryptoPrekeysResult::invalid_argument("Invalid signed prekey: " + val_err);
        }

        std::optional<domain::DevicePublicKeyEntity> id_key_opt;
        try {
            id_key_opt = public_key_repo_->find_active_identity_key(target_device_id);
        } catch (const std::exception& ex) {
            return UpdateCryptoPrekeysResult::internal_error(std::string("Repository error fetching identity key: ") +
                                                             ex.what());
        }

        if (!id_key_opt) {
            return UpdateCryptoPrekeysResult::internal_error("Active identity key not found for device");
        }

        std::string sig_err;
        if (!crypto::PrekeySignatureVerifier::verify(id_key_opt->public_key, new_signed_prekey, new_signature,
                                                     &sig_err)) {
            return UpdateCryptoPrekeysResult::invalid_argument("Signed prekey signature verification failed: " +
                                                               sig_err);
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
        } catch (const std::exception& ex) {
            return UpdateCryptoPrekeysResult::internal_error(std::string("Repository error storing signed prekey: ") +
                                                             ex.what());
        }

        signed_prekey_rotated = true;
        if (audit_publisher_) {
            audit_publisher_->publish(
                domain::AuditEvent::signed_prekey_rotated(target_dev.user_id, target_device_id, client_ip));
        }
    }

    // Handle One-Time Prekeys replenishment
    if (!new_one_time_prekeys.empty()) {
        std::string val_err;
        if (!crypto::DeviceKeyValidator::validate_one_time_prekeys(new_one_time_prekeys, &val_err)) {
            return UpdateCryptoPrekeysResult::invalid_argument("Invalid one-time prekeys: " + val_err);
        }

        try {
            public_key_repo_->store_one_time_prekeys(target_device_id, new_one_time_prekeys);
        } catch (const std::exception& ex) {
            return UpdateCryptoPrekeysResult::internal_error(
                std::string("Repository error storing one-time prekeys: ") + ex.what());
        }

        one_time_prekeys_added = static_cast<int32_t>(new_one_time_prekeys.size());

        int32_t current_active_otk = 0;
        try {
            current_active_otk = public_key_repo_->count_active_one_time_prekeys(target_device_id);
        } catch (const std::exception& ex) {
            return UpdateCryptoPrekeysResult::internal_error(
                std::string("Repository error counting one-time prekeys: ") + ex.what());
        }

        if (audit_publisher_) {
            audit_publisher_->publish(domain::AuditEvent::prekeys_updated(target_dev.user_id, target_device_id,
                                                                          current_active_otk, client_ip));
        }
    }

    int32_t total_active_otk = 0;
    try {
        total_active_otk = public_key_repo_->count_active_one_time_prekeys(target_device_id);
    } catch (const std::exception& ex) {
        return UpdateCryptoPrekeysResult::internal_error(std::string("Repository error counting one-time prekeys: ") +
                                                         ex.what());
    }

    return UpdateCryptoPrekeysResult::success(target_device_id, signed_prekey_rotated, one_time_prekeys_added,
                                              total_active_otk);
}

} // namespace securecloud::auth::service
