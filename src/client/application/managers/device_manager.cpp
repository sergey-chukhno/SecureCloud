#include "application/managers/device_manager.hpp"

#include "application/managers/ratchet_session_manager.hpp"
#include "domain/prekey_policy.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"

namespace securecloud::client::application::managers {

namespace {

constexpr std::string_view kLocalDeviceIdKey = "device.local.id";

} // namespace

DeviceManager::DeviceManager(interfaces::IGatewayClient& gateway, interfaces::ISecureStorage& secure_storage,
                             interfaces::ICryptoProvider& crypto_provider)
    : gateway_(gateway), secure_storage_(secure_storage), crypto_provider_(crypto_provider),
      coordinator_(gateway, secure_storage, crypto_provider) {}

ClientResult<domain::Device> DeviceManager::initialize_or_load_device(const domain::UserId& user_id,
                                                                      std::string_view display_name) {
    if (local_device_.has_value()) {
        return ClientResult<domain::Device>::ok(*local_device_);
    }

    auto has_id_res = secure_storage_.has_secret(kLocalDeviceIdKey);
    if (has_id_res.is_ok() && has_id_res.value()) {
        auto id_secret_res = secure_storage_.get_secret(kLocalDeviceIdKey);
        if (id_secret_res.is_ok()) {
            const std::string dev_id_str = id_secret_res.value().expose_unredacted_secret();
            if (!dev_id_str.empty()) {
                const domain::DeviceId dev_id(dev_id_str);
                auto has_bundle_res = infrastructure::adapters::KeyStorageHelper::has_bundle(secure_storage_, dev_id);
                if (has_bundle_res.is_ok() && has_bundle_res.value()) {
                    auto load_res = infrastructure::adapters::KeyStorageHelper::load_bundle(secure_storage_, dev_id);
                    if (load_res.is_ok()) {
                        const auto& bundle = load_res.value();
                        auto fp_res = crypto_provider_.compute_identity_fingerprint(bundle.identity_public_key());
                        std::string fp = fp_res.is_ok() ? fp_res.value() : "SHA256:UNKNOWN";

                        domain::CryptoIdentity identity(
                            bundle.identity_public_key(), std::move(fp), domain::KeyVerificationStatus::Verified,
                            bundle.signed_prekey_public_key(), bundle.signed_prekey_signature(), bundle.created_at());

                        std::string dname = display_name.empty() ? "Primary Device" : std::string(display_name);
                        local_device_ =
                            domain::Device(dev_id, user_id, std::move(dname), std::move(identity),
                                           domain::DeviceAuthorizationStatus::Authorized, bundle.created_at());
                        return ClientResult<domain::Device>::ok(*local_device_);
                    }
                }
            }
        }
    }

    // No local device found; proceed with new registration
    return register_device(user_id, display_name);
}

ClientResult<domain::Device> DeviceManager::register_device(const domain::UserId& user_id,
                                                            std::string_view display_name) {
    if (user_id.empty()) {
        return ClientResult<domain::Device>::error(
            ClientError::validation("User ID cannot be empty for device registration"));
    }

    // 1. Generate identity keypair
    auto id_res = crypto_provider_.generate_identity_keypair();
    if (!id_res.is_ok()) {
        return ClientResult<domain::Device>::error(id_res.error());
    }
    auto id_pair = std::move(id_res).value();

    // 2. Generate signed prekey
    auto spk_res = crypto_provider_.generate_signed_prekey(id_pair.private_key);
    if (!spk_res.is_ok()) {
        return ClientResult<domain::Device>::error(spk_res.error());
    }
    auto spk_result = std::move(spk_res).value();

    // 3. Generate initial batch of 100 OTPKs
    auto otpk_res = crypto_provider_.generate_one_time_prekeys(domain::PrekeyPolicy::kInitialPrekeyBatchSize, 1);
    if (!otpk_res.is_ok()) {
        return ClientResult<domain::Device>::error(otpk_res.error());
    }
    auto otpk_pairs = std::move(otpk_res).value();

    std::vector<domain::OneTimePrekeyRecord> pub_records;
    pub_records.reserve(otpk_pairs.size());
    std::unordered_map<std::string, securecloud::common::configuration::SecretString> otpk_privates;
    otpk_privates.reserve(otpk_pairs.size());

    for (auto& p : otpk_pairs) {
        pub_records.push_back(p.record);
        otpk_privates.emplace(p.record.id(), std::move(p.private_key));
    }

    // 4. Package into public PrekeyBundle
    domain::PrekeyBundle public_bundle(id_pair.public_key, spk_result.public_key, spk_result.signature,
                                       std::move(pub_records));

    // 5. Transmit registration to backend via Gateway
    auto reg_res = gateway_.register_device(user_id, public_bundle);
    if (!reg_res.is_ok()) {
        return ClientResult<domain::Device>::error(reg_res.error());
    }
    const auto& reg_result = reg_res.value();
    const domain::DeviceId assigned_id = reg_result.device_id;

    // 6. Assemble DevicePrivateBundle and store in ISecureStorage
    domain::DevicePrivateBundle priv_bundle(assigned_id, id_pair.public_key, std::move(id_pair.private_key),
                                            spk_result.public_key, std::move(spk_result.private_key),
                                            spk_result.signature, std::move(otpk_privates));

    auto save_res = infrastructure::adapters::KeyStorageHelper::save_bundle(secure_storage_, priv_bundle);
    if (!save_res.is_ok()) {
        return ClientResult<domain::Device>::error(save_res.error());
    }

    // 7. Store local device ID pointer
    auto id_store_res = secure_storage_.store_secret(
        kLocalDeviceIdKey, securecloud::common::configuration::SecretString(assigned_id.value()));
    if (!id_store_res.is_ok()) {
        return ClientResult<domain::Device>::error(id_store_res.error());
    }

    // 8. Compute fingerprint and create Device entity
    auto fp_res = crypto_provider_.compute_identity_fingerprint(id_pair.public_key);
    std::string fp = fp_res.is_ok() ? fp_res.value() : "SHA256:UNKNOWN";

    domain::CryptoIdentity identity(id_pair.public_key, std::move(fp), domain::KeyVerificationStatus::Verified,
                                    spk_result.public_key, spk_result.signature);

    std::string dname = display_name.empty() ? "Primary Device" : std::string(display_name);
    local_device_ = domain::Device(assigned_id, user_id, std::move(dname), std::move(identity), reg_result.status,
                                   reg_result.registered_at);

    return ClientResult<domain::Device>::ok(*local_device_);
}

ClientResult<domain::Device> DeviceManager::get_local_device() const {
    if (!local_device_.has_value()) {
        return ClientResult<domain::Device>::error(ClientError::validation("No local device registered or loaded"));
    }
    return ClientResult<domain::Device>::ok(*local_device_);
}

ClientResult<domain::PrekeyInventoryStatus> DeviceManager::check_prekey_inventory() {
    if (!local_device_.has_value()) {
        return ClientResult<domain::PrekeyInventoryStatus>::error(
            ClientError::validation("Cannot check prekey inventory: no local device active"));
    }
    return coordinator_.check_inventory(local_device_->device_id());
}

ClientResult<std::size_t> DeviceManager::replenish_prekeys(std::size_t batch_size) {
    if (!local_device_.has_value()) {
        return ClientResult<std::size_t>::error(
            ClientError::validation("Cannot replenish prekeys: no local device active"));
    }
    return coordinator_.replenish_one_time_prekeys(local_device_->device_id(), batch_size);
}

ClientResult<void> DeviceManager::rotate_signed_prekey() {
    if (!local_device_.has_value()) {
        return ClientResult<void>::error(
            ClientError::validation("Cannot rotate signed prekey: no local device active"));
    }
    auto rot_res = coordinator_.rotate_signed_prekey(local_device_->device_id());
    if (!rot_res.is_ok()) {
        return rot_res;
    }

    // Reload updated bundle to update local_device_ crypto identity
    auto load_res =
        infrastructure::adapters::KeyStorageHelper::load_bundle(secure_storage_, local_device_->device_id());
    if (load_res.is_ok()) {
        const auto& bundle = load_res.value();
        domain::CryptoIdentity updated_id(bundle.identity_public_key(), local_device_->crypto_identity().fingerprint(),
                                          local_device_->crypto_identity().verification_status(),
                                          bundle.signed_prekey_public_key(), bundle.signed_prekey_signature());
        local_device_ =
            domain::Device(local_device_->device_id(), local_device_->user_id(), local_device_->display_name(),
                           std::move(updated_id), local_device_->status(), local_device_->last_seen_at());
    }

    return ClientResult<void>::ok();
}

ClientResult<bool> DeviceManager::reconcile_prekeys() {
    if (!local_device_.has_value()) {
        return ClientResult<bool>::error(ClientError::validation("Cannot reconcile prekeys: no local device active"));
    }
    return coordinator_.reconcile_prekeys(local_device_->device_id());
}

ClientResult<std::vector<domain::Device>> DeviceManager::list_devices() {
    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<std::vector<domain::Device>>::error(probe_res.error());
    }

    std::vector<domain::Device> devices;
    if (local_device_.has_value()) {
        devices.push_back(*local_device_);
    }
    return ClientResult<std::vector<domain::Device>>::ok(std::move(devices));
}

ClientResult<void> DeviceManager::revoke_device(const domain::DeviceId& device_id, std::string_view mfa_token) {
    if (device_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Device ID cannot be empty"));
    }

    // 1. Local Device Self-Wipe
    if (local_device_.has_value() && local_device_->device_id() == device_id) {
        infrastructure::adapters::KeyStorageHelper::wipe_device_keys(secure_storage_, device_id);
        secure_storage_.delete_secret(kLocalDeviceIdKey);
        local_device_.reset();

        if (ratchet_session_manager_ != nullptr) {
            ratchet_session_manager_->purge_device_sessions(device_id);
        }
        return ClientResult<void>::ok();
    }

    // 2. Remote Companion Device Revocation via Gateway
    auto gate_res = gateway_.revoke_device(device_id, mfa_token);
    if (!gate_res.is_ok()) {
        return gate_res;
    }

    // 3. Purge cryptographic sessions for that companion device
    if (ratchet_session_manager_ != nullptr) {
        auto purge_res = ratchet_session_manager_->purge_device_sessions(device_id);
        if (!purge_res.is_ok()) {
            return purge_res;
        }
    }

    return ClientResult<void>::ok();
}

} // namespace securecloud::client::application::managers
