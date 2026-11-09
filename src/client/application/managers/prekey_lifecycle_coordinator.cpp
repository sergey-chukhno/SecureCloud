#include "application/managers/prekey_lifecycle_coordinator.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"

namespace securecloud::client::application::managers {

PrekeyLifecycleCoordinator::PrekeyLifecycleCoordinator(interfaces::IGatewayClient& gateway,
                                                       interfaces::ISecureStorage& secure_storage,
                                                       interfaces::ICryptoProvider& crypto_provider)
    : gateway_(gateway), secure_storage_(secure_storage), crypto_provider_(crypto_provider) {}

ClientResult<domain::PrekeyInventoryStatus>
PrekeyLifecycleCoordinator::check_inventory(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return ClientResult<domain::PrekeyInventoryStatus>::error(
            ClientError::validation("Device ID cannot be empty when checking prekey inventory"));
    }
    return gateway_.get_prekey_inventory_status(device_id);
}

ClientResult<std::size_t>
PrekeyLifecycleCoordinator::replenish_one_time_prekeys(const domain::DeviceId& device_id, std::size_t batch_size) {
    if (device_id.empty()) {
        return ClientResult<std::size_t>::error(
            ClientError::validation("Device ID cannot be empty when replenishing prekeys"));
    }
    if (batch_size == 0) {
        return ClientResult<std::size_t>::ok(0);
    }

    // 1. Load local private bundle
    auto load_res = infrastructure::adapters::KeyStorageHelper::load_bundle(secure_storage_, device_id);
    if (!load_res.is_ok()) {
        return ClientResult<std::size_t>::error(load_res.error());
    }
    auto bundle = std::move(load_res).value();

    // 2. Generate new OTPKs
    const std::size_t start_index = bundle.one_time_prekey_count() + 1;
    auto gen_res = crypto_provider_.generate_one_time_prekeys(batch_size, start_index);
    if (!gen_res.is_ok()) {
        return ClientResult<std::size_t>::error(gen_res.error());
    }
    auto otpk_pairs = std::move(gen_res).value();

    // 3. Save private keys locally in bundle and collect public records
    std::vector<domain::OneTimePrekeyRecord> public_records;
    public_records.reserve(otpk_pairs.size());

    for (auto& pair : otpk_pairs) {
        public_records.push_back(pair.record);
        bundle.add_one_time_prekey(pair.record.id(), std::move(pair.private_key));
    }

    auto save_res = infrastructure::adapters::KeyStorageHelper::save_bundle(secure_storage_, bundle);
    if (!save_res.is_ok()) {
        return ClientResult<std::size_t>::error(save_res.error());
    }

    // 4. Upload public prekeys to backend via Gateway
    auto upload_res = gateway_.update_crypto_prekeys(device_id, std::nullopt, std::nullopt, std::move(public_records));
    if (!upload_res.is_ok()) {
        return ClientResult<std::size_t>::error(upload_res.error());
    }

    return ClientResult<std::size_t>::ok(batch_size);
}

ClientResult<void> PrekeyLifecycleCoordinator::rotate_signed_prekey(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Device ID cannot be empty when rotating signed prekey"));
    }

    // 1. Load local private bundle
    auto load_res = infrastructure::adapters::KeyStorageHelper::load_bundle(secure_storage_, device_id);
    if (!load_res.is_ok()) {
        return ClientResult<void>::error(load_res.error());
    }
    auto bundle = std::move(load_res).value();

    // 2. Generate new signed prekey signed by identity key
    auto spk_res = crypto_provider_.generate_signed_prekey(bundle.identity_private_key());
    if (!spk_res.is_ok()) {
        return ClientResult<void>::error(spk_res.error());
    }
    auto spk = std::move(spk_res).value();

    // 3. Update bundle and persist to ISecureStorage
    bundle.update_signed_prekey(spk.public_key, std::move(spk.private_key), spk.signature);
    auto save_res = infrastructure::adapters::KeyStorageHelper::save_bundle(secure_storage_, bundle);
    if (!save_res.is_ok()) {
        return ClientResult<void>::error(save_res.error());
    }

    // 4. Upload new signed prekey and signature to Gateway
    auto upload_res = gateway_.update_crypto_prekeys(device_id, spk.public_key, spk.signature, {});
    if (!upload_res.is_ok()) {
        return ClientResult<void>::error(upload_res.error());
    }

    return ClientResult<void>::ok();
}

ClientResult<bool> PrekeyLifecycleCoordinator::reconcile_prekeys(const domain::DeviceId& device_id) {
    auto inv_res = check_inventory(device_id);
    if (!inv_res.is_ok()) {
        return ClientResult<bool>::error(inv_res.error());
    }
    const auto& status = inv_res.value();
    bool action_taken = false;

    if (status.needs_replenishment()) {
        auto repl_res = replenish_one_time_prekeys(device_id);
        if (!repl_res.is_ok()) {
            return ClientResult<bool>::error(repl_res.error());
        }
        action_taken = true;
    }

    if (status.needs_rotation()) {
        auto rot_res = rotate_signed_prekey(device_id);
        if (!rot_res.is_ok()) {
            return ClientResult<bool>::error(rot_res.error());
        }
        action_taken = true;
    }

    return ClientResult<bool>::ok(action_taken);
}

} // namespace securecloud::client::application::managers

