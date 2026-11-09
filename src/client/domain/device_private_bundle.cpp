#include "domain/device_private_bundle.hpp"

#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

DevicePrivateBundle::DevicePrivateBundle(
    DeviceId device_id, std::vector<uint8_t> identity_public_key,
    securecloud::common::configuration::SecretString identity_private_key,
    std::vector<uint8_t> signed_prekey_public_key,
    securecloud::common::configuration::SecretString signed_prekey_private_key,
    std::vector<uint8_t> signed_prekey_signature,
    std::unordered_map<std::string, securecloud::common::configuration::SecretString> one_time_prekey_privates,
    std::chrono::system_clock::time_point created_at)
    : device_id_(std::move(device_id)), identity_public_key_(std::move(identity_public_key)),
      identity_private_key_(std::move(identity_private_key)),
      signed_prekey_public_key_(std::move(signed_prekey_public_key)),
      signed_prekey_private_key_(std::move(signed_prekey_private_key)),
      signed_prekey_signature_(std::move(signed_prekey_signature)),
      one_time_prekey_privates_(std::move(one_time_prekey_privates)), created_at_(created_at) {
    if (device_id_.empty()) {
        throw std::invalid_argument("DevicePrivateBundle: device ID must not be empty");
    }
    if (identity_public_key_.size() != PrekeyPolicy::kEd25519PublicKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: identity public key must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519PublicKeySize) + " bytes, got " +
                                    std::to_string(identity_public_key_.size()));
    }
    if (identity_private_key_.size() != PrekeyPolicy::kEd25519PrivateKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: identity private key must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519PrivateKeySize) + " bytes, got " +
                                    std::to_string(identity_private_key_.size()));
    }
    if (signed_prekey_public_key_.size() != PrekeyPolicy::kX25519PublicKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: signed prekey public key must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PublicKeySize) + " bytes, got " +
                                    std::to_string(signed_prekey_public_key_.size()));
    }
    if (signed_prekey_private_key_.size() != PrekeyPolicy::kX25519PrivateKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: signed prekey private key must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PrivateKeySize) + " bytes, got " +
                                    std::to_string(signed_prekey_private_key_.size()));
    }
    if (signed_prekey_signature_.size() != PrekeyPolicy::kEd25519SignatureSize) {
        throw std::invalid_argument("DevicePrivateBundle: signed prekey signature must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519SignatureSize) + " bytes, got " +
                                    std::to_string(signed_prekey_signature_.size()));
    }

    for (const auto& [otpk_id, otpk_priv] : one_time_prekey_privates_) {
        if (otpk_id.empty()) {
            throw std::invalid_argument("DevicePrivateBundle: one-time prekey ID must not be empty");
        }
        if (otpk_priv.size() != PrekeyPolicy::kX25519PrivateKeySize) {
            throw std::invalid_argument("DevicePrivateBundle: one-time prekey private key for " + otpk_id +
                                        " must be exactly " + std::to_string(PrekeyPolicy::kX25519PrivateKeySize) +
                                        " bytes, got " + std::to_string(otpk_priv.size()));
        }
    }
}

bool DevicePrivateBundle::has_one_time_prekey(std::string_view prekey_id) const noexcept {
    return one_time_prekey_privates_.contains(std::string(prekey_id));
}

std::optional<securecloud::common::configuration::SecretString>
DevicePrivateBundle::take_one_time_prekey(std::string_view prekey_id) {
    auto it = one_time_prekey_privates_.find(std::string(prekey_id));
    if (it == one_time_prekey_privates_.end()) {
        return std::nullopt;
    }
    securecloud::common::configuration::SecretString secret = std::move(it->second);
    one_time_prekey_privates_.erase(it);
    return secret;
}

void DevicePrivateBundle::add_one_time_prekey(std::string prekey_id,
                                              securecloud::common::configuration::SecretString private_key) {
    if (prekey_id.empty()) {
        throw std::invalid_argument("DevicePrivateBundle: one-time prekey ID must not be empty");
    }
    if (private_key.size() != PrekeyPolicy::kX25519PrivateKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: one-time prekey private key must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PrivateKeySize) + " bytes, got " +
                                    std::to_string(private_key.size()));
    }
    one_time_prekey_privates_.insert_or_assign(std::move(prekey_id), std::move(private_key));
}

void DevicePrivateBundle::update_signed_prekey(std::vector<uint8_t> new_public_key,
                                               securecloud::common::configuration::SecretString new_private_key,
                                               std::vector<uint8_t> new_signature) {
    if (new_public_key.size() != PrekeyPolicy::kX25519PublicKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: signed prekey public key must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PublicKeySize) + " bytes, got " +
                                    std::to_string(new_public_key.size()));
    }
    if (new_private_key.size() != PrekeyPolicy::kX25519PrivateKeySize) {
        throw std::invalid_argument("DevicePrivateBundle: signed prekey private key must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PrivateKeySize) + " bytes, got " +
                                    std::to_string(new_private_key.size()));
    }
    if (new_signature.size() != PrekeyPolicy::kEd25519SignatureSize) {
        throw std::invalid_argument("DevicePrivateBundle: signed prekey signature must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519SignatureSize) + " bytes, got " +
                                    std::to_string(new_signature.size()));
    }

    signed_prekey_public_key_ = std::move(new_public_key);
    signed_prekey_private_key_ = std::move(new_private_key);
    signed_prekey_signature_ = std::move(new_signature);
}

PrekeyBundle DevicePrivateBundle::to_public_bundle(const std::vector<OneTimePrekeyRecord>& otpk_public_records) const {
    return PrekeyBundle(identity_public_key_, signed_prekey_public_key_, signed_prekey_signature_, otpk_public_records,
                        created_at_);
}

bool DevicePrivateBundle::operator==(const DevicePrivateBundle& other) const noexcept {
    if (device_id_ != other.device_id_ || identity_public_key_ != other.identity_public_key_ ||
        identity_private_key_ != other.identity_private_key_ ||
        signed_prekey_public_key_ != other.signed_prekey_public_key_ ||
        signed_prekey_private_key_ != other.signed_prekey_private_key_ ||
        signed_prekey_signature_ != other.signed_prekey_signature_ ||
        one_time_prekey_privates_.size() != other.one_time_prekey_privates_.size()) {
        return false;
    }

    for (const auto& [id, priv] : one_time_prekey_privates_) {
        auto it = other.one_time_prekey_privates_.find(id);
        if (it == other.one_time_prekey_privates_.end() || it->second != priv) {
            return false;
        }
    }
    return true;
}

} // namespace securecloud::client::domain
