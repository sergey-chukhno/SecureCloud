#include "domain/crypto/x3dh_models.hpp"

#include <cstring>

namespace securecloud::client::domain::crypto {

X3dhHeader::X3dhHeader(DeviceId initiator_device_id, std::vector<uint8_t> initiator_identity_key,
                       std::vector<uint8_t> initiator_ephemeral_key, std::vector<uint8_t> initiator_dh_key,
                       std::optional<std::string> one_time_prekey_id)
    : initiator_device_id_(std::move(initiator_device_id)), initiator_identity_key_(std::move(initiator_identity_key)),
      initiator_ephemeral_key_(std::move(initiator_ephemeral_key)), initiator_dh_key_(std::move(initiator_dh_key)),
      one_time_prekey_id_(std::move(one_time_prekey_id)) {}

bool X3dhHeader::operator==(const X3dhHeader& other) const noexcept {
    return initiator_device_id_ == other.initiator_device_id_ &&
           initiator_identity_key_ == other.initiator_identity_key_ &&
           initiator_ephemeral_key_ == other.initiator_ephemeral_key_ && initiator_dh_key_ == other.initiator_dh_key_ &&
           one_time_prekey_id_ == other.one_time_prekey_id_;
}

std::vector<uint8_t> X3dhHeader::serialize() const {
    std::vector<uint8_t> buf;
    const std::string dev_id_str = initiator_device_id_.value();
    const uint8_t dev_id_len = static_cast<uint8_t>(dev_id_str.size());

    const std::size_t total_size = 2 + 1 + dev_id_len + initiator_identity_key_.size() +
                                   initiator_ephemeral_key_.size() + initiator_dh_key_.size() + 1 +
                                   (one_time_prekey_id_.has_value() ? (1 + one_time_prekey_id_->size()) : 0);
    buf.reserve(total_size);

    buf.push_back(kMagicByte);
    buf.push_back(kVersion);

    buf.push_back(dev_id_len);
    buf.insert(buf.end(), dev_id_str.begin(), dev_id_str.end());

    buf.insert(buf.end(), initiator_identity_key_.begin(), initiator_identity_key_.end());
    buf.insert(buf.end(), initiator_ephemeral_key_.begin(), initiator_ephemeral_key_.end());
    buf.insert(buf.end(), initiator_dh_key_.begin(), initiator_dh_key_.end());

    if (one_time_prekey_id_.has_value()) {
        buf.push_back(0x01);
        const uint8_t otpk_len = static_cast<uint8_t>(one_time_prekey_id_->size());
        buf.push_back(otpk_len);
        buf.insert(buf.end(), one_time_prekey_id_->begin(), one_time_prekey_id_->end());
    } else {
        buf.push_back(0x00);
    }

    return buf;
}

application::ClientResult<X3dhHeader> X3dhHeader::deserialize(std::span<const uint8_t> bytes) {
    if (bytes.size() < 2 + 1 + PrekeyPolicy::kEd25519PublicKeySize + (PrekeyPolicy::kX25519PublicKeySize * 2) + 1) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("X3dhHeader buffer too small"));
    }

    std::size_t offset = 0;
    if (bytes[offset++] != kMagicByte || bytes[offset++] != kVersion) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("Invalid X3dhHeader magic or version"));
    }

    const uint8_t dev_id_len = bytes[offset++];
    if (offset + dev_id_len > bytes.size()) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("Invalid device ID length in X3dhHeader"));
    }
    std::string dev_id_str(reinterpret_cast<const char*>(bytes.data() + offset), dev_id_len);
    offset += dev_id_len;

    if (offset + PrekeyPolicy::kEd25519PublicKeySize > bytes.size()) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("Truncated identity key in X3dhHeader"));
    }
    std::vector<uint8_t> id_key(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                bytes.begin() +
                                    static_cast<std::ptrdiff_t>(offset + PrekeyPolicy::kEd25519PublicKeySize));
    offset += PrekeyPolicy::kEd25519PublicKeySize;

    if (offset + PrekeyPolicy::kX25519PublicKeySize > bytes.size()) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("Truncated ephemeral key in X3dhHeader"));
    }
    std::vector<uint8_t> eph_key(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                 bytes.begin() +
                                     static_cast<std::ptrdiff_t>(offset + PrekeyPolicy::kX25519PublicKeySize));
    offset += PrekeyPolicy::kX25519PublicKeySize;

    if (offset + PrekeyPolicy::kX25519PublicKeySize > bytes.size()) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("Truncated DH key in X3dhHeader"));
    }
    std::vector<uint8_t> dh_key(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                                bytes.begin() +
                                    static_cast<std::ptrdiff_t>(offset + PrekeyPolicy::kX25519PublicKeySize));
    offset += PrekeyPolicy::kX25519PublicKeySize;

    if (offset >= bytes.size()) {
        return application::ClientResult<X3dhHeader>::error(
            application::ClientError::validation("Missing OTPK presence flag in X3dhHeader"));
    }

    std::optional<std::string> otpk_id;
    const uint8_t has_otpk = bytes[offset++];
    if (has_otpk == 0x01) {
        if (offset >= bytes.size()) {
            return application::ClientResult<X3dhHeader>::error(
                application::ClientError::validation("Missing OTPK ID length in X3dhHeader"));
        }
        const uint8_t otpk_len = bytes[offset++];
        if (offset + otpk_len > bytes.size()) {
            return application::ClientResult<X3dhHeader>::error(
                application::ClientError::validation("Truncated OTPK ID in X3dhHeader"));
        }
        otpk_id = std::string(reinterpret_cast<const char*>(bytes.data() + offset), otpk_len);
        offset += otpk_len;
    }

    return application::ClientResult<X3dhHeader>::ok(X3dhHeader(
        DeviceId(std::move(dev_id_str)), std::move(id_key), std::move(eph_key), std::move(dh_key), std::move(otpk_id)));
}

} // namespace securecloud::client::domain::crypto
