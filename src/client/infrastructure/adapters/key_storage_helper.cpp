#include "infrastructure/adapters/key_storage_helper.hpp"

#include "domain/prekey_policy.hpp"

#include <cstring>
#include <openssl/crypto.h>
#include <span>
#include <vector>

namespace securecloud::client::infrastructure::adapters {

namespace {

constexpr uint8_t kMagic[4] = {'S', 'C', 'P', 'B'};
constexpr uint16_t kFormatVersion = 1;

void write_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void write_i64(std::vector<uint8_t>& buf, int64_t val) {
    const auto uval = static_cast<uint64_t>(val);
    for (int i = 7; i >= 0; --i) {
        buf.push_back(static_cast<uint8_t>((uval >> (static_cast<unsigned int>(i) * 8)) & 0xFF));
    }
}

bool read_u16(std::span<const uint8_t>& in, uint16_t& val) {
    if (in.size() < 2) {
        return false;
    }
    val = static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
    in = in.subspan(2);
    return true;
}

bool read_u32(std::span<const uint8_t>& in, uint32_t& val) {
    if (in.size() < 4) {
        return false;
    }
    val = (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
          (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
    in = in.subspan(4);
    return true;
}

bool read_i64(std::span<const uint8_t>& in, int64_t& val) {
    if (in.size() < 8) {
        return false;
    }
    uint64_t uval = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        uval = (uval << 8) | static_cast<uint64_t>(in[i]);
    }
    val = static_cast<int64_t>(uval);
    in = in.subspan(8);
    return true;
}

bool read_bytes(std::span<const uint8_t>& in, std::span<uint8_t> out) {
    if (in.size() < out.size()) {
        return false;
    }
    std::memcpy(out.data(), in.data(), out.size());
    in = in.subspan(out.size());
    return true;
}

} // namespace

std::string KeyStorageHelper::make_storage_key(const domain::DeviceId& device_id) {
    return "device.crypto.bundle." + device_id.value();
}

application::ClientResult<securecloud::common::configuration::SecretString>
KeyStorageHelper::serialize(const domain::DevicePrivateBundle& bundle) {
    std::vector<uint8_t> buf;
    buf.reserve(512 + (bundle.one_time_prekey_count() * 40));

    // Magic & Version
    buf.insert(buf.end(), kMagic, kMagic + 4);
    write_u16(buf, kFormatVersion);

    // Device ID
    const std::string& dev_id = bundle.device_id().value();
    if (dev_id.size() > 65535) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Device ID too long for serialization"));
    }
    write_u16(buf, static_cast<uint16_t>(dev_id.size()));
    buf.insert(buf.end(), dev_id.begin(), dev_id.end());

    // Created At Epoch Ms
    const auto ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(bundle.created_at().time_since_epoch()).count();
    write_i64(buf, ms);

    // Identity Public Key (32 bytes)
    buf.insert(buf.end(), bundle.identity_public_key().begin(), bundle.identity_public_key().end());

    // Identity Private Key (32 bytes)
    const auto& id_priv = bundle.identity_private_key().expose_unredacted_secret();
    buf.insert(buf.end(), id_priv.begin(), id_priv.end());

    // Signed Prekey Public Key (32 bytes)
    buf.insert(buf.end(), bundle.signed_prekey_public_key().begin(), bundle.signed_prekey_public_key().end());

    // Signed Prekey Private Key (32 bytes)
    const auto& spk_priv = bundle.signed_prekey_private_key().expose_unredacted_secret();
    buf.insert(buf.end(), spk_priv.begin(), spk_priv.end());

    // Signed Prekey Signature (64 bytes)
    buf.insert(buf.end(), bundle.signed_prekey_signature().begin(), bundle.signed_prekey_signature().end());

    // One-Time Prekeys
    const auto& otpks = bundle.one_time_prekey_privates();
    write_u32(buf, static_cast<uint32_t>(otpks.size()));

    for (const auto& [otpk_id, otpk_priv] : otpks) {
        if (otpk_id.size() > 65535) {
            OPENSSL_cleanse(buf.data(), buf.size());
            return application::ClientResult<securecloud::common::configuration::SecretString>::error(
                application::ClientError::crypto("One-time prekey ID too long"));
        }
        write_u16(buf, static_cast<uint16_t>(otpk_id.size()));
        buf.insert(buf.end(), otpk_id.begin(), otpk_id.end());

        const auto& priv_bytes = otpk_priv.expose_unredacted_secret();
        buf.insert(buf.end(), priv_bytes.begin(), priv_bytes.end());
    }

    std::string secret_str(reinterpret_cast<const char*>(buf.data()), buf.size());
    OPENSSL_cleanse(buf.data(), buf.size());

    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(secret_str)));
}

application::ClientResult<domain::DevicePrivateBundle>
KeyStorageHelper::deserialize(const securecloud::common::configuration::SecretString& serialized_data) {
    const auto& data = serialized_data.expose_unredacted_secret();
    std::span<const uint8_t> in(reinterpret_cast<const uint8_t*>(data.data()), data.size());

    // Check magic
    if (in.size() < 4 || std::memcmp(in.data(), kMagic, 4) != 0) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Invalid magic header in private bundle"));
    }
    in = in.subspan(4);

    // Version
    uint16_t version = 0;
    if (!read_u16(in, version) || version != kFormatVersion) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Unsupported format version in private bundle"));
    }

    // Device ID
    uint16_t dev_id_len = 0;
    if (!read_u16(in, dev_id_len) || in.size() < dev_id_len) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated device ID in private bundle"));
    }
    std::string dev_id_str(reinterpret_cast<const char*>(in.data()), dev_id_len);
    in = in.subspan(dev_id_len);

    // Created At
    int64_t created_at_ms = 0;
    if (!read_i64(in, created_at_ms)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated timestamp in private bundle"));
    }
    const auto created_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(created_at_ms));

    // Identity Public Key (32 bytes)
    std::vector<uint8_t> id_pub(domain::PrekeyPolicy::kEd25519PublicKeySize);
    if (!read_bytes(in, id_pub)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated identity public key"));
    }

    // Identity Private Key (32 bytes)
    std::vector<uint8_t> id_priv_buf(domain::PrekeyPolicy::kEd25519PrivateKeySize);
    if (!read_bytes(in, id_priv_buf)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated identity private key"));
    }
    std::string id_priv_str(reinterpret_cast<const char*>(id_priv_buf.data()), id_priv_buf.size());
    OPENSSL_cleanse(id_priv_buf.data(), id_priv_buf.size());
    securecloud::common::configuration::SecretString id_priv(std::move(id_priv_str));

    // Signed Prekey Public Key (32 bytes)
    std::vector<uint8_t> spk_pub(domain::PrekeyPolicy::kX25519PublicKeySize);
    if (!read_bytes(in, spk_pub)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated signed prekey public key"));
    }

    // Signed Prekey Private Key (32 bytes)
    std::vector<uint8_t> spk_priv_buf(domain::PrekeyPolicy::kX25519PrivateKeySize);
    if (!read_bytes(in, spk_priv_buf)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated signed prekey private key"));
    }
    std::string spk_priv_str(reinterpret_cast<const char*>(spk_priv_buf.data()), spk_priv_buf.size());
    OPENSSL_cleanse(spk_priv_buf.data(), spk_priv_buf.size());
    securecloud::common::configuration::SecretString spk_priv(std::move(spk_priv_str));

    // Signed Prekey Signature (64 bytes)
    std::vector<uint8_t> spk_sig(domain::PrekeyPolicy::kEd25519SignatureSize);
    if (!read_bytes(in, spk_sig)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated signed prekey signature"));
    }

    // OTPK count
    uint32_t otpk_count = 0;
    if (!read_u32(in, otpk_count)) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto("Truncated OTPK count in private bundle"));
    }

    std::unordered_map<std::string, securecloud::common::configuration::SecretString> otpks;
    otpks.reserve(otpk_count);

    for (uint32_t i = 0; i < otpk_count; ++i) {
        uint16_t otpk_id_len = 0;
        if (!read_u16(in, otpk_id_len) || in.size() < otpk_id_len) {
            return application::ClientResult<domain::DevicePrivateBundle>::error(
                application::ClientError::crypto("Truncated OTPK ID in private bundle"));
        }
        std::string otpk_id(reinterpret_cast<const char*>(in.data()), otpk_id_len);
        in = in.subspan(otpk_id_len);

        std::vector<uint8_t> otpk_priv_buf(domain::PrekeyPolicy::kX25519PrivateKeySize);
        if (!read_bytes(in, otpk_priv_buf)) {
            return application::ClientResult<domain::DevicePrivateBundle>::error(
                application::ClientError::crypto("Truncated OTPK private key in private bundle"));
        }
        std::string otpk_priv_str(reinterpret_cast<const char*>(otpk_priv_buf.data()), otpk_priv_buf.size());
        OPENSSL_cleanse(otpk_priv_buf.data(), otpk_priv_buf.size());
        otpks.emplace(std::move(otpk_id), securecloud::common::configuration::SecretString(std::move(otpk_priv_str)));
    }

    try {
        domain::DevicePrivateBundle bundle(domain::DeviceId(std::move(dev_id_str)), std::move(id_pub),
                                           std::move(id_priv), std::move(spk_pub), std::move(spk_priv),
                                           std::move(spk_sig), std::move(otpks), created_at);
        return application::ClientResult<domain::DevicePrivateBundle>::ok(std::move(bundle));
    } catch (const std::exception& e) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(
            application::ClientError::crypto(std::string("Failed to construct DevicePrivateBundle: ") + e.what()));
    }
}

application::ClientResult<void> KeyStorageHelper::save_bundle(application::interfaces::ISecureStorage& storage,
                                                              const domain::DevicePrivateBundle& bundle) {
    auto ser_res = serialize(bundle);
    if (!ser_res.is_ok()) {
        return application::ClientResult<void>::error(ser_res.error());
    }
    const std::string key = make_storage_key(bundle.device_id());
    return storage.store_secret(key, ser_res.value());
}

application::ClientResult<domain::DevicePrivateBundle>
KeyStorageHelper::load_bundle(application::interfaces::ISecureStorage& storage, const domain::DeviceId& device_id) {
    const std::string key = make_storage_key(device_id);
    auto secret_res = storage.get_secret(key);
    if (!secret_res.is_ok()) {
        return application::ClientResult<domain::DevicePrivateBundle>::error(secret_res.error());
    }
    return deserialize(secret_res.value());
}

application::ClientResult<bool> KeyStorageHelper::has_bundle(application::interfaces::ISecureStorage& storage,
                                                             const domain::DeviceId& device_id) {
    const std::string key = make_storage_key(device_id);
    return storage.has_secret(key);
}

application::ClientResult<void>
KeyStorageHelper::remove_one_time_prekey(application::interfaces::ISecureStorage& storage,
                                         const domain::DeviceId& device_id, std::string_view prekey_id) {
    auto load_res = load_bundle(storage, device_id);
    if (!load_res.is_ok()) {
        return application::ClientResult<void>::error(load_res.error());
    }

    auto bundle = std::move(load_res).value();
    if (!bundle.has_one_time_prekey(prekey_id)) {
        return application::ClientResult<void>::ok();
    }

    bundle.take_one_time_prekey(prekey_id);
    return save_bundle(storage, bundle);
}

application::ClientResult<void> KeyStorageHelper::wipe_device_keys(application::interfaces::ISecureStorage& storage,
                                                                   const domain::DeviceId& device_id) {
    const std::string key = make_storage_key(device_id);
    return storage.delete_secret(key);
}

} // namespace securecloud::client::infrastructure::adapters
