#include "domain/crypto/sender_key_models.hpp"

#include <cstring>
#include <openssl/crypto.h>

namespace securecloud::client::domain::crypto {

namespace {

void write_u32_be(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void write_u64_be(std::vector<uint8_t>& out, uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>((v >> static_cast<unsigned>(shift)) & 0xFFULL));
    }
}

void write_bytes_u32(std::vector<uint8_t>& out, std::span<const uint8_t> data) {
    write_u32_be(out, static_cast<uint32_t>(data.size()));
    out.insert(out.end(), data.begin(), data.end());
}

void write_string_u32(std::vector<uint8_t>& out, std::string_view s) {
    write_u32_be(out, static_cast<uint32_t>(s.size()));
    for (char ch : s) {
        out.push_back(static_cast<uint8_t>(static_cast<unsigned char>(ch)));
    }
}

void write_sender_key_id(std::vector<uint8_t>& out, const SenderKeyId& id) {
    write_string_u32(out, id.conversation_id.value());
    write_string_u32(out, id.sender_user_id.value());
    write_string_u32(out, id.sender_device_id.value());
    write_u64_be(out, id.key_epoch);
}

class BinaryReader {
  public:
    explicit BinaryReader(std::span<const uint8_t> data) noexcept : data_(data) {}

    [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }

    bool read_exact(std::size_t count, std::span<const uint8_t>& out) noexcept {
        if (remaining() < count) {
            return false;
        }
        out = data_.subspan(offset_, count);
        offset_ += count;
        return true;
    }

    bool read_u8(uint8_t& out) noexcept {
        if (remaining() < 1) {
            return false;
        }
        out = data_[offset_++];
        return true;
    }

    bool read_u32_be(uint32_t& out) noexcept {
        if (remaining() < 4) {
            return false;
        }
        out = (static_cast<uint32_t>(data_[offset_]) << 24) | (static_cast<uint32_t>(data_[offset_ + 1]) << 16) |
              (static_cast<uint32_t>(data_[offset_ + 2]) << 8) | static_cast<uint32_t>(data_[offset_ + 3]);
        offset_ += 4;
        return true;
    }

    bool read_u64_be(uint64_t& out) noexcept {
        if (remaining() < 8) {
            return false;
        }
        out = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            out = (out << 8) | static_cast<uint64_t>(data_[offset_ + i]);
        }
        offset_ += 8;
        return true;
    }

    bool read_bytes_u32(std::vector<uint8_t>& out, std::size_t max_len = 16u * 1024u * 1024u) {
        uint32_t len = 0;
        if (!read_u32_be(len) || len > max_len || remaining() < len) {
            return false;
        }
        const auto sub = data_.subspan(offset_, len);
        out.assign(sub.begin(), sub.end());
        offset_ += len;
        return true;
    }

    bool read_string_u32(std::string& out, std::size_t max_len = 4096u) {
        uint32_t len = 0;
        if (!read_u32_be(len) || len > max_len || remaining() < len) {
            return false;
        }
        const auto sub = data_.subspan(offset_, len);
        out.assign(reinterpret_cast<const char*>(sub.data()), sub.size());
        offset_ += len;
        return true;
    }

    bool read_secret_u32(common::configuration::SecretString& out, std::size_t max_len = 4096u) {
        uint32_t len = 0;
        if (!read_u32_be(len) || len > max_len || remaining() < len) {
            return false;
        }
        const auto sub = data_.subspan(offset_, len);
        std::string tmp(reinterpret_cast<const char*>(sub.data()), sub.size());
        out = common::configuration::SecretString(tmp);
        OPENSSL_cleanse(tmp.data(), tmp.size());
        offset_ += len;
        return true;
    }

    bool read_sender_key_id(SenderKeyId& id) {
        std::string cid;
        std::string uid;
        std::string did;
        uint64_t epoch = 0;
        if (!read_string_u32(cid) || !read_string_u32(uid) || !read_string_u32(did) || !read_u64_be(epoch)) {
            return false;
        }
        if (cid.empty() || uid.empty() || did.empty()) {
            return false;
        }
        id.conversation_id = domain::ConversationId(std::move(cid));
        id.sender_user_id = domain::UserId(std::move(uid));
        id.sender_device_id = domain::DeviceId(std::move(did));
        id.key_epoch = epoch;
        return true;
    }

  private:
    std::span<const uint8_t> data_;
    std::size_t offset_{0};
};

} // namespace

std::string SenderKeyId::storage_key() const {
    return "sender_key:" + conversation_id.value() + ":" + sender_user_id.value() + ":" + sender_device_id.value() +
           ":" + std::to_string(key_epoch);
}

std::vector<uint8_t> SenderKeyDistributionMessage::serialize() const {
    std::vector<uint8_t> out;
    out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
    out.push_back(kFormatVersion);
    write_sender_key_id(out, id);
    write_u32_be(out, iteration);
    write_bytes_u32(out, chain_key);
    write_bytes_u32(out, signing_public_key);
    return out;
}

application::ClientResult<SenderKeyDistributionMessage>
SenderKeyDistributionMessage::deserialize(std::span<const uint8_t> bytes) {
    BinaryReader reader(bytes);
    std::span<const uint8_t> magic;
    uint8_t version = 0;
    if (!reader.read_exact(sizeof(kMagic), magic) || std::memcmp(magic.data(), kMagic, sizeof(kMagic)) != 0 ||
        !reader.read_u8(version) || version != kFormatVersion) {
        return application::ClientResult<SenderKeyDistributionMessage>::error(
            application::ClientError::crypto("Invalid SenderKeyDistributionMessage header"));
    }

    SenderKeyDistributionMessage msg;
    if (!reader.read_sender_key_id(msg.id) || !reader.read_u32_be(msg.iteration) ||
        !reader.read_bytes_u32(msg.chain_key, 256) || !reader.read_bytes_u32(msg.signing_public_key, 256) ||
        reader.remaining() != 0) {
        return application::ClientResult<SenderKeyDistributionMessage>::error(
            application::ClientError::crypto("Corrupt SenderKeyDistributionMessage payload"));
    }
    return application::ClientResult<SenderKeyDistributionMessage>::ok(std::move(msg));
}

std::vector<uint8_t> GroupEncryptedEnvelope::canonical_signed_bytes() const {
    std::vector<uint8_t> out;
    out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
    out.push_back(kFormatVersion);
    write_sender_key_id(out, id);
    write_u32_be(out, iteration);
    write_bytes_u32(out, iv);
    write_bytes_u32(out, auth_tag);
    write_bytes_u32(out, ciphertext);
    return out;
}

std::vector<uint8_t> GroupEncryptedEnvelope::serialize() const {
    std::vector<uint8_t> out = canonical_signed_bytes();
    write_bytes_u32(out, signature);
    return out;
}

application::ClientResult<GroupEncryptedEnvelope> GroupEncryptedEnvelope::deserialize(std::span<const uint8_t> bytes) {
    BinaryReader reader(bytes);
    std::span<const uint8_t> magic;
    uint8_t version = 0;
    if (!reader.read_exact(sizeof(kMagic), magic) || std::memcmp(magic.data(), kMagic, sizeof(kMagic)) != 0 ||
        !reader.read_u8(version) || version != kFormatVersion) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(
            application::ClientError::crypto("Invalid GroupEncryptedEnvelope header"));
    }

    GroupEncryptedEnvelope env;
    if (!reader.read_sender_key_id(env.id) || !reader.read_u32_be(env.iteration) ||
        !reader.read_bytes_u32(env.iv, 64) || !reader.read_bytes_u32(env.auth_tag, 64) ||
        !reader.read_bytes_u32(env.ciphertext) || !reader.read_bytes_u32(env.signature, 256) ||
        reader.remaining() != 0) {
        return application::ClientResult<GroupEncryptedEnvelope>::error(
            application::ClientError::crypto("Corrupt GroupEncryptedEnvelope payload"));
    }
    return application::ClientResult<GroupEncryptedEnvelope>::ok(std::move(env));
}

std::vector<uint8_t> SenderKeyState::serialize() const {
    std::vector<uint8_t> out;
    out.insert(out.end(), std::begin(kMagic), std::end(kMagic));
    out.push_back(kFormatVersion);
    write_sender_key_id(out, id);
    write_u32_be(out, iteration);
    write_string_u32(out, chain_key.expose_unredacted_secret());
    write_bytes_u32(out, signing_public_key);
    out.push_back(signing_private_key.has_value() ? 1u : 0u);
    if (signing_private_key.has_value()) {
        write_string_u32(out, signing_private_key->expose_unredacted_secret());
    }
    write_u32_be(out, static_cast<uint32_t>(skipped_message_keys.size()));
    for (const auto& [iter, mk] : skipped_message_keys) {
        write_u32_be(out, iter);
        write_string_u32(out, mk.expose_unredacted_secret());
    }
    return out;
}

application::ClientResult<SenderKeyState> SenderKeyState::deserialize(std::span<const uint8_t> bytes) {
    BinaryReader reader(bytes);
    std::span<const uint8_t> magic;
    uint8_t version = 0;
    if (!reader.read_exact(sizeof(kMagic), magic) || std::memcmp(magic.data(), kMagic, sizeof(kMagic)) != 0 ||
        !reader.read_u8(version) || version != kFormatVersion) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Invalid SenderKeyState header"));
    }

    SenderKeyState state;
    uint8_t has_priv = 0;
    uint32_t skipped_count = 0;
    if (!reader.read_sender_key_id(state.id) || !reader.read_u32_be(state.iteration) ||
        !reader.read_secret_u32(state.chain_key) || !reader.read_bytes_u32(state.signing_public_key, 256) ||
        !reader.read_u8(has_priv)) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Corrupt SenderKeyState payload"));
    }

    if (has_priv == 1u) {
        common::configuration::SecretString priv;
        if (!reader.read_secret_u32(priv)) {
            return application::ClientResult<SenderKeyState>::error(
                application::ClientError::crypto("Corrupt SenderKeyState private key"));
        }
        state.signing_private_key = std::move(priv);
    } else if (has_priv != 0u) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Invalid SenderKeyState private-key flag"));
    }

    if (!reader.read_u32_be(skipped_count) || skipped_count > 1000u) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Invalid SenderKeyState skipped key count"));
    }

    for (uint32_t i = 0; i < skipped_count; ++i) {
        uint32_t iter = 0;
        common::configuration::SecretString mk;
        if (!reader.read_u32_be(iter) || !reader.read_secret_u32(mk)) {
            return application::ClientResult<SenderKeyState>::error(
                application::ClientError::crypto("Corrupt SenderKeyState skipped key entry"));
        }
        state.skipped_message_keys.emplace(iter, std::move(mk));
    }

    if (reader.remaining() != 0) {
        return application::ClientResult<SenderKeyState>::error(
            application::ClientError::crypto("Trailing bytes in SenderKeyState"));
    }
    return application::ClientResult<SenderKeyState>::ok(std::move(state));
}

} // namespace securecloud::client::domain::crypto
