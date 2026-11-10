#include "domain/crypto/ratchet_models.hpp"

#include <cstring>

namespace securecloud::client::domain::crypto {

namespace {

void write_uint32_be(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

uint32_t read_uint32_be(std::span<const uint8_t> bytes, std::size_t offset) {
    return (static_cast<uint32_t>(bytes[offset]) << 24) | (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) | static_cast<uint32_t>(bytes[offset + 3]);
}

} // namespace

RatchetHeader::RatchetHeader(std::vector<uint8_t> dh_pub, uint32_t pn, uint32_t n)
    : dh_pub_(std::move(dh_pub)), pn_(pn), n_(n) {}

bool RatchetHeader::operator==(const RatchetHeader& other) const noexcept {
    return dh_pub_ == other.dh_pub_ && pn_ == other.pn_ && n_ == other.n_;
}

std::vector<uint8_t> RatchetHeader::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(kSerializedSize);

    buf.push_back(kMagicByte);
    buf.push_back(kVersion);

    if (dh_pub_.size() == PrekeyPolicy::kX25519PublicKeySize) {
        buf.insert(buf.end(), dh_pub_.begin(), dh_pub_.end());
    } else {
        buf.insert(buf.end(), PrekeyPolicy::kX25519PublicKeySize, 0x00);
    }

    write_uint32_be(buf, pn_);
    write_uint32_be(buf, n_);

    return buf;
}

application::ClientResult<RatchetHeader> RatchetHeader::deserialize(std::span<const uint8_t> bytes) {
    if (bytes.size() < kSerializedSize) {
        return application::ClientResult<RatchetHeader>::error(
            application::ClientError::validation("RatchetHeader buffer too small for header layout"));
    }

    if (bytes[0] != kMagicByte || bytes[1] != kVersion) {
        return application::ClientResult<RatchetHeader>::error(
            application::ClientError::validation("Invalid RatchetHeader magic or version"));
    }

    std::vector<uint8_t> dh_pub(bytes.begin() + 2, bytes.begin() + 2 + PrekeyPolicy::kX25519PublicKeySize);
    const uint32_t pn = read_uint32_be(bytes, 2 + PrekeyPolicy::kX25519PublicKeySize);
    const uint32_t n = read_uint32_be(bytes, 2 + PrekeyPolicy::kX25519PublicKeySize + 4);

    return application::ClientResult<RatchetHeader>::ok(RatchetHeader(std::move(dh_pub), pn, n));
}

bool DoubleRatchetMessage::operator==(const DoubleRatchetMessage& other) const noexcept {
    return header == other.header && ciphertext == other.ciphertext && iv == other.iv && auth_tag == other.auth_tag;
}

std::vector<uint8_t> DoubleRatchetMessage::serialize() const {
    const auto header_bytes = header.serialize();
    const std::size_t total_size = header_bytes.size() + iv.size() + auth_tag.size() + 4 + ciphertext.size();

    std::vector<uint8_t> buf;
    buf.reserve(total_size);

    buf.insert(buf.end(), header_bytes.begin(), header_bytes.end());
    buf.insert(buf.end(), iv.begin(), iv.end());
    buf.insert(buf.end(), auth_tag.begin(), auth_tag.end());

    write_uint32_be(buf, static_cast<uint32_t>(ciphertext.size()));
    buf.insert(buf.end(), ciphertext.begin(), ciphertext.end());

    return buf;
}

application::ClientResult<DoubleRatchetMessage> DoubleRatchetMessage::deserialize(std::span<const uint8_t> bytes) {
    constexpr std::size_t kMinSize =
        RatchetHeader::kSerializedSize + PrekeyPolicy::kAeadGcmIvSize + PrekeyPolicy::kAeadGcmTagSize + 4;
    if (bytes.size() < kMinSize) {
        return application::ClientResult<DoubleRatchetMessage>::error(
            application::ClientError::validation("DoubleRatchetMessage buffer too small"));
    }

    auto header_res = RatchetHeader::deserialize(bytes.subspan(0, RatchetHeader::kSerializedSize));
    if (!header_res.is_ok()) {
        return application::ClientResult<DoubleRatchetMessage>::error(header_res.error());
    }

    std::size_t offset = RatchetHeader::kSerializedSize;

    std::vector<uint8_t> iv(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                            bytes.begin() + static_cast<std::ptrdiff_t>(offset + PrekeyPolicy::kAeadGcmIvSize));
    offset += PrekeyPolicy::kAeadGcmIvSize;

    std::vector<uint8_t> tag(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                             bytes.begin() + static_cast<std::ptrdiff_t>(offset + PrekeyPolicy::kAeadGcmTagSize));
    offset += PrekeyPolicy::kAeadGcmTagSize;

    const uint32_t ct_len = read_uint32_be(bytes, offset);
    offset += 4;

    if (offset + ct_len > bytes.size()) {
        return application::ClientResult<DoubleRatchetMessage>::error(
            application::ClientError::validation("Truncated ciphertext in DoubleRatchetMessage"));
    }

    std::vector<uint8_t> ct(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                            bytes.begin() + static_cast<std::ptrdiff_t>(offset + ct_len));

    return application::ClientResult<DoubleRatchetMessage>::ok(
        DoubleRatchetMessage{.header = std::move(header_res).value(),
                             .ciphertext = std::move(ct),
                             .iv = std::move(iv),
                             .auth_tag = std::move(tag)});
}

} // namespace securecloud::client::domain::crypto
