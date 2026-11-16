#include "domain/prekey_bundle.hpp"

#include <stdexcept>
#include <utility>

namespace securecloud::client::domain {

namespace {

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const uint8_t b : bytes) {
        result.push_back(hex_chars[(b >> 4) & 0x0F]);
        result.push_back(hex_chars[b & 0x0F]);
    }
    return result;
}

} // namespace

PrekeyBundle::PrekeyBundle(std::vector<uint8_t> identity_key, std::vector<uint8_t> signed_prekey,
                           std::vector<uint8_t> signed_prekey_signature,
                           std::vector<OneTimePrekeyRecord> one_time_prekeys,
                           std::chrono::system_clock::time_point created_at)
    : identity_key_(std::move(identity_key)), signed_prekey_(std::move(signed_prekey)),
      signed_prekey_signature_(std::move(signed_prekey_signature)), one_time_prekeys_(std::move(one_time_prekeys)),
      created_at_(created_at) {
    if (!identity_key_.empty() && identity_key_.size() != PrekeyPolicy::kEd25519PublicKeySize) {
        throw std::invalid_argument("PrekeyBundle: identity key must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519PublicKeySize) + " bytes, got " +
                                    std::to_string(identity_key_.size()));
    }
    if (!signed_prekey_.empty() && signed_prekey_.size() != PrekeyPolicy::kX25519PublicKeySize) {
        throw std::invalid_argument("PrekeyBundle: signed prekey must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PublicKeySize) + " bytes, got " +
                                    std::to_string(signed_prekey_.size()));
    }
    if (!signed_prekey_signature_.empty() && signed_prekey_signature_.size() != PrekeyPolicy::kEd25519SignatureSize) {
        throw std::invalid_argument("PrekeyBundle: signed prekey signature must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519SignatureSize) + " bytes, got " +
                                    std::to_string(signed_prekey_signature_.size()));
    }
}

std::string PrekeyBundle::identity_key_hex() const {
    return bytes_to_hex(identity_key_);
}

std::string PrekeyBundle::signed_prekey_hex() const {
    return bytes_to_hex(signed_prekey_);
}

std::string PrekeyBundle::signed_prekey_signature_hex() const {
    return bytes_to_hex(signed_prekey_signature_);
}

void PrekeyBundle::add_one_time_prekey(OneTimePrekeyRecord record) {
    one_time_prekeys_.push_back(std::move(record));
}

void PrekeyBundle::set_signed_prekey(std::vector<uint8_t> signed_prekey, std::vector<uint8_t> signature) {
    if (signed_prekey.size() != PrekeyPolicy::kX25519PublicKeySize) {
        throw std::invalid_argument("PrekeyBundle: signed prekey must be exactly " +
                                    std::to_string(PrekeyPolicy::kX25519PublicKeySize) + " bytes, got " +
                                    std::to_string(signed_prekey.size()));
    }
    if (signature.size() != PrekeyPolicy::kEd25519SignatureSize) {
        throw std::invalid_argument("PrekeyBundle: signed prekey signature must be exactly " +
                                    std::to_string(PrekeyPolicy::kEd25519SignatureSize) + " bytes, got " +
                                    std::to_string(signature.size()));
    }
    signed_prekey_ = std::move(signed_prekey);
    signed_prekey_signature_ = std::move(signature);
}

bool PrekeyBundle::operator==(const PrekeyBundle& other) const noexcept {
    return identity_key_ == other.identity_key_ && signed_prekey_ == other.signed_prekey_ &&
           signed_prekey_signature_ == other.signed_prekey_signature_ && one_time_prekeys_ == other.one_time_prekeys_;
}

} // namespace securecloud::client::domain
