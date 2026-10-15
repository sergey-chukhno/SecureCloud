#include "domain/submission_fingerprint.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace securecloud::messaging::domain {

namespace {

constexpr char kHexCharsLower[] = "0123456789abcdef";

std::string compute_sha256_hex(std::string_view data) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (!ctx) {
        throw std::runtime_error("Failed to allocate OpenSSL EVP_MD_CTX for submission fingerprint");
    }

    std::array<uint8_t, 32> digest{};
    unsigned int md_len = 0;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest.data(), &md_len) != 1) {
        throw std::runtime_error("OpenSSL SHA-256 digest calculation failed for submission fingerprint");
    }

    std::string hex;
    hex.reserve(64);
    for (std::size_t i = 0; i < md_len; ++i) {
        hex.push_back(kHexCharsLower[(digest[i] >> 4) & 0x0F]);
        hex.push_back(kHexCharsLower[digest[i] & 0x0F]);
    }
    return hex;
}

} // namespace

std::string calculate_submission_fingerprint(const MessageSubmissionCommand& cmd) {
    // 1. Sort delivery targets canonically by recipient_device_id, then recipient_user_id
    std::vector<const DeviceDeliveryTarget*> sorted_targets;
    sorted_targets.reserve(cmd.delivery_targets.size());
    for (const auto& target : cmd.delivery_targets) {
        sorted_targets.push_back(&target);
    }
    std::sort(sorted_targets.begin(), sorted_targets.end(), [](const auto* a, const auto* b) {
        if (a->recipient_device_id.str() != b->recipient_device_id.str()) {
            return a->recipient_device_id.str() < b->recipient_device_id.str();
        }
        return a->recipient_user_id.str() < b->recipient_user_id.str();
    });

    // 2. Build canonical targets representation
    std::string targets_repr;
    for (std::size_t i = 0; i < sorted_targets.size(); ++i) {
        if (i > 0) {
            targets_repr.push_back(';');
        }
        const auto* target = sorted_targets[i];
        targets_repr.append(target->recipient_device_id.str());
        targets_repr.push_back(':');
        targets_repr.append(compute_sha256_hex(target->ciphertext_blob));
    }

    // 3. Construct canonical input string:
    // conversation_id | sender_device_id | priority_str | sorted_targets
    std::string canonical_payload;
    canonical_payload.reserve(128 + targets_repr.size());
    canonical_payload.append(cmd.conversation_id.to_string());
    canonical_payload.push_back('|');
    canonical_payload.append(cmd.sender_device_id.str());
    canonical_payload.push_back('|');
    canonical_payload.append(to_string(cmd.priority));
    canonical_payload.push_back('|');
    canonical_payload.append(targets_repr);

    // 4. Return SHA-256 hex of the canonical payload
    return compute_sha256_hex(canonical_payload);
}

} // namespace securecloud::messaging::domain
