#include "domain/event_payload_fingerprint.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <bit>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>

namespace securecloud::audit::domain {

namespace {

void update_uint8(EVP_MD_CTX* ctx, uint8_t val) {
    EVP_DigestUpdate(ctx, &val, sizeof(val));
}

void update_uint32_be(EVP_MD_CTX* ctx, uint32_t val) {
    uint32_t be_val = std::endian::native == std::endian::big ? val : __builtin_bswap32(val);
    EVP_DigestUpdate(ctx, &be_val, sizeof(be_val));
}

void update_int64_be(EVP_MD_CTX* ctx, int64_t val) {
    uint64_t uval = static_cast<uint64_t>(val);
    uint64_t be_val = std::endian::native == std::endian::big ? uval : __builtin_bswap64(uval);
    EVP_DigestUpdate(ctx, &be_val, sizeof(be_val));
}

void update_string(EVP_MD_CTX* ctx, std::string_view str) {
    update_uint32_be(ctx, static_cast<uint32_t>(str.size()));
    if (!str.empty()) {
        EVP_DigestUpdate(ctx, str.data(), str.size());
    }
}

} // namespace

EventPayloadFingerprint EventPayloadFingerprint::compute(const AuditEvent& event) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to allocate OpenSSL EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize OpenSSL SHA-256 digest");
    }

    // 1. event_id (16 bytes RFC 9562 UUIDv7)
    const auto& id_bytes = event.event_id.bytes();
    EVP_DigestUpdate(ctx, id_bytes.data(), id_bytes.size());

    // 2. occurred_at_ms (int64 big-endian epoch UTC ms)
    auto occurred_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(event.occurred_at.time_since_epoch()).count();
    update_int64_be(ctx, occurred_ms);

    // 3. event_type
    update_string(ctx, event.event_type);

    // 4. severity
    update_uint8(ctx, static_cast<uint8_t>(event.severity));

    // 5. producer_service
    update_uint8(ctx, static_cast<uint8_t>(event.producer_service));

    // 6. producer_instance
    update_string(ctx, event.producer_instance);

    // 7. actor_type
    update_uint8(ctx, static_cast<uint8_t>(event.actor_type));

    // 8. actor_id
    update_string(ctx, event.actor_id);

    // 9. target_type
    update_uint8(ctx, static_cast<uint8_t>(event.target_type));

    // 10. target_id
    update_string(ctx, event.target_id);

    // 11. correlation_id
    update_string(ctx, event.correlation_id);

    // 12. causation_id (uint8 flag + optional string)
    if (event.causation_id.has_value()) {
        update_uint8(ctx, 1);
        update_string(ctx, event.causation_id.value());
    } else {
        update_uint8(ctx, 0);
    }

    // 13. sorted metadata (uint32 count + lexicographically sorted pairs)
    std::map<std::string_view, std::string_view> sorted_meta;
    for (const auto& [k, v] : event.metadata) {
        sorted_meta.emplace(k, v);
    }

    update_uint32_be(ctx, static_cast<uint32_t>(sorted_meta.size()));
    for (const auto& [k, v] : sorted_meta) {
        update_string(ctx, k);
        update_string(ctx, v);
    }

    digest_type digest{};
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, digest.data(), &len);
    EVP_MD_CTX_free(ctx);

    return EventPayloadFingerprint(digest);
}

std::string EventPayloadFingerprint::to_hex_prefix(size_t byte_count) const {
    size_t count = std::min(byte_count, digest_.size());
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i) {
        ss << std::setw(2) << static_cast<int>(digest_[i]);
    }
    return ss.str();
}

} // namespace securecloud::audit::domain