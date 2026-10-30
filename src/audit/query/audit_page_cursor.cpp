#include "query/audit_page_cursor.hpp"

#include <algorithm>
#include <cstring>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sstream>

namespace securecloud::audit::query {

namespace {

constexpr std::string_view kBase64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_encode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    uint32_t val = 0;
    int valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kBase64UrlAlphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(kBase64UrlAlphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> base64url_decode(std::string_view input) {
    std::vector<int> T(256, -1);
    for (size_t i = 0; i < kBase64UrlAlphabet.size(); ++i) {
        T[static_cast<unsigned char>(kBase64UrlAlphabet[i])] = static_cast<int>(i);
    }

    std::vector<uint8_t> out;
    out.reserve((input.size() * 3) / 4);

    uint32_t val = 0;
    int valb = -8;
    for (char c : input) {
        int v = T[static_cast<unsigned char>(c)];
        if (v == -1)
            return std::nullopt;
        val = (val << 6) + static_cast<uint32_t>(v);
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

void hash_uint64(EVP_MD_CTX* ctx, uint64_t val) {
    uint64_t net_val = val; // Big-endian normalization
    EVP_DigestUpdate(ctx, &net_val, sizeof(net_val));
}

void hash_string(EVP_MD_CTX* ctx, std::string_view str) {
    uint32_t len = static_cast<uint32_t>(str.size());
    EVP_DigestUpdate(ctx, &len, sizeof(len));
    if (!str.empty()) {
        EVP_DigestUpdate(ctx, str.data(), str.size());
    }
}

} // namespace

std::array<uint8_t, 16> AuditPageCursorCodec::compute_filter_hash(const AuditQueryFilter& filter) {
    std::array<uint8_t, 16> truncated_hash{};
    unsigned char full_hash[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return truncated_hash;

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    // 1. Time bounds
    int64_t start_ms =
        filter.start_occurred_at.has_value()
            ? std::chrono::duration_cast<std::chrono::milliseconds>(filter.start_occurred_at->time_since_epoch())
                  .count()
            : 0;
    hash_uint64(ctx, static_cast<uint64_t>(start_ms));

    int64_t end_ms =
        filter.end_occurred_at.has_value()
            ? std::chrono::duration_cast<std::chrono::milliseconds>(filter.end_occurred_at->time_since_epoch()).count()
            : 0;
    hash_uint64(ctx, static_cast<uint64_t>(end_ms));

    // 2. Producer services (sorted)
    auto sorted_producers = filter.producer_services;
    std::sort(sorted_producers.begin(), sorted_producers.end());
    uint32_t prod_count = static_cast<uint32_t>(sorted_producers.size());
    EVP_DigestUpdate(ctx, &prod_count, sizeof(prod_count));
    for (auto p : sorted_producers) {
        uint8_t val = static_cast<uint8_t>(p);
        EVP_DigestUpdate(ctx, &val, sizeof(val));
    }

    // 3. Event types (sorted)
    auto sorted_types = filter.event_types;
    std::sort(sorted_types.begin(), sorted_types.end());
    uint32_t type_count = static_cast<uint32_t>(sorted_types.size());
    EVP_DigestUpdate(ctx, &type_count, sizeof(type_count));
    for (const auto& t : sorted_types) {
        hash_string(ctx, t);
    }

    // 4. Severities (sorted)
    auto sorted_sevs = filter.severities;
    std::sort(sorted_sevs.begin(), sorted_sevs.end());
    uint32_t sev_count = static_cast<uint32_t>(sorted_sevs.size());
    EVP_DigestUpdate(ctx, &sev_count, sizeof(sev_count));
    for (auto s : sorted_sevs) {
        uint8_t val = static_cast<uint8_t>(s);
        EVP_DigestUpdate(ctx, &val, sizeof(val));
    }

    // 5. Actor
    uint8_t has_act = filter.actor_type.has_value() ? 1 : 0;
    EVP_DigestUpdate(ctx, &has_act, sizeof(has_act));
    if (filter.actor_type.has_value()) {
        uint8_t val = static_cast<uint8_t>(*filter.actor_type);
        EVP_DigestUpdate(ctx, &val, sizeof(val));
    }
    hash_string(ctx, filter.actor_id.value_or(""));

    // 6. Target
    uint8_t has_tgt = filter.target_type.has_value() ? 1 : 0;
    EVP_DigestUpdate(ctx, &has_tgt, sizeof(has_tgt));
    if (filter.target_type.has_value()) {
        uint8_t val = static_cast<uint8_t>(*filter.target_type);
        EVP_DigestUpdate(ctx, &val, sizeof(val));
    }
    hash_string(ctx, filter.target_id.value_or(""));

    // 7. Correlation ID & Sort order
    hash_string(ctx, filter.correlation_id.value_or(""));
    uint8_t sort_val = static_cast<uint8_t>(filter.sort_order);
    EVP_DigestUpdate(ctx, &sort_val, sizeof(sort_val));

    EVP_DigestFinal_ex(ctx, full_hash, &md_len);
    EVP_MD_CTX_free(ctx);

    std::memcpy(truncated_hash.data(), full_hash, 16);
    return truncated_hash;
}

std::string AuditPageCursorCodec::encode(const AuditPageCursor& cursor) {
    std::vector<uint8_t> buffer;
    buffer.reserve(128);

    // 1. last_occurred_at_ms (8 bytes, int64_t)
    uint64_t ts = static_cast<uint64_t>(cursor.last_occurred_at_ms);
    for (int i = 7; i >= 0; --i) {
        buffer.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
    }

    // 2. last_producer_service string
    uint16_t prod_len = static_cast<uint16_t>(cursor.last_producer_service.size());
    buffer.push_back(static_cast<uint8_t>((prod_len >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(prod_len & 0xFF));
    buffer.insert(buffer.end(), cursor.last_producer_service.begin(), cursor.last_producer_service.end());

    // 3. last_event_type string
    uint16_t type_len = static_cast<uint16_t>(cursor.last_event_type.size());
    buffer.push_back(static_cast<uint8_t>((type_len >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(type_len & 0xFF));
    buffer.insert(buffer.end(), cursor.last_event_type.begin(), cursor.last_event_type.end());

    // 4. last_event_id (16 bytes UUIDv7)
    const auto& id_bytes = cursor.last_event_id.bytes();
    buffer.insert(buffer.end(), id_bytes.begin(), id_bytes.end());

    // 5. sort_order (1 byte)
    buffer.push_back(static_cast<uint8_t>(cursor.sort_order));

    // 6. filter_hash (16 bytes)
    buffer.insert(buffer.end(), cursor.filter_hash.begin(), cursor.filter_hash.end());

    return base64url_encode(buffer);
}

std::optional<AuditPageCursor> AuditPageCursorCodec::decode(std::string_view token,
                                                            const std::array<uint8_t, 16>& expected_filter_hash) {

    if (token.empty())
        return std::nullopt;

    auto raw_opt = base64url_decode(token);
    if (!raw_opt.has_value())
        return std::nullopt;

    const auto& bytes = *raw_opt;
    if (bytes.size() < 8 + 2 + 2 + 16 + 1 + 16)
        return std::nullopt;

    size_t offset = 0;

    // 1. last_occurred_at_ms
    uint64_t ts = 0;
    for (int i = 0; i < 8; ++i) {
        ts = (ts << 8) | bytes[offset++];
    }

    // 2. last_producer_service
    uint16_t prod_len = static_cast<uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
    offset += 2;
    if (offset + prod_len > bytes.size())
        return std::nullopt;
    std::string last_prod(reinterpret_cast<const char*>(&bytes[offset]), prod_len);
    offset += prod_len;

    // 3. last_event_type
    if (offset + 2 > bytes.size())
        return std::nullopt;
    uint16_t type_len = static_cast<uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
    offset += 2;
    if (offset + type_len > bytes.size())
        return std::nullopt;
    std::string last_type(reinterpret_cast<const char*>(&bytes[offset]), type_len);
    offset += type_len;

    // 4. last_event_id
    if (offset + 16 > bytes.size())
        return std::nullopt;
    std::array<uint8_t, 16> uuid_bytes{};
    std::memcpy(uuid_bytes.data(), &bytes[offset], 16);
    offset += 16;

    domain::EventId event_id{uuid_bytes};
    if (!event_id.is_nil() && (event_id.version() != 7 || event_id.variant() != 2)) {
        return std::nullopt;
    }

    // 5. sort_order
    if (offset + 1 > bytes.size())
        return std::nullopt;
    uint8_t sort_val = bytes[offset++];

    // 6. filter_hash
    if (offset + 16 != bytes.size())
        return std::nullopt;
    std::array<uint8_t, 16> token_filter_hash{};
    std::memcpy(token_filter_hash.data(), &bytes[offset], 16);

    // Constant-time verification against expected_filter_hash
    if (CRYPTO_memcmp(token_filter_hash.data(), expected_filter_hash.data(), 16) != 0) {
        return std::nullopt; // Tampered or mismatched cursor filter
    }

    AuditPageCursor cursor;
    cursor.last_occurred_at_ms = static_cast<int64_t>(ts);
    cursor.last_producer_service = std::move(last_prod);
    cursor.last_event_type = std::move(last_type);
    cursor.last_event_id = event_id;
    cursor.sort_order = static_cast<SortOrder>(sort_val);
    cursor.filter_hash = token_filter_hash;

    return cursor;
}

} // namespace securecloud::audit::query