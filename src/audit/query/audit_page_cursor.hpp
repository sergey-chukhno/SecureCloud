#pragma once

#include "query/audit_query_types.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::audit::query {

class AuditPageCursorCodec {
  public:
    /// Computes a 16-byte (128-bit) truncated SHA-256 fingerprint over canonical query filter parameters.
    [[nodiscard]] static std::array<uint8_t, 16> compute_filter_hash(const AuditQueryFilter& filter);

    /// Encodes an AuditPageCursor into a URL-safe Base64URL page_token string.
    [[nodiscard]] static std::string encode(const AuditPageCursor& cursor);

    /// Decodes a URL-safe Base64URL page_token string into an AuditPageCursor.
    /// Verifies the decoded filter_hash against expected_filter_hash in constant time.
    /// Returns std::nullopt if the token is malformed or if filter_hash mismatches.
    [[nodiscard]] static std::optional<AuditPageCursor> decode(std::string_view token,
                                                               const std::array<uint8_t, 16>& expected_filter_hash);
};

} // namespace securecloud::audit::query