#pragma once

#include "domain/user_id.hpp"
#include "domain/user_settings.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

inline constexpr std::size_t kMaxDisplayNameBytes = 128U;
inline constexpr std::size_t kMaxBioStatusBytes = 512U;
inline constexpr std::size_t kMinPublicHandleLength = 3U;
inline constexpr std::size_t kMaxPublicHandleLength = 64U;
inline constexpr std::size_t kMaxAvatarFileIdBytes = 128U;

/// Editable public/social identity metadata persisted encrypted in local SQLCipher (`user_profile`).
/// Distinct from `domain::User` (account/device aggregate). Avatars reference E2EE Files blobs (`ADR-008 §20`).
struct UserProfile {
    UserId user_id{};
    std::string public_handle{};
    std::string display_name{};
    std::string bio_status{};
    std::string avatar_file_id{};
    std::string avatar_sha256{};
    bool allow_handle_discovery{true};
    int64_t updated_at_ms{0};

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<UserProfile> from_json(std::string_view json_str);

    bool operator==(const UserProfile& other) const noexcept = default;
};

} // namespace securecloud::client::domain
