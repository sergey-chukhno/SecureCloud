#pragma once

#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

enum class PanicTriggerSource { Hotkey, UiPanicButton, DuressPin, Programmatic };

[[nodiscard]] std::string_view to_string(PanicTriggerSource source) noexcept;
[[nodiscard]] std::optional<PanicTriggerSource> panic_trigger_source_from_string(std::string_view str) noexcept;

enum class PostWipeMode { EmergencyLocked, UnconfiguredReset, DecoyWorkspace };

[[nodiscard]] std::string_view to_string(PostWipeMode mode) noexcept;
[[nodiscard]] std::optional<PostWipeMode> post_wipe_mode_from_string(std::string_view str) noexcept;

enum class WipeStepStatus { Succeeded, Skipped, Failed };

[[nodiscard]] std::string_view to_string(WipeStepStatus status) noexcept;
[[nodiscard]] std::optional<WipeStepStatus> wipe_step_status_from_string(std::string_view str) noexcept;

struct WipeArtifactResult {
    std::string artifact_category;
    std::size_t items_processed{0};
    WipeStepStatus status{WipeStepStatus::Succeeded};
    std::string detail;

    bool operator==(const WipeArtifactResult& other) const noexcept = default;
};

/// Strictly non-secret operational summary produced after an emergency panic wipe.
/// Never contains private keys, raw file paths, plaintext payloads, or credentials.
struct EmergencyWipeReport {
    PanicTriggerSource trigger_source{PanicTriggerSource::Programmatic};
    PostWipeMode post_wipe_mode{PostWipeMode::EmergencyLocked};
    bool broadcast_attempted{false};
    bool broadcast_acknowledged{false};
    std::size_t secrets_purged_count{0};
    std::size_t files_shredded_count{0};
    std::size_t volatile_caches_cleared{0};
    int64_t duration_ms{0};
    bool all_critical_steps_succeeded{false};
    std::vector<WipeArtifactResult> step_results;

    [[nodiscard]] std::string to_safe_summary_json() const;

    bool operator==(const EmergencyWipeReport& other) const noexcept = default;
};

struct EmergencyBroadcastRequest {
    static constexpr std::chrono::milliseconds kDefaultAckTimeout{1500};
    static constexpr std::chrono::milliseconds kMaxAckTimeout{15000};

    ConversationId conversation_id;
    UserId sender_user_id;
    DeviceId sender_device_id;
    std::string alert_plaintext;
    std::optional<std::string> encrypted_location_json;
    bool wait_for_acknowledgement{false};
    std::chrono::milliseconds ack_timeout{kDefaultAckTimeout};

    [[nodiscard]] bool is_valid() const noexcept;

    bool operator==(const EmergencyBroadcastRequest& other) const noexcept = default;
};

struct EmergencyBroadcastResult {
    bool submitted{false};
    bool acknowledged{false};
    MessageId message_id;
    std::string error_detail;

    bool operator==(const EmergencyBroadcastResult& other) const noexcept = default;
};

/// One-way salted PBKDF2-HMAC-SHA256 verifier configuration for login Duress PIN panic wipe.
/// Persisted solely inside ISecureStorage under `kStorageKey` and self-destructed upon wipe.
struct DuressPinConfig {
    static constexpr std::string_view kStorageKey = "emergency.duress_pin_config";
    static constexpr uint32_t kMinPbkdf2Iterations = 100000U;
    static constexpr std::size_t kMinSaltHexLength = 32U;
    static constexpr std::size_t kExpectedHashHexLength = 64U;

    bool enabled{false};
    PostWipeMode post_wipe_mode{PostWipeMode::DecoyWorkspace};
    uint32_t pbkdf2_iterations{kMinPbkdf2Iterations};
    std::string salt_hex;
    std::string derived_hash_hex;
    int64_t configured_at_ms{0};

    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<DuressPinConfig> from_json(std::string_view json_str);

    bool operator==(const DuressPinConfig& other) const noexcept = default;
};

} // namespace securecloud::client::domain
