#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

inline constexpr std::string_view kGenesisAuditHash =
    "0000000000000000000000000000000000000000000000000000000000000000";
inline constexpr std::size_t kMaxAuditSummaryBytes = 512U;
inline constexpr std::size_t kMaxAuditFieldBytes = 128U;

enum class LocalAuditCategory {
    CryptoSelfTest = 0,
    Authentication = 1,
    DeviceTrust = 2,
    KeyLifecycle = 3,
    MessagingSecurity = 4,
    EmergencyDefense = 5,
    SettingsNetwork = 6,
};

[[nodiscard]] std::string_view to_string(LocalAuditCategory category) noexcept;
[[nodiscard]] std::optional<LocalAuditCategory> local_audit_category_from_string(std::string_view value) noexcept;

enum class LocalAuditOutcome {
    Success = 0,
    Failure = 1,
    Rejected = 2,
    Triggered = 3,
};

[[nodiscard]] std::string_view to_string(LocalAuditOutcome outcome) noexcept;
[[nodiscard]] std::optional<LocalAuditOutcome> local_audit_outcome_from_string(std::string_view value) noexcept;

/// Strictly endpoint-local, tamper-evident security audit record stored in SQLCipher `local_audit_log`.
/// Never contains secrets, raw credentials, plaintext payloads, or unredacted PII, and is never uploaded
/// to backend services (ADR-008 / AUDIT-016 §1.1).
struct LocalAuditEvent {
    int64_t sequence_id{0};
    int64_t occurred_at_ms{0};
    LocalAuditCategory category{LocalAuditCategory::Authentication};
    std::string event_type{};
    LocalAuditOutcome outcome{LocalAuditOutcome::Success};
    std::string actor_opaque_id{};
    std::string target_opaque_id{};
    std::string sanitized_summary{};
    std::string prev_hash_sha256{kGenesisAuditHash};
    std::string entry_hash_sha256{};

    [[nodiscard]] std::string compute_canonical_hash() const;
    [[nodiscard]] bool has_valid_hash() const;
    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<LocalAuditEvent> from_json(std::string_view json_str);
    [[nodiscard]] static bool is_valid_sha256_hex(std::string_view hex) noexcept;

    bool operator==(const LocalAuditEvent& other) const noexcept = default;
};

struct AuditChainVerificationResult {
    bool valid{true};
    std::size_t verified_count{0U};
    std::optional<int64_t> first_corrupted_sequence{};
    std::string latest_hash_sha256{kGenesisAuditHash};
    std::string failure_reason{};

    bool operator==(const AuditChainVerificationResult& other) const noexcept = default;
};

} // namespace securecloud::client::domain
