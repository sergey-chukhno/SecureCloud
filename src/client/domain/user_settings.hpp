#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain {

inline constexpr std::size_t kSha256HexLength = 64U;
inline constexpr std::string_view kProxyPasswordStorageKey = "network.proxy.password";
inline constexpr std::string_view kRecoveryVerifierStorageKey = "recovery.phrase.verifier";

inline constexpr double kMinFontScale = 0.85;
inline constexpr double kMaxFontScale = 1.40;
inline constexpr int kMinThemeMode = 0;
inline constexpr int kMaxThemeMode = 2;
inline constexpr uint16_t kDefaultGatewayPort = 8443U;
inline constexpr uint32_t kUserSettingsSchemaVersion = 1U;

[[nodiscard]] bool is_valid_sha256_hex(std::string_view value) noexcept;
[[nodiscard]] std::string normalize_hex_lower(std::string_view value);

enum class ProxyType { None = 0, Http = 1, Socks5 = 2 };

[[nodiscard]] std::string_view to_string(ProxyType type) noexcept;
[[nodiscard]] std::optional<ProxyType> proxy_type_from_string(std::string_view value) noexcept;

enum class DisappearingTimerPreset : int64_t {
    Off = 0,
    OneHour = 3600,
    TwentyFourHours = 86400,
    SevenDays = 604800,
};

[[nodiscard]] std::string_view to_string(DisappearingTimerPreset preset) noexcept;
[[nodiscard]] std::optional<DisappearingTimerPreset>
disappearing_timer_preset_from_string(std::string_view value) noexcept;
[[nodiscard]] std::optional<DisappearingTimerPreset> disappearing_timer_preset_from_seconds(int64_t seconds) noexcept;

/// Endpoint-local HTTP/SOCKS5 proxy configuration.
/// Deliberately omits `has_password` so SQLCipher settings never duplicate credential state
/// owned by ISecureStorage (`kProxyPasswordStorageKey`).
struct ProxyConfig {
    ProxyType type{ProxyType::None};
    std::string host{};
    uint16_t port{0};
    std::string username{};

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool is_valid() const noexcept;

    bool operator==(const ProxyConfig& other) const noexcept = default;
};

/// Gateway endpoint override & Subject Public Key Info (SPKI) SHA-256 TLS pinning config.
struct TlsPinConfig {
    std::string custom_gateway_host{};
    uint16_t custom_gateway_port{kDefaultGatewayPort};
    std::string pinned_spki_sha256_hex{};
    bool enforce_strict_pinning{true};

    [[nodiscard]] std::string normalized_pin() const;
    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool is_valid() const noexcept;

    bool operator==(const TlsPinConfig& other) const noexcept = default;
};

/// Strictly endpoint-local preferences and security/network policy persisted encrypted in SQLCipher.
/// Never transmitted to backend services or peers (`ADR-008`). Never stores proxy passwords or BIP-39 seeds.
struct UserSettings {
    int theme_mode{1}; // 0=System, 1=Dark, 2=Light (matches ui::ThemeMode)
    double font_scale{1.0};
    bool high_contrast_enabled{false};

    bool read_receipts_enabled{true};
    DisappearingTimerPreset default_disappearing_timer{DisappearingTimerPreset::Off};
    bool mfa_required_on_login{true};
    bool hardware_key_enforced{true};
    bool recovery_phrase_verified{false};

    bool use_live_gateway_transport{false};
    ProxyConfig proxy{};
    TlsPinConfig tls{};

    uint32_t schema_version{kUserSettingsSchemaVersion};
    int64_t updated_at_ms{0};

    [[nodiscard]] std::vector<std::string> validate() const;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] static std::optional<UserSettings> from_json(std::string_view json_str);

    bool operator==(const UserSettings& other) const noexcept = default;
};

} // namespace securecloud::client::domain
