#include "application/client_config.hpp"
#include "domain/user_profile.hpp"
#include "domain/user_settings.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"

#include <cstdlib>
#include <gtest/gtest.h>
#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using securecloud::client::infrastructure::adapters::DefaultGatewayClient;
using securecloud::common::configuration::SecretString;

constexpr std::string_view kValidPinUpper = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90";
constexpr std::string_view kValidPinLower = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
constexpr std::string_view kOtherPinLower = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

class ScopedEnvGuard {
  public:
    ~ScopedEnvGuard() {
        for (const auto& [name, prev] : saved_) {
#if defined(_WIN32)
            _putenv_s(name.c_str(), prev.has_value() ? prev->c_str() : "");
#else
            if (prev.has_value()) {
                setenv(name.c_str(), prev->c_str(), 1);
            } else {
                unsetenv(name.c_str());
            }
#endif
        }
    }

    void set(const char* name, const char* value) {
        if (!contains(name)) {
            const char* existing = std::getenv(name);
            saved_.emplace_back(name, existing != nullptr ? std::optional<std::string>(existing) : std::nullopt);
        }
#if defined(_WIN32)
        _putenv_s(name, value);
#else
        setenv(name, value, 1);
#endif
    }

  private:
    [[nodiscard]] bool contains(const std::string& name) const {
        for (const auto& [key, _] : saved_) {
            if (key == name) {
                return true;
            }
        }
        return false;
    }

    std::vector<std::pair<std::string, std::optional<std::string>>> saved_;
};

TEST(UserSettingsAndProfileDomainTest, UserProfileValidationAndLosslessJsonRoundTrip) {
    UserProfile profile;
    profile.user_id = UserId("user-alice-001");
    profile.public_handle = "alice.secure_01-node";
    profile.display_name = "Alice Researcher";
    profile.bio_status = "End-to-end encrypted field notes\nTimezone: UTC+1";
    profile.avatar_file_id = "file-avatar-01928374";
    profile.avatar_sha256 = std::string(kValidPinUpper);
    profile.allow_handle_discovery = false;
    profile.updated_at_ms = 1764000000123LL;

    EXPECT_TRUE(profile.is_valid());
    EXPECT_TRUE(profile.validate().empty());

    const std::string json_str = profile.to_json();
    const auto parsed = UserProfile::from_json(json_str);
    ASSERT_TRUE(parsed.has_value());

    UserProfile expected = profile;
    expected.avatar_sha256 = std::string(kValidPinLower);
    EXPECT_EQ(*parsed, expected);

    // Ensure UserProfile JSON never leaks secrets or plaintext URLs.
    EXPECT_EQ(json_str.find("password"), std::string::npos);
    EXPECT_EQ(json_str.find("mnemonic"), std::string::npos);
    EXPECT_EQ(json_str.find("https://"), std::string::npos);
}

TEST(UserSettingsAndProfileDomainTest, UserProfileRejectsInvalidFields) {
    UserProfile base;
    base.user_id = UserId("user-alice-001");
    base.display_name = "Alice";
    ASSERT_TRUE(base.is_valid());

    {
        auto p = base;
        p.user_id = UserId{};
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.display_name = "";
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.display_name = std::string(kMaxDisplayNameBytes + 1U, 'a');
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.display_name = "Alice\nBob";
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.bio_status = std::string(kMaxBioStatusBytes + 1U, 'b');
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.bio_status = std::string("bad\x07 bell", 9);
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.public_handle = "ab";
        EXPECT_FALSE(p.is_valid());
        p.public_handle = std::string(kMaxPublicHandleLength + 1U, 'c');
        EXPECT_FALSE(p.is_valid());
        p.public_handle = "Alice";
        EXPECT_FALSE(p.is_valid());
        p.public_handle = "alice@example";
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.avatar_file_id = "https://cdn.example.com/avatar.png";
        EXPECT_FALSE(p.is_valid());
        p.avatar_file_id = "file with space";
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.avatar_sha256 = "short";
        EXPECT_FALSE(p.is_valid());
        p.avatar_sha256 = "g" + std::string(63U, '0');
        EXPECT_FALSE(p.is_valid());
    }
    {
        auto p = base;
        p.updated_at_ms = -1;
        EXPECT_FALSE(p.is_valid());
    }

    EXPECT_FALSE(UserProfile::from_json("{not json").has_value());
    EXPECT_FALSE(UserProfile::from_json(R"({"user_id":"u1","display_name":""})").has_value());
    EXPECT_FALSE(UserProfile::from_json(R"({"user_id":"","display_name":"Alice"})").has_value());
}

TEST(UserSettingsAndProfileDomainTest, UserSettingsValidationAndLosslessJsonRoundTrip) {
    const UserSettings defaults;
    EXPECT_TRUE(defaults.is_valid());
    const auto roundtrip_default = UserSettings::from_json(defaults.to_json());
    ASSERT_TRUE(roundtrip_default.has_value());
    EXPECT_EQ(*roundtrip_default, defaults);

    UserSettings custom;
    custom.theme_mode = 2; // Light
    custom.font_scale = 1.35;
    custom.high_contrast_enabled = true;
    custom.read_receipts_enabled = false;
    custom.default_disappearing_timer = DisappearingTimerPreset::SevenDays;
    custom.mfa_required_on_login = false;
    custom.hardware_key_enforced = false;
    custom.recovery_phrase_verified = true;
    custom.use_live_gateway_transport = true;
    custom.proxy.type = ProxyType::Socks5;
    custom.proxy.host = "127.0.0.1";
    custom.proxy.port = 1080U;
    custom.proxy.username = "field-ops";
    custom.tls.custom_gateway_host = "gw.internal.local";
    custom.tls.custom_gateway_port = 9443U;
    custom.tls.pinned_spki_sha256_hex = std::string(kValidPinUpper);
    custom.tls.enforce_strict_pinning = true;
    custom.updated_at_ms = 1764000000999LL;

    EXPECT_TRUE(custom.is_valid());

    const std::string serialized = custom.to_json();
    const auto parsed = UserSettings::from_json(serialized);
    ASSERT_TRUE(parsed.has_value());

    UserSettings expected = custom;
    expected.tls.pinned_spki_sha256_hex = std::string(kValidPinLower);
    EXPECT_EQ(*parsed, expected);

    // Zero secret leakage and confirm dropped `has_password` field never appears in serialized JSON.
    EXPECT_EQ(serialized.find("password"), std::string::npos);
    EXPECT_EQ(serialized.find("has_password"), std::string::npos);
    EXPECT_EQ(serialized.find("mnemonic"), std::string::npos);
    EXPECT_EQ(serialized.find("recovery_phrase\""), std::string::npos);
    EXPECT_EQ(serialized.find("seed"), std::string::npos);

    const auto doc = nlohmann::json::parse(serialized);
    EXPECT_FALSE(doc["proxy"].contains("has_password"));
    EXPECT_FALSE(doc["proxy"].contains("password"));
}

TEST(UserSettingsAndProfileDomainTest, UserSettingsRejectsOutOfBoundsValues) {
    const UserSettings base;
    ASSERT_TRUE(base.is_valid());

    {
        auto s = base;
        s.theme_mode = -1;
        EXPECT_FALSE(s.is_valid());
        s.theme_mode = 3;
        EXPECT_FALSE(s.is_valid());
    }
    {
        auto s = base;
        s.font_scale = 0.84;
        EXPECT_FALSE(s.is_valid());
        s.font_scale = 1.41;
        EXPECT_FALSE(s.is_valid());
        s.font_scale = std::numeric_limits<double>::quiet_NaN();
        EXPECT_FALSE(s.is_valid());
        s.font_scale = std::numeric_limits<double>::infinity();
        EXPECT_FALSE(s.is_valid());
    }
    {
        auto s = base;
        s.proxy.type = ProxyType::Http;
        s.proxy.host = "";
        s.proxy.port = 8080U;
        EXPECT_FALSE(s.is_valid());

        s.proxy.host = "proxy.local";
        s.proxy.port = 0U;
        EXPECT_FALSE(s.is_valid());

        s.proxy.host = "bad host";
        s.proxy.port = 8080U;
        EXPECT_FALSE(s.is_valid());
    }
    {
        auto s = base;
        s.tls.custom_gateway_port = 0U;
        EXPECT_FALSE(s.is_valid());
    }
    {
        auto s = base;
        s.tls.pinned_spki_sha256_hex = "abcd";
        EXPECT_FALSE(s.is_valid());
        s.tls.pinned_spki_sha256_hex = "z" + std::string(63U, '0');
        EXPECT_FALSE(s.is_valid());
    }

    EXPECT_FALSE(UserSettings::from_json("[]").has_value());
    EXPECT_FALSE(UserSettings::from_json(R"({"default_disappearing_timer_seconds":123})").has_value());
    EXPECT_FALSE(UserSettings::from_json(R"({"font_scale":2.0})").has_value());
}

TEST(UserSettingsAndProfileDomainTest, EnumConversionsRoundTripCleanly) {
    EXPECT_EQ(proxy_type_from_string("NONE"), ProxyType::None);
    EXPECT_EQ(proxy_type_from_string("Http"), ProxyType::Http);
    EXPECT_EQ(proxy_type_from_string("socks5"), ProxyType::Socks5);
    EXPECT_FALSE(proxy_type_from_string("ftp").has_value());

    EXPECT_EQ(to_string(ProxyType::None), "none");
    EXPECT_EQ(to_string(ProxyType::Http), "http");
    EXPECT_EQ(to_string(ProxyType::Socks5), "socks5");

    EXPECT_EQ(disappearing_timer_preset_from_string("off"), DisappearingTimerPreset::Off);
    EXPECT_EQ(disappearing_timer_preset_from_string("1H"), DisappearingTimerPreset::OneHour);
    EXPECT_EQ(disappearing_timer_preset_from_string("24h"), DisappearingTimerPreset::TwentyFourHours);
    EXPECT_EQ(disappearing_timer_preset_from_string("7d"), DisappearingTimerPreset::SevenDays);
    EXPECT_FALSE(disappearing_timer_preset_from_string("99d").has_value());

    EXPECT_EQ(disappearing_timer_preset_from_seconds(0), DisappearingTimerPreset::Off);
    EXPECT_EQ(disappearing_timer_preset_from_seconds(3600), DisappearingTimerPreset::OneHour);
    EXPECT_EQ(disappearing_timer_preset_from_seconds(86400), DisappearingTimerPreset::TwentyFourHours);
    EXPECT_EQ(disappearing_timer_preset_from_seconds(604800), DisappearingTimerPreset::SevenDays);
    EXPECT_FALSE(disappearing_timer_preset_from_seconds(42).has_value());
}

TEST(ClientConfigNetworkTest, EnvironmentOverridesAndSecretRedaction) {
    ScopedEnvGuard env;
    env.set("SECURECLOUD_USE_LIVE_GATEWAY", "true");
    env.set("SECURECLOUD_PROXY_TYPE", "socks5");
    env.set("SECURECLOUD_PROXY_HOST", "127.0.0.1");
    env.set("SECURECLOUD_PROXY_PORT", "9050");
    env.set("SECURECLOUD_PROXY_USER", "alice");
    env.set("SECURECLOUD_PROXY_PASS", "super-secret-proxy-pass");
    env.set("SECURECLOUD_TLS_PIN_SPKI_SHA256", std::string(kValidPinUpper).c_str());
    env.set("SECURECLOUD_TLS_ENFORCE_PINNING", "false");

    const ClientConfig config = ClientConfig::from_environment();
    EXPECT_TRUE(config.is_valid());
    EXPECT_TRUE(config.use_live_gateway_transport);
    EXPECT_EQ(config.proxy_type, ProxyType::Socks5);
    EXPECT_EQ(config.proxy_host, "127.0.0.1");
    EXPECT_EQ(config.proxy_port, 9050U);
    EXPECT_EQ(config.proxy_username, "alice");
    EXPECT_EQ(config.proxy_password.expose_unredacted_secret(), "super-secret-proxy-pass");
    EXPECT_EQ(config.pinned_tls_spki_sha256, kValidPinLower);
    EXPECT_FALSE(config.enforce_tls_pinning);

    const std::string safe = config.to_safe_string();
    EXPECT_EQ(safe.find("super-secret-proxy-pass"), std::string::npos);
    EXPECT_NE(safe.find("proxy_password: [REDACTED]"), std::string::npos);
    EXPECT_NE(safe.find("use_live_gateway_transport: true"), std::string::npos);
}

TEST(ClientConfigNetworkTest, ValidatesProxyAndPinnedSpkiHex) {
    auto config = ClientConfig::create_default();
    EXPECT_FALSE(config.use_live_gateway_transport);
    EXPECT_EQ(config.proxy_type, ProxyType::None);
    EXPECT_TRUE(config.enforce_tls_pinning);
    EXPECT_NE(config.to_safe_string().find("proxy_password: [EMPTY]"), std::string::npos);

    config.proxy_type = ProxyType::Http;
    config.proxy_host = "";
    config.proxy_port = 0U;
    EXPECT_FALSE(config.is_valid());
    EXPECT_GE(config.validate().size(), 2u);

    config = ClientConfig::create_default();
    config.pinned_tls_spki_sha256 = "not-valid-sha256";
    EXPECT_FALSE(config.is_valid());
    EXPECT_EQ(config.validate().size(), 1u);
}

TEST(DefaultGatewayProfileAndTlsTest, ProfileSyncRespectsPrivacyAndServerSupport) {
    auto config = ClientConfig::create_default();
    config.pinned_tls_spki_sha256 = std::string(kValidPinUpper);
    DefaultGatewayClient gateway(config);

    // Unseen user hydrates deterministic defaults; empty ID fails validation.
    EXPECT_TRUE(gateway.get_user_profile(UserId{}).is_error());
    const auto hydrated = gateway.get_user_profile(UserId("user-1"));
    ASSERT_TRUE(hydrated.is_ok());
    EXPECT_EQ(hydrated.value().user_id, UserId("user-1"));

    // Opted-in public profile syncs cleanly and increments remote call count.
    UserProfile profile;
    profile.user_id = UserId("user-1");
    profile.public_handle = "alice.node";
    profile.display_name = "Alice";
    profile.allow_handle_discovery = true;

    const auto synced = gateway.update_user_profile(profile);
    ASSERT_TRUE(synced.is_ok());
    EXPECT_EQ(synced.value().sync_status, ProfileSyncStatus::Synced);
    EXPECT_EQ(gateway.profile_update_call_count(), 1u);

    const auto reloaded = gateway.get_user_profile(UserId("user-1"));
    ASSERT_TRUE(reloaded.is_ok());
    EXPECT_EQ(reloaded.value().display_name, "Alice");
    EXPECT_EQ(reloaded.value().public_handle, "alice.node");

    // When allow_handle_discovery is false, client skips remote mutation cleanly.
    UserProfile private_profile = profile;
    private_profile.display_name = "Private Alias";
    private_profile.allow_handle_discovery = false;
    const auto skipped = gateway.update_user_profile(private_profile);
    ASSERT_TRUE(skipped.is_ok());
    EXPECT_EQ(skipped.value().sync_status, ProfileSyncStatus::SyncDisabledByPrivacyPolicy);
    EXPECT_EQ(gateway.profile_update_call_count(), 1u);

    // Remote state stays intact when discovery was disabled.
    const auto still_public = gateway.get_user_profile(UserId("user-1"));
    ASSERT_TRUE(still_public.is_ok());
    EXPECT_EQ(still_public.value().display_name, "Alice");

    // Live Gateway 404/501 simulation degrades cleanly to LocalOnlyServerUnsupported.
    gateway.set_simulated_profile_sync_unsupported(true);
    const auto unsupported = gateway.update_user_profile(profile);
    ASSERT_TRUE(unsupported.is_ok());
    EXPECT_EQ(unsupported.value().sync_status, ProfileSyncStatus::LocalOnlyServerUnsupported);
    EXPECT_EQ(gateway.profile_update_call_count(), 2u);

    // Invalid profile fails validation.
    UserProfile invalid;
    invalid.user_id = UserId("user-1");
    invalid.display_name = "";
    EXPECT_TRUE(gateway.update_user_profile(invalid).is_error());
}

TEST(DefaultGatewayProfileAndTlsTest, TlsCertificateInspectionEvaluatesSpkiPin) {
    DefaultGatewayClient unpinned(ClientConfig::create_default());
    EXPECT_TRUE(unpinned.inspect_tls_certificate("", 8443).is_error());
    EXPECT_TRUE(unpinned.inspect_tls_certificate("127.0.0.1", 0).is_error());

    const auto no_pin_info = unpinned.inspect_tls_certificate("gateway.local", 8443);
    ASSERT_TRUE(no_pin_info.is_ok());
    EXPECT_FALSE(no_pin_info.value().has_pinned_key);
    EXPECT_TRUE(no_pin_info.value().matches_pinned_key);
    EXPECT_TRUE(is_valid_sha256_hex(no_pin_info.value().spki_sha256_hex));

    auto pinned_cfg = ClientConfig::create_default();
    pinned_cfg.pinned_tls_spki_sha256 = std::string(kValidPinUpper);
    DefaultGatewayClient pinned(pinned_cfg);

    TlsCertificateInfo matching_cert;
    matching_cert.subject_cn = "gateway.securecloud.test";
    matching_cert.issuer_cn = "SecureCloud Root CA";
    matching_cert.spki_sha256_hex = std::string(kValidPinLower);
    pinned.set_simulated_tls_certificate(matching_cert);

    const auto match_res = pinned.inspect_tls_certificate("gateway.securecloud.test", 9443);
    ASSERT_TRUE(match_res.is_ok());
    EXPECT_TRUE(match_res.value().has_pinned_key);
    EXPECT_TRUE(match_res.value().matches_pinned_key);
    EXPECT_EQ(match_res.value().spki_sha256_hex, kValidPinLower);

    // Rotate pin -> detects mismatch immediately.
    pinned.set_pinned_tls_spki_sha256(std::string(kOtherPinLower));
    const auto mismatch_res = pinned.inspect_tls_certificate("gateway.securecloud.test", 9443);
    ASSERT_TRUE(mismatch_res.is_ok());
    EXPECT_TRUE(mismatch_res.value().has_pinned_key);
    EXPECT_FALSE(mismatch_res.value().matches_pinned_key);
}

} // namespace
