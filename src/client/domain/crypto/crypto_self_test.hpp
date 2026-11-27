#pragma once

#include "application/interfaces/i_secure_storage.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::domain::crypto {

struct CryptoSelfTestCheckResult {
    std::string check_name{};
    bool passed{false};
    std::string detail{};
    int64_t duration_us{0};

    bool operator==(const CryptoSelfTestCheckResult& other) const noexcept = default;
};

struct CryptoSelfTestReport {
    bool overall_passed{false};
    int64_t total_duration_us{0};
    int64_t executed_at_ms{0};
    std::string crypto_backend{};
    std::vector<CryptoSelfTestCheckResult> checks{};

    [[nodiscard]] std::string to_json() const;
    [[nodiscard]] std::string failed_checks_summary() const;

    bool operator==(const CryptoSelfTestReport& other) const noexcept = default;
};

/// Real OpenSSL 3.x Known-Answer Tests (RFC 8032 Ed25519, RFC 7748 X25519, NIST SP 800-38D AES-256-GCM,
/// RFC 5869 HKDF-SHA256), CSPRNG entropy health validation, and ephemeral ISecureStorage canary probe.
/// Invoked fail-closed during ClientApplication::initialize() before opening any Gateway network session.
class CryptoSelfTest final {
  public:
    static constexpr std::string_view kCanaryStorageKey = "selftest.canary.probe";

    /// Optional test-only callback returning a non-empty fault reason to deterministically simulate
    /// a failure for `check_name`. Must remain unset in production boots.
    using FaultInjector = std::function<std::optional<std::string>(std::string_view check_name)>;

    [[nodiscard]] static CryptoSelfTestReport run_all(application::interfaces::ISecureStorage* secure_storage,
                                                      const FaultInjector& fault_injector = {});

    [[nodiscard]] static CryptoSelfTestCheckResult run_ed25519_kat(const FaultInjector& fault_injector = {});
    [[nodiscard]] static CryptoSelfTestCheckResult run_x25519_kat(const FaultInjector& fault_injector = {});
    [[nodiscard]] static CryptoSelfTestCheckResult run_aes_256_gcm_kat(const FaultInjector& fault_injector = {});
    [[nodiscard]] static CryptoSelfTestCheckResult run_hkdf_sha256_kat(const FaultInjector& fault_injector = {});
    [[nodiscard]] static CryptoSelfTestCheckResult run_csprng_health_check(const FaultInjector& fault_injector = {});
    [[nodiscard]] static CryptoSelfTestCheckResult
    run_secure_storage_canary(application::interfaces::ISecureStorage* secure_storage,
                              const FaultInjector& fault_injector = {});
};

} // namespace securecloud::client::domain::crypto
