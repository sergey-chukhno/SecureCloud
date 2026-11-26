#pragma once

#include "application/client_config.hpp"
#include "application/client_error.hpp"
#include "domain/crypto/crypto_self_test.hpp"
#include "domain/diagnostics_models.hpp"
#include "infrastructure/adapters/platform_telemetry_collector.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::client::application::managers {

class FileManager;
class LocalAuditLogger;
class MessagingManager;
class RatchetSessionManager;
class SettingsManager;
class SyncManager;

/// Aggregates cross-platform OS resource telemetry, live manager/transport metrics, and exports
/// sanitized, OpenSSL AES-256-GCM encrypted `.scdiag` support bundles with zero secret/PII leakage.
class DiagnosticsManager {
  public:
    static constexpr std::size_t kDefaultMaxAuditEvents = 100U;
    static constexpr std::size_t kMaxBundleAuditEvents = 500U;
    static constexpr std::size_t kMaxDecryptBundleBytes = 16U * 1024U * 1024U;
    static constexpr uint32_t kBundlePbkdf2Iterations = 100000U;

    using SelfTestReportProvider = std::function<std::optional<domain::crypto::CryptoSelfTestReport>()>;
    using TransportMetricsProvider = std::function<domain::GatewayTransportMetrics()>;
    using LiveTransportProvider = std::function<bool()>;

    DiagnosticsManager(const ClientConfig& config, LocalAuditLogger* audit_logger, MessagingManager* messaging_manager,
                       FileManager* file_manager, SyncManager* sync_manager, SettingsManager* settings_manager,
                       RatchetSessionManager* ratchet_session_manager = nullptr,
                       SelfTestReportProvider self_test_provider = {},
                       TransportMetricsProvider transport_metrics_provider = {},
                       LiveTransportProvider live_transport_provider = {});
    ~DiagnosticsManager() = default;

    DiagnosticsManager(const DiagnosticsManager&) = delete;
    DiagnosticsManager& operator=(const DiagnosticsManager&) = delete;

    void set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept;

    [[nodiscard]] domain::TelemetrySnapshot collect_telemetry();

    [[nodiscard]] ClientResult<domain::DiagnosticBundleExportResult>
    export_encrypted_bundle(const std::filesystem::path& output_path,
                            std::optional<common::configuration::SecretString> passphrase = std::nullopt,
                            std::size_t max_audit_events = kDefaultMaxAuditEvents,
                            const std::vector<std::string>& extra_sensitive_literals = {});

    [[nodiscard]] static ClientResult<std::string>
    decrypt_and_verify_bundle(const std::filesystem::path& bundle_path,
                              const common::configuration::SecretString& key_or_passphrase);

  private:
    const ClientConfig& config_;
    LocalAuditLogger* audit_logger_{nullptr};
    MessagingManager* messaging_manager_{nullptr};
    FileManager* file_manager_{nullptr};
    SyncManager* sync_manager_{nullptr};
    SettingsManager* settings_manager_{nullptr};
    RatchetSessionManager* ratchet_session_manager_{nullptr};
    SelfTestReportProvider self_test_provider_{};
    TransportMetricsProvider transport_metrics_provider_{};
    LiveTransportProvider live_transport_provider_{};
    mutable std::mutex mutex_;
    infrastructure::adapters::PlatformTelemetryCollector telemetry_collector_{};
};

} // namespace securecloud::client::application::managers
