#pragma once

#include "application/client_application.hpp"
#include "domain/crypto/crypto_self_test.hpp"
#include "ui/navigation_controller.hpp"

#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>
#include <QtGlobal>
#include <optional>

namespace securecloud::client::ui {

/// Presentation ViewModel exposing live telemetry, OpenSSL crypto self-test diagnostics,
/// hash-chained audit verification, and AES-256-GCM .scdiag export to DiagnosticsView.qml.
class DiagnosticsViewModel : public QObject {
    Q_OBJECT

    // Live Telemetry Properties
    Q_PROPERTY(double rssMegabytes READ rssMegabytes NOTIFY telemetryChanged)
    Q_PROPERTY(double cpuPercent READ cpuPercent NOTIFY telemetryChanged)
    Q_PROPERTY(int activeRatchetSessions READ activeRatchetSessions NOTIFY telemetryChanged)
    Q_PROPERTY(int pendingOutboxCount READ pendingOutboxCount NOTIFY telemetryChanged)
    Q_PROPERTY(int pendingRetryCount READ pendingRetryCount NOTIFY telemetryChanged)
    Q_PROPERTY(int activeFileTransfers READ activeFileTransfers NOTIFY telemetryChanged)
    Q_PROPERTY(QString connectivityState READ connectivityState NOTIFY telemetryChanged)
    Q_PROPERTY(qint64 gatewayRttMs READ gatewayRttMs NOTIFY telemetryChanged)
    Q_PROPERTY(qint64 gatewayAvgRttMs READ gatewayAvgRttMs NOTIFY telemetryChanged)
    Q_PROPERTY(quint64 gatewayRequestsTotal READ gatewayRequestsTotal NOTIFY telemetryChanged)
    Q_PROPERTY(quint64 gatewayRequestsFailed READ gatewayRequestsFailed NOTIFY telemetryChanged)
    Q_PROPERTY(QString gatewayTransportMode READ gatewayTransportMode NOTIFY telemetryChanged)
    Q_PROPERTY(QString lastSampledAtText READ lastSampledAtText NOTIFY telemetryChanged)

    // Boot / Manual Crypto Self-Test Properties
    Q_PROPERTY(bool selfTestPassed READ selfTestPassed NOTIFY selfTestChanged)
    Q_PROPERTY(QString selfTestSummary READ selfTestSummary NOTIFY selfTestChanged)
    Q_PROPERTY(QString selfTestBackend READ selfTestBackend NOTIFY selfTestChanged)
    Q_PROPERTY(QVariantList selfTestChecks READ selfTestChecks NOTIFY selfTestChanged)

    // Hash-Chained Local Audit Trail Properties
    Q_PROPERTY(bool auditChainValid READ auditChainValid NOTIFY auditChanged)
    Q_PROPERTY(int auditEventCount READ auditEventCount NOTIFY auditChanged)
    Q_PROPERTY(QString auditIntegrityStatusText READ auditIntegrityStatusText NOTIFY auditChanged)
    Q_PROPERTY(QVariantList auditEvents READ auditEvents NOTIFY auditChanged)

    // Encrypted .scdiag Exporter State Properties (never exposes keys/passphrases)
    Q_PROPERTY(QString lastExportStatusText READ lastExportStatusText NOTIFY exportStateChanged)
    Q_PROPERTY(QString lastExportPath READ lastExportPath NOTIFY exportStateChanged)
    Q_PROPERTY(QString lastExportSha256 READ lastExportSha256 NOTIFY exportStateChanged)
    Q_PROPERTY(bool lastExportSucceeded READ lastExportSucceeded NOTIFY exportStateChanged)

    // Visibility-gated Polling Status
    Q_PROPERTY(bool autoRefreshActive READ autoRefreshActive NOTIFY autoRefreshActiveChanged)

  public:
    static constexpr int kAutoRefreshIntervalMs = 2000;

    DiagnosticsViewModel(application::ClientApplication& app, NavigationController& nav_controller,
                         QObject* parent = nullptr);
    ~DiagnosticsViewModel() override = default;

    DiagnosticsViewModel(const DiagnosticsViewModel&) = delete;
    DiagnosticsViewModel& operator=(const DiagnosticsViewModel&) = delete;

    // Telemetry Getters
    [[nodiscard]] double rssMegabytes() const noexcept { return rss_megabytes_; }
    [[nodiscard]] double cpuPercent() const noexcept { return cpu_percent_; }
    [[nodiscard]] int activeRatchetSessions() const noexcept { return active_ratchet_sessions_; }
    [[nodiscard]] int pendingOutboxCount() const noexcept { return pending_outbox_count_; }
    [[nodiscard]] int pendingRetryCount() const noexcept { return pending_retry_count_; }
    [[nodiscard]] int activeFileTransfers() const noexcept { return active_file_transfers_; }
    [[nodiscard]] QString connectivityState() const { return connectivity_state_; }
    [[nodiscard]] qint64 gatewayRttMs() const noexcept { return gateway_rtt_ms_; }
    [[nodiscard]] qint64 gatewayAvgRttMs() const noexcept { return gateway_avg_rtt_ms_; }
    [[nodiscard]] quint64 gatewayRequestsTotal() const noexcept { return gateway_requests_total_; }
    [[nodiscard]] quint64 gatewayRequestsFailed() const noexcept { return gateway_requests_failed_; }
    [[nodiscard]] QString gatewayTransportMode() const { return gateway_transport_mode_; }
    [[nodiscard]] QString lastSampledAtText() const { return last_sampled_at_text_; }

    // Crypto Self-Test Getters
    [[nodiscard]] bool selfTestPassed() const noexcept { return self_test_passed_; }
    [[nodiscard]] QString selfTestSummary() const { return self_test_summary_; }
    [[nodiscard]] QString selfTestBackend() const { return self_test_backend_; }
    [[nodiscard]] QVariantList selfTestChecks() const { return self_test_checks_; }

    // Audit Trail Getters
    [[nodiscard]] bool auditChainValid() const noexcept { return audit_chain_valid_; }
    [[nodiscard]] int auditEventCount() const noexcept { return audit_event_count_; }
    [[nodiscard]] QString auditIntegrityStatusText() const { return audit_integrity_status_text_; }
    [[nodiscard]] QVariantList auditEvents() const { return audit_events_; }

    // Exporter Getters
    [[nodiscard]] QString lastExportStatusText() const { return last_export_status_text_; }
    [[nodiscard]] QString lastExportPath() const { return last_export_path_; }
    [[nodiscard]] QString lastExportSha256() const { return last_export_sha256_; }
    [[nodiscard]] bool lastExportSucceeded() const noexcept { return last_export_succeeded_; }

    // Polling Getters
    [[nodiscard]] bool autoRefreshActive() const noexcept { return refresh_timer_.isActive(); }

    // Actions
    Q_INVOKABLE void refreshDiagnostics();
    Q_INVOKABLE void refreshTelemetry();
    Q_INVOKABLE bool runCryptoSelfTestNow();
    Q_INVOKABLE bool verifyAuditChainNow();
    Q_INVOKABLE bool exportSanitizedBundle(const QString& destinationPath, const QString& passphrase = QString());
    Q_INVOKABLE void setAutoRefreshEnabled(bool enabled);
    Q_INVOKABLE void resetForEmergencyWipe();

  signals:
    void telemetryChanged();
    void selfTestChanged();
    void auditChanged();
    void exportStateChanged();
    void autoRefreshActiveChanged();
    void operationError(const QString& message);

  private:
    void syncSelfTestFromReport(const std::optional<domain::crypto::CryptoSelfTestReport>& report_opt);
    [[nodiscard]] std::vector<std::string> collectSensitiveLiterals() const;

    application::ClientApplication& app_;
    NavigationController& nav_controller_;
    QTimer refresh_timer_;

    double rss_megabytes_{0.0};
    double cpu_percent_{0.0};
    int active_ratchet_sessions_{0};
    int pending_outbox_count_{0};
    int pending_retry_count_{0};
    int active_file_transfers_{0};
    QString connectivity_state_{QStringLiteral("Online")};
    qint64 gateway_rtt_ms_{0};
    qint64 gateway_avg_rtt_ms_{0};
    quint64 gateway_requests_total_{0};
    quint64 gateway_requests_failed_{0};
    QString gateway_transport_mode_{QStringLiteral("Simulated")};
    QString last_sampled_at_text_{QStringLiteral("—")};

    bool self_test_passed_{false};
    QString self_test_summary_{QStringLiteral("Not executed")};
    QString self_test_backend_{QStringLiteral("OpenSSL")};
    QVariantList self_test_checks_;

    bool audit_chain_valid_{true};
    int audit_event_count_{0};
    QString audit_integrity_status_text_{QStringLiteral("Pending verification")};
    QVariantList audit_events_;

    QString last_export_status_text_;
    QString last_export_path_;
    QString last_export_sha256_;
    bool last_export_succeeded_{false};
};

} // namespace securecloud::client::ui
