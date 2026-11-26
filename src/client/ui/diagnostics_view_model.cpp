#include "ui/diagnostics_view_model.hpp"

#include "application/managers/diagnostic_sanitizer.hpp"
#include "application/managers/diagnostics_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/settings_manager.hpp"
#include "domain/diagnostics_models.hpp"
#include "domain/local_audit_event.hpp"
#include "domain/offline_sync_models.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <QDateTime>
#include <QVariantMap>
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <sstream>

namespace securecloud::client::ui {
namespace {

constexpr std::size_t kMaxUiAuditEvents = 50U;

[[nodiscard]] int clampToInt(std::size_t value) noexcept {
    constexpr std::size_t kMaxInt = static_cast<std::size_t>(std::numeric_limits<int>::max());
    return static_cast<int>(std::min(value, kMaxInt));
}

[[nodiscard]] QString toQString(std::string_view text) {
    return QString::fromUtf8(text.data(), static_cast<qsizetype>(text.size()));
}

[[nodiscard]] QString scrubToQString(std::string_view raw, const std::vector<std::string>& sensitive_literals) {
    const std::string scrubbed = application::managers::DiagnosticSanitizer::scrub_text(raw, sensitive_literals);
    if (application::managers::DiagnosticSanitizer::contains_unredacted_secret_marker(scrubbed)) {
        return QStringLiteral("[REDACTED_SECRET_MARKER]");
    }
    return toQString(scrubbed);
}

[[nodiscard]] QString formatTimestampMs(int64_t unix_ms) {
    if (unix_ms <= 0) {
        return QStringLiteral("—");
    }
    return QDateTime::fromMSecsSinceEpoch(unix_ms).toUTC().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss 'UTC'"));
}

[[nodiscard]] QString connectivityLabel(domain::ConnectivityState state) {
    switch (state) {
    case domain::ConnectivityState::Online:
        return QStringLiteral("Online");
    case domain::ConnectivityState::Offline:
        return QStringLiteral("Offline");
    case domain::ConnectivityState::Syncing:
        return QStringLiteral("Syncing");
    }
    return QStringLiteral("Online");
}

} // namespace

DiagnosticsViewModel::DiagnosticsViewModel(application::ClientApplication& app, NavigationController& nav_controller,
                                           QObject* parent)
    : QObject(parent), app_(app), nav_controller_(nav_controller) {
    refresh_timer_.setInterval(kAutoRefreshIntervalMs);
    refresh_timer_.setSingleShot(false);
    connect(&refresh_timer_, &QTimer::timeout, this, &DiagnosticsViewModel::refreshTelemetry);

    connect(&nav_controller_, &NavigationController::stateChanged, this,
            [this](NavigationController::NavigationState newState) {
                const bool on_diagnostics = (newState == NavigationController::NavigationState::Diagnostics) &&
                                            nav_controller_.isAuthenticated();
                if (on_diagnostics) {
                    refreshDiagnostics();
                    setAutoRefreshEnabled(true);
                } else {
                    setAutoRefreshEnabled(false);
                }
            });

    connect(&nav_controller_, &NavigationController::authenticationChanged, this, [this](bool authenticated) {
        if (!authenticated) {
            setAutoRefreshEnabled(false);
        }
    });

    refreshDiagnostics();
}

void DiagnosticsViewModel::refreshDiagnostics() {
    refreshTelemetry();
    syncSelfTestFromReport(app_.last_self_test_report());
    (void)verifyAuditChainNow();
}

void DiagnosticsViewModel::refreshTelemetry() {
    const domain::TelemetrySnapshot snap = app_.bootstrap().diagnostics_manager().collect_telemetry();
    rss_megabytes_ = std::round(snap.rss_megabytes * 100.0) / 100.0;
    cpu_percent_ = std::round(snap.cpu_percent * 100.0) / 100.0;
    active_ratchet_sessions_ = clampToInt(snap.active_ratchet_sessions);
    pending_outbox_count_ = clampToInt(snap.pending_outbox_count);
    pending_retry_count_ = clampToInt(snap.pending_retry_count);
    active_file_transfers_ = clampToInt(snap.active_file_transfers);
    connectivity_state_ = connectivityLabel(snap.connectivity_state);
    gateway_rtt_ms_ = static_cast<qint64>(snap.last_gateway_rtt_ms);
    gateway_avg_rtt_ms_ = static_cast<qint64>(snap.avg_gateway_rtt_ms);
    gateway_requests_total_ = static_cast<quint64>(snap.gateway_requests_total);
    gateway_requests_failed_ = static_cast<quint64>(snap.gateway_requests_failed);
    gateway_transport_mode_ =
        snap.live_gateway_transport ? QStringLiteral("Live TLS 1.3 Gateway") : QStringLiteral("Simulated Offline");
    last_sampled_at_text_ = formatTimestampMs(snap.sampled_at_ms);
    emit telemetryChanged();
}

bool DiagnosticsViewModel::runCryptoSelfTestNow() {
    auto& bootstrap = app_.bootstrap();
    const auto report =
        domain::crypto::CryptoSelfTest::run_all(&bootstrap.secure_storage(), bootstrap.self_test_fault_injector());
    bootstrap.set_last_self_test_report(report);

    if (auto* audit = bootstrap.local_audit_logger(); audit != nullptr) {
        std::ostringstream msg;
        msg << std::fixed << std::setprecision(2) << "Manual OpenSSL self-test "
            << (report.overall_passed ? "passed" : "failed") << " (" << report.checks.size() << " checks in "
            << (static_cast<double>(report.total_duration_us) / 1000.0) << " ms)";
        (void)audit->record_event(domain::LocalAuditCategory::CryptoSelfTest, "crypto.self_test.manual",
                                  report.overall_passed ? domain::LocalAuditOutcome::Success
                                                        : domain::LocalAuditOutcome::Failure,
                                  "ui", "crypto_self_test", msg.str());
    }

    syncSelfTestFromReport(report);
    (void)verifyAuditChainNow();
    return report.overall_passed;
}

bool DiagnosticsViewModel::verifyAuditChainNow() {
    const auto literals = collectSensitiveLiterals();
    auto* audit = app_.bootstrap().local_audit_logger();
    if (audit == nullptr) {
        audit_chain_valid_ = false;
        audit_event_count_ = 0;
        audit_integrity_status_text_ = QStringLiteral("Local audit trail unavailable");
        audit_events_.clear();
        emit auditChanged();
        return false;
    }

    const auto verify_res = audit->verify_chain_integrity();
    const auto count_res = audit->event_count();
    const auto recent_res = audit->recent_events(kMaxUiAuditEvents);

    if (verify_res.is_ok()) {
        const auto& v = verify_res.value();
        audit_chain_valid_ = v.valid;
        const std::size_t count = count_res.is_ok() ? count_res.value() : v.verified_count;
        audit_event_count_ = clampToInt(count);

        if (v.valid) {
            const QString head_prefix = toQString(v.latest_hash_sha256).left(12);
            audit_integrity_status_text_ =
                QStringLiteral("Verified (%1 entries · Head %2...)").arg(v.verified_count).arg(head_prefix);
        } else {
            const QString reason = scrubToQString(v.failure_reason, literals);
            audit_integrity_status_text_ = QStringLiteral("Integrity Alert: %1").arg(reason);
        }
    } else {
        audit_chain_valid_ = false;
        audit_integrity_status_text_ =
            QStringLiteral("Verification error: %1").arg(scrubToQString(verify_res.error().user_message(), literals));
    }

    audit_events_.clear();
    if (recent_res.is_ok()) {
        audit_events_.reserve(clampToInt(recent_res.value().size()));
        for (const auto& ev : recent_res.value()) {
            QVariantMap row;
            row.insert(QStringLiteral("sequenceId"), static_cast<qint64>(ev.sequence_id));
            row.insert(QStringLiteral("occurredAtText"), formatTimestampMs(ev.occurred_at_ms));
            row.insert(QStringLiteral("category"), toQString(domain::to_string(ev.category)));
            row.insert(QStringLiteral("eventType"), scrubToQString(ev.event_type, literals));
            row.insert(QStringLiteral("outcome"), toQString(domain::to_string(ev.outcome)));
            row.insert(QStringLiteral("summary"), scrubToQString(ev.sanitized_summary, literals));
            row.insert(QStringLiteral("entryHashPrefix"), toQString(ev.entry_hash_sha256).left(16));
            audit_events_.append(std::move(row));
        }
    }

    emit auditChanged();
    return audit_chain_valid_;
}

bool DiagnosticsViewModel::exportSanitizedBundle(const QString& destinationPath, const QString& passphrase) {
    const QString trimmed_path = destinationPath.trimmed();
    const auto literals = collectSensitiveLiterals();

    if (trimmed_path.isEmpty()) {
        last_export_succeeded_ = false;
        last_export_path_.clear();
        last_export_sha256_.clear();
        last_export_status_text_ = QStringLiteral("Export failed: destination file path is required.");
        emit exportStateChanged();
        emit operationError(last_export_status_text_);
        return false;
    }

    std::optional<common::configuration::SecretString> passphrase_opt;
    std::vector<std::string> extra_literals = literals;
    if (!passphrase.isEmpty()) {
        std::string raw_pass = passphrase.toStdString();
        extra_literals.push_back(raw_pass);
        passphrase_opt = common::configuration::SecretString(std::move(raw_pass));
    }

    const QByteArray utf8_path = trimmed_path.toUtf8();
    const std::filesystem::path fs_path(
        std::string_view(utf8_path.constData(), static_cast<std::size_t>(utf8_path.size())));

    const auto export_res = app_.bootstrap().diagnostics_manager().export_encrypted_bundle(
        fs_path, std::move(passphrase_opt), application::managers::DiagnosticsManager::kDefaultMaxAuditEvents,
        extra_literals);

    if (export_res.is_error()) {
        last_export_succeeded_ = false;
        last_export_path_.clear();
        last_export_sha256_.clear();
        last_export_status_text_ =
            QStringLiteral("Export failed: %1").arg(scrubToQString(export_res.error().user_message(), extra_literals));
        emit exportStateChanged();
        emit operationError(last_export_status_text_);
        return false;
    }

    const auto& info = export_res.value();
    last_export_succeeded_ = true;
    last_export_path_ = toQString(info.output_path);
    last_export_sha256_ = toQString(info.bundle_sha256_hex);

    const QString mode_label = info.used_passphrase ? QStringLiteral("passphrase-protected AES-256-GCM")
                                                    : QStringLiteral("CSPRNG 256-bit key");
    last_export_status_text_ = QStringLiteral("Exported %1 B encrypted .scdiag (%2) · SHA-256: %3...")
                                   .arg(static_cast<qulonglong>(info.encrypted_bytes))
                                   .arg(mode_label)
                                   .arg(last_export_sha256_.left(16));

    emit exportStateChanged();
    (void)verifyAuditChainNow();
    return true;
}

void DiagnosticsViewModel::setAutoRefreshEnabled(bool enabled) {
    const bool was_active = refresh_timer_.isActive();
    if (enabled && !was_active) {
        refresh_timer_.start();
        emit autoRefreshActiveChanged();
    } else if (!enabled && was_active) {
        refresh_timer_.stop();
        emit autoRefreshActiveChanged();
    }
}

void DiagnosticsViewModel::resetForEmergencyWipe() {
    setAutoRefreshEnabled(false);

    audit_chain_valid_ = true;
    audit_event_count_ = 0;
    audit_integrity_status_text_ = QStringLiteral("Cleared");
    audit_events_.clear();
    emit auditChanged();

    last_export_succeeded_ = false;
    last_export_path_.clear();
    last_export_sha256_.clear();
    last_export_status_text_.clear();
    emit exportStateChanged();
}

void DiagnosticsViewModel::syncSelfTestFromReport(
    const std::optional<domain::crypto::CryptoSelfTestReport>& report_opt) {
    const auto literals = collectSensitiveLiterals();
    self_test_checks_.clear();

    if (!report_opt.has_value()) {
        self_test_passed_ = false;
        self_test_backend_ = QStringLiteral("OpenSSL");
        self_test_summary_ = QStringLiteral("Boot self-test report unavailable");
        emit selfTestChanged();
        return;
    }

    const auto& report = *report_opt;
    self_test_passed_ = report.overall_passed;
    self_test_backend_ = scrubToQString(report.crypto_backend, literals);

    const double total_ms = static_cast<double>(report.total_duration_us) / 1000.0;
    if (report.overall_passed) {
        self_test_summary_ = QStringLiteral("All %1 OpenSSL KAT & CSPRNG checks passed (%2 ms)")
                                 .arg(report.checks.size())
                                 .arg(total_ms, 0, 'f', 2);
    } else {
        const QString failed_list = scrubToQString(report.failed_checks_summary(), literals);
        self_test_summary_ = QStringLiteral("Self-test failed: %1").arg(failed_list);
    }

    self_test_checks_.reserve(clampToInt(report.checks.size()));
    for (const auto& check : report.checks) {
        QVariantMap item;
        item.insert(QStringLiteral("checkName"), scrubToQString(check.check_name, literals));
        item.insert(QStringLiteral("passed"), check.passed);
        item.insert(QStringLiteral("durationUs"), static_cast<qint64>(check.duration_us));
        item.insert(QStringLiteral("detail"), scrubToQString(check.detail, literals));
        self_test_checks_.append(std::move(item));
    }

    emit selfTestChanged();
}

std::vector<std::string> DiagnosticsViewModel::collectSensitiveLiterals() const {
    std::vector<std::string> literals;
    const auto& cfg = app_.bootstrap().config();
    if (!cfg.proxy_username.empty()) {
        literals.push_back(cfg.proxy_username);
    }
    const auto profile_opt = app_.bootstrap().settings_manager().cached_profile();
    if (profile_opt.has_value()) {
        if (!profile_opt->display_name.empty()) {
            literals.push_back(profile_opt->display_name);
        }
        if (!profile_opt->public_handle.empty()) {
            literals.push_back(profile_opt->public_handle);
        }
        if (!profile_opt->bio_status.empty()) {
            literals.push_back(profile_opt->bio_status);
        }
    }
    return literals;
}

} // namespace securecloud::client::ui
