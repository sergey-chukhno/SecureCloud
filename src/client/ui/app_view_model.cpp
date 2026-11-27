#include "ui/app_view_model.hpp"

#include "application/client_error.hpp"
#include "domain/emergency_models.hpp"
#include "domain/offline_sync_models.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "ui/workspace_view_model.hpp"

#include <QMetaObject>
#include <QPointer>

namespace securecloud::client::ui {
namespace {

domain::PostWipeMode postWipeModeFromInt(int value) noexcept {
    switch (value) {
    case 1:
        return domain::PostWipeMode::UnconfiguredReset;
    case 2:
        return domain::PostWipeMode::DecoyWorkspace;
    case 0:
    default:
        return domain::PostWipeMode::EmergencyLocked;
    }
}

int intFromPostWipeMode(domain::PostWipeMode mode) noexcept {
    switch (mode) {
    case domain::PostWipeMode::EmergencyLocked:
        return 0;
    case domain::PostWipeMode::UnconfiguredReset:
        return 1;
    case domain::PostWipeMode::DecoyWorkspace:
        return 2;
    }
    return 0;
}

} // namespace

AppViewModel::AppViewModel(application::ClientApplication& app, NavigationController& nav_controller, QObject* parent)
    : QObject(parent), app_(app), nav_controller_(nav_controller) {
    QPointer<AppViewModel> self(this);
    connectivity_sub_id_ =
        app_.bootstrap().sync_manager().subscribe_connectivity_state([self](domain::ConnectivityState state) {
            if (!self) {
                return;
            }
            QMetaObject::invokeMethod(
                self.data(),
                [self, state]() {
                    if (!self) {
                        return;
                    }
                    if (!self->isEmergencyWiped()) {
                        switch (state) {
                        case domain::ConnectivityState::Online:
                            self->connectionStatus_ = QStringLiteral("Connected");
                            break;
                        case domain::ConnectivityState::Offline:
                            self->connectionStatus_ = QStringLiteral("Offline");
                            break;
                        case domain::ConnectivityState::Syncing:
                            self->connectionStatus_ = QStringLiteral("Syncing");
                            break;
                        }
                    }
                    emit self->connectionStatusChanged();
                },
                Qt::AutoConnection);
        });
}

AppViewModel::~AppViewModel() {
    if (connectivity_sub_id_ != 0) {
        app_.bootstrap().sync_manager().unsubscribe_connectivity_state(connectivity_sub_id_);
        connectivity_sub_id_ = 0;
    }
}

void AppViewModel::setWorkspaceViewModel(WorkspaceViewModel* workspace_vm) {
    workspace_vm_ = workspace_vm;
    if (workspace_vm_ != nullptr) {
        connect(workspace_vm_, &QObject::destroyed, this, [this]() { workspace_vm_ = nullptr; });
    }
}

QString AppViewModel::connectionStatus() const {
    if (isDecoySession()) {
        return QStringLiteral("Connected");
    }
    if (isEmergencyWiped()) {
        return QStringLiteral("Offline (Wiped)");
    }
    switch (app_.bootstrap().sync_manager().connectivity_state()) {
    case domain::ConnectivityState::Offline:
        return QStringLiteral("Offline");
    case domain::ConnectivityState::Syncing:
        return QStringLiteral("Syncing");
    case domain::ConnectivityState::Online:
        return connectionStatus_;
    }
    return connectionStatus_;
}

QString AppViewModel::connectivityState() const {
    const auto sv = domain::to_string(app_.bootstrap().sync_manager().connectivity_state());
    return QString::fromUtf8(sv.data(), static_cast<qsizetype>(sv.size()));
}

QString AppViewModel::sessionStatusText() const {
    if (isDecoySession()) {
        return QStringLiteral("Authenticated Session (%1)").arg(currentUser());
    }
    if (isEmergencyWiped()) {
        return QStringLiteral("Emergency Wipe Active — Local State Zeroized");
    }
    if (!isAuthenticated()) {
        return QStringLiteral("Unauthenticated — Awaiting Credentials");
    }
    const auto state = app_.bootstrap().sync_manager().connectivity_state();
    if (state == domain::ConnectivityState::Offline) {
        return QStringLiteral("Offline Mode — Authenticated Session (%1)").arg(currentUser());
    }
    if (state == domain::ConnectivityState::Syncing) {
        return QStringLiteral("Catch-Up Sync Active — (%1)").arg(currentUser());
    }
    return QStringLiteral("Authenticated Session (%1)").arg(currentUser());
}

QString AppViewModel::securityStatusText() const {
    if (isDecoySession()) {
        return QStringLiteral("Authenticated Session · Identity Unverified");
    }
    if (isEmergencyWiped()) {
        return QStringLiteral("Local Secrets Zeroized");
    }
    if (!isAuthenticated()) {
        return QStringLiteral("TLS 1.3 Gateway Ready · No Active Session");
    }
    if (is_identity_verified_) {
        return QStringLiteral("Authenticated Session · Identity Verified");
    }
    return QStringLiteral("Authenticated Session · Identity Unverified");
}

QString AppViewModel::securityBadgeType() const {
    if (isDecoySession()) {
        return QStringLiteral("Info");
    }
    if (isEmergencyWiped()) {
        return QStringLiteral("Danger");
    }
    if (!isAuthenticated()) {
        return QStringLiteral("Offline");
    }
    if (is_identity_verified_) {
        return QStringLiteral("Verified");
    }
    return QStringLiteral("Info");
}

void AppViewModel::setIdentityVerified(bool verified) {
    if (is_identity_verified_ == verified) {
        return;
    }
    is_identity_verified_ = verified;
    emit connectionStatusChanged();
}

QString AppViewModel::currentUser() const {
    const auto& user = app_.bootstrap().auth_manager().current_user();
    return QString::fromStdString(user.value());
}

bool AppViewModel::isAuthenticated() const {
    return app_.bootstrap().auth_manager().is_authenticated();
}

bool AppViewModel::isRunning() const {
    return app_.is_running();
}

bool AppViewModel::isEmergencyWiped() const {
    return app_.bootstrap().emergency_manager().is_wiped();
}

bool AppViewModel::isDecoySession() const {
    return app_.bootstrap().auth_manager().is_decoy_session();
}

bool AppViewModel::hasDuressPinConfigured() const {
    return app_.bootstrap().emergency_manager().has_duress_pin();
}

int AppViewModel::configuredDuressPostWipeMode() const {
    const auto mode = app_.bootstrap().emergency_manager().duress_post_wipe_mode();
    if (!mode.has_value()) {
        return 2; // DecoyWorkspace default
    }
    return intFromPostWipeMode(*mode);
}

QVariantMap AppViewModel::lastWipeReportSummary() const {
    // OPSEC: Never expose forensic wipe telemetry inside a Decoy Workspace session.
    if (isDecoySession()) {
        return QVariantMap{};
    }

    const auto report_opt = app_.bootstrap().emergency_manager().last_wipe_report();
    if (!report_opt.has_value()) {
        return QVariantMap{{QStringLiteral("hasReport"), false}};
    }

    const auto& r = *report_opt;
    const auto src_sv = domain::to_string(r.trigger_source);
    const auto mode_sv = domain::to_string(r.post_wipe_mode);

    QVariantList step_list;
    step_list.reserve(static_cast<qsizetype>(r.step_results.size()));
    for (const auto& step : r.step_results) {
        const auto status_sv = domain::to_string(step.status);
        QVariantMap step_map;
        step_map.insert(QStringLiteral("category"), QString::fromStdString(step.artifact_category));
        step_map.insert(QStringLiteral("itemsProcessed"), static_cast<qulonglong>(step.items_processed));
        step_map.insert(QStringLiteral("status"),
                        QString::fromUtf8(status_sv.data(), static_cast<qsizetype>(status_sv.size())));
        step_map.insert(QStringLiteral("detail"), QString::fromStdString(step.detail));
        step_list.push_back(step_map);
    }

    QVariantMap summary;
    summary.insert(QStringLiteral("hasReport"), true);
    summary.insert(QStringLiteral("triggerSource"),
                   QString::fromUtf8(src_sv.data(), static_cast<qsizetype>(src_sv.size())));
    summary.insert(QStringLiteral("postWipeMode"),
                   QString::fromUtf8(mode_sv.data(), static_cast<qsizetype>(mode_sv.size())));
    summary.insert(QStringLiteral("broadcastAttempted"), r.broadcast_attempted);
    summary.insert(QStringLiteral("broadcastAcknowledged"), r.broadcast_acknowledged);
    summary.insert(QStringLiteral("secretsPurgedCount"), static_cast<qulonglong>(r.secrets_purged_count));
    summary.insert(QStringLiteral("filesShreddedCount"), static_cast<qulonglong>(r.files_shredded_count));
    summary.insert(QStringLiteral("volatileCachesCleared"), static_cast<qulonglong>(r.volatile_caches_cleared));
    summary.insert(QStringLiteral("durationMs"), static_cast<qlonglong>(r.duration_ms));
    summary.insert(QStringLiteral("allCriticalStepsSucceeded"), r.all_critical_steps_succeeded);
    summary.insert(QStringLiteral("stepResults"), step_list);
    return summary;
}

void AppViewModel::setError(const QString& category, const QString& message) {
    last_error_category_ = category;
    last_error_message_ = message;
    emit errorStateChanged();
    if (!message.isEmpty()) {
        emit operationError(message);
    }
}

void AppViewModel::clearError() {
    if (last_error_message_.isEmpty() && last_error_category_.isEmpty()) {
        return;
    }
    last_error_category_.clear();
    last_error_message_.clear();
    emit errorStateChanged();
}

void AppViewModel::requestLogin(const QString& username, const QString& password) {
    clearError();
    is_authenticating_ = true;
    emit authenticatingChanged();

    // Pass password raw bytes untouched (no trimming) so Duress PIN & PasswordCredential formats match identically.
    const auto auth_res = app_.bootstrap().auth_manager().authenticate_with_duress_check(
        username.trimmed().toStdString(), password.toStdString());

    is_authenticating_ = false;
    emit authenticatingChanged();

    if (auth_res.is_error()) {
        const auto& err = auth_res.error();
        const QString category =
            QString::fromUtf8(application::to_string(err.category()).data(),
                              static_cast<qsizetype>(application::to_string(err.category()).size()));
        setError(category, QString::fromStdString(err.user_message()));
        return;
    }

    pending_username_.clear();
    pending_password_.clear();

    const auto& login = auth_res.value();
    if (login.outcome == application::managers::AuthOutcome::DuressWipeTriggered) {
        is_identity_verified_ = false;
        if (login.is_decoy_session) {
            if (workspace_vm_ != nullptr) {
                workspace_vm_->enterDecoyWorkspace();
            }
            connectionStatus_ = QStringLiteral("Connected");
            nav_controller_.setAuthenticated(true);
            nav_controller_.reset(NavigationController::NavigationState::MainWorkspace);
        } else {
            if (workspace_vm_ != nullptr) {
                workspace_vm_->resetForEmergencyWipe();
            }
            connectionStatus_ = QStringLiteral("Offline (Wiped)");
            nav_controller_.setAuthenticated(false);
            nav_controller_.reset(login.post_wipe_mode == domain::PostWipeMode::EmergencyLocked
                                      ? NavigationController::NavigationState::EmergencyMode
                                      : NavigationController::NavigationState::Unauthenticated);
        }
        emit emergencyWipedChanged();
        emit duressPolicyChanged();
        emit currentUserChanged();
        emit connectionStatusChanged();
        return;
    }

    if (app_.bootstrap().emergency_manager().is_wiped()) {
        app_.bootstrap().emergency_manager().reset_wiped_state();
        app_.bootstrap().device_manager().clear_local_device();
        const std::string db_path = app_.bootstrap().config().database_path;
        const auto open_res = app_.bootstrap().local_store().open(db_path.empty() ? ":memory:" : db_path);
        if (open_res.is_error()) {
            setError(QStringLiteral("Storage"), QString::fromStdString(open_res.error().user_message()));
        }
        emit emergencyWipedChanged();
    }

    if (app_.bootstrap().is_live_gateway_transport_active() && !login.mfa_required) {
        const auto dev_res = app_.bootstrap().device_manager().initialize_or_load_device(
            app_.bootstrap().auth_manager().current_user(), "Desktop Workstation");
        if (dev_res.is_ok()) {
            app_.bootstrap().initialize_ratchet_session_manager(app_.bootstrap().auth_manager().current_user(),
                                                                dev_res.value().device_id());
        }
    }

    connectionStatus_ = QStringLiteral("Connected");
    nav_controller_.setAuthenticated(true);
    nav_controller_.reset(NavigationController::NavigationState::MainWorkspace);
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::beginMfaChallenge(const QString& username, const QString& password) {
    clearError();
    if (username.trimmed().isEmpty() || password.isEmpty()) {
        setError(QStringLiteral("Validation"), QStringLiteral("Username and password cannot be empty"));
        return;
    }

    // Intercept duress PIN immediately even when MFA flow button was clicked.
    const auto duress_match = app_.bootstrap().emergency_manager().verify_duress_credential(
        common::configuration::SecretString(password.toStdString()));
    if (duress_match.is_ok() && duress_match.value()) {
        requestLogin(username, password);
        return;
    }

    pending_username_ = username.trimmed();
    pending_password_ = password;
    (void)nav_controller_.navigateTo(NavigationController::NavigationState::MfaVerification);
}

void AppViewModel::submitMfaCode(const QString& code) {
    clearError();
    const QString trimmed = code.trimmed();
    if (trimmed.length() != 6) {
        setError(QStringLiteral("Authentication"), QStringLiteral("Enter a valid 6-digit verification code"));
        return;
    }
    for (const QChar ch : trimmed) {
        if (!ch.isDigit()) {
            setError(QStringLiteral("Authentication"), QStringLiteral("Verification code must contain only digits"));
            return;
        }
    }
    requestLogin(pending_username_.isEmpty() ? QStringLiteral("operator") : pending_username_,
                 pending_password_.isEmpty() ? QStringLiteral("mfa-session") : pending_password_);
}

void AppViewModel::cancelMfaChallenge() {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    nav_controller_.reset(NavigationController::NavigationState::Unauthenticated);
}

void AppViewModel::requestLogout() {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    (void)app_.bootstrap().auth_manager().logout();
    if (app_.bootstrap().emergency_manager().is_wiped()) {
        resetClientAfterWipe();
        return;
    }
    nav_controller_.setAuthenticated(false);
    nav_controller_.reset(NavigationController::NavigationState::Unauthenticated);
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::triggerEmergencyWipe() {
    triggerInstantPanicWipe(0);
}

void AppViewModel::triggerInstantPanicWipe(int postWipeMode) {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    is_identity_verified_ = false;

    const domain::PostWipeMode mode = postWipeModeFromInt(postWipeMode);
    (void)app_.bootstrap().emergency_manager().execute_panic_wipe(domain::PanicTriggerSource::UiPanicButton, mode);

    if (workspace_vm_ != nullptr) {
        if (mode == domain::PostWipeMode::DecoyWorkspace) {
            workspace_vm_->enterDecoyWorkspace();
        } else {
            workspace_vm_->resetForEmergencyWipe();
        }
    }

    connectionStatus_ = QStringLiteral("Offline (Wiped)");
    nav_controller_.setAuthenticated(false);
    nav_controller_.reset(mode == domain::PostWipeMode::EmergencyLocked
                              ? NavigationController::NavigationState::EmergencyMode
                              : NavigationController::NavigationState::Unauthenticated);
    emit emergencyWipedChanged();
    emit duressPolicyChanged();
    emit currentUserChanged();
    emit connectionStatusChanged();
}

void AppViewModel::triggerBroadcastAndPanicWipe(const QString& conversationId, const QString& alertText,
                                                const QString& locationJson, bool waitForAck) {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    is_identity_verified_ = false;

    domain::UserId sender_user = app_.bootstrap().auth_manager().current_user();
    if (sender_user.empty()) {
        sender_user = domain::UserId("operator");
    }
    domain::DeviceId sender_device = app_.bootstrap().messaging_manager().local_device_id();
    if (sender_device.empty()) {
        sender_device = domain::DeviceId("dev-local-01");
    }

    domain::EmergencyBroadcastRequest req;
    req.conversation_id = domain::ConversationId(conversationId.trimmed().toStdString());
    req.sender_user_id = std::move(sender_user);
    req.sender_device_id = std::move(sender_device);

    const QString trimmed_alert = alertText.trimmed();
    req.alert_plaintext =
        trimmed_alert.isEmpty() ? std::string("EMERGENCY PANIC WIPE INITIATED") : trimmed_alert.toStdString();

    const QString trimmed_loc = locationJson.trimmed();
    if (!trimmed_loc.isEmpty()) {
        req.encrypted_location_json = trimmed_loc.toStdString();
    }
    req.wait_for_acknowledgement = waitForAck;
    req.ack_timeout = domain::EmergencyBroadcastRequest::kDefaultAckTimeout;

    (void)app_.bootstrap().emergency_manager().execute_broadcast_and_wipe(
        req, domain::PanicTriggerSource::UiPanicButton, domain::PostWipeMode::EmergencyLocked);

    if (workspace_vm_ != nullptr) {
        workspace_vm_->resetForEmergencyWipe();
    }

    connectionStatus_ = QStringLiteral("Offline (Wiped)");
    nav_controller_.setAuthenticated(false);
    nav_controller_.reset(NavigationController::NavigationState::EmergencyMode);
    emit emergencyWipedChanged();
    emit duressPolicyChanged();
    emit currentUserChanged();
    emit connectionStatusChanged();
}

bool AppViewModel::configureDuressPin(const QString& pin, int postWipeMode) {
    // Option A: preserve exact raw bytes without trimming.
    const common::configuration::SecretString secret(pin.toStdString());
    const auto res =
        app_.bootstrap().emergency_manager().configure_duress_pin(secret, postWipeModeFromInt(postWipeMode));
    if (res.is_error()) {
        const auto& err = res.error();
        const QString category =
            QString::fromUtf8(application::to_string(err.category()).data(),
                              static_cast<qsizetype>(application::to_string(err.category()).size()));
        setError(category, QString::fromStdString(err.user_message()));
        return false;
    }

    clearError();
    emit duressPolicyChanged();
    return true;
}

bool AppViewModel::clearDuressPin() {
    const auto res = app_.bootstrap().emergency_manager().clear_duress_pin();
    if (res.is_error()) {
        const auto& err = res.error();
        const QString category =
            QString::fromUtf8(application::to_string(err.category()).data(),
                              static_cast<qsizetype>(application::to_string(err.category()).size()));
        setError(category, QString::fromStdString(err.user_message()));
        return false;
    }

    clearError();
    emit duressPolicyChanged();
    return true;
}

void AppViewModel::resetClientAfterWipe() {
    clearError();
    pending_username_.clear();
    pending_password_.clear();
    is_identity_verified_ = false;

    app_.bootstrap().auth_manager().force_clear_session();
    app_.bootstrap().emergency_manager().reset_wiped_state();
    app_.bootstrap().device_manager().clear_local_device();

    const std::string db_path = app_.bootstrap().config().database_path;
    const auto open_res = app_.bootstrap().local_store().open(db_path.empty() ? ":memory:" : db_path);
    if (open_res.is_error()) {
        setError(QStringLiteral("Storage"), QString::fromStdString(open_res.error().user_message()));
    }

    if (workspace_vm_ != nullptr) {
        workspace_vm_->resetForEmergencyWipe();
    }

    connectionStatus_ = QStringLiteral("Connected");
    nav_controller_.setAuthenticated(false);
    nav_controller_.reset(NavigationController::NavigationState::Unauthenticated);
    emit emergencyWipedChanged();
    emit duressPolicyChanged();
    emit currentUserChanged();
    emit connectionStatusChanged();
}

} // namespace securecloud::client::ui
