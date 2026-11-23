#include "application/managers/emergency_manager.hpp"

#include "application/managers/auth_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "infrastructure/adapters/file_shredder.hpp"
#include "infrastructure/client_logger.hpp"

#include <algorithm>
#include <chrono>
#include <nlohmann/json.hpp>
#include <thread>

namespace securecloud::client::application::managers {
namespace {

std::string build_broadcast_plaintext(const domain::EmergencyBroadcastRequest& request) {
    if (!request.encrypted_location_json.has_value() || request.encrypted_location_json->empty()) {
        return request.alert_plaintext;
    }

    const nlohmann::json loc_parsed = nlohmann::json::parse(request.encrypted_location_json->begin(),
                                                            request.encrypted_location_json->end(), nullptr, false);
    const nlohmann::json envelope{
        {"type", "securecloud.emergency_broadcast.v1"},
        {"alert", request.alert_plaintext},
        {"location", loc_parsed.is_discarded() ? nlohmann::json(*request.encrypted_location_json) : loc_parsed},
    };
    return envelope.dump();
}

} // namespace

EmergencyManager::EmergencyManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage)
    : local_store_(local_store), secure_storage_(secure_storage) {}

void EmergencyManager::set_gateway_client(interfaces::IGatewayClient* gateway) noexcept {
    gateway_ = gateway;
}

void EmergencyManager::set_messaging_manager(MessagingManager* messaging_manager) noexcept {
    messaging_manager_ = messaging_manager;
}

void EmergencyManager::set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept {
    ratchet_session_manager_ = ratchet_session_manager;
}

void EmergencyManager::set_file_manager(FileManager* file_manager) noexcept {
    file_manager_ = file_manager;
}

void EmergencyManager::set_sync_manager(SyncManager* sync_manager) noexcept {
    sync_manager_ = sync_manager;
}

void EmergencyManager::set_auth_manager(AuthManager* auth_manager) noexcept {
    auth_manager_ = auth_manager;
}

void EmergencyManager::register_shred_artifact_path(const std::filesystem::path& path) {
    if (path.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (std::find(artifact_paths_.begin(), artifact_paths_.end(), path) == artifact_paths_.end()) {
        artifact_paths_.push_back(path);
    }
}

void EmergencyManager::register_shred_directory(const std::filesystem::path& dir, std::vector<std::string> suffixes) {
    if (dir.empty() || suffixes.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    directory_targets_.push_back(DirectoryShredTarget{.directory = dir, .suffixes = std::move(suffixes)});
}

void EmergencyManager::clear_registered_shred_targets() {
    std::lock_guard<std::mutex> lock(mutex_);
    artifact_paths_.clear();
    directory_targets_.clear();
}

void EmergencyManager::reset_wiped_state() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    is_wiped_.store(false, std::memory_order_release);
    last_wipe_report_.reset();
    last_broadcast_result_.reset();
}

std::optional<domain::EmergencyWipeReport> EmergencyManager::last_wipe_report() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_wipe_report_;
}

std::optional<domain::EmergencyBroadcastResult> EmergencyManager::last_broadcast_result() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_broadcast_result_;
}

ClientResult<void> EmergencyManager::trigger_emergency_wipe() {
    const auto res =
        execute_panic_wipe(domain::PanicTriggerSource::Programmatic, domain::PostWipeMode::EmergencyLocked);
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    return ClientResult<void>::ok();
}

ClientResult<domain::EmergencyWipeReport> EmergencyManager::execute_panic_wipe(domain::PanicTriggerSource source,
                                                                               domain::PostWipeMode mode) {
    const auto report = run_destruction_phases(source, mode, std::nullopt);
    return ClientResult<domain::EmergencyWipeReport>::ok(report);
}

ClientResult<domain::EmergencyWipeReport>
EmergencyManager::execute_broadcast_and_wipe(const domain::EmergencyBroadcastRequest& request,
                                             domain::PanicTriggerSource source, domain::PostWipeMode mode) {
    // Phase 0 (optional E2EE broadcast) must NEVER abort or throw before Phases 1-3 local destruction.
    const auto broadcast_result = attempt_pre_wipe_broadcast(request);
    const auto report = run_destruction_phases(source, mode, broadcast_result);
    return ClientResult<domain::EmergencyWipeReport>::ok(report);
}

domain::EmergencyBroadcastResult
EmergencyManager::attempt_pre_wipe_broadcast(const domain::EmergencyBroadcastRequest& request) {
    domain::EmergencyBroadcastResult result;

    if (!request.is_valid()) {
        result.error_detail = "Invalid emergency broadcast request parameters";
        return result;
    }
    if (messaging_manager_ == nullptr) {
        result.error_detail = "MessagingManager unavailable for pre-wipe emergency broadcast";
        return result;
    }

    const std::string plaintext = build_broadcast_plaintext(request);
    // Priority 3 = Emergency per ADR-007 & MessagingManager semantics; standard E2EE path (ADR-008 §22).
    const auto send_res = messaging_manager_->stage_outbound_message(request.conversation_id, request.sender_user_id,
                                                                     request.sender_device_id, plaintext, 3);
    if (send_res.is_error()) {
        result.error_detail = send_res.error().user_message();
        return result;
    }

    const auto& msg = send_res.value();
    result.message_id = msg.message_id();
    result.submitted = (msg.delivery_state() != domain::DeliveryState::LocalPending &&
                        msg.delivery_state() != domain::DeliveryState::Failed);
    if (!result.submitted) {
        result.error_detail = "Pre-wipe broadcast could not reach Gateway immediately (network unavailable)";
        return result;
    }

    if (msg.delivery_state() == domain::DeliveryState::Delivered ||
        msg.delivery_state() == domain::DeliveryState::Read) {
        result.acknowledged = true;
        return result;
    }

    if (request.wait_for_acknowledgement && gateway_ != nullptr) {
        const auto deadline = std::chrono::steady_clock::now() + request.ack_timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto status_res = gateway_->get_message_delivery_status(request.conversation_id, result.message_id);
            if (status_res.is_ok()) {
                const auto state = status_res.value().delivery_state;
                if (state == domain::DeliveryState::Delivered || state == domain::DeliveryState::Read) {
                    result.acknowledged = true;
                    break;
                }
            }
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                break;
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            const auto sleep_slice = std::min(std::chrono::milliseconds(5), remaining);
            if (sleep_slice.count() > 0) {
                std::this_thread::sleep_for(sleep_slice);
            }
        }
        if (!result.acknowledged) {
            result.error_detail = "Pre-wipe broadcast submitted; operator acknowledgement timed out";
        }
    }

    return result;
}

domain::EmergencyWipeReport
EmergencyManager::run_destruction_phases(domain::PanicTriggerSource source, domain::PostWipeMode mode,
                                         std::optional<domain::EmergencyBroadcastResult> broadcast) {
    const auto wipe_start = std::chrono::steady_clock::now();
    is_wiped_.store(true, std::memory_order_release);

    std::vector<std::filesystem::path> registered_files;
    std::vector<DirectoryShredTarget> registered_dirs;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        registered_files = artifact_paths_;
        registered_dirs = directory_targets_;
    }

    domain::EmergencyWipeReport report;
    report.trigger_source = source;
    report.post_wipe_mode = mode;
    if (broadcast.has_value()) {
        report.broadcast_attempted = true;
        report.broadcast_acknowledged = broadcast->acknowledged;
        report.step_results.push_back(domain::WipeArtifactResult{
            .artifact_category = "pre_wipe_broadcast",
            .items_processed = broadcast->submitted ? 1U : 0U,
            .status = broadcast->submitted ? domain::WipeStepStatus::Succeeded : domain::WipeStepStatus::Skipped,
            .detail = broadcast->error_detail.empty()
                          ? (broadcast->acknowledged ? "Emergency E2EE broadcast acknowledged"
                                                     : "Emergency E2EE broadcast submitted")
                          : broadcast->error_detail,
        });
    }

    // Phase 1: Volatile memory zeroization across all client managers.
    std::size_t managers_cleared = 0U;
    std::vector<std::filesystem::path> part_paths_to_shred;
    if (file_manager_ != nullptr) {
        part_paths_to_shred = file_manager_->wipe_volatile_state();
        ++managers_cleared;
    }
    if (ratchet_session_manager_ != nullptr) {
        (void)ratchet_session_manager_->wipe_all_sessions();
        ++managers_cleared;
    }
    if (messaging_manager_ != nullptr) {
        (void)messaging_manager_->wipe_volatile_state();
        ++managers_cleared;
    }
    if (sync_manager_ != nullptr) {
        (void)sync_manager_->wipe_volatile_state();
        ++managers_cleared;
    }
    if (auth_manager_ != nullptr) {
        auth_manager_->force_clear_session();
        ++managers_cleared;
    }

    report.volatile_caches_cleared = managers_cleared;
    report.step_results.push_back(domain::WipeArtifactResult{
        .artifact_category = "volatile_managers",
        .items_processed = managers_cleared,
        .status = domain::WipeStepStatus::Succeeded,
        .detail = "Cleared in-memory ratchet sessions, retry queues, sync cursors, and session state",
    });

    // Phase 2: Complete endpoint secret purge across ISecureStorage (all 7+ namespaces).
    bool secrets_ok = false;
    const auto purge_res = secure_storage_.purge_all_secrets();
    if (purge_res.is_ok()) {
        report.secrets_purged_count = purge_res.value();
        const auto remaining_res = secure_storage_.list_secret_keys();
        secrets_ok = remaining_res.is_ok() && remaining_res.value().empty();
    } else {
        // Fallback explicit delete if purge fails partially.
        (void)secure_storage_.delete_secret("session_auth_token");
        (void)secure_storage_.delete_secret("device_private_identity_key");
    }

    report.step_results.push_back(domain::WipeArtifactResult{
        .artifact_category = "secure_storage",
        .items_processed = report.secrets_purged_count,
        .status = secrets_ok ? domain::WipeStepStatus::Succeeded : domain::WipeStepStatus::Failed,
        .detail = secrets_ok ? "All endpoint secrets zeroized and purged" : "ISecureStorage reported incomplete purge",
    });

    // Phase 3: Forensic on-disk shredding (SQLCipher vault + sidecars, .part caches, disk logs).
    std::size_t db_files_shredded = 0U;
    bool db_ok = false;
    const auto db_destroy_res = local_store_.destroy_and_shred();
    if (db_destroy_res.is_ok()) {
        db_files_shredded = db_destroy_res.value();
        db_ok = true;
    }

    report.step_results.push_back(domain::WipeArtifactResult{
        .artifact_category = "local_database",
        .items_processed = db_files_shredded,
        .status = db_ok ? domain::WipeStepStatus::Succeeded : domain::WipeStepStatus::Failed,
        .detail = db_ok ? "SQLCipher vault and journal artifacts shredded" : db_destroy_res.error().user_message(),
    });

    const std::filesystem::path closed_log_path = infrastructure::ClientLogger::flush_and_close_log_file();
    if (!closed_log_path.empty()) {
        part_paths_to_shred.push_back(closed_log_path);
    }
    for (const auto& p : registered_files) {
        part_paths_to_shred.push_back(p);
    }

    std::size_t artifact_files_shredded = 0U;
    bool artifacts_ok = true;
    if (!part_paths_to_shred.empty()) {
        const auto files_res = infrastructure::adapters::FileShredder::shred_files(part_paths_to_shred);
        if (files_res.is_error()) {
            artifacts_ok = false;
        } else {
            artifact_files_shredded += files_res.value().files_shredded;
            if (!files_res.value().failed_paths.empty()) {
                artifacts_ok = false;
            }
        }
    }

    for (const auto& dir_target : registered_dirs) {
        const auto dir_res = infrastructure::adapters::FileShredder::shred_directory_artifacts(dir_target.directory,
                                                                                               dir_target.suffixes);
        if (dir_res.is_error()) {
            artifacts_ok = false;
        } else {
            artifact_files_shredded += dir_res.value().files_shredded;
            if (!dir_res.value().failed_paths.empty()) {
                artifacts_ok = false;
            }
        }
    }

    report.files_shredded_count = db_files_shredded + artifact_files_shredded;
    report.step_results.push_back(domain::WipeArtifactResult{
        .artifact_category = "disk_artifacts",
        .items_processed = artifact_files_shredded,
        .status = artifacts_ok ? domain::WipeStepStatus::Succeeded : domain::WipeStepStatus::Failed,
        .detail = artifacts_ok ? "Temporary caches and disk log artifacts shredded"
                               : "One or more disk artifacts could not be shredded",
    });

    const auto wipe_end = std::chrono::steady_clock::now();
    report.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(wipe_end - wipe_start).count();
    report.all_critical_steps_succeeded = secrets_ok && db_ok && artifacts_ok;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_wipe_report_ = report;
        last_broadcast_result_ = std::move(broadcast);
    }

    return report;
}

ClientResult<void> EmergencyManager::acknowledge_emergency_message(const domain::ConversationId& conversation_id,
                                                                   const domain::MessageId& message_id,
                                                                   const domain::UserId& /*acknowledger_user_id*/) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Conversation ID and Message ID required"));
    }

    auto msg_res = local_store_.get_message(conversation_id, message_id);
    if (msg_res.is_error()) {
        return ClientResult<void>::error(msg_res.error());
    }

    auto msg = msg_res.value();
    msg.set_emergency_acknowledged(true);
    return local_store_.update_message(msg);
}

size_t EmergencyManager::unacknowledged_emergency_count(const domain::ConversationId& conversation_id) {
    if (conversation_id.empty()) {
        return 0;
    }

    const auto msgs_res = local_store_.get_messages(conversation_id, 0);
    if (msgs_res.is_error()) {
        return 0;
    }

    size_t count = 0;
    for (const auto& msg : msgs_res.value()) {
        // priority 2 is Urgent, priority 3 (and legacy >=2) indicates priority/emergency alert
        if (msg.priority() >= 2 && !msg.emergency_acknowledged()) {
            count++;
        }
    }
    return count;
}

} // namespace securecloud::client::application::managers
