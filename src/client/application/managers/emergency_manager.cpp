#include "application/managers/emergency_manager.hpp"

#include "application/managers/auth_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/settings_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "infrastructure/adapters/file_shredder.hpp"
#include "infrastructure/client_logger.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <span>
#include <thread>

namespace securecloud::client::application::managers {
namespace {

constexpr std::size_t kDuressSaltBytes = 16U;
constexpr std::size_t kDuressHashBytes = 32U;

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const uint8_t b : bytes) {
        out.push_back(kHexDigits[static_cast<std::size_t>(b >> 4U) & 0x0FU]);
        out.push_back(kHexDigits[static_cast<std::size_t>(b) & 0x0FU]);
    }
    return out;
}

std::optional<uint8_t> hex_nibble(char ch) noexcept {
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
        return static_cast<uint8_t>(10 + (ch - 'A'));
    }
    return std::nullopt;
}

bool hex_to_bytes(std::string_view hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.empty() || (hex.size() % 2U) != 0U) {
        return false;
    }
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const auto hi = hex_nibble(hex[i]);
        const auto lo = hex_nibble(hex[i + 1U]);
        if (!hi.has_value() || !lo.has_value()) {
            out.clear();
            return false;
        }
        out.push_back(static_cast<uint8_t>((static_cast<unsigned int>(*hi) << 4U) | static_cast<unsigned int>(*lo)));
    }
    return true;
}

bool derive_pbkdf2_sha256(std::string_view raw_secret, std::span<const uint8_t> salt, uint32_t iterations,
                          std::array<uint8_t, kDuressHashBytes>& out_digest) {
    if (raw_secret.empty() || salt.empty() || iterations == 0U) {
        return false;
    }
    if (raw_secret.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        salt.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        iterations > static_cast<uint32_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    const int rc = PKCS5_PBKDF2_HMAC(raw_secret.data(), static_cast<int>(raw_secret.size()), salt.data(),
                                     static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha256(),
                                     static_cast<int>(out_digest.size()), out_digest.data());
    return rc == 1;
}

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

void EmergencyManager::set_settings_manager(SettingsManager* settings_manager) noexcept {
    settings_manager_ = settings_manager;
}

void EmergencyManager::set_local_audit_logger(LocalAuditLogger* local_audit_logger) noexcept {
    local_audit_logger_ = local_audit_logger;
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

std::optional<domain::DuressPinConfig> EmergencyManager::load_duress_pin_config() const {
    const auto stored = secure_storage_.get_secret(std::string(domain::DuressPinConfig::kStorageKey));
    if (stored.is_error() || stored.value().empty()) {
        return std::nullopt;
    }

    const auto parsed = domain::DuressPinConfig::from_json(stored.value().expose_unredacted_secret());
    if (!parsed.has_value() || !parsed->enabled || !parsed->is_valid()) {
        return std::nullopt;
    }
    return parsed;
}

ClientResult<void> EmergencyManager::configure_duress_pin(const common::configuration::SecretString& duress_pin,
                                                          domain::PostWipeMode mode) {
    // Exact byte check without trimming so Duress PIN matches PasswordCredential character/byte semantics.
    if (duress_pin.size() < kMinDuressPinLength || duress_pin.size() > kMaxDuressPinLength) {
        return ClientResult<void>::error(ClientError::validation("Duress PIN must be between 6 and 1024 bytes"));
    }

    std::array<uint8_t, kDuressSaltBytes> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        OPENSSL_cleanse(salt.data(), salt.size());
        return ClientResult<void>::error(ClientError::crypto("Failed to generate cryptographic salt for duress PIN"));
    }

    std::array<uint8_t, kDuressHashBytes> digest{};
    if (!derive_pbkdf2_sha256(duress_pin.expose_unredacted_secret(), salt,
                              domain::DuressPinConfig::kMinPbkdf2Iterations, digest)) {
        OPENSSL_cleanse(salt.data(), salt.size());
        OPENSSL_cleanse(digest.data(), digest.size());
        return ClientResult<void>::error(ClientError::crypto("Failed to derive PBKDF2 verifier for duress PIN"));
    }

    domain::DuressPinConfig cfg;
    cfg.enabled = true;
    cfg.post_wipe_mode = mode;
    cfg.pbkdf2_iterations = domain::DuressPinConfig::kMinPbkdf2Iterations;
    cfg.salt_hex = bytes_to_hex(salt);
    cfg.derived_hash_hex = bytes_to_hex(digest);
    cfg.configured_at_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();

    OPENSSL_cleanse(salt.data(), salt.size());
    OPENSSL_cleanse(digest.data(), digest.size());

    const common::configuration::SecretString serialized(cfg.to_json());
    const auto store_res = secure_storage_.store_secret(std::string(domain::DuressPinConfig::kStorageKey), serialized);
    if (store_res.is_ok() && local_audit_logger_ != nullptr) {
        (void)local_audit_logger_->record_event(domain::LocalAuditCategory::EmergencyDefense,
                                                "emergency.duress_pin_configured", domain::LocalAuditOutcome::Success,
                                                "", "", "Duress PIN verifier configured");
    }
    return store_res;
}

ClientResult<void> EmergencyManager::clear_duress_pin() {
    if (!secure_storage_.has_secret(std::string(domain::DuressPinConfig::kStorageKey))) {
        return ClientResult<void>::ok();
    }
    const auto del_res = secure_storage_.delete_secret(std::string(domain::DuressPinConfig::kStorageKey));
    if (del_res.is_ok() && local_audit_logger_ != nullptr) {
        (void)local_audit_logger_->record_event(domain::LocalAuditCategory::EmergencyDefense,
                                                "emergency.duress_pin_cleared", domain::LocalAuditOutcome::Success, "",
                                                "", "Duress PIN verifier cleared");
    }
    return del_res;
}

bool EmergencyManager::has_duress_pin() const {
    return load_duress_pin_config().has_value();
}

std::optional<domain::PostWipeMode> EmergencyManager::duress_post_wipe_mode() const {
    const auto cfg = load_duress_pin_config();
    if (!cfg.has_value()) {
        return std::nullopt;
    }
    return cfg->post_wipe_mode;
}

ClientResult<bool>
EmergencyManager::verify_duress_credential(const common::configuration::SecretString& candidate) const {
    const auto cfg = load_duress_pin_config();
    if (!cfg.has_value()) {
        return ClientResult<bool>::ok(false);
    }
    if (candidate.empty() || candidate.size() > kMaxDuressPinLength) {
        return ClientResult<bool>::ok(false);
    }

    std::vector<uint8_t> salt;
    std::vector<uint8_t> expected;
    if (!hex_to_bytes(cfg->salt_hex, salt) || !hex_to_bytes(cfg->derived_hash_hex, expected) ||
        salt.size() < kDuressSaltBytes || expected.size() != kDuressHashBytes) {
        if (!salt.empty()) {
            OPENSSL_cleanse(salt.data(), salt.size());
        }
        if (!expected.empty()) {
            OPENSSL_cleanse(expected.data(), expected.size());
        }
        return ClientResult<bool>::ok(false);
    }

    std::array<uint8_t, kDuressHashBytes> derived{};
    const bool derived_ok =
        derive_pbkdf2_sha256(candidate.expose_unredacted_secret(), salt, cfg->pbkdf2_iterations, derived);
    if (!derived_ok) {
        OPENSSL_cleanse(derived.data(), derived.size());
        OPENSSL_cleanse(salt.data(), salt.size());
        OPENSSL_cleanse(expected.data(), expected.size());
        return ClientResult<bool>::error(ClientError::crypto("Failed to verify duress credential"));
    }

    const bool matched = (CRYPTO_memcmp(derived.data(), expected.data(), kDuressHashBytes) == 0);
    OPENSSL_cleanse(derived.data(), derived.size());
    OPENSSL_cleanse(salt.data(), salt.size());
    OPENSSL_cleanse(expected.data(), expected.size());
    return ClientResult<bool>::ok(matched);
}

ClientResult<std::optional<domain::EmergencyWipeReport>>
EmergencyManager::check_and_execute_duress_login(const common::configuration::SecretString& candidate) {
    const auto cfg = load_duress_pin_config();
    if (!cfg.has_value()) {
        return ClientResult<std::optional<domain::EmergencyWipeReport>>::ok(std::nullopt);
    }

    // Capture target post-wipe mode BEFORE Phase 2 purges ISecureStorage (self-destructing DuressPinConfig).
    const domain::PostWipeMode mode = cfg->post_wipe_mode;
    const auto verify_res = verify_duress_credential(candidate);
    if (verify_res.is_error()) {
        return ClientResult<std::optional<domain::EmergencyWipeReport>>::error(verify_res.error());
    }
    if (!verify_res.value()) {
        return ClientResult<std::optional<domain::EmergencyWipeReport>>::ok(std::nullopt);
    }

    const auto wipe_res = execute_panic_wipe(domain::PanicTriggerSource::DuressPin, mode);
    if (wipe_res.is_error()) {
        return ClientResult<std::optional<domain::EmergencyWipeReport>>::error(wipe_res.error());
    }
    return ClientResult<std::optional<domain::EmergencyWipeReport>>::ok(wipe_res.value());
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

    if (local_audit_logger_ != nullptr) {
        (void)local_audit_logger_->record_event(domain::LocalAuditCategory::EmergencyDefense,
                                                "emergency.panic_wipe_started", domain::LocalAuditOutcome::Triggered,
                                                "", "", "Emergency panic wipe initiated");
    }

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
    if (settings_manager_ != nullptr) {
        settings_manager_->wipe_volatile_state();
        ++managers_cleared;
    }
    if (local_audit_logger_ != nullptr) {
        local_audit_logger_->wipe_volatile_state();
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
