#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/conversation_id.hpp"
#include "domain/emergency_models.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <atomic>
#include <cstddef>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::client::application::managers {

class AuthManager;
class FileManager;
class MessagingManager;
class RatchetSessionManager;
class SettingsManager;
class SyncManager;

class EmergencyManager {
  public:
    static constexpr std::size_t kMinDuressPinLength = 6U;
    static constexpr std::size_t kMaxDuressPinLength = 1024U;

    EmergencyManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage);
    ~EmergencyManager() = default;

    EmergencyManager(const EmergencyManager&) = delete;
    EmergencyManager& operator=(const EmergencyManager&) = delete;

    // Optional sibling wiring (non-owning; never dereferenced in destructor)
    void set_gateway_client(interfaces::IGatewayClient* gateway) noexcept;
    void set_messaging_manager(MessagingManager* messaging_manager) noexcept;
    void set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept;
    void set_file_manager(FileManager* file_manager) noexcept;
    void set_sync_manager(SyncManager* sync_manager) noexcept;
    void set_auth_manager(AuthManager* auth_manager) noexcept;
    void set_settings_manager(SettingsManager* settings_manager) noexcept;

    // Additional filesystem artifacts to shred alongside SQLCipher vault & disk logs
    void register_shred_artifact_path(const std::filesystem::path& path);
    void register_shred_directory(const std::filesystem::path& dir, std::vector<std::string> suffixes);
    void clear_registered_shred_targets();

    // Production 3-phase destruction & optional Phase 0 E2EE broadcast
    ClientResult<void> trigger_emergency_wipe();
    ClientResult<domain::EmergencyWipeReport>
    execute_panic_wipe(domain::PanicTriggerSource source,
                       domain::PostWipeMode mode = domain::PostWipeMode::EmergencyLocked);
    ClientResult<domain::EmergencyWipeReport>
    execute_broadcast_and_wipe(const domain::EmergencyBroadcastRequest& request, domain::PanicTriggerSource source,
                               domain::PostWipeMode mode = domain::PostWipeMode::EmergencyLocked);

    void reset_wiped_state() noexcept;
    [[nodiscard]] bool is_wiped() const noexcept { return is_wiped_.load(std::memory_order_acquire); }
    [[nodiscard]] std::optional<domain::EmergencyWipeReport> last_wipe_report() const;
    [[nodiscard]] std::optional<domain::EmergencyBroadcastResult> last_broadcast_result() const;

    // Login Duress PIN management (salted PBKDF2-HMAC-SHA256 + constant-time CRYPTO_memcmp)
    ClientResult<void> configure_duress_pin(const common::configuration::SecretString& duress_pin,
                                            domain::PostWipeMode mode = domain::PostWipeMode::DecoyWorkspace);
    ClientResult<void> clear_duress_pin();
    [[nodiscard]] bool has_duress_pin() const;
    [[nodiscard]] std::optional<domain::PostWipeMode> duress_post_wipe_mode() const;
    ClientResult<bool> verify_duress_credential(const common::configuration::SecretString& candidate) const;
    ClientResult<std::optional<domain::EmergencyWipeReport>>
    check_and_execute_duress_login(const common::configuration::SecretString& candidate);

    // Emergency priority message acknowledgement tracking (ADR-007)
    ClientResult<void> acknowledge_emergency_message(const domain::ConversationId& conversation_id,
                                                     const domain::MessageId& message_id,
                                                     const domain::UserId& acknowledger_user_id);

    [[nodiscard]] size_t unacknowledged_emergency_count(const domain::ConversationId& conversation_id);

  private:
    struct DirectoryShredTarget {
        std::filesystem::path directory;
        std::vector<std::string> suffixes;
    };

    [[nodiscard]] std::optional<domain::DuressPinConfig> load_duress_pin_config() const;
    domain::EmergencyBroadcastResult attempt_pre_wipe_broadcast(const domain::EmergencyBroadcastRequest& request);
    domain::EmergencyWipeReport run_destruction_phases(domain::PanicTriggerSource source, domain::PostWipeMode mode,
                                                       std::optional<domain::EmergencyBroadcastResult> broadcast);

    interfaces::ILocalStore& local_store_;
    interfaces::ISecureStorage& secure_storage_;
    interfaces::IGatewayClient* gateway_{nullptr};
    MessagingManager* messaging_manager_{nullptr};
    RatchetSessionManager* ratchet_session_manager_{nullptr};
    FileManager* file_manager_{nullptr};
    SyncManager* sync_manager_{nullptr};
    AuthManager* auth_manager_{nullptr};
    SettingsManager* settings_manager_{nullptr};

    std::atomic<bool> is_wiped_{false};
    mutable std::mutex mutex_;
    std::vector<std::filesystem::path> artifact_paths_;
    std::vector<DirectoryShredTarget> directory_targets_;
    std::optional<domain::EmergencyWipeReport> last_wipe_report_;
    std::optional<domain::EmergencyBroadcastResult> last_broadcast_result_;
};

} // namespace securecloud::client::application::managers
