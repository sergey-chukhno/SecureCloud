#pragma once

#include "application/client_config.hpp"
#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/crypto/recovery_phrase_engine.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"
#include "domain/user_profile.hpp"
#include "domain/user_settings.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securecloud::client::application::managers {

class FileManager;
class MessagingManager;

using NetworkConfigReloadCallback = std::function<void(const ClientConfig&)>;

struct GeneratedRecoveryPhrase {
    common::configuration::SecretString mnemonic{};
    domain::crypto::RecoveryVerificationChallenge challenge{};

    bool operator==(const GeneratedRecoveryPhrase& other) const noexcept = default;
};

/// Coordinates persisted SQLCipher user settings/profile, ISecureStorage secrets (proxy password &
/// BIP-39 verifier), E2EE avatar uploads, live ClientConfig reload hooks, TLS SPKI pinning, and
/// endpoint-only recovery phrase workflows (`ADR-008 §7, §20, §27, §28`).
class SettingsManager {
  public:
    static constexpr std::string_view kDefaultSettingsKey = "active";
    static constexpr uint64_t kMaxAvatarSizeBytes = 5ULL * 1024ULL * 1024ULL;

    SettingsManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage,
                    interfaces::IGatewayClient& gateway, ClientConfig& config, FileManager* file_manager = nullptr,
                    MessagingManager* messaging_manager = nullptr);
    ~SettingsManager() = default;

    SettingsManager(const SettingsManager&) = delete;
    SettingsManager& operator=(const SettingsManager&) = delete;

    void set_file_manager(FileManager* file_manager) noexcept;
    void set_messaging_manager(MessagingManager* messaging_manager) noexcept;
    void set_network_config_reload_callback(NetworkConfigReloadCallback callback);

    // Persisted Preferences & Proxy Secret Lifecycle
    ClientResult<domain::UserSettings> load_settings();
    ClientResult<domain::UserSettings>
    save_settings(domain::UserSettings settings,
                  std::optional<common::configuration::SecretString> proxy_password = std::nullopt,
                  bool clear_proxy_password = false);
    [[nodiscard]] bool has_saved_proxy_password() const;
    [[nodiscard]] ClientResult<std::optional<common::configuration::SecretString>> load_proxy_password() const;
    [[nodiscard]] domain::UserSettings current_settings() const;

    // Profile & E2EE Avatar Workflow
    ClientResult<domain::UserProfile> load_profile(const domain::UserId& user_id);
    ClientResult<interfaces::UserProfileSyncResult> update_profile(domain::UserProfile profile,
                                                                   bool sync_public_fields_to_gateway = true);
    ClientResult<domain::UserProfile> upload_encrypted_avatar(const domain::UserId& user_id,
                                                              const domain::DeviceId& device_id,
                                                              std::string_view local_image_path);
    [[nodiscard]] std::optional<domain::UserProfile> cached_profile() const;

    // TLS Fingerprint Inspection & Pinning
    ClientResult<interfaces::TlsCertificateInfo>
    inspect_and_optionally_pin_gateway_tls(std::string_view host, uint16_t port, bool save_pin = false);

    // Endpoint-Only BIP-39 Recovery Lifecycle (0 Gateway calls)
    ClientResult<GeneratedRecoveryPhrase> generate_recovery_phrase(
        domain::crypto::RecoveryPhraseLength length = domain::crypto::RecoveryPhraseLength::Words12);
    ClientResult<void>
    confirm_recovery_phrase_backup(const common::configuration::SecretString& mnemonic,
                                   const std::vector<std::pair<std::size_t, std::string>>& challenge_answers);
    [[nodiscard]] ClientResult<bool>
    verify_existing_recovery_phrase(const common::configuration::SecretString& candidate) const;
    [[nodiscard]] bool has_verified_recovery_phrase() const;

    // Panic Wipe Volatile Cleanup (CLIENT-013 Integration)
    void wipe_volatile_state() noexcept;

  private:
    void apply_settings_to_runtime_locked(const domain::UserSettings& settings);
    [[nodiscard]] static std::optional<std::string> detect_avatar_mime_type(std::string_view path);

    interfaces::ILocalStore& local_store_;
    interfaces::ISecureStorage& secure_storage_;
    interfaces::IGatewayClient& gateway_;
    ClientConfig& config_;
    FileManager* file_manager_{nullptr};
    MessagingManager* messaging_manager_{nullptr};

    mutable std::mutex mutex_;
    domain::UserSettings cached_settings_{};
    std::optional<domain::UserProfile> cached_profile_;
    std::optional<common::configuration::SecretString> pending_recovery_phrase_;
    std::optional<domain::crypto::RecoveryVerificationChallenge> pending_recovery_challenge_;
    NetworkConfigReloadCallback network_reload_callback_;
};

} // namespace securecloud::client::application::managers
