#include "application/managers/settings_manager.hpp"

#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"

#include <cctype>
#include <chrono>
#include <filesystem>

namespace securecloud::client::application::managers {
namespace {

using common::configuration::SecretString;

[[nodiscard]] int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

} // namespace

SettingsManager::SettingsManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage,
                                 interfaces::IGatewayClient& gateway, ClientConfig& config, FileManager* file_manager,
                                 MessagingManager* messaging_manager)
    : local_store_(local_store), secure_storage_(secure_storage), gateway_(gateway), config_(config),
      file_manager_(file_manager), messaging_manager_(messaging_manager) {}

void SettingsManager::set_file_manager(FileManager* file_manager) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    file_manager_ = file_manager;
}

void SettingsManager::set_messaging_manager(MessagingManager* messaging_manager) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    messaging_manager_ = messaging_manager;
}

void SettingsManager::set_network_config_reload_callback(NetworkConfigReloadCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    network_reload_callback_ = std::move(callback);
}

std::optional<std::string> SettingsManager::detect_avatar_mime_type(std::string_view path) {
    const std::string ext = to_lower_ascii(std::filesystem::path(path).extension().string());
    if (ext == ".png") {
        return std::string("image/png");
    }
    if (ext == ".jpg" || ext == ".jpeg") {
        return std::string("image/jpeg");
    }
    if (ext == ".webp") {
        return std::string("image/webp");
    }
    return std::nullopt;
}

void SettingsManager::apply_settings_to_runtime_locked(const domain::UserSettings& settings) {
    cached_settings_ = settings;

    if (!settings.tls.custom_gateway_host.empty()) {
        if (settings.tls.custom_gateway_host.rfind("https://", 0U) == 0U ||
            settings.tls.custom_gateway_host.rfind("http://", 0U) == 0U) {
            config_.gateway_url = settings.tls.custom_gateway_host;
        } else {
            config_.gateway_url = "https://" + settings.tls.custom_gateway_host;
        }
    }
    config_.gateway_port = settings.tls.custom_gateway_port;
    config_.use_live_gateway_transport = settings.use_live_gateway_transport;
    config_.proxy_type = settings.proxy.type;
    config_.proxy_host = settings.proxy.host;
    config_.proxy_port = settings.proxy.port;
    config_.proxy_username = settings.proxy.username;
    config_.pinned_tls_spki_sha256 = settings.tls.normalized_pin();
    config_.enforce_tls_pinning = settings.tls.enforce_strict_pinning;

    const auto has_res = secure_storage_.has_secret(domain::kProxyPasswordStorageKey);
    if (has_res.is_ok() && has_res.value()) {
        const auto secret_res = secure_storage_.get_secret(domain::kProxyPasswordStorageKey);
        if (secret_res.is_ok()) {
            config_.proxy_password = secret_res.value();
        } else {
            config_.proxy_password = SecretString("");
        }
    } else {
        config_.proxy_password = SecretString("");
    }
}

ClientResult<domain::UserSettings> SettingsManager::load_settings() {
    const auto load_res = local_store_.get_user_settings(kDefaultSettingsKey);
    if (load_res.is_error()) {
        return ClientResult<domain::UserSettings>::error(load_res.error());
    }

    domain::UserSettings settings;
    if (load_res.value().has_value()) {
        settings = *load_res.value();
    }

    MessagingManager* msg_mgr = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        apply_settings_to_runtime_locked(settings);
        msg_mgr = messaging_manager_;
    }

    if (msg_mgr != nullptr) {
        (void)msg_mgr->set_read_receipts_enabled(settings.read_receipts_enabled);
        msg_mgr->set_default_disappearing_ttl_seconds(static_cast<int64_t>(settings.default_disappearing_timer));
    }

    return ClientResult<domain::UserSettings>::ok(std::move(settings));
}

ClientResult<domain::UserSettings> SettingsManager::save_settings(domain::UserSettings settings,
                                                                  std::optional<SecretString> proxy_password,
                                                                  bool clear_proxy_password) {
    settings.tls.pinned_spki_sha256_hex = settings.tls.normalized_pin();
    if (settings.updated_at_ms == 0) {
        settings.updated_at_ms = current_unix_ms();
    }

    const auto errors = settings.validate();
    if (!errors.empty()) {
        return ClientResult<domain::UserSettings>::error(ClientError::validation(errors.front()));
    }

    const auto save_res = local_store_.save_user_settings(kDefaultSettingsKey, settings);
    if (save_res.is_error()) {
        return ClientResult<domain::UserSettings>::error(save_res.error());
    }

    if (clear_proxy_password || (proxy_password.has_value() && proxy_password->empty())) {
        const auto del_res = secure_storage_.delete_secret(domain::kProxyPasswordStorageKey);
        if (del_res.is_error()) {
            return ClientResult<domain::UserSettings>::error(del_res.error());
        }
    } else if (proxy_password.has_value()) {
        const auto store_res = secure_storage_.store_secret(domain::kProxyPasswordStorageKey, *proxy_password);
        if (store_res.is_error()) {
            return ClientResult<domain::UserSettings>::error(store_res.error());
        }
    }

    MessagingManager* msg_mgr = nullptr;
    NetworkConfigReloadCallback reload_cb;
    ClientConfig config_snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        apply_settings_to_runtime_locked(settings);
        msg_mgr = messaging_manager_;
        reload_cb = network_reload_callback_;
        config_snapshot = config_;
    }

    if (msg_mgr != nullptr) {
        (void)msg_mgr->set_read_receipts_enabled(settings.read_receipts_enabled);
        msg_mgr->set_default_disappearing_ttl_seconds(static_cast<int64_t>(settings.default_disappearing_timer));
    }
    if (reload_cb) {
        reload_cb(config_snapshot);
    }

    return ClientResult<domain::UserSettings>::ok(std::move(settings));
}

bool SettingsManager::has_saved_proxy_password() const {
    const auto has_res = secure_storage_.has_secret(domain::kProxyPasswordStorageKey);
    return has_res.is_ok() && has_res.value();
}

ClientResult<std::optional<SecretString>> SettingsManager::load_proxy_password() const {
    const auto has_res = secure_storage_.has_secret(domain::kProxyPasswordStorageKey);
    if (has_res.is_error()) {
        return ClientResult<std::optional<SecretString>>::error(has_res.error());
    }
    if (!has_res.value()) {
        return ClientResult<std::optional<SecretString>>::ok(std::nullopt);
    }
    const auto get_res = secure_storage_.get_secret(domain::kProxyPasswordStorageKey);
    if (get_res.is_error()) {
        return ClientResult<std::optional<SecretString>>::error(get_res.error());
    }
    return ClientResult<std::optional<SecretString>>::ok(get_res.value());
}

domain::UserSettings SettingsManager::current_settings() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cached_settings_;
}

ClientResult<domain::UserProfile> SettingsManager::load_profile(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return ClientResult<domain::UserProfile>::error(ClientError::validation("User ID cannot be empty"));
    }

    const auto local_res = local_store_.get_user_profile(user_id);
    if (local_res.is_error()) {
        return ClientResult<domain::UserProfile>::error(local_res.error());
    }

    domain::UserProfile profile;
    if (local_res.value().has_value()) {
        profile = *local_res.value();
        if (profile.public_handle.empty() && profile.allow_handle_discovery) {
            const auto remote_res = gateway_.get_user_profile(user_id);
            if (remote_res.is_ok() && !remote_res.value().public_handle.empty()) {
                profile.public_handle = remote_res.value().public_handle;
            }
        }
    } else {
        const auto remote_res = gateway_.get_user_profile(user_id);
        if (remote_res.is_ok() && remote_res.value().is_valid()) {
            profile = remote_res.value();
        } else {
            profile.user_id = user_id;
            profile.display_name = user_id.value();
            profile.allow_handle_discovery = true;
            profile.updated_at_ms = current_unix_ms();
        }
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        cached_profile_ = profile;
    }
    return ClientResult<domain::UserProfile>::ok(std::move(profile));
}

ClientResult<interfaces::UserProfileSyncResult> SettingsManager::update_profile(domain::UserProfile profile,
                                                                                bool sync_public_fields_to_gateway) {
    profile.avatar_sha256 = domain::normalize_hex_lower(profile.avatar_sha256);
    if (profile.updated_at_ms == 0) {
        profile.updated_at_ms = current_unix_ms();
    }

    const auto errors = profile.validate();
    if (!errors.empty()) {
        return ClientResult<interfaces::UserProfileSyncResult>::error(ClientError::validation(errors.front()));
    }

    const auto save_res = local_store_.save_user_profile(profile);
    if (save_res.is_error()) {
        return ClientResult<interfaces::UserProfileSyncResult>::error(save_res.error());
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        cached_profile_ = profile;
    }

    if (!sync_public_fields_to_gateway || !profile.allow_handle_discovery) {
        interfaces::UserProfileSyncResult local_only;
        local_only.profile = std::move(profile);
        local_only.sync_status = interfaces::ProfileSyncStatus::SyncDisabledByPrivacyPolicy;
        return ClientResult<interfaces::UserProfileSyncResult>::ok(std::move(local_only));
    }

    const auto sync_res = gateway_.update_user_profile(profile);
    if (sync_res.is_ok()) {
        std::lock_guard<std::mutex> lock(mutex_);
        cached_profile_ = sync_res.value().profile;
    }
    return sync_res;
}

ClientResult<domain::UserProfile> SettingsManager::upload_encrypted_avatar(const domain::UserId& user_id,
                                                                           const domain::DeviceId& device_id,
                                                                           std::string_view local_image_path) {
    if (user_id.empty() || device_id.empty() || local_image_path.empty()) {
        return ClientResult<domain::UserProfile>::error(
            ClientError::validation("User ID, device ID, and local image path are required for avatar upload"));
    }

    FileManager* fm = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fm = file_manager_;
    }
    if (fm == nullptr) {
        return ClientResult<domain::UserProfile>::error(
            ClientError::internal_error("FileManager is not configured for SettingsManager"));
    }

    const auto mime_opt = detect_avatar_mime_type(local_image_path);
    if (!mime_opt.has_value()) {
        return ClientResult<domain::UserProfile>::error(
            ClientError::validation("Unsupported avatar format; allowed extensions are .png, .jpg, .jpeg, .webp"));
    }

    std::error_code ec;
    const std::filesystem::path img_path(local_image_path);
    if (!std::filesystem::exists(img_path, ec) || ec || !std::filesystem::is_regular_file(img_path, ec) || ec) {
        return ClientResult<domain::UserProfile>::error(
            ClientError::validation("Avatar file does not exist or is not a regular file"));
    }

    const uint64_t size_bytes = std::filesystem::file_size(img_path, ec);
    if (ec || size_bytes == 0ULL || size_bytes > kMaxAvatarSizeBytes) {
        return ClientResult<domain::UserProfile>::error(
            ClientError::validation("Avatar file size must be between 1 byte and 5 MiB"));
    }

    FileUploadRequest upload_req;
    upload_req.conversation_id = domain::ConversationId("profile-avatar:" + user_id.value());
    upload_req.owner_user_id = user_id;
    upload_req.owner_device_id = device_id;
    upload_req.local_file_path = std::string(local_image_path);
    upload_req.mime_type = *mime_opt;
    upload_req.dispatch_key_envelope = false;
    upload_req.is_profile_asset = true;

    const auto upload_res = fm->start_upload(upload_req);
    if (upload_res.is_error()) {
        return ClientResult<domain::UserProfile>::error(upload_res.error());
    }

    domain::UserProfile profile;
    const auto existing_res = local_store_.get_user_profile(user_id);
    if (existing_res.is_error()) {
        return ClientResult<domain::UserProfile>::error(existing_res.error());
    }
    if (existing_res.value().has_value()) {
        profile = *existing_res.value();
    } else {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cached_profile_.has_value() && cached_profile_->user_id == user_id) {
            profile = *cached_profile_;
        } else {
            profile.user_id = user_id;
            profile.display_name = user_id.value();
            profile.allow_handle_discovery = true;
        }
    }

    profile.avatar_file_id = upload_res.value().record.file_id;
    profile.avatar_sha256 = domain::normalize_hex_lower(upload_res.value().record.ciphertext_sha256);
    profile.updated_at_ms = current_unix_ms();

    const auto save_res = local_store_.save_user_profile(profile);
    if (save_res.is_error()) {
        return ClientResult<domain::UserProfile>::error(save_res.error());
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        cached_profile_ = profile;
    }
    return ClientResult<domain::UserProfile>::ok(std::move(profile));
}

std::optional<domain::UserProfile> SettingsManager::cached_profile() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cached_profile_;
}

ClientResult<interfaces::TlsCertificateInfo>
SettingsManager::inspect_and_optionally_pin_gateway_tls(std::string_view host, uint16_t port, bool save_pin) {
    auto inspect_res = gateway_.inspect_tls_certificate(host, port);
    if (inspect_res.is_error()) {
        return inspect_res;
    }

    if (!save_pin) {
        return inspect_res;
    }

    const std::string normalized_pin = domain::normalize_hex_lower(inspect_res.value().spki_sha256_hex);
    if (!domain::is_valid_sha256_hex(normalized_pin)) {
        return ClientResult<interfaces::TlsCertificateInfo>::error(
            ClientError::crypto("Gateway TLS certificate did not return a valid 64-char SPKI SHA-256 fingerprint"));
    }

    domain::UserSettings updated = current_settings();
    updated.tls.custom_gateway_host = std::string(host);
    updated.tls.custom_gateway_port = port;
    updated.tls.pinned_spki_sha256_hex = normalized_pin;
    updated.updated_at_ms = current_unix_ms();

    const auto save_res = save_settings(std::move(updated));
    if (save_res.is_error()) {
        return ClientResult<interfaces::TlsCertificateInfo>::error(save_res.error());
    }

    inspect_res.value().has_pinned_key = true;
    inspect_res.value().matches_pinned_key = true;
    return inspect_res;
}

ClientResult<GeneratedRecoveryPhrase>
SettingsManager::generate_recovery_phrase(domain::crypto::RecoveryPhraseLength length) {
    const auto mn_res = domain::crypto::RecoveryPhraseEngine::generate_mnemonic(length);
    if (mn_res.is_error()) {
        return ClientResult<GeneratedRecoveryPhrase>::error(mn_res.error());
    }

    const std::size_t word_count = (length == domain::crypto::RecoveryPhraseLength::Words24)
                                       ? domain::crypto::RecoveryPhraseEngine::kWordCount24
                                       : domain::crypto::RecoveryPhraseEngine::kWordCount12;
    const auto challenge_res = domain::crypto::RecoveryPhraseEngine::build_challenge(word_count, 3U);
    if (challenge_res.is_error()) {
        return ClientResult<GeneratedRecoveryPhrase>::error(challenge_res.error());
    }

    GeneratedRecoveryPhrase generated;
    generated.mnemonic = mn_res.value();
    generated.challenge = challenge_res.value();

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_recovery_phrase_ = generated.mnemonic;
        pending_recovery_challenge_ = generated.challenge;
    }

    return ClientResult<GeneratedRecoveryPhrase>::ok(std::move(generated));
}

ClientResult<void> SettingsManager::confirm_recovery_phrase_backup(
    const SecretString& mnemonic, const std::vector<std::pair<std::size_t, std::string>>& challenge_answers) {
    const auto verify_res = domain::crypto::RecoveryPhraseEngine::verify_challenge_words(mnemonic, challenge_answers);
    if (verify_res.is_error()) {
        return ClientResult<void>::error(verify_res.error());
    }
    if (!verify_res.value()) {
        return ClientResult<void>::error(
            ClientError::validation("Recovery phrase confirmation challenge answers did not match"));
    }

    const auto digest_res = domain::crypto::RecoveryPhraseEngine::compute_salted_verification_digest(mnemonic);
    if (digest_res.is_error()) {
        return ClientResult<void>::error(digest_res.error());
    }

    const auto store_res =
        secure_storage_.store_secret(domain::kRecoveryVerifierStorageKey, SecretString(digest_res.value()));
    if (store_res.is_error()) {
        return ClientResult<void>::error(store_res.error());
    }

    domain::UserSettings updated = current_settings();
    updated.recovery_phrase_verified = true;
    updated.updated_at_ms = current_unix_ms();

    const auto save_res = save_settings(std::move(updated));
    if (save_res.is_error()) {
        return ClientResult<void>::error(save_res.error());
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_recovery_phrase_.reset();
        pending_recovery_challenge_.reset();
    }

    return ClientResult<void>::ok();
}

ClientResult<bool> SettingsManager::verify_existing_recovery_phrase(const SecretString& candidate) const {
    const auto has_res = secure_storage_.has_secret(domain::kRecoveryVerifierStorageKey);
    if (has_res.is_error()) {
        return ClientResult<bool>::error(has_res.error());
    }
    if (!has_res.value()) {
        return ClientResult<bool>::ok(false);
    }

    const auto get_res = secure_storage_.get_secret(domain::kRecoveryVerifierStorageKey);
    if (get_res.is_error()) {
        return ClientResult<bool>::error(get_res.error());
    }

    const SecretString& digest = get_res.value();
    return domain::crypto::RecoveryPhraseEngine::verify_against_digest(candidate, digest.expose_unredacted_secret());
}

bool SettingsManager::has_verified_recovery_phrase() const {
    const auto has_res = secure_storage_.has_secret(domain::kRecoveryVerifierStorageKey);
    if (has_res.is_error() || !has_res.value()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return cached_settings_.recovery_phrase_verified;
}

void SettingsManager::wipe_volatile_state() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    cached_settings_ = domain::UserSettings{};
    cached_profile_.reset();
    pending_recovery_phrase_.reset();
    pending_recovery_challenge_.reset();
    config_.proxy_password = SecretString("");
    config_.auth_token = SecretString("");
}

} // namespace securecloud::client::application::managers
