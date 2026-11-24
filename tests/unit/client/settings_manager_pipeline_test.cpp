#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "domain/crypto/recovery_phrase_engine.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::domain;
using namespace securecloud::client::domain::crypto;
using namespace securecloud::client::infrastructure::adapters;
using securecloud::common::configuration::SecretString;

class SettingsManagerPipelineTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_t04_settings_mgr_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "vault.db";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::unique_ptr<ClientBootstrap> create_sqlcipher_bootstrap(const std::filesystem::path& path) {
        auto cfg = ClientConfig::create_default();
        cfg.database_path = path.string();

        auto secure = std::make_unique<MemorySecureStorage>();
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto store = std::make_unique<SqlCipherLocalStore>(*secure, *crypto);
        EXPECT_TRUE(store->open(path.string()).is_ok());

        auto gw = std::make_unique<DefaultGatewayClient>(cfg);
        return ClientBootstrap::create_with_adapters(cfg, std::move(gw), std::move(store), std::move(secure),
                                                     std::move(crypto));
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(SettingsManagerPipelineTest, SaveAndLoadSettingsSyncsConfigMessagingSecretsAndReloadCallback) {
    auto bootstrap = create_sqlcipher_bootstrap(db_path_);
    auto& mgr = bootstrap->settings_manager();

    // Missing saved settings hydrate defaults cleanly.
    const auto initial_res = mgr.load_settings();
    ASSERT_TRUE(initial_res.is_ok());
    EXPECT_EQ(initial_res.value(), UserSettings{});
    EXPECT_FALSE(mgr.has_saved_proxy_password());

    std::size_t reload_calls = 0U;
    ClientConfig last_reloaded;
    mgr.set_network_config_reload_callback([&](const ClientConfig& cfg) {
        ++reload_calls;
        last_reloaded = cfg;
    });

    UserSettings settings;
    settings.theme_mode = 2;
    settings.font_scale = 1.25;
    settings.high_contrast_enabled = true;
    settings.read_receipts_enabled = false;
    settings.default_disappearing_timer = DisappearingTimerPreset::OneHour;
    settings.use_live_gateway_transport = true;
    settings.proxy.type = ProxyType::Socks5;
    settings.proxy.host = "proxy.corp.internal";
    settings.proxy.port = 1080U;
    settings.proxy.username = "j.doe";
    settings.tls.custom_gateway_host = "gw.corp.internal";
    settings.tls.custom_gateway_port = 9443U;
    settings.tls.pinned_spki_sha256_hex = std::string(64U, 'A');

    const auto save_res = mgr.save_settings(settings, SecretString("corp-proxy-secret"));
    ASSERT_TRUE(save_res.is_ok());
    EXPECT_EQ(reload_calls, 1U);
    EXPECT_EQ(last_reloaded.gateway_url, "https://gw.corp.internal");
    EXPECT_EQ(last_reloaded.gateway_port, 9443U);
    EXPECT_TRUE(last_reloaded.use_live_gateway_transport);
    EXPECT_EQ(last_reloaded.proxy_type, ProxyType::Socks5);
    EXPECT_EQ(last_reloaded.proxy_host, "proxy.corp.internal");
    EXPECT_EQ(last_reloaded.proxy_port, 1080U);
    EXPECT_EQ(last_reloaded.proxy_username, "j.doe");
    EXPECT_EQ(last_reloaded.proxy_password.expose_unredacted_secret(), "corp-proxy-secret");
    EXPECT_EQ(last_reloaded.pinned_tls_spki_sha256, std::string(64U, 'a'));

    // Password is in ISecureStorage only; MessagingManager reflects read receipt & TTL settings.
    EXPECT_TRUE(mgr.has_saved_proxy_password());
    const auto pw_res = mgr.load_proxy_password();
    ASSERT_TRUE(pw_res.is_ok());
    ASSERT_TRUE(pw_res.value().has_value());
    EXPECT_EQ(pw_res.value()->expose_unredacted_secret(), "corp-proxy-secret");

    EXPECT_FALSE(bootstrap->messaging_manager().read_receipts_enabled());
    EXPECT_EQ(bootstrap->messaging_manager().default_disappearing_ttl_seconds(), 3600);

    // Explicitly clearing proxy password removes it cleanly from ISecureStorage & ClientConfig.
    const auto clear_res = mgr.save_settings(settings, std::nullopt, /*clear_proxy_password=*/true);
    ASSERT_TRUE(clear_res.is_ok());
    EXPECT_EQ(reload_calls, 2U);
    EXPECT_FALSE(mgr.has_saved_proxy_password());
    EXPECT_TRUE(last_reloaded.proxy_password.empty());
}

TEST_F(SettingsManagerPipelineTest, ProfileHydrationPrivacyGateAndGracefulUnsupportedSync) {
    auto cfg = ClientConfig::create_default();
    MemorySecureStorage secure;
    OpenSslCryptoProvider crypto;
    MemoryLocalStore store;
    DefaultGatewayClient gw(cfg);
    SettingsManager mgr(store, secure, gw, cfg);

    const UserId uid("user-alice-t04");
    const auto hydrated = mgr.load_profile(uid);
    ASSERT_TRUE(hydrated.is_ok());
    EXPECT_EQ(hydrated.value().user_id, uid);

    // Privacy gate disabled -> saves locally cleanly, 0 calls to gateway update_user_profile.
    UserProfile priv_profile;
    priv_profile.user_id = uid;
    priv_profile.display_name = "Alice Local Only";
    priv_profile.public_handle = "alice.local";
    priv_profile.bio_status = "Private profile";
    priv_profile.allow_handle_discovery = false;

    const auto priv_res = mgr.update_profile(priv_profile, true);
    ASSERT_TRUE(priv_res.is_ok());
    EXPECT_EQ(priv_res.value().sync_status, ProfileSyncStatus::SyncDisabledByPrivacyPolicy);
    EXPECT_EQ(gw.profile_update_call_count(), 0U);
    EXPECT_EQ(store.get_user_profile(uid).value()->display_name, "Alice Local Only");

    // Opt-in public sync succeeds.
    UserProfile pub_profile = priv_profile;
    pub_profile.display_name = "Alice Public";
    pub_profile.allow_handle_discovery = true;
    const auto pub_res = mgr.update_profile(pub_profile, true);
    ASSERT_TRUE(pub_res.is_ok());
    EXPECT_EQ(pub_res.value().sync_status, ProfileSyncStatus::Synced);
    EXPECT_EQ(gw.profile_update_call_count(), 1U);

    // Live server lacking UpdateUserProfile degrades cleanly while persisting locally.
    gw.set_simulated_profile_sync_unsupported(true);
    pub_profile.bio_status = "Updated Bio Even Without Server RPC";
    const auto unsupp_res = mgr.update_profile(pub_profile, true);
    ASSERT_TRUE(unsupp_res.is_ok());
    EXPECT_EQ(unsupp_res.value().sync_status, ProfileSyncStatus::LocalOnlyServerUnsupported);
    EXPECT_EQ(store.get_user_profile(uid).value()->bio_status, "Updated Bio Even Without Server RPC");
}

TEST_F(SettingsManagerPipelineTest, EncryptedAvatarUploadUsesFileManagerWithoutPlaintextOrChatMessage) {
    auto cfg = ClientConfig::create_default();
    auto secure = std::make_unique<MemorySecureStorage>();
    auto crypto = std::make_unique<OpenSslCryptoProvider>();
    auto store = std::make_unique<MemoryLocalStore>();
    auto gw = std::make_unique<DefaultGatewayClient>(cfg);
    auto* raw_gw = gw.get();
    auto* raw_secure = secure.get();
    auto* raw_store = store.get();

    auto bootstrap = ClientBootstrap::create_with_adapters(cfg, std::move(gw), std::move(store), std::move(secure),
                                                           std::move(crypto));

    const UserId uid("user-avatar-01");
    const DeviceId did("dev-avatar-01");

    // Reject unsupported extension and empty file.
    const std::filesystem::path bad_ext = temp_dir_ / "malware.exe";
    {
        std::ofstream ofs(bad_ext, std::ios::binary);
        ofs << "bad";
    }
    EXPECT_TRUE(bootstrap->settings_manager().upload_encrypted_avatar(uid, did, bad_ext.string()).is_error());

    const std::filesystem::path empty_png = temp_dir_ / "empty.png";
    {
        std::ofstream ofs(empty_png, std::ios::binary);
    }
    EXPECT_TRUE(bootstrap->settings_manager().upload_encrypted_avatar(uid, did, empty_png.string()).is_error());

    // Valid PNG containing identifiable plaintext marker must arrive strictly encrypted on Gateway.
    const std::filesystem::path valid_png = temp_dir_ / "avatar.png";
    const std::string plaintext_marker = "RAW_AVATAR_PNG_SECRET_MARKER_XYZ";
    {
        std::ofstream ofs(valid_png, std::ios::binary);
        ofs << "\x89PNG\r\n\x1a\n" << plaintext_marker << std::string(2048U, 'P');
    }

    const auto up_res = bootstrap->settings_manager().upload_encrypted_avatar(uid, did, valid_png.string());
    ASSERT_TRUE(up_res.is_ok());
    EXPECT_FALSE(up_res.value().avatar_file_id.empty());
    EXPECT_TRUE(is_valid_sha256_hex(up_res.value().avatar_sha256));

    // Verify encrypted bytes on Gateway contain zero plaintext avatar bytes and no chat message was sent.
    ASSERT_TRUE(raw_gw->has_stored_file(up_res.value().avatar_file_id));
    const std::vector<uint8_t> cipher_bytes = raw_gw->stored_file_raw_bytes(up_res.value().avatar_file_id);
    const std::string cipher_str(cipher_bytes.begin(), cipher_bytes.end());
    EXPECT_EQ(cipher_str.find(plaintext_marker), std::string::npos);
    EXPECT_TRUE(raw_gw->submitted_fanouts().empty());

    // Content key persisted inside ISecureStorage and profile saved in ILocalStore.
    const auto has_key = raw_secure->has_secret(FileManager::file_key_storage_id(up_res.value().avatar_file_id));
    ASSERT_TRUE(has_key.is_ok());
    EXPECT_TRUE(has_key.value());
    EXPECT_EQ(raw_store->get_user_profile(uid).value()->avatar_file_id, up_res.value().avatar_file_id);
}

TEST_F(SettingsManagerPipelineTest, InspectAndPinGatewayTlsPersistsSpkiPinAndUpdatesConfig) {
    auto cfg = ClientConfig::create_default();
    MemorySecureStorage secure;
    OpenSslCryptoProvider crypto;
    MemoryLocalStore store;
    DefaultGatewayClient gw(cfg);
    SettingsManager mgr(store, secure, gw, cfg);

    TlsCertificateInfo cert;
    cert.subject_cn = "gw.field.local";
    cert.issuer_cn = "SecureCloud Root CA";
    cert.spki_sha256_hex = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";
    gw.set_simulated_tls_certificate(cert);

    bool reloaded = false;
    mgr.set_network_config_reload_callback([&](const ClientConfig&) { reloaded = true; });

    const auto inspect_only = mgr.inspect_and_optionally_pin_gateway_tls("gw.field.local", 9443U, false);
    ASSERT_TRUE(inspect_only.is_ok());
    EXPECT_FALSE(inspect_only.value().has_pinned_key);
    EXPECT_FALSE(reloaded);

    const auto pinned = mgr.inspect_and_optionally_pin_gateway_tls("gw.field.local", 9443U, true);
    ASSERT_TRUE(pinned.is_ok());
    EXPECT_TRUE(pinned.value().has_pinned_key);
    EXPECT_TRUE(pinned.value().matches_pinned_key);
    EXPECT_TRUE(reloaded);
    EXPECT_EQ(cfg.pinned_tls_spki_sha256, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    EXPECT_EQ(cfg.gateway_url, "https://gw.field.local");
    EXPECT_EQ(cfg.gateway_port, 9443U);
}

TEST_F(SettingsManagerPipelineTest, DisappearingMessageTimersStampOutboundAndInboundAndPurgeDeterministically) {
    auto bootstrap = create_sqlcipher_bootstrap(db_path_);
    auto& msg_mgr = bootstrap->messaging_manager();
    auto& settings_mgr = bootstrap->settings_manager();

    const UserId alice("alice-ttl");
    const DeviceId alice_dev("dev-alice-ttl");
    const UserId bob("bob-ttl");
    const DeviceId bob_dev("dev-bob-ttl");
    const Contact bob_contact(bob, "Bob", KeyVerificationStatus::Verified, "fp-bob", false);
    ASSERT_TRUE(bootstrap->contact_manager().add_or_update_contact(bob_contact).is_ok());

    UserSettings settings;
    settings.default_disappearing_timer = DisappearingTimerPreset::OneHour;
    ASSERT_TRUE(settings_mgr.save_settings(settings).is_ok());

    // Direct conversation inherits workspace 1h TTL default; group overridden to 24h.
    const auto direct_res = msg_mgr.open_direct_conversation(alice, bob, "Direct 1h");
    ASSERT_TRUE(direct_res.is_ok());
    EXPECT_EQ(direct_res.value().disappearing_ttl_seconds(), 3600);

    const auto group_res = msg_mgr.create_group_conversation(alice, "Group 24h", {bob});
    ASSERT_TRUE(group_res.is_ok());
    const auto updated_group = msg_mgr.set_conversation_disappearing_timer(group_res.value().conversation_id(), 86400);
    ASSERT_TRUE(updated_group.is_ok());
    EXPECT_EQ(updated_group.value().disappearing_ttl_seconds(), 86400);

    // Also create one persistent conversation (explicit 0 TTL) with default reset to 0 temporarily.
    ASSERT_TRUE(msg_mgr.set_conversation_disappearing_timer(direct_res.value().conversation_id(), 3600).is_ok());

    const auto out_1h = msg_mgr.send_message(direct_res.value().conversation_id(), alice, alice_dev, bob_dev, "hello");
    ASSERT_TRUE(out_1h.is_ok());
    const int64_t out_sent_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(out_1h.value().sent_at().time_since_epoch()).count();
    EXPECT_EQ(out_1h.value().expires_at_ms(), out_sent_ms + 3600LL * 1000LL);

    const auto enc_in = bootstrap->crypto_provider().encrypt_message(bob_dev, "inbound ephemeral");
    ASSERT_TRUE(enc_in.is_ok());
    PerDeviceDeliveryPayload in_payload{
        .recipient_user_id = alice,
        .recipient_device_id = alice_dev,
        .ciphertext_blob = enc_in.value(),
        .algorithm = "Stub",
    };
    const auto in_24h = msg_mgr.process_inbound_message(group_res.value().conversation_id(), bob, bob_dev, in_payload);
    ASSERT_TRUE(in_24h.is_ok());
    const int64_t in_sent_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(in_24h.value().sent_at().time_since_epoch()).count();
    EXPECT_EQ(in_24h.value().expires_at_ms(), in_sent_ms + 86400LL * 1000LL);

    // Purge just after 1h -> removes 1h message while retaining 24h message.
    const auto purge_res = msg_mgr.purge_expired_messages(out_sent_ms + 3601LL * 1000LL);
    ASSERT_TRUE(purge_res.is_ok());
    EXPECT_EQ(purge_res.value(), 1U);
    EXPECT_TRUE(msg_mgr.get_conversation_messages(direct_res.value().conversation_id()).value().empty());
    EXPECT_EQ(msg_mgr.get_conversation_messages(group_res.value().conversation_id()).value().size(), 1U);
}

TEST_F(SettingsManagerPipelineTest, EndpointOnlyBip39RecoveryLifecyclePerformsZeroGatewayCalls) {
    auto cfg = ClientConfig::create_default();
    MemorySecureStorage secure;
    OpenSslCryptoProvider crypto;
    MemoryLocalStore store;
    DefaultGatewayClient gw(cfg);
    SettingsManager mgr(store, secure, gw, cfg);

    // Default 12-word phrase generation + 3-word spot-check challenge.
    const auto gen_res = mgr.generate_recovery_phrase();
    ASSERT_TRUE(gen_res.is_ok());
    ASSERT_EQ(gen_res.value().challenge.word_indices.size(), 3U);
    EXPECT_FALSE(mgr.has_verified_recovery_phrase());

    // Split phrase locally solely to answer the quiz in the test.
    std::vector<std::string> words;
    std::string cur;
    for (const char ch : gen_res.value().mnemonic.expose_unredacted_secret()) {
        if (ch == ' ') {
            words.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) {
        words.push_back(cur);
    }
    ASSERT_EQ(words.size(), 12U);

    // Wrong answer fails closed and leaves recovery unverified.
    std::vector<std::pair<std::size_t, std::string>> bad_answers;
    for (const std::size_t idx : gen_res.value().challenge.word_indices) {
        bad_answers.emplace_back(idx, words[idx] == "abandon" ? "zoo" : "abandon");
    }
    EXPECT_TRUE(mgr.confirm_recovery_phrase_backup(gen_res.value().mnemonic, bad_answers).is_error());
    EXPECT_FALSE(mgr.has_verified_recovery_phrase());

    // Exact answers persist salted verifier ONLY and mark settings verified.
    std::vector<std::pair<std::size_t, std::string>> good_answers;
    for (const std::size_t idx : gen_res.value().challenge.word_indices) {
        good_answers.emplace_back(idx, words[idx]);
    }
    ASSERT_TRUE(mgr.confirm_recovery_phrase_backup(gen_res.value().mnemonic, good_answers).is_ok());
    EXPECT_TRUE(mgr.has_verified_recovery_phrase());
    EXPECT_TRUE(mgr.current_settings().recovery_phrase_verified);
    EXPECT_TRUE(mgr.verify_existing_recovery_phrase(gen_res.value().mnemonic).value());

    const auto wrong_mn = RecoveryPhraseEngine::generate_mnemonic(RecoveryPhraseLength::Words12).value();
    if (wrong_mn != gen_res.value().mnemonic) {
        EXPECT_FALSE(mgr.verify_existing_recovery_phrase(wrong_mn).value());
    }

    // Stored verifier contains no raw words and Gateway saw 0 requests.
    const auto verifier_res = secure.get_secret(kRecoveryVerifierStorageKey);
    ASSERT_TRUE(verifier_res.is_ok());
    EXPECT_NE(verifier_res.value().expose_unredacted_secret().find("sc-bip39-v1:"), std::string::npos);
    EXPECT_EQ(gw.profile_update_call_count(), 0U);
    EXPECT_TRUE(gw.submitted_fanouts().empty());
}

TEST_F(SettingsManagerPipelineTest, EmergencyPanicWipeClearsSettingsManagerVolatileCachesAndSecrets) {
    auto bootstrap = create_sqlcipher_bootstrap(db_path_);
    bootstrap->initialize_ratchet_session_manager(UserId("user-wipe-settings"), DeviceId("dev-wipe-settings"));
    auto& settings_mgr = bootstrap->settings_manager();

    UserSettings settings;
    settings.high_contrast_enabled = true;
    settings.proxy.type = ProxyType::Http;
    settings.proxy.host = "proxy.wipe.test";
    settings.proxy.port = 8080U;
    ASSERT_TRUE(settings_mgr.save_settings(settings, SecretString("wipe-proxy-pass")).is_ok());

    UserProfile profile;
    profile.user_id = UserId("user-wipe-settings");
    profile.display_name = "Wipe Test User";
    ASSERT_TRUE(settings_mgr.update_profile(profile, /*sync_public_fields_to_gateway=*/false).is_ok());

    const auto gen_res = settings_mgr.generate_recovery_phrase();
    ASSERT_TRUE(gen_res.is_ok());
    std::vector<std::pair<std::size_t, std::string>> answers;
    {
        std::vector<std::string> words;
        std::string cur;
        for (const char ch : gen_res.value().mnemonic.expose_unredacted_secret()) {
            if (ch == ' ') {
                words.push_back(cur);
                cur.clear();
            } else {
                cur.push_back(ch);
            }
        }
        if (!cur.empty()) {
            words.push_back(cur);
        }
        for (const std::size_t idx : gen_res.value().challenge.word_indices) {
            answers.emplace_back(idx, words[idx]);
        }
    }
    ASSERT_TRUE(settings_mgr.confirm_recovery_phrase_backup(gen_res.value().mnemonic, answers).is_ok());
    ASSERT_TRUE(settings_mgr.cached_profile().has_value());
    ASSERT_TRUE(settings_mgr.has_saved_proxy_password());
    ASSERT_TRUE(settings_mgr.has_verified_recovery_phrase());

    const auto wipe_res = bootstrap->emergency_manager().execute_panic_wipe(PanicTriggerSource::UiPanicButton,
                                                                            PostWipeMode::EmergencyLocked);
    ASSERT_TRUE(wipe_res.is_ok());
    EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
    EXPECT_EQ(wipe_res.value().volatile_caches_cleared, 6U);

    EXPECT_FALSE(settings_mgr.cached_profile().has_value());
    EXPECT_FALSE(settings_mgr.current_settings().high_contrast_enabled);
    EXPECT_FALSE(settings_mgr.has_saved_proxy_password());
    EXPECT_FALSE(settings_mgr.has_verified_recovery_phrase());
    EXPECT_TRUE(bootstrap->config().proxy_password.empty());
    EXPECT_TRUE(bootstrap->secure_storage().list_secret_keys().value().empty());
}

} // namespace
