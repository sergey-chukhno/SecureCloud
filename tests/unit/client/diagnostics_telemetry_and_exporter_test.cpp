#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/diagnostic_sanitizer.hpp"
#include "application/managers/diagnostics_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/settings_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/file_transfer.hpp"
#include "domain/offline_sync_models.hpp"
#include "domain/user_id.hpp"
#include "domain/user_profile.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/platform_telemetry_collector.hpp"
#include "infrastructure/adapters/qt_http_gateway_client.hpp"
#include "infrastructure/adapters/switchable_gateway_client.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <vector>

namespace securecloud::client::application::managers::test {
namespace {

using common::configuration::SecretString;
using infrastructure::adapters::PlatformTelemetryCollector;
using infrastructure::adapters::SwitchableGatewayClient;

class DiagnosticsTelemetryAndExporterTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_diagnostics_test_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = (temp_dir_ / "diag_vault.db").string();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::vector<uint8_t> read_binary_file(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    static std::string read_raw_string(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    static void write_binary_file(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(ofs.is_open());
        ofs.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        ofs.flush();
        ASSERT_TRUE(ofs.good());
        ofs.close();
    }

    std::filesystem::path temp_dir_;
    std::string db_path_;
};

TEST_F(DiagnosticsTelemetryAndExporterTest, PlatformTelemetryCollectorAndLiveManagerMetricsTrackRuntimeState) {
    PlatformTelemetryCollector collector;
    const auto first_sample = collector.sample();
    EXPECT_GT(first_sample.rss_bytes, 0U);
    EXPECT_GT(first_sample.rss_megabytes, 0.0);
    EXPECT_TRUE(std::isfinite(first_sample.cpu_percent));
    EXPECT_GE(first_sample.cpu_percent, 0.0);
    EXPECT_GT(first_sample.sampled_at_ms, 0);

    // Burn a tiny amount of deterministic CPU work before second sample.
    volatile uint64_t accumulator = 0U;
    for (uint64_t i = 0U; i < 200000U; ++i) {
        accumulator += i;
    }
    (void)accumulator;

    const auto second_sample = collector.sample();
    EXPECT_GT(second_sample.rss_bytes, 0U);
    EXPECT_TRUE(std::isfinite(second_sample.cpu_percent));
    EXPECT_GE(second_sample.cpu_percent, 0.0);

    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_;
    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());

    auto& bootstrap = app.bootstrap();
    const auto initial_snap = bootstrap.diagnostics_manager().collect_telemetry();
    EXPECT_GT(initial_snap.rss_bytes, 0U);
    EXPECT_EQ(initial_snap.active_ratchet_sessions, 0U);
    EXPECT_EQ(initial_snap.pending_outbox_count, 0U);
    EXPECT_EQ(initial_snap.active_file_transfers, 0U);
    EXPECT_EQ(initial_snap.connectivity_state, domain::ConnectivityState::Online);

    // Register local alice device & remote bob device in simulated gateway so X3DH + Double Ratchet session
    // establishes.
    const domain::UserId alice("usr-alice-diag");
    const domain::UserId bob("usr-bob-diag");
    auto alice_dev_res = bootstrap.device_manager().register_device(alice, "AliceWorkstation");
    ASSERT_TRUE(alice_dev_res.is_ok());
    bootstrap.initialize_ratchet_session_manager(alice, alice_dev_res.value().device_id());

    auto bob_id = bootstrap.crypto_provider().generate_identity_keypair();
    ASSERT_TRUE(bob_id.is_ok());
    auto bob_spk = bootstrap.crypto_provider().generate_signed_prekey(bob_id.value().private_key);
    ASSERT_TRUE(bob_spk.is_ok());
    auto bob_otk = bootstrap.crypto_provider().generate_one_time_prekeys(1U, 1U);
    ASSERT_TRUE(bob_otk.is_ok());
    domain::PrekeyBundle bob_bundle(bob_id.value().public_key, bob_spk.value().public_key, bob_spk.value().signature,
                                    {bob_otk.value().front().record});
    auto bob_reg = bootstrap.gateway().register_device(bob, bob_bundle);
    ASSERT_TRUE(bob_reg.is_ok());

    const auto bob_fp = bootstrap.crypto_provider().compute_identity_fingerprint(bob_id.value().public_key);
    ASSERT_TRUE(bob_fp.is_ok());
    const interfaces::DeviceCryptoDirectoryEntry bob_entry{
        .device_id = bob_reg.value().device_id,
        .identity_key = bob_id.value().public_key,
        .signed_prekey = bob_spk.value().public_key,
        .signed_prekey_signature = bob_spk.value().signature,
        .one_time_prekey = bob_otk.value().front().record.public_key(),
        .one_time_prekey_id = bob_otk.value().front().record.id(),
        .status = domain::DeviceAuthorizationStatus::Authorized,
        .identity_key_fingerprint = bob_fp.value(),
        .remaining_one_time_prekeys = 1,
        .signed_prekey_created_at = std::chrono::system_clock::now(),
    };
    auto* default_gw = dynamic_cast<infrastructure::adapters::DefaultGatewayClient*>(&bootstrap.gateway());
    ASSERT_NE(default_gw, nullptr);
    default_gw->set_simulated_user_directory(bob, {bob_entry});

    const std::string hello = "telemetry session bootstrap";
    const std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(hello.data()), hello.size());
    ASSERT_TRUE(
        bootstrap.ratchet_session_manager()->encrypt_for_device(bob, bob_reg.value().device_id, pt_span).is_ok());

    // Queue an offline message into durable outbox.
    const auto conv_res = bootstrap.messaging_manager().open_direct_conversation(alice, bob, "DiagConv");
    ASSERT_TRUE(conv_res.is_ok());
    const domain::ConversationId cid = conv_res.value().conversation_id();
    bootstrap.messaging_manager().set_offline_mode(true);
    ASSERT_TRUE(bootstrap.messaging_manager()
                    .stage_outbound_message(cid, alice, alice_dev_res.value().device_id(), "queued offline")
                    .is_ok());

    // Save an in-progress file transfer record.
    domain::FileTransferRecord transfer;
    transfer.transfer_id = "tx-diag-1";
    transfer.file_id = "file-diag-1";
    transfer.conversation_id = cid;
    transfer.peer_user_id = bob;
    transfer.file_name = "report.bin";
    transfer.status = domain::FileTransferStatus::InProgress;
    transfer.plaintext_size_bytes = 4096U;
    transfer.encrypted_size_bytes = 4124U;
    transfer.total_chunks = 1U;
    transfer.created_at_ms = 1760000001000LL;
    transfer.updated_at_ms = 1760000001000LL;
    ASSERT_TRUE(bootstrap.local_store().save_file_transfer(transfer).is_ok());

    ASSERT_TRUE(bootstrap.sync_manager().set_simulated_offline(true).is_ok());

    const auto active_snap = bootstrap.diagnostics_manager().collect_telemetry();
    EXPECT_EQ(active_snap.active_ratchet_sessions, 1U);
    EXPECT_GE(active_snap.pending_outbox_count, 1U);
    EXPECT_GE(active_snap.active_file_transfers, 1U);
    EXPECT_EQ(active_snap.connectivity_state, domain::ConnectivityState::Offline);

    const nlohmann::json snap_json = nlohmann::json::parse(active_snap.to_json(), nullptr, false);
    ASSERT_FALSE(snap_json.is_discarded());
    EXPECT_EQ(snap_json["active_ratchet_sessions"].get<std::size_t>(), 1U);

    // Verify SwitchableGatewayClient -> QtHttpGatewayClient RTT tracking records live transport attempts cleanly.
    ClientConfig rtt_cfg = ClientConfig::create_default();
    rtt_cfg.use_live_gateway_transport = true;
    rtt_cfg.gateway_url = "https://127.0.0.1";
    rtt_cfg.gateway_port = 1;
    rtt_cfg.connect_timeout_ms = std::chrono::milliseconds(150);
    rtt_cfg.request_timeout_ms = std::chrono::milliseconds(150);
    SwitchableGatewayClient switchable_gw(rtt_cfg);
    (void)switchable_gw.probe_gateway("/health/live");
    const auto rtt_metrics = switchable_gw.transport_metrics();
    EXPECT_GE(rtt_metrics.requests_total, 1U);
    EXPECT_GE(rtt_metrics.requests_failed, 1U);
    EXPECT_GE(rtt_metrics.last_rtt_ms, 0);

    EXPECT_TRUE(app.shutdown().is_ok());
}

TEST_F(DiagnosticsTelemetryAndExporterTest, TwelveCategorySecretAndPiiCanarySuiteHasZeroLeakageInBundleOrDisk) {
    // All 12 secret/PII categories required by CLIENT-015-T03
    const std::string c1_password = "canPass_99xA_secretPW";
    const std::string c2_duress_pin = "canDur_884422_PIN";
    const std::string c3_bearer_jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJjYW5hcnlfMTIifQ.c2lnX2NhbmFyeV8xMg";
    const std::string c4_proxy_pass = "canProxy_77xB_pw";
    const std::string c5_ed25519_pem = "MC4CAQAwBQYDK2VwBCIEICanaryEd25519PrivMaterial";
    const std::string c6_x25519_priv = "canX25519_priv_hex_deadbeef11223344";
    const std::string c7_root_key = "canRootKey_cafebabe99887766";
    const std::string c8_file_key = "canFileKey_0123456789abcdef";
    const std::string c9_sqlcipher_key = "canSqlKey_feedface88776655";
    const std::string c10_bip39 = "abandon ability able about above absent absorb abstract canaryword12";
    const std::string c10_verifier = "sc-bip39-v1:canarydigest9900";
    const std::string c11_plaintext = "UltraSecretPlaintextBodyCanary99";
    const std::string c12_email = "alice.canary@example.org";
    const std::string c12_handle = "@alice_canary_handle";
    const std::string c12_display_name = "Alice Canary DisplayName";
    const std::string c12_mac_user = "canaryuser_mac";
    const std::string c12_linux_user = "canaryuser_linux";
    const std::string c12_win_user = "canaryuser_win";

    const std::vector<std::string> all_canaries = {
        c1_password, c2_duress_pin, c3_bearer_jwt,    c4_proxy_pass,  c5_ed25519_pem, c6_x25519_priv,
        c7_root_key, c8_file_key,   c9_sqlcipher_key, "canaryword12", c10_verifier,   c11_plaintext,
        c12_email,   c12_handle,    c12_display_name, c12_mac_user,   c12_linux_user, c12_win_user,
    };

    // Direct DiagnosticSanitizer checks across paths, handles, PEMs, and JSON/KV fields
    const std::string raw_sample =
        "Authorization: Bearer " + c3_bearer_jwt + " password=" + c1_password + " duress_pin=" + c2_duress_pin +
        " proxy_username: " + c12_display_name + " x25519_private=" + c6_x25519_priv + " root_key=" + c7_root_key +
        " file_key=" + c8_file_key + " sqlcipher_key=" + c9_sqlcipher_key + " mnemonic=\"" + c10_bip39 +
        "\" verifier=" + c10_verifier + " plaintext=\"" + c11_plaintext + "\" email=" + c12_email +
        " handle=" + c12_handle + " -----BEGIN PRIVATE KEY-----\n" + c5_ed25519_pem + "\n-----END PRIVATE KEY----- " +
        "/Users/" + c12_mac_user + "/vault.db /home/" + c12_linux_user + "/logs.txt C:\\Users\\" + c12_win_user +
        "\\AppData";

    EXPECT_TRUE(DiagnosticSanitizer::contains_unredacted_secret_marker(raw_sample));
    const std::string scrubbed = DiagnosticSanitizer::scrub_text(raw_sample, {c12_display_name});
    EXPECT_FALSE(DiagnosticSanitizer::contains_unredacted_secret_marker(scrubbed));
    for (const auto& canary : all_canaries) {
        EXPECT_EQ(scrubbed.find(canary), std::string::npos) << "Canary leaked in DiagnosticSanitizer: " << canary;
    }

    // Full ClientBootstrap -> DiagnosticsManager -> encrypted .scdiag export pipeline test
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_;
    cfg.auth_token = SecretString(c3_bearer_jwt);
    cfg.proxy_type = domain::ProxyType::Socks5;
    cfg.proxy_host = "127.0.0.1";
    cfg.proxy_port = 1080;
    cfg.proxy_username = "canary_proxy_user";
    cfg.proxy_password = SecretString(c4_proxy_pass);

    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());

    // Cache a profile with PII and inject adversarial strings into extra audit events.
    domain::UserProfile profile;
    profile.user_id = domain::UserId("usr-canary-profile");
    profile.display_name = c12_display_name;
    profile.public_handle = "alice_canary_handle";
    profile.bio_status = "Contact " + c12_email;
    profile.updated_at_ms = 1760000002000LL;
    ASSERT_TRUE(app.bootstrap().settings_manager().update_profile(profile, false).is_ok());

    ASSERT_TRUE(app.bootstrap()
                    .local_audit_logger()
                    ->record_event(domain::LocalAuditCategory::SettingsNetwork, "test.canary_payload",
                                   domain::LocalAuditOutcome::Success, c12_email, "target-1",
                                   "pw=" + c1_password + " duress_pin=" + c2_duress_pin +
                                       " x25519_private=" + c6_x25519_priv + " root_key=" + c7_root_key +
                                       " file_key=" + c8_file_key + " sqlcipher_key=" + c9_sqlcipher_key +
                                       " mnemonic=\"" + c10_bip39 + "\" verifier=" + c10_verifier + " plaintext=\"" +
                                       c11_plaintext + "\" /Users/" + c12_mac_user + "/vault.db")
                    .is_ok());

    const std::filesystem::path bundle_path = temp_dir_ / "zero_leak.scdiag";
    const auto export_res = app.bootstrap().diagnostics_manager().export_encrypted_bundle(
        bundle_path, std::nullopt, DiagnosticsManager::kDefaultMaxAuditEvents,
        {c5_ed25519_pem, c12_linux_user, c12_win_user});
    ASSERT_TRUE(export_res.is_ok()) << export_res.error().user_message();
    EXPECT_FALSE(export_res.value().used_passphrase);
    EXPECT_EQ(export_res.value().generated_export_key_hex.size(), 64U);

    // 1. Raw encrypted .scdiag ciphertext on disk must contain zero plaintext structure or canaries.
    const std::string raw_disk = read_raw_string(bundle_path);
    EXPECT_EQ(raw_disk.find("safe_config"), std::string::npos);
    EXPECT_EQ(raw_disk.find("telemetry"), std::string::npos);
    for (const auto& canary : all_canaries) {
        EXPECT_EQ(raw_disk.find(canary), std::string::npos) << "Canary leaked on disk in .scdiag: " << canary;
    }

    // 2. Decrypt and inspect every character of decrypted JSON: ZERO canaries allowed.
    const auto decrypted_res =
        DiagnosticsManager::decrypt_and_verify_bundle(bundle_path, export_res.value().generated_export_key_hex);
    ASSERT_TRUE(decrypted_res.is_ok()) << decrypted_res.error().user_message();
    const std::string& decrypted_json = decrypted_res.value();
    EXPECT_FALSE(DiagnosticSanitizer::contains_unredacted_secret_marker(decrypted_json));

    for (const auto& canary : all_canaries) {
        EXPECT_EQ(decrypted_json.find(canary), std::string::npos)
            << "Canary leaked in decrypted .scdiag JSON: " << canary;
    }
    EXPECT_EQ(decrypted_json.find("canary_proxy_user"), std::string::npos);
    EXPECT_EQ(decrypted_json.find("alice_canary_handle"), std::string::npos);

    EXPECT_TRUE(app.shutdown().is_ok());
}

TEST_F(DiagnosticsTelemetryAndExporterTest, EncryptedScdiagPassphraseAndCsprngRoundTripAndTamperRejection) {
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_;
    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());

    auto& diag = app.bootstrap().diagnostics_manager();

    // 1. Passphrase-derived export & verification
    const std::filesystem::path pass_bundle = temp_dir_ / "pass_bundle.scdiag";
    const SecretString pass("correct-horse-battery-canary");
    const auto pass_export = diag.export_encrypted_bundle(pass_bundle, pass);
    ASSERT_TRUE(pass_export.is_ok()) << pass_export.error().user_message();
    EXPECT_TRUE(pass_export.value().used_passphrase);
    EXPECT_TRUE(pass_export.value().generated_export_key_hex.empty());
    EXPECT_GT(pass_export.value().plaintext_bytes, 0U);
    EXPECT_GT(pass_export.value().encrypted_bytes, 54U);
    EXPECT_EQ(pass_export.value().bundle_sha256_hex.size(), 64U);

    const auto raw_pass_bytes = read_binary_file(pass_bundle);
    const auto computed_digest = domain::crypto::StreamingSha256::digest_hex(raw_pass_bytes);
    ASSERT_TRUE(computed_digest.is_ok());
    EXPECT_EQ(computed_digest.value(), pass_export.value().bundle_sha256_hex);

    const auto dec_ok = DiagnosticsManager::decrypt_and_verify_bundle(pass_bundle, pass);
    ASSERT_TRUE(dec_ok.is_ok()) << dec_ok.error().user_message();
    const nlohmann::json parsed_json = nlohmann::json::parse(dec_ok.value(), nullptr, false);
    ASSERT_FALSE(parsed_json.is_discarded());
    EXPECT_EQ(parsed_json["format_version"].get<int>(), 1);
    EXPECT_TRUE(parsed_json["crypto_self_test"]["overall_passed"].get<bool>());
    EXPECT_TRUE(parsed_json["audit_chain_verification"]["valid"].get<bool>());

    // Wrong passphrase must fail closed.
    EXPECT_TRUE(
        DiagnosticsManager::decrypt_and_verify_bundle(pass_bundle, SecretString("wrong-passphrase")).is_error());

    // 2. Tamper detection: 1-bit flip in header AAD, GCM tag, and ciphertext must ALL fail.
    {
        auto tamper_header = raw_pass_bytes;
        tamper_header[12] ^= 0x01U;
        const std::filesystem::path p = temp_dir_ / "tamper_hdr.scdiag";
        write_binary_file(p, tamper_header);
        EXPECT_TRUE(DiagnosticsManager::decrypt_and_verify_bundle(p, pass).is_error());
    }
    {
        auto tamper_tag = raw_pass_bytes;
        tamper_tag[40] ^= 0x01U;
        const std::filesystem::path p = temp_dir_ / "tamper_tag.scdiag";
        write_binary_file(p, tamper_tag);
        EXPECT_TRUE(DiagnosticsManager::decrypt_and_verify_bundle(p, pass).is_error());
    }
    {
        auto tamper_ct = raw_pass_bytes;
        tamper_ct.back() ^= 0x01U;
        const std::filesystem::path p = temp_dir_ / "tamper_ct.scdiag";
        write_binary_file(p, tamper_ct);
        EXPECT_TRUE(DiagnosticsManager::decrypt_and_verify_bundle(p, pass).is_error());
    }

    // 3. Invalid paths and empty passphrases fail closed with zero .tmp artifacts.
    EXPECT_TRUE(diag.export_encrypted_bundle(std::filesystem::path{}).is_error());
    EXPECT_TRUE(diag.export_encrypted_bundle(temp_dir_).is_error());
    EXPECT_TRUE(diag.export_encrypted_bundle(temp_dir_ / "nonexistent_subdir" / "out.scdiag").is_error());
    EXPECT_TRUE(diag.export_encrypted_bundle(temp_dir_ / "empty_pass.scdiag", SecretString("")).is_error());
    EXPECT_FALSE(std::filesystem::exists(temp_dir_ / "empty_pass.scdiag.tmp"));

    // Verify export action itself was recorded cleanly in hash-chained local audit log.
    const auto verify_chain = app.bootstrap().local_audit_logger()->verify_chain_integrity();
    ASSERT_TRUE(verify_chain.is_ok());
    EXPECT_TRUE(verify_chain.value().valid);
    const auto recent = app.bootstrap().local_audit_logger()->recent_events(5U);
    ASSERT_TRUE(recent.is_ok());
    EXPECT_EQ(recent.value().front().event_type, "diagnostics.bundle_exported");

    EXPECT_TRUE(app.shutdown().is_ok());
}

} // namespace
} // namespace securecloud::client::application::managers::test
