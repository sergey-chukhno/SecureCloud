#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/double_ratchet_engine.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/crypto/ratchet_models.hpp"
#include "domain/crypto/x3dh_engine.hpp"
#include "domain/delivery_state.hpp"
#include "domain/device_id.hpp"
#include "domain/device_private_bundle.hpp"
#include "domain/file_transfer.hpp"
#include "domain/message.hpp"
#include "domain/message_id.hpp"
#include "domain/prekey_policy.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/key_storage_helper.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/platform_telemetry_collector.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "securecloud/configuration/secret_string.hpp"
#include "ui/app_view_model.hpp"
#include "ui/diagnostics_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QGuiApplication>
#include <QProcess>
#include <QProcessEnvironment>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QQuickItem>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QUrl>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <optional>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef SECURECLOUD_CLIENT_BINARY_PATH
#define SECURECLOUD_CLIENT_BINARY_PATH ""
#endif

namespace securecloud::client::tests {
namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::domain::crypto;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;
using common::configuration::SecretString;

[[nodiscard]] bool is_full_benchmark_mode() noexcept {
    const char* env = std::getenv("SECURECLOUD_RUN_CLIENT_BENCHMARKS");
    return env != nullptr && std::string_view(env) == "1";
}

[[nodiscard]] std::string build_mode_label() noexcept {
#ifdef NDEBUG
    return "Release";
#else
    return "Debug";
#endif
}

struct LatencyStats {
    double mean_ms{0.0};
    double p50_ms{0.0};
    double p95_ms{0.0};
    double p99_ms{0.0};
    double max_ms{0.0};
};

[[nodiscard]] LatencyStats compute_latency_stats_ms(std::vector<double> samples_ms) {
    LatencyStats stats;
    if (samples_ms.empty()) {
        return stats;
    }
    std::sort(samples_ms.begin(), samples_ms.end());
    const double sum = std::accumulate(samples_ms.begin(), samples_ms.end(), 0.0);
    stats.mean_ms = sum / static_cast<double>(samples_ms.size());

    auto percentile = [&](double p) -> double {
        const double idx_f = p * static_cast<double>(samples_ms.size() - 1U);
        const std::size_t idx = static_cast<std::size_t>(std::ceil(idx_f));
        return samples_ms[std::min(idx, samples_ms.size() - 1U)];
    };

    stats.p50_ms = percentile(0.50);
    stats.p95_ms = percentile(0.95);
    stats.p99_ms = percentile(0.99);
    stats.max_ms = samples_ms.back();
    return stats;
}

/// Deterministic NUL-free fixed-block padding helper aligning with ADR-008 §26 / ADR-010 §16.
[[nodiscard]] std::string pad_to_fixed_block(std::string_view plaintext, std::size_t block_size) {
    constexpr std::size_t kHeaderBytes = 6U; // 5-digit length + ':'
    const std::size_t needed = kHeaderBytes + plaintext.size();
    const std::size_t padded_len = ((needed + block_size - 1U) / block_size) * block_size;
    std::string out;
    out.reserve(padded_len);

    char header[8] = {};
    std::snprintf(header, sizeof(header), "%05zu:", plaintext.size());
    out.append(header, kHeaderBytes);
    out.append(plaintext.data(), plaintext.size());
    if (out.size() < padded_len) {
        out.append(padded_len - out.size(), ' ');
    }
    return out;
}

[[nodiscard]] std::optional<std::string> unpad_fixed_block(std::string_view padded) {
    constexpr std::size_t kHeaderBytes = 6U;
    if (padded.size() < kHeaderBytes || padded[5] != ':') {
        return std::nullopt;
    }
    std::size_t len = 0U;
    for (std::size_t i = 0U; i < 5U; ++i) {
        const char ch = padded[i];
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        len = (len * 10U) + static_cast<std::size_t>(ch - '0');
    }
    if (kHeaderBytes + len > padded.size()) {
        return std::nullopt;
    }
    return std::string(padded.substr(kHeaderBytes, len));
}

class ForwardingSecureStorage final : public ISecureStorage {
  public:
    explicit ForwardingSecureStorage(std::shared_ptr<MemorySecureStorage> inner) : inner_(std::move(inner)) {}

    ClientResult<void> store_secret(std::string_view key_id, const SecretString& secret) override {
        return inner_->store_secret(key_id, secret);
    }
    ClientResult<SecretString> get_secret(std::string_view key_id) override { return inner_->get_secret(key_id); }
    ClientResult<void> delete_secret(std::string_view key_id) override { return inner_->delete_secret(key_id); }
    ClientResult<bool> has_secret(std::string_view key_id) override { return inner_->has_secret(key_id); }
    ClientResult<std::vector<std::string>> list_secret_keys() override { return inner_->list_secret_keys(); }
    ClientResult<std::size_t> purge_all_secrets() override { return inner_->purge_all_secrets(); }

  private:
    std::shared_ptr<MemorySecureStorage> inner_;
};

/// Gateway adapter that mirrors remote encrypted chunk upload ingestion by hashing & releasing
/// each incoming chunk buffer rather than buffering multi-MiB server storage in the client process RSS.
class StreamingSinkGateway final : public IGatewayClient {
  public:
    explicit StreamingSinkGateway(const ClientConfig& cfg) : inner_(cfg) {}

    DefaultGatewayClient& inner() noexcept { return inner_; }
    [[nodiscard]] std::size_t uploaded_chunks() const noexcept { return uploaded_chunks_; }
    [[nodiscard]] uint64_t uploaded_bytes() const noexcept { return uploaded_bytes_; }

    ClientResult<bool> probe_gateway(std::string_view path) override { return inner_.probe_gateway(path); }
    ClientResult<std::string> send_message(const ConversationId& cid, std::string_view env) override {
        return inner_.send_message(cid, env);
    }
    ClientResult<std::string> submit_encrypted_message(const FanOutSubmissionRequest& req) override {
        return inner_.submit_encrypted_message(req);
    }
    ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) override {
        return inner_.sync_messages(cursor);
    }
    ClientResult<DeliveryState> acknowledge_delivery(const MessageId& mid, const DeviceId& did, int64_t ts) override {
        return inner_.acknowledge_delivery(mid, did, ts);
    }
    ClientResult<DeliveryState> send_read_receipt(const ConversationId& cid, const MessageId& mid, const DeviceId& did,
                                                  int64_t ts) override {
        return inner_.send_read_receipt(cid, mid, did, ts);
    }
    ClientResult<MessageDeliveryStatusInfo> get_message_delivery_status(const ConversationId& cid,
                                                                        const MessageId& mid) override {
        return inner_.get_message_delivery_status(cid, mid);
    }
    ClientResult<ConversationMessagesPage> fetch_conversation_messages(const ConversationId& cid, const DeviceId& did,
                                                                       uint64_t seq, std::size_t max) override {
        return inner_.fetch_conversation_messages(cid, did, seq, max);
    }
    ClientResult<SyncCursorRecord> get_sync_cursor(const DeviceId& did, const ConversationId& cid) override {
        return inner_.get_sync_cursor(did, cid);
    }
    ClientResult<SyncCursorRecord> update_sync_cursor(const SyncCursorRecord& cursor) override {
        return inner_.update_sync_cursor(cursor);
    }
    ClientResult<std::vector<RemoteConversationSummary>> list_remote_conversations(const UserId& uid,
                                                                                   std::size_t max) override {
        return inner_.list_remote_conversations(uid, max);
    }
    uint64_t subscribe_realtime_events(RealtimeEventHandler handler) override {
        return inner_.subscribe_realtime_events(std::move(handler));
    }
    void unsubscribe_realtime_events(uint64_t sub_id) override { inner_.unsubscribe_realtime_events(sub_id); }
    ClientResult<bool> validate_token(std::string_view token) override { return inner_.validate_token(token); }
    ClientResult<void> disconnect() override { return inner_.disconnect(); }
    ClientResult<DeviceRegistrationResult> register_device(const UserId& uid, const PrekeyBundle& bundle) override {
        return inner_.register_device(uid, bundle);
    }
    ClientResult<PrekeyUpdateResult> update_crypto_prekeys(const DeviceId& did, std::optional<std::vector<uint8_t>> spk,
                                                           std::optional<std::vector<uint8_t>> sig,
                                                           std::vector<OneTimePrekeyRecord> otpks) override {
        return inner_.update_crypto_prekeys(did, std::move(spk), std::move(sig), std::move(otpks));
    }
    ClientResult<PrekeyInventoryStatus> get_prekey_inventory_status(const DeviceId& did) override {
        return inner_.get_prekey_inventory_status(did);
    }
    ClientResult<std::vector<DeviceCryptoDirectoryEntry>>
    get_device_crypto_directory(const UserId& uid, const std::vector<DeviceId>& dids) override {
        return inner_.get_device_crypto_directory(uid, dids);
    }
    ClientResult<PairingInitiationResult> initiate_device_pairing(const DeviceId& did) override {
        return inner_.initiate_device_pairing(did);
    }
    ClientResult<void> authorize_device_pairing(const DeviceId& did, std::string_view code,
                                                std::string_view mfa) override {
        return inner_.authorize_device_pairing(did, code, mfa);
    }
    ClientResult<std::vector<Device>> list_user_devices(const UserId& uid) override {
        return inner_.list_user_devices(uid);
    }
    ClientResult<void> revoke_device(const DeviceId& did, std::string_view mfa) override {
        return inner_.revoke_device(did, mfa);
    }
    ClientResult<std::vector<DirectoryUserEntry>> search_directory_users(std::string_view query,
                                                                         std::size_t limit) override {
        return inner_.search_directory_users(query, limit);
    }
    ClientResult<DirectoryUserEntry> lookup_user_identity(const UserId& uid) override {
        return inner_.lookup_user_identity(uid);
    }

    ClientResult<FileUploadInitResult> init_file_upload(const FileUploadInitRequest& request) override {
        ++upload_counter_;
        const std::string uid = "upl-bench-" + std::to_string(upload_counter_);
        active_uploads_[uid] = request.file_id;
        return ClientResult<FileUploadInitResult>::ok(FileUploadInitResult{
            .upload_id = uid,
            .file_id = request.file_id,
            .status = "TRANSFER_STATUS_UPLOADING",
            .expires_at_unix_ms = 0,
        });
    }

    ClientResult<FileChunkUploadResult> upload_file_chunk(const FileChunkUploadRequest& request) override {
        const auto sha_res = StreamingSha256::digest_hex(request.encrypted_data);
        if (sha_res.is_error()) {
            return ClientResult<FileChunkUploadResult>::error(sha_res.error());
        }
        if (sha_res.value() != request.ciphertext_sha256) {
            return ClientResult<FileChunkUploadResult>::error(ClientError::crypto("Chunk SHA-256 mismatch in sink"));
        }
        ++uploaded_chunks_;
        uploaded_bytes_ += static_cast<uint64_t>(request.encrypted_data.size());
        return ClientResult<FileChunkUploadResult>::ok(FileChunkUploadResult{
            .upload_id = request.upload_id,
            .chunk_index = request.chunk_index,
            .accepted = true,
            .received_sha256 = sha_res.value(),
        });
    }

    ClientResult<FileUploadFinalizeResult> finalize_file_upload(const FileUploadFinalizeRequest& request) override {
        active_uploads_.erase(request.upload_id);
        return ClientResult<FileUploadFinalizeResult>::ok(FileUploadFinalizeResult{
            .file_id = request.file_id,
            .lifecycle_state = "FILE_LIFECYCLE_STATE_AVAILABLE",
            .available_at_unix_ms = 0,
        });
    }

    ClientResult<void> cancel_file_upload(std::string_view upload_id, std::string_view reason) override {
        return inner_.cancel_file_upload(upload_id, reason);
    }
    ClientResult<RemoteFileMetadata> get_file_metadata(std::string_view file_id) override {
        return inner_.get_file_metadata(file_id);
    }
    ClientResult<FileChunkDownloadResult> download_file_chunk(std::string_view file_id, uint32_t chunk_index) override {
        return inner_.download_file_chunk(file_id, chunk_index);
    }
    ClientResult<void> delete_file(std::string_view file_id) override { return inner_.delete_file(file_id); }
    ClientResult<UserProfile> get_user_profile(const UserId& uid) override { return inner_.get_user_profile(uid); }
    ClientResult<UserProfileSyncResult> update_user_profile(const UserProfile& profile) override {
        return inner_.update_user_profile(profile);
    }
    ClientResult<TlsCertificateInfo> inspect_tls_certificate(std::string_view host, uint16_t port) override {
        return inner_.inspect_tls_certificate(host, port);
    }

  private:
    DefaultGatewayClient inner_;
    uint64_t upload_counter_{0U};
    std::unordered_map<std::string, std::string> active_uploads_;
    std::size_t uploaded_chunks_{0U};
    uint64_t uploaded_bytes_{0U};
};

class ClientPerformanceBenchmarkTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_client_bench_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "bench_vault.db";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    static std::unique_ptr<ClientApplication> create_persistent_app(const std::filesystem::path& db_path,
                                                                    std::shared_ptr<MemorySecureStorage> shared_storage,
                                                                    DefaultGatewayClient** out_gateway = nullptr) {
        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = db_path.string();
        auto gateway = std::make_unique<DefaultGatewayClient>(cfg);
        if (out_gateway != nullptr) {
            *out_gateway = gateway.get();
        }
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto sec = std::make_unique<ForwardingSecureStorage>(shared_storage);
        auto sql = std::make_unique<SqlCipherLocalStore>(*shared_storage, *crypto);

        auto bootstrap = ClientBootstrap::create_with_adapters(std::move(cfg), std::move(gateway), std::move(sql),
                                                               std::move(sec), std::move(crypto));
        auto app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        return app;
    }

    static std::pair<DevicePrivateBundle, DeviceCryptoDirectoryEntry>
    create_x3dh_identity(OpenSslCryptoProvider& crypto, const std::string& dev_id_str) {
        auto ik = crypto.generate_identity_keypair().value();
        auto spk = crypto.generate_signed_prekey(ik.private_key).value();
        auto otk = crypto.generate_dh_keypair().value();
        const std::string otpk_id = dev_id_str + "-otpk-1";
        std::unordered_map<std::string, SecretString> otpk_privs;
        otpk_privs.emplace(otpk_id, std::move(otk.private_key));

        DevicePrivateBundle priv(DeviceId(dev_id_str), ik.public_key, std::move(ik.private_key), spk.public_key,
                                 std::move(spk.private_key), spk.signature, std::move(otpk_privs));
        DeviceCryptoDirectoryEntry dir{
            .device_id = DeviceId(dev_id_str),
            .identity_key = priv.identity_public_key(),
            .signed_prekey = priv.signed_prekey_public_key(),
            .signed_prekey_signature = priv.signed_prekey_signature(),
            .one_time_prekey = otk.public_key,
            .one_time_prekey_id = otpk_id,
            .status = DeviceAuthorizationStatus::Authorized,
            .identity_key_fingerprint = crypto.compute_identity_fingerprint(priv.identity_public_key()).value_or(""),
            .remaining_one_time_prekeys = 1,
            .signed_prekey_created_at = std::chrono::system_clock::now(),
        };
        return {std::move(priv), std::move(dir)};
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

// Benchmark A: Idle Baseline RSS (< 80 MB) & Idle CPU (< 1%) of real securecloud-client process
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkA_IdleBaselineRssAndCpu) {
    const std::string bin_path = SECURECLOUD_CLIENT_BINARY_PATH;
    ASSERT_FALSE(bin_path.empty());
    ASSERT_TRUE(std::filesystem::exists(bin_path)) << "Missing binary: " << bin_path;

    const int idle_ms = is_full_benchmark_mode() ? 5000 : 1000;
    QProcess proc;
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    env.insert(QStringLiteral("QT_QPA_PLATFORM"), QStringLiteral("offscreen"));
    env.insert(QStringLiteral("SECURECLOUD_DATABASE_PATH"), QString::fromStdString((temp_dir_ / "idle.db").string()));
    proc.setProcessEnvironment(env);
    proc.start(QString::fromStdString(bin_path), {QStringLiteral("--benchmark-idle-ms"), QString::number(idle_ms)});
    ASSERT_TRUE(proc.waitForFinished(30000)) << "Idle benchmark process timed out";
    ASSERT_EQ(proc.exitStatus(), QProcess::NormalExit);
    ASSERT_EQ(proc.exitCode(), 0);

    const std::string stdout_str = proc.readAllStandardOutput().toStdString();
    static const std::regex kIdleRe(
        "\\[SecureCloud BenchmarkIdle\\] idle_ms=(\\d+) rss_bytes=(\\d+) rss_mb=([0-9.]+) cpu_percent=([0-9.]+)");
    std::smatch match;
    ASSERT_TRUE(std::regex_search(stdout_str, match, kIdleRe)) << "Stdout missing metric line:\n" << stdout_str;

    const double rss_mb = std::stod(match[3].str());
    const double cpu_pct = std::stod(match[4].str());

    std::cout << std::fixed << std::setprecision(2) << "[BenchmarkA] mode=" << build_mode_label()
              << " full=" << (is_full_benchmark_mode() ? 1 : 0) << " idle_ms=" << idle_ms << " rss_mb=" << rss_mb
              << " cpu_percent=" << cpu_pct << "\n";

    EXPECT_GT(rss_mb, 0.0);
    EXPECT_LT(rss_mb, 80.0);
    EXPECT_GE(cpu_pct, 0.0);
    EXPECT_LT(cpu_pct, 1.0);
}

// Benchmark B: Loaded Workspace RSS (< 150 MB) with 50 Conversations / 5,000 SQLCipher Messages
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkB_LoadedWorkspaceRss50Conversations5000SqlCipherMessages) {
    const std::size_t kConvCount = 50U;
    const std::size_t msgs_per_conv = is_full_benchmark_mode() ? 100U : 20U;
    const std::size_t total_msgs = kConvCount * msgs_per_conv;

    auto shared_storage = std::make_shared<MemorySecureStorage>();
    const UserId alice("usr-bench-alice");
    const DeviceId dev("dev-bench-alice-1");

    const auto seed_start = std::chrono::steady_clock::now();
    {
        auto seed_app = create_persistent_app(db_path_, shared_storage);
        auto& store = seed_app->bootstrap().local_store();
        const auto base_tp = std::chrono::system_clock::now() - std::chrono::hours(24);

        for (std::size_t c = 0U; c < kConvCount; ++c) {
            const UserId peer("usr-bench-peer-" + std::to_string(c));
            const ConversationId cid("conv-bench-" + std::to_string(c));
            Conversation conv(cid, ConversationType::Direct, "Bench Peer " + std::to_string(c), {alice, peer}, base_tp,
                              base_tp);
            ASSERT_TRUE(store.save_conversation(conv).is_ok());

            Contact contact(peer, "Bench Peer " + std::to_string(c), KeyVerificationStatus::Verified,
                            "fp-bench-" + std::to_string(c));
            ASSERT_TRUE(store.save_contact(contact).is_ok());

            for (std::size_t m = 0U; m < msgs_per_conv; ++m) {
                const MessageId mid("msg-" + std::to_string(c) + "-" + std::to_string(m));
                const Message msg(mid, cid, (m % 2U == 0U) ? alice : peer, dev, DeliveryState::Delivered,
                                  base_tp + std::chrono::seconds(static_cast<int64_t>(m)),
                                  "SQLCipher encrypted workspace benchmark payload #" + std::to_string(m), 0,
                                  "Bench Sender");
                ASSERT_TRUE(store.save_message(msg).is_ok());
            }
        }
        EXPECT_TRUE(seed_app->shutdown().is_ok());
    }
    const double seed_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - seed_start).count();

    PlatformTelemetryCollector collector;
    const auto pre_sample = collector.sample();

    auto loaded_app = create_persistent_app(db_path_, shared_storage);
    NavigationController nav;
    AppViewModel app_vm(*loaded_app, nav);
    DiagnosticsViewModel diag_vm(*loaded_app, nav);
    WorkspaceViewModel workspace_vm(*loaded_app, nav);
    UiTheme theme;
    WindowStateManager win_state;
    app_vm.setWorkspaceViewModel(&workspace_vm);
    workspace_vm.setUiTheme(&theme);

    nav.setAuthenticated(true);
    ASSERT_TRUE(nav.navigateTo(NavigationController::NavigationState::MainWorkspace));
    workspace_vm.selectConversation(QStringLiteral("conv-bench-0"));
    EXPECT_EQ(workspace_vm.conversations().size(), static_cast<int>(kConvCount));
    EXPECT_EQ(workspace_vm.activeMessages().size(), static_cast<int>(msgs_per_conv));

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("diagnosticsViewModel"), &diag_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    {
        QQmlComponent workspace_comp(&engine, QUrl(QStringLiteral("qrc:/qml/WorkspacePlaceholder.qml")));
        ASSERT_TRUE(workspace_comp.isReady()) << workspace_comp.errorString().toStdString();
        QObject* root_obj = workspace_comp.create();
        ASSERT_NE(root_obj, nullptr);
        for (int i = 0; i < 6; ++i) {
            QCoreApplication::processEvents();
        }

        const auto loaded_sample = collector.sample();
        const double delta_mb = std::max(0.0, loaded_sample.rss_megabytes - pre_sample.rss_megabytes);

        std::cout << std::fixed << std::setprecision(2) << "[BenchmarkB] mode=" << build_mode_label()
                  << " convs=" << kConvCount << " total_msgs=" << total_msgs << " seed_ms=" << seed_ms
                  << " rss_mb=" << loaded_sample.rss_megabytes << " delta_mb=" << delta_mb << "\n";

        EXPECT_LT(loaded_sample.rss_megabytes, 150.0);

        delete root_obj;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    engine.clearComponentCache();
    EXPECT_TRUE(loaded_app->shutdown().is_ok());
}

// Benchmark C: Chunked Encrypted Streaming Buffer Overhead (< 32 MB RSS delta across 16 MiB transfer)
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkC_ChunkedEncryptedStreamingBufferOverhead) {
    const std::size_t file_size_bytes = is_full_benchmark_mode() ? (16U * 1024U * 1024U) : (8U * 1024U * 1024U);
    const std::filesystem::path payload_path = temp_dir_ / "streaming_benchmark.bin";
    {
        std::ofstream ofs(payload_path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(ofs.is_open());
        std::vector<char> block(65536U, 'S');
        for (std::size_t written = 0U; written < file_size_bytes; written += block.size()) {
            const std::size_t to_write = std::min(block.size(), file_size_bytes - written);
            ofs.write(block.data(), static_cast<std::streamsize>(to_write));
        }
        ofs.flush();
        ASSERT_TRUE(ofs.good());
        ofs.close();
    }

    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();
    auto gateway_ptr = std::make_unique<StreamingSinkGateway>(cfg);
    StreamingSinkGateway* sink_gw = gateway_ptr.get();
    auto crypto = std::make_unique<OpenSslCryptoProvider>();
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto sec = std::make_unique<ForwardingSecureStorage>(shared_storage);
    auto sql = std::make_unique<SqlCipherLocalStore>(*shared_storage, *crypto);

    auto bootstrap = ClientBootstrap::create_with_adapters(std::move(cfg), std::move(gateway_ptr), std::move(sql),
                                                           std::move(sec), std::move(crypto));
    ClientApplication app(std::move(bootstrap));
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());

    const UserId alice("usr-stream-alice");
    const UserId bob("usr-stream-bob");
    auto alice_dev = app.bootstrap().device_manager().register_device(alice, "StreamSender");
    ASSERT_TRUE(alice_dev.is_ok());
    app.bootstrap().initialize_ratchet_session_manager(alice, alice_dev.value().device_id());

    OpenSslCryptoProvider helper_crypto;
    const auto bob_ident = create_x3dh_identity(helper_crypto, "dev-stream-bob-1");
    sink_gw->inner().set_simulated_user_directory(bob, {bob_ident.second});

    const ConversationId cid("conv-stream-bench");
    Conversation conv(cid, ConversationType::Direct, "Stream Bench", {alice, bob});
    ASSERT_TRUE(app.bootstrap().local_store().save_conversation(conv).is_ok());
    ASSERT_TRUE(
        app.bootstrap().local_store().save_contact(Contact(bob, "Bob", KeyVerificationStatus::Verified, "fp")).is_ok());

    PlatformTelemetryCollector collector;
    const auto pre_sample = collector.sample();
    double peak_rss_mb = pre_sample.rss_megabytes;

    app.bootstrap().file_manager().set_progress_callback([&](const FileTransferRecord&) {
        const auto s = collector.sample();
        peak_rss_mb = std::max(peak_rss_mb, s.rss_megabytes);
    });

    application::managers::FileUploadRequest req;
    req.conversation_id = cid;
    req.owner_user_id = alice;
    req.owner_device_id = alice_dev.value().device_id();
    req.peer_user_id = bob;
    req.local_file_path = payload_path.string();
    req.sender_display_name = "Alice";
    req.dispatch_key_envelope = true;

    const auto start_tp = std::chrono::steady_clock::now();
    const auto upload_res = app.bootstrap().file_manager().start_upload(req);
    const double upload_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start_tp).count();
    ASSERT_TRUE(upload_res.is_ok()) << upload_res.error().user_message();

    const auto post_sample = collector.sample();
    peak_rss_mb = std::max(peak_rss_mb, post_sample.rss_megabytes);
    const double delta_mb = std::max(0.0, peak_rss_mb - pre_sample.rss_megabytes);

    std::cout << std::fixed << std::setprecision(2) << "[BenchmarkC] mode=" << build_mode_label()
              << " file_mib=" << (static_cast<double>(file_size_bytes) / (1024.0 * 1024.0))
              << " chunks=" << sink_gw->uploaded_chunks() << " elapsed_ms=" << upload_ms
              << " pre_rss_mb=" << pre_sample.rss_megabytes << " peak_rss_mb=" << peak_rss_mb
              << " delta_mb=" << delta_mb << "\n";

    EXPECT_GT(sink_gw->uploaded_chunks(), 1U);
    EXPECT_GT(sink_gw->uploaded_bytes(), file_size_bytes);
    EXPECT_LT(delta_mb, 32.0);
    EXPECT_TRUE(app.shutdown().is_ok());
}

// Benchmark D: Active Conversation Scroll & Render Frame Pacing (< 5% Active CPU at 60 fps)
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkD_ActiveConversationScrollAndFramePacing) {
    const std::size_t kMessageCount = is_full_benchmark_mode() ? 100U : 60U;
    const std::size_t kFrameCount = is_full_benchmark_mode() ? 120U : 30U;

    auto shared_storage = std::make_shared<MemorySecureStorage>();
    const UserId alice("usr-scroll-alice");
    const UserId bob("usr-scroll-bob");
    const ConversationId cid("conv-scroll-bench");
    const DeviceId dev("dev-scroll-1");

    {
        auto seed_app = create_persistent_app(db_path_, shared_storage);
        auto& store = seed_app->bootstrap().local_store();
        const auto base_tp = std::chrono::system_clock::now() - std::chrono::hours(1);
        ASSERT_TRUE(
            store.save_conversation(Conversation(cid, ConversationType::Direct, "Scroll Peer", {alice, bob})).is_ok());
        ASSERT_TRUE(
            store.save_contact(Contact(bob, "Scroll Peer", KeyVerificationStatus::Verified, "fp-scroll")).is_ok());
        for (std::size_t i = 0U; i < kMessageCount; ++i) {
            const MessageId mid("msg-scroll-" + std::to_string(i));
            const Message msg(mid, cid, (i % 2U == 0U) ? alice : bob, dev, DeliveryState::Delivered,
                              base_tp + std::chrono::seconds(static_cast<int64_t>(i)),
                              "Scroll frame pacing benchmark line #" + std::to_string(i) +
                                  " with standard multi-word body text.",
                              0, "Scroll Sender");
            ASSERT_TRUE(store.save_message(msg).is_ok());
        }
        EXPECT_TRUE(seed_app->shutdown().is_ok());
    }

    auto app = create_persistent_app(db_path_, shared_storage);
    NavigationController nav;
    AppViewModel app_vm(*app, nav);
    DiagnosticsViewModel diag_vm(*app, nav);
    WorkspaceViewModel workspace_vm(*app, nav);
    UiTheme theme;
    WindowStateManager win_state;
    app_vm.setWorkspaceViewModel(&workspace_vm);
    workspace_vm.setUiTheme(&theme);

    nav.setAuthenticated(true);
    ASSERT_TRUE(nav.navigateTo(NavigationController::NavigationState::MainWorkspace));
    workspace_vm.selectConversation(QStringLiteral("conv-scroll-bench"));
    ASSERT_EQ(workspace_vm.activeMessages().size(), static_cast<int>(kMessageCount));

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("diagnosticsViewModel"), &diag_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    QQuickWindow host_window;
    host_window.setWidth(1200);
    host_window.setHeight(800);
    host_window.show();

    {
        QQmlComponent workspace_comp(&engine, QUrl(QStringLiteral("qrc:/qml/WorkspacePlaceholder.qml")));
        ASSERT_TRUE(workspace_comp.isReady()) << workspace_comp.errorString().toStdString();
        QObject* root_obj = workspace_comp.create();
        auto* root_item = qobject_cast<QQuickItem*>(root_obj);
        ASSERT_NE(root_item, nullptr);
        root_item->setParentItem(host_window.contentItem());
        root_item->setWidth(1200.0);
        root_item->setHeight(800.0);

        for (int i = 0; i < 8; ++i) {
            QCoreApplication::processEvents();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        auto* msg_list = root_obj->findChild<QQuickItem*>(QStringLiteral("messageListView"));
        ASSERT_NE(msg_list, nullptr);
        const double content_h = msg_list->property("contentHeight").toDouble();
        const double view_h = msg_list->height();
        const double max_y = std::max(0.0, content_h - view_h);
        EXPECT_GT(max_y, 0.0);

        PlatformTelemetryCollector collector;
        (void)collector.sample();

        std::vector<double> work_ms;
        work_ms.reserve(kFrameCount);
        constexpr auto kFrameBudget = std::chrono::microseconds(16667); // 60 fps
        auto next_deadline = std::chrono::steady_clock::now();

        for (std::size_t frame = 0U; frame < kFrameCount; ++frame) {
            const auto work_start = std::chrono::steady_clock::now();
            const double progress = static_cast<double>(frame) / static_cast<double>(kFrameCount - 1U);
            msg_list->setProperty("contentY", max_y * (1.0 - progress));
            host_window.requestUpdate();
            QCoreApplication::processEvents();
            const double frame_ms =
                std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - work_start).count();
            work_ms.push_back(frame_ms);

            next_deadline += kFrameBudget;
            const auto now = std::chrono::steady_clock::now();
            if (now < next_deadline) {
                std::this_thread::sleep_until(next_deadline);
            }
        }

        const auto end_sample = collector.sample();
        const auto work_stats = compute_latency_stats_ms(work_ms);
        const unsigned int logical_cores = std::max(1U, std::thread::hardware_concurrency());
        const double single_core_cpu_pct = end_sample.cpu_percent * static_cast<double>(logical_cores);

        std::cout << std::fixed << std::setprecision(2) << "[BenchmarkD] mode=" << build_mode_label()
                  << " frames=" << kFrameCount << " logical_cores=" << logical_cores
                  << " active_cpu_percent=" << end_sample.cpu_percent
                  << " single_core_cpu_percent=" << single_core_cpu_pct << " mean_frame_work_ms=" << work_stats.mean_ms
                  << " p95_frame_work_ms=" << work_stats.p95_ms << " rss_mb=" << end_sample.rss_megabytes << "\n";

#if defined(NDEBUG)
        constexpr double kMaxActiveCpuPercent = 5.0;
#else
        constexpr double kMaxActiveCpuPercent = 8.0; // Debug (-O0) + offscreen software rendering
#endif

        EXPECT_LT(end_sample.cpu_percent, kMaxActiveCpuPercent);
        EXPECT_LT(work_stats.p95_ms, 16.67);

        delete root_obj;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    host_window.close();
    engine.clearComponentCache();
    EXPECT_TRUE(app->shutdown().is_ok());
}

// Benchmark E: Cold Startup Latency (< 1.5 seconds across N=5 fresh cold spawns)
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkE_ColdStartupLatency) {
    const std::string bin_path = SECURECLOUD_CLIENT_BINARY_PATH;
    ASSERT_FALSE(bin_path.empty());

    const std::size_t run_count = is_full_benchmark_mode() ? 5U : 3U;
    std::vector<double> durations_ms;
    durations_ms.reserve(run_count);

    for (std::size_t i = 0U; i < run_count; ++i) {
        QProcess proc;
        QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert(QStringLiteral("QT_QPA_PLATFORM"), QStringLiteral("offscreen"));
        env.insert(QStringLiteral("SECURECLOUD_DATABASE_PATH"),
                   QString::fromStdString((temp_dir_ / ("cold_" + std::to_string(i) + ".db")).string()));
        proc.setProcessEnvironment(env);

        const auto t0 = std::chrono::steady_clock::now();
        proc.start(QString::fromStdString(bin_path), {QStringLiteral("--smoke-test")});
        ASSERT_TRUE(proc.waitForFinished(30000));
        const double elapsed_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        ASSERT_EQ(proc.exitStatus(), QProcess::NormalExit);
        ASSERT_EQ(proc.exitCode(), 0);
        durations_ms.push_back(elapsed_ms);
    }

    const auto stats = compute_latency_stats_ms(durations_ms);
    std::cout << std::fixed << std::setprecision(2) << "[BenchmarkE] mode=" << build_mode_label()
              << " runs=" << run_count << " mean_ms=" << stats.mean_ms << " p50_ms=" << stats.p50_ms
              << " p95_ms=" << stats.p95_ms << " max_ms=" << stats.max_ms << "\n";

    EXPECT_LT(stats.p50_ms, 1500.0);
    EXPECT_LT(stats.p95_ms, 1500.0);
}

// Benchmark F: Real OpenSSL 3.x X3DH + Double Ratchet + AES-256-GCM Throughput on Fixed-Block Padded Payloads
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkF_DoubleRatchetAndAeadThroughputOnPaddedPayloads) {
    OpenSslCryptoProvider crypto;
    const std::size_t msg_count = is_full_benchmark_mode() ? 2000U : 400U;
    const std::vector<std::size_t> block_sizes = {256U, 1024U, 4096U};
    const std::string raw_sample = "Benchmark secret message payload checking real X3DH + Double Ratchet + AES-256-GCM";

    for (const std::size_t block_size : block_sizes) {
        auto alice_id = create_x3dh_identity(crypto, "dev-f-alice-" + std::to_string(block_size));
        auto bob_id = create_x3dh_identity(crypto, "dev-f-bob-" + std::to_string(block_size));

        const auto x3dh_init = X3dhEngine::initiate_handshake(crypto, alice_id.first, bob_id.second);
        ASSERT_TRUE(x3dh_init.is_ok());
        const auto x3dh_resp = X3dhEngine::process_handshake(crypto, bob_id.first, x3dh_init.value().header);
        ASSERT_TRUE(x3dh_resp.is_ok());

        auto alice_state = DoubleRatchetEngine::initialize_alice(crypto, x3dh_init.value().shared_secret,
                                                                 bob_id.first.signed_prekey_public_key())
                               .value();
        auto bob_state = DoubleRatchetEngine::initialize_bob(crypto, x3dh_resp.value().shared_secret,
                                                             DhKeyPair{bob_id.first.signed_prekey_public_key(),
                                                                       bob_id.first.signed_prekey_private_key()})
                             .value();

        std::vector<double> roundtrip_ms;
        roundtrip_ms.reserve(msg_count);
        const std::string padded = pad_to_fixed_block(raw_sample + " [" + std::to_string(block_size) + "]", block_size);
        const std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(padded.data()), padded.size());

        // Warmup 20 messages before timing
        for (int w = 0; w < 20; ++w) {
            auto enc = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, pt_span).value();
            auto dec = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, enc).value();
            EXPECT_EQ(unpad_fixed_block(dec.expose_unredacted_secret()).value_or(""),
                      raw_sample + " [" + std::to_string(block_size) + "]");
        }

        const auto batch_start = std::chrono::steady_clock::now();
        for (std::size_t i = 0U; i < msg_count; ++i) {
            const bool alice_to_bob = ((i / 10U) % 2U == 0U);
            auto& sender = alice_to_bob ? alice_state : bob_state;
            auto& receiver = alice_to_bob ? bob_state : alice_state;

            const auto m0 = std::chrono::steady_clock::now();
            auto enc_res = DoubleRatchetEngine::ratchet_encrypt(crypto, sender, pt_span);
            ASSERT_TRUE(enc_res.is_ok());
            auto dec_res = DoubleRatchetEngine::ratchet_decrypt(crypto, receiver, enc_res.value());
            ASSERT_TRUE(dec_res.is_ok());
            const double m_ms =
                std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - m0).count();
            roundtrip_ms.push_back(m_ms);

            const auto unpadded = unpad_fixed_block(dec_res.value().expose_unredacted_secret());
            ASSERT_TRUE(unpadded.has_value());
        }
        const double total_sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - batch_start).count();
        const double throughput = static_cast<double>(msg_count) / std::max(total_sec, 1e-9);
        const double padding_overhead_ratio =
            static_cast<double>(padded.size()) / static_cast<double>(raw_sample.size());
        const auto stats = compute_latency_stats_ms(roundtrip_ms);

        std::cout << std::fixed << std::setprecision(4) << "[BenchmarkF] mode=" << build_mode_label()
                  << " block_bytes=" << block_size << " msgs=" << msg_count
                  << " padding_ratio=" << padding_overhead_ratio << " mean_ms=" << stats.mean_ms
                  << " p50_ms=" << stats.p50_ms << " p95_ms=" << stats.p95_ms << " p99_ms=" << stats.p99_ms
                  << " max_ms=" << stats.max_ms << " throughput_msg_s=" << throughput << "\n";

        EXPECT_LT(stats.mean_ms, 2.0);
        EXPECT_LT(stats.p95_ms, 2.0);
        EXPECT_GT(throughput, 500.0);
    }

    // Multi-device 3-recipient fan-out benchmark (1 KiB padded block)
    const std::size_t fanout_msgs = is_full_benchmark_mode() ? 500U : 100U;
    std::vector<RatchetState> sender_sessions;
    std::vector<RatchetState> recipient_sessions;
    for (int d = 0; d < 3; ++d) {
        auto s_id = create_x3dh_identity(crypto, "dev-fan-s-" + std::to_string(d));
        auto r_id = create_x3dh_identity(crypto, "dev-fan-r-" + std::to_string(d));
        auto init = X3dhEngine::initiate_handshake(crypto, s_id.first, r_id.second).value();
        auto resp = X3dhEngine::process_handshake(crypto, r_id.first, init.header).value();
        sender_sessions.push_back(
            DoubleRatchetEngine::initialize_alice(crypto, init.shared_secret, r_id.first.signed_prekey_public_key())
                .value());
        recipient_sessions.push_back(
            DoubleRatchetEngine::initialize_bob(
                crypto, resp.shared_secret,
                DhKeyPair{r_id.first.signed_prekey_public_key(), r_id.first.signed_prekey_private_key()})
                .value());
    }

    const std::string fanout_padded = pad_to_fixed_block(raw_sample, 1024U);
    const std::span<const uint8_t> fanout_span(reinterpret_cast<const uint8_t*>(fanout_padded.data()),
                                               fanout_padded.size());
    std::vector<double> fanout_lat_ms;
    fanout_lat_ms.reserve(fanout_msgs);
    const auto f_start = std::chrono::steady_clock::now();
    for (std::size_t i = 0U; i < fanout_msgs; ++i) {
        const auto m0 = std::chrono::steady_clock::now();
        for (std::size_t d = 0U; d < 3U; ++d) {
            auto enc = DoubleRatchetEngine::ratchet_encrypt(crypto, sender_sessions[d], fanout_span).value();
            auto dec = DoubleRatchetEngine::ratchet_decrypt(crypto, recipient_sessions[d], enc).value();
            ASSERT_EQ(dec.expose_unredacted_secret().size(), 1024U);
        }
        fanout_lat_ms.push_back(
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - m0).count());
    }
    const double fanout_sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - f_start).count();
    const double fanout_throughput = static_cast<double>(fanout_msgs) / std::max(fanout_sec, 1e-9);
    const auto fanout_stats = compute_latency_stats_ms(fanout_lat_ms);

    std::cout << std::fixed << std::setprecision(4) << "[BenchmarkF_Fanout3] mode=" << build_mode_label()
              << " logical_msgs=" << fanout_msgs << " mean_ms=" << fanout_stats.mean_ms
              << " p50_ms=" << fanout_stats.p50_ms << " p95_ms=" << fanout_stats.p95_ms
              << " p99_ms=" << fanout_stats.p99_ms << " max_ms=" << fanout_stats.max_ms
              << " throughput_msg_s=" << fanout_throughput << "\n";

    EXPECT_LT(fanout_stats.mean_ms, 2.0);
    EXPECT_LT(fanout_stats.p95_ms, 2.0);
    EXPECT_GT(fanout_throughput, 500.0);
}

// Benchmark G: Memory Stability Check Across 1,000 Real Crypto + SQLCipher Persistence Cycles
TEST_F(ClientPerformanceBenchmarkTest, BenchmarkG_MemoryStabilityAcross1000CryptoAndSqlCipherCycles) {
    OpenSslCryptoProvider crypto;
    MemorySecureStorage secure_storage;
    SqlCipherLocalStore sql(secure_storage, crypto);
    ASSERT_TRUE(sql.open(db_path_.string()).is_ok());

    const UserId alice("usr-stab-alice");
    const UserId bob("usr-stab-bob");
    const ConversationId cid("conv-stab-1");
    const DeviceId dev("dev-stab-1");
    ASSERT_TRUE(sql.save_conversation(Conversation(cid, ConversationType::Direct, "Stability", {alice, bob})).is_ok());

    auto alice_id = create_x3dh_identity(crypto, "dev-stab-alice");
    auto bob_id = create_x3dh_identity(crypto, "dev-stab-bob");
    auto init = X3dhEngine::initiate_handshake(crypto, alice_id.first, bob_id.second).value();
    auto resp = X3dhEngine::process_handshake(crypto, bob_id.first, init.header).value();
    auto alice_state =
        DoubleRatchetEngine::initialize_alice(crypto, init.shared_secret, bob_id.first.signed_prekey_public_key())
            .value();
    auto bob_state = DoubleRatchetEngine::initialize_bob(
                         crypto, resp.shared_secret,
                         DhKeyPair{bob_id.first.signed_prekey_public_key(), bob_id.first.signed_prekey_private_key()})
                         .value();

    const std::string sample = pad_to_fixed_block("Leak check cycle payload", 256U);
    const std::span<const uint8_t> pt_span(reinterpret_cast<const uint8_t*>(sample.data()), sample.size());
    const auto base_tp = std::chrono::system_clock::now();

    // Warmup 100 cycles to populate allocator/SQLite page cache
    for (int w = 0; w < 100; ++w) {
        auto enc = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, pt_span).value();
        auto dec = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, enc).value();
        EXPECT_EQ(dec.expose_unredacted_secret().size(), 256U);
    }

    PlatformTelemetryCollector collector;
    const auto baseline = collector.sample();
    const std::size_t cycles = is_full_benchmark_mode() ? 1000U : 250U;

    for (std::size_t i = 0U; i < cycles; ++i) {
        auto enc = DoubleRatchetEngine::ratchet_encrypt(crypto, alice_state, pt_span).value();
        auto dec = DoubleRatchetEngine::ratchet_decrypt(crypto, bob_state, enc).value();
        ASSERT_EQ(dec.expose_unredacted_secret().size(), 256U);

        const Message msg(MessageId("msg-stab-" + std::to_string(i)), cid, alice, dev, DeliveryState::Delivered,
                          base_tp + std::chrono::milliseconds(static_cast<int64_t>(i)),
                          "stability record #" + std::to_string(i));
        ASSERT_TRUE(sql.save_message(msg).is_ok());

        if ((i % 100U) == 99U) {
            const auto fetched = sql.get_messages(cid, 50U);
            ASSERT_TRUE(fetched.is_ok());
            ASSERT_FALSE(fetched.value().empty());
        }
    }

    const auto after = collector.sample();
    const double rss_growth_mb = after.rss_megabytes - baseline.rss_megabytes;

    std::cout << std::fixed << std::setprecision(2) << "[BenchmarkG] mode=" << build_mode_label()
              << " cycles=" << cycles << " baseline_rss_mb=" << baseline.rss_megabytes
              << " end_rss_mb=" << after.rss_megabytes << " net_growth_mb=" << rss_growth_mb << "\n";

    EXPECT_LT(rss_growth_mb, 16.0);
    EXPECT_TRUE(sql.close().is_ok());
}

} // namespace
} // namespace securecloud::client::tests

int main(int argc, char** argv) {
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) {
        qputenv("QT_QPA_PLATFORM", "offscreen");
    }
    QGuiApplication app(argc, argv);
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
