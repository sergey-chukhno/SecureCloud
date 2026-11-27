#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/diagnostics_manager.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/settings_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "auth/crypto/argon2id_hasher.hpp"
#include "auth/crypto/base32.hpp"
#include "auth/crypto/totp_engine.hpp"
#include "auth/domain/uuid.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/user_settings.hpp"
#include "files/storage/s3_client.hpp"
#include "messaging/db/scylla_session.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <numeric>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <optional>
#include <pqxx/pqxx>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::application::managers;
using namespace securecloud::client::domain;
using namespace securecloud::client::domain::crypto;
using namespace securecloud::client::infrastructure::adapters;
using securecloud::common::configuration::SecretString;

[[nodiscard]] bool live_compose_e2e_enabled() {
    const char* flag = std::getenv("SECURECLOUD_RUN_LIVE_COMPOSE_E2E");
    if (flag == nullptr || *flag == '\0') {
        return false;
    }
    const std::string_view sv(flag);
    return sv == "1" || sv == "true" || sv == "TRUE" || sv == "yes" || sv == "YES";
}

[[nodiscard]] std::string env_or_default(const char* name, std::string_view fallback) {
    const char* val = std::getenv(name);
    if (val != nullptr && *val != '\0') {
        return std::string(val);
    }
    return std::string(fallback);
}

[[nodiscard]] uint16_t env_port_or_default(const char* name, uint16_t fallback) {
    const char* val = std::getenv(name);
    if (val != nullptr && *val != '\0') {
        const long parsed = std::strtol(val, nullptr, 10);
        if (parsed > 0 && parsed <= 65535) {
            return static_cast<uint16_t>(parsed);
        }
    }
    return fallback;
}

[[nodiscard]] std::string compute_cert_spki_sha256_hex(const std::filesystem::path& cert_path) {
    const std::string cert_path_str = cert_path.string();
    FILE* fp = std::fopen(cert_path_str.c_str(), "rb");
    if (fp == nullptr) {
        return {};
    }
    std::unique_ptr<X509, decltype(&X509_free)> x509(PEM_read_X509(fp, nullptr, nullptr, nullptr), &X509_free);
    std::fclose(fp);
    if (!x509) {
        return {};
    }

    const X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(x509.get());
    if (pubkey == nullptr) {
        return {};
    }
    const int spki_len = i2d_X509_PUBKEY(pubkey, nullptr);
    if (spki_len <= 0) {
        return {};
    }
    std::vector<uint8_t> spki_der(static_cast<std::size_t>(spki_len));
    unsigned char* p = spki_der.data();
    if (i2d_X509_PUBKEY(pubkey, &p) != spki_len) {
        return {};
    }
    const auto digest = StreamingSha256::digest_hex(spki_der);
    return digest.is_ok() ? digest.value() : std::string{};
}

[[nodiscard]] std::string bytes_to_hex(std::span<const uint8_t> data) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2U);
    for (const uint8_t b : data) {
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

[[nodiscard]] std::vector<uint8_t> hex_to_bytes_lossless(std::string_view hex) {
    if ((hex.size() % 2U) != 0U) {
        return {};
    }
    auto nibble = [](char c) noexcept -> int {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }
        if (c >= 'A' && c <= 'F') {
            return 10 + (c - 'A');
        }
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

[[nodiscard]] bool contains_subsequence(std::string_view haystack, std::string_view needle) noexcept {
    return !needle.empty() && haystack.find(needle) != std::string_view::npos;
}

[[nodiscard]] bool contains_bytes_or_hex(std::string_view raw_bytes, std::string_view needle) {
    if (contains_subsequence(raw_bytes, needle)) {
        return true;
    }
    const std::span<const uint8_t> needle_span(reinterpret_cast<const uint8_t*>(needle.data()), needle.size());
    const std::string needle_hex = bytes_to_hex(needle_span);
    return contains_subsequence(raw_bytes, needle_hex);
}

[[nodiscard]] double sorted_percentile(const std::vector<double>& sorted_ms, double pct) noexcept {
    if (sorted_ms.empty()) {
        return 0.0;
    }
    const std::size_t idx =
        std::min<std::size_t>(sorted_ms.size() - 1U, static_cast<std::size_t>((pct / 100.0) * sorted_ms.size()));
    return sorted_ms[idx];
}

struct LiveWorkstation {
    std::string email{};
    std::string password{};
    UserId user_id{};
    DeviceId device_id{};
    std::filesystem::path db_path{};
    std::unique_ptr<ClientApplication> app{};

    ClientBootstrap& bootstrap() noexcept { return app->bootstrap(); }
};

class ClientGatewayBackendIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        if (!live_compose_e2e_enabled()) {
            GTEST_SKIP() << "Set SECURECLOUD_RUN_LIVE_COMPOSE_E2E=1 with running Docker Compose stack to execute.";
        }

        const std::filesystem::path pki_root(SECURECLOUD_DEV_PKI_DIR);
        ca_cert_path_ = pki_root / "ca" / "ca.crt";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        audit_cert_path_ = pki_root / "services" / "audit" / "audit.crt";
        audit_key_path_ = pki_root / "services" / "audit" / "audit.key";

        ASSERT_TRUE(std::filesystem::exists(ca_cert_path_)) << ca_cert_path_;
        ASSERT_TRUE(std::filesystem::exists(gateway_cert_path_)) << gateway_cert_path_;
        ASSERT_TRUE(std::filesystem::exists(audit_cert_path_)) << audit_cert_path_;
        ASSERT_TRUE(std::filesystem::exists(audit_key_path_)) << audit_key_path_;

        gateway_host_ = env_or_default("SECURECLOUD_GATEWAY_HOST", "127.0.0.1");
        gateway_port_ = env_port_or_default("GATEWAY_HTTPS_HOST_PORT", 8443);
        gateway_spki_hex_ = compute_cert_spki_sha256_hex(gateway_cert_path_);
        ASSERT_EQ(gateway_spki_hex_.size(), 64U);

        pg_host_ = env_or_default("POSTGRES_HOST", "127.0.0.1");
        pg_port_ = env_port_or_default("POSTGRES_HOST_PORT", 5433);
        auth_db_name_ = env_or_default("AUTH_DB_NAME", "securecloud_auth");
        auth_db_user_ = env_or_default("AUTH_DB_USER", "auth_user");
        auth_db_pass_ = env_or_default("AUTH_DB_PASSWORD", "auth_dev_db_secret");
        files_db_name_ = env_or_default("FILES_DB_NAME", "securecloud_files");
        files_db_user_ = env_or_default("FILES_DB_USER", "files_user");
        files_db_pass_ = env_or_default("FILES_DB_PASSWORD", "files_dev_db_secret");

        scylla_host_ = env_or_default("SCYLLA_HOST", "127.0.0.1");
        scylla_port_ = env_port_or_default("SCYLLA_HOST_PORT", 9042);

        minio_host_ = env_or_default("MINIO_HOST", "127.0.0.1");
        minio_port_ = env_port_or_default("MINIO_HOST_PORT", 9000);
        minio_bucket_ = env_or_default("FILES_MINIO_BUCKET", "securecloud-files-encrypted");
        minio_user_ = env_or_default("FILES_MINIO_USER", "files_minio_user");
        minio_pass_ = env_or_default("FILES_MINIO_PASSWORD", "files_dev_minio_secret");

        audit_endpoint_ = env_or_default("AUDIT_GRPC_ENDPOINT", "127.0.0.1:50055");

        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_t06_live_e2e_" + suffix);
        std::filesystem::create_directories(temp_dir_);

        hasher_ = std::make_unique<securecloud::auth::crypto::OpenSslArgon2idHasher>(
            securecloud::auth::crypto::Argon2idConfig{
                .memory_cost_kib = 16384,
                .iterations = 2,
                .parallelism = 1,
            });
    }

    void TearDown() override {
        for (auto* ws : workstations_) {
            if (ws != nullptr && ws->app) {
                (void)ws->app->shutdown();
                ws->app.reset();
            }
        }
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    [[nodiscard]] std::string auth_conn_string() const {
        return "host=" + pg_host_ + " port=" + std::to_string(pg_port_) + " dbname=" + auth_db_name_ +
               " user=" + auth_db_user_ + " password=" + auth_db_pass_ + " connect_timeout=5";
    }

    [[nodiscard]] std::string files_conn_string() const {
        return "host=" + pg_host_ + " port=" + std::to_string(pg_port_) + " dbname=" + files_db_name_ +
               " user=" + files_db_user_ + " password=" + files_db_pass_ + " connect_timeout=5";
    }

    [[nodiscard]] std::pair<std::string, std::string> seed_auth_user(const std::string& label) {
        const std::string user_uuid = securecloud::auth::domain::Uuid::generate_v7().to_string();
        const std::string email =
            label + "_" + securecloud::auth::domain::Uuid::generate_v7().to_string() + "@securecloud.local";
        const std::string password = "LiveE2e#Pass!" + label;
        const std::string verifier = hasher_->hash_password(SecretString(password));

        pqxx::connection conn(auth_conn_string());
        pqxx::work tx(conn);
        tx.exec("INSERT INTO users (user_id, credential_identifier, password_verifier, password_algorithm, "
                "password_updated_at, account_status, created_at, updated_at, version) "
                "VALUES ($1, $2, $3, 'argon2id', NOW(), 'Active', NOW(), NOW(), 1) "
                "ON CONFLICT (credential_identifier) DO UPDATE SET password_verifier = EXCLUDED.password_verifier",
                pqxx::params{user_uuid, email, verifier});
        tx.commit();
        return {email, password};
    }

    [[nodiscard]] LiveWorkstation create_logged_in_workstation(const std::string& label, const std::string& email,
                                                               const std::string& password,
                                                               bool register_device = true) {
        LiveWorkstation ws;
        ws.email = email;
        ws.password = password;
        ws.db_path = temp_dir_ / (label + ".db");

        ClientConfig cfg = ClientConfig::create_default();
        cfg.database_path = ws.db_path.string();
        cfg.gateway_url = "https://" + gateway_host_;
        cfg.gateway_port = gateway_port_;
        cfg.tls_ca_cert_path = ca_cert_path_.string();
        cfg.pinned_tls_spki_sha256 = gateway_spki_hex_;
        cfg.enforce_tls_pinning = true;
        cfg.use_live_gateway_transport = true;

        auto bootstrap = std::make_unique<ClientBootstrap>(cfg);
        ws.app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(ws.app->initialize().is_ok());
        EXPECT_TRUE(ws.app->start().is_ok());

        const auto login_res = ws.app->bootstrap().auth_manager().authenticate_with_duress_check(email, password);
        EXPECT_TRUE(login_res.is_ok()) << (login_res.is_error() ? login_res.error().to_string() : "");
        ws.user_id = ws.app->bootstrap().auth_manager().current_user();

        if (register_device) {
            const auto dev_res = ws.app->bootstrap().device_manager().register_device(ws.user_id, label + "-device");
            EXPECT_TRUE(dev_res.is_ok()) << (dev_res.is_error() ? dev_res.error().to_string() : "");
            if (dev_res.is_ok()) {
                ws.device_id = dev_res.value().device_id();
                ws.app->bootstrap().initialize_ratchet_session_manager(ws.user_id, ws.device_id);
            }
        }
        return ws;
    }

    void setup_direct_conversation_locally(LiveWorkstation& a, LiveWorkstation& b, const ConversationId& cid) {
        const auto now = std::chrono::system_clock::now();
        Conversation conv(cid, ConversationType::Direct, b.email, {a.user_id, b.user_id}, now, now);
        ASSERT_TRUE(a.bootstrap().local_store().save_conversation(conv).is_ok());
        ASSERT_TRUE(b.bootstrap().local_store().save_conversation(conv).is_ok());
    }

    void grant_file_read_access(const std::string& file_id, const UserId& grantee_user_id,
                                const UserId& grantor_user_id) {
        pqxx::connection conn(files_conn_string());
        pqxx::work tx(conn);
        const std::string access_id = securecloud::auth::domain::Uuid::generate_v7().to_string();
        tx.exec("INSERT INTO file_access (access_id, file_id, grantee_user_id, permission, granted_by) "
                "VALUES ($1, $2, $3, 'READ', $4) ON CONFLICT (file_id, grantee_user_id) DO NOTHING",
                pqxx::params{access_id, file_id, grantee_user_id.value(), grantor_user_id.value()});
        tx.commit();
    }

    [[nodiscard]] std::unique_ptr<securecloud::messaging::db::ScyllaSession> open_scylla_session() const {
        securecloud::messaging::ScyllaConfig scfg;
        scfg.host = scylla_host_;
        scfg.port = scylla_port_;
        scfg.keyspace = "securecloud_messaging";
        scfg.connect_timeout_ms = 5000;
        scfg.request_timeout_ms = 5000;
        scfg.connection_pool_size = 2;
        return std::make_unique<securecloud::messaging::db::ScyllaSession>(scfg);
    }

    [[nodiscard]] std::shared_ptr<securecloud::files::storage::S3Client> open_s3_client() const {
        securecloud::files::storage::S3ClientConfig cfg;
        cfg.endpoint = "http://" + minio_host_ + ":" + std::to_string(minio_port_);
        cfg.bucket = minio_bucket_;
        cfg.access_key = minio_user_;
        cfg.secret_key = SecretString(minio_pass_);
        cfg.default_timeout = std::chrono::milliseconds(5000);
        return std::make_shared<securecloud::files::storage::S3Client>(cfg);
    }

    std::filesystem::path ca_cert_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path audit_cert_path_;
    std::filesystem::path audit_key_path_;
    std::filesystem::path temp_dir_;

    std::string gateway_host_;
    uint16_t gateway_port_{8443};
    std::string gateway_spki_hex_;

    std::string pg_host_;
    uint16_t pg_port_{5433};
    std::string auth_db_name_;
    std::string auth_db_user_;
    std::string auth_db_pass_;
    std::string files_db_name_;
    std::string files_db_user_;
    std::string files_db_pass_;

    std::string scylla_host_;
    uint16_t scylla_port_{9042};

    std::string minio_host_;
    uint16_t minio_port_{9000};
    std::string minio_bucket_;
    std::string minio_user_;
    std::string minio_pass_;

    std::string audit_endpoint_;

    std::unique_ptr<securecloud::auth::crypto::OpenSslArgon2idHasher> hasher_;
    std::vector<LiveWorkstation*> workstations_;
};

TEST_F(ClientGatewayBackendIntegrationTest, Scenario1_LiveAuthDeviceEnrollmentAndPrekeyUpload) {
    const auto [alice_email, alice_pass] = seed_auth_user("s1_alice");
    const auto [bob_email, bob_pass] = seed_auth_user("s1_bob");

    auto alice = create_logged_in_workstation("s1_alice", alice_email, alice_pass, /*register_device=*/true);
    workstations_.push_back(&alice);
    auto bob = create_logged_in_workstation("s1_bob", bob_email, bob_pass, /*register_device=*/true);
    workstations_.push_back(&bob);

    ASSERT_FALSE(alice.user_id.empty());
    ASSERT_FALSE(alice.device_id.empty());
    ASSERT_FALSE(bob.user_id.empty());
    ASSERT_FALSE(bob.device_id.empty());
    EXPECT_TRUE(alice.bootstrap().is_live_gateway_transport_active());

    const auto pre_token = alice.bootstrap().auth_manager().session_token();
    ASSERT_TRUE(pre_token.is_ok()) << pre_token.error().to_string();
    ASSERT_TRUE(alice.bootstrap().auth_manager().refresh_session().is_ok());
    const auto post_token = alice.bootstrap().auth_manager().session_token();
    ASSERT_TRUE(post_token.is_ok());
    EXPECT_NE(pre_token.value().expose_unredacted_secret(), post_token.value().expose_unredacted_secret());

    const auto inv_before = alice.bootstrap().device_manager().check_prekey_inventory();
    ASSERT_TRUE(inv_before.is_ok()) << inv_before.error().to_string();
    EXPECT_GE(inv_before.value().active_prekey_count(), 1);

    const auto replenish_res = alice.bootstrap().device_manager().replenish_prekeys(10U);
    ASSERT_TRUE(replenish_res.is_ok()) << replenish_res.error().to_string();
    EXPECT_EQ(replenish_res.value(), 10U);

    const auto inv_after = alice.bootstrap().device_manager().check_prekey_inventory();
    ASSERT_TRUE(inv_after.is_ok()) << inv_after.error().to_string();
    EXPECT_GT(inv_after.value().active_prekey_count(), inv_before.value().active_prekey_count());

    const auto bob_dir = alice.bootstrap().gateway().get_device_crypto_directory(bob.user_id);
    ASSERT_TRUE(bob_dir.is_ok()) << bob_dir.error().to_string();
    ASSERT_FALSE(bob_dir.value().empty());
    EXPECT_EQ(bob_dir.value()[0].device_id, bob.device_id);
    EXPECT_EQ(bob_dir.value()[0].status, DeviceAuthorizationStatus::Authorized);
}

TEST_F(ClientGatewayBackendIntegrationTest, Scenario2_TwoClientLiveE2eeDoubleRatchetMessagingAndZeroPlaintextScylla) {
    const auto [alice_email, alice_pass] = seed_auth_user("s2_alice");
    const auto [bob_email, bob_pass] = seed_auth_user("s2_bob");

    auto alice = create_logged_in_workstation("s2_alice", alice_email, alice_pass, true);
    workstations_.push_back(&alice);
    auto bob = create_logged_in_workstation("s2_bob", bob_email, bob_pass, true);
    workstations_.push_back(&bob);

    const auto conv_res = alice.bootstrap().gateway().create_direct_conversation(bob.user_id);
    ASSERT_TRUE(conv_res.is_ok()) << conv_res.error().to_string();
    const ConversationId conv_id = conv_res.value().conversation_id;
    ASSERT_FALSE(conv_id.empty());
    setup_direct_conversation_locally(alice, bob, conv_id);

    const std::string sentinel = "SC_E2EE_SENTINEL_MSG_" + securecloud::auth::domain::Uuid::generate_v7().to_string();

    const auto sent_res = alice.bootstrap().messaging_manager().stage_outbound_message(
        conv_id, alice.user_id, alice.device_id, sentinel, /*priority=*/0, "Alice Live");
    ASSERT_TRUE(sent_res.is_ok()) << sent_res.error().to_string();
    EXPECT_EQ(sent_res.value().delivery_state(), DeliveryState::Accepted);

    const auto page_res = bob.bootstrap().gateway().fetch_conversation_messages(conv_id, bob.device_id, 0, 50);
    ASSERT_TRUE(page_res.is_ok()) << page_res.error().to_string();
    ASSERT_EQ(page_res.value().events.size(), 1U);

    const auto& ev = page_res.value().events[0];
    ASSERT_TRUE(ev.direct_payload.has_value());
    const auto inbound_res = bob.bootstrap().messaging_manager().process_inbound_realtime_event(ev);
    ASSERT_TRUE(inbound_res.is_ok()) << inbound_res.error().to_string();
    ASSERT_TRUE(inbound_res.value().has_value());
    EXPECT_EQ(inbound_res.value()->encrypted_envelope_ref(), sentinel);

    const int64_t now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    const auto ack_res = bob.bootstrap().gateway().acknowledge_delivery(ev.message_id, bob.device_id, now_ms);
    ASSERT_TRUE(ack_res.is_ok()) << ack_res.error().to_string();
    const auto read_res = bob.bootstrap().gateway().send_read_receipt(conv_id, ev.message_id, bob.device_id, now_ms);
    ASSERT_TRUE(read_res.is_ok()) << read_res.error().to_string();

    // Direct ScyllaDB zero-plaintext scan across both message body and per-device delivery queue
    auto scylla = open_scylla_session();
    const auto msg_rows = scylla->execute("SELECT message_id, ciphertext_envelope FROM "
                                          "securecloud_messaging.messages_by_conversation WHERE conversation_id = '" +
                                          conv_id.value() + "' ALLOW FILTERING;");
    EXPECT_FALSE(msg_rows.empty());
    for (const auto& row : msg_rows) {
        if (row.has_column("ciphertext_envelope") && !row.is_null("ciphertext_envelope")) {
            EXPECT_FALSE(contains_bytes_or_hex(row.get_string("ciphertext_envelope"), sentinel));
        }
    }

    const auto deliv_rows = scylla->execute("SELECT device_id, message_id, ciphertext_blob FROM "
                                            "securecloud_messaging.pending_deliveries_by_device WHERE device_id = '" +
                                            bob.device_id.value() + "' ALLOW FILTERING;");
    EXPECT_FALSE(deliv_rows.empty());
    for (const auto& row : deliv_rows) {
        if (row.has_column("ciphertext_blob") && !row.is_null("ciphertext_blob")) {
            const auto& blob = row.get_blob("ciphertext_blob");
            const std::string blob_str(reinterpret_cast<const char*>(blob.data()), blob.size());
            EXPECT_FALSE(contains_bytes_or_hex(blob_str, sentinel));
        }
    }
}

TEST_F(ClientGatewayBackendIntegrationTest, Scenario3_LiveEncryptedChunkedFileTransferAndZeroPlaintextStorage) {
    const auto [alice_email, alice_pass] = seed_auth_user("s3_alice");
    const auto [bob_email, bob_pass] = seed_auth_user("s3_bob");

    auto alice = create_logged_in_workstation("s3_alice", alice_email, alice_pass, true);
    workstations_.push_back(&alice);
    auto bob = create_logged_in_workstation("s3_bob", bob_email, bob_pass, true);
    workstations_.push_back(&bob);

    const auto conv_res = alice.bootstrap().gateway().create_direct_conversation(bob.user_id);
    ASSERT_TRUE(conv_res.is_ok()) << conv_res.error().to_string();
    const ConversationId conv_id = conv_res.value().conversation_id;
    setup_direct_conversation_locally(alice, bob, conv_id);

    const std::string uid_tag = securecloud::auth::domain::Uuid::generate_v7().to_string();
    const std::string sentinel = "SC_E2EE_SENTINEL_FILE_" + uid_tag;
    const std::string secret_filename = "classified-mvp-dossier-" + uid_tag + ".bin";
    const std::filesystem::path src_path = temp_dir_ / "alice_files" / secret_filename;
    const std::filesystem::path dst_path = temp_dir_ / "bob_files" / secret_filename;
    std::filesystem::create_directories(src_path.parent_path());

    // 5 MiB payload -> 2 chunks under standard 4 MiB chunking (4,194,304 B + 1,048,632 B)
    constexpr std::size_t kPayloadBytes = 5U * 1024U * 1024U;
    std::vector<uint8_t> original_bytes(kPayloadBytes);
    for (std::size_t i = 0; i < kPayloadBytes; ++i) {
        original_bytes[i] = static_cast<uint8_t>((i * 41U + 13U) & 0xFFU);
    }
    std::memcpy(original_bytes.data() + 1024U, sentinel.data(), sentinel.size());
    std::memcpy(original_bytes.data() + (4U * 1024U * 1024U) + 128U, sentinel.data(), sentinel.size());

    {
        std::ofstream ofs(src_path, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(original_bytes.data()),
                  static_cast<std::streamsize>(original_bytes.size()));
    }
    const std::string expected_pt_sha = StreamingSha256::digest_hex(original_bytes).value();

    const auto up_res = alice.bootstrap().file_manager().start_upload(FileUploadRequest{
        .conversation_id = conv_id,
        .owner_user_id = alice.user_id,
        .owner_device_id = alice.device_id,
        .peer_user_id = bob.user_id,
        .local_file_path = src_path.string(),
        .mime_type = "application/octet-stream",
        .sender_display_name = "Alice",
        .dispatch_key_envelope = true,
    });
    ASSERT_TRUE(up_res.is_ok()) << up_res.error().to_string();
    EXPECT_EQ(up_res.value().record.status, FileTransferStatus::Completed);
    EXPECT_EQ(up_res.value().record.total_chunks, 2U);
    EXPECT_EQ(up_res.value().record.completed_chunks, 2U);
    const std::string remote_file_id = up_res.value().record.file_id;
    ASSERT_FALSE(remote_file_id.empty());

    // Fetch & decrypt the E2EE file key envelope message on Bob
    const auto page_res = bob.bootstrap().gateway().fetch_conversation_messages(conv_id, bob.device_id, 0, 50);
    ASSERT_TRUE(page_res.is_ok()) << page_res.error().to_string();
    ASSERT_FALSE(page_res.value().events.empty());

    std::string envelope_json;
    for (const auto& ev : page_res.value().events) {
        const auto dec_res = bob.bootstrap().messaging_manager().process_inbound_realtime_event(ev);
        ASSERT_TRUE(dec_res.is_ok()) << dec_res.error().to_string();
        if (dec_res.value().has_value() &&
            FileAttachmentKeyEnvelope::is_file_attachment_envelope(dec_res.value()->encrypted_envelope_ref())) {
            envelope_json = dec_res.value()->encrypted_envelope_ref();
            break;
        }
    }
    ASSERT_FALSE(envelope_json.empty());

    const auto ingest_res =
        bob.bootstrap().file_manager().ingest_inbound_key_envelope_json(conv_id, alice.user_id, envelope_json);
    ASSERT_TRUE(ingest_res.is_ok()) << ingest_res.error().to_string();

    grant_file_read_access(remote_file_id, bob.user_id, alice.user_id);

    const auto dl_res =
        bob.bootstrap().file_manager().start_download(ingest_res.value().transfer_id, dst_path.string());
    ASSERT_TRUE(dl_res.is_ok()) << dl_res.error().to_string();
    EXPECT_EQ(dl_res.value().status, FileTransferStatus::Completed);

    std::ifstream ifs(dst_path, std::ios::binary);
    ASSERT_TRUE(ifs.is_open());
    const std::vector<uint8_t> downloaded_bytes((std::istreambuf_iterator<char>(ifs)),
                                                std::istreambuf_iterator<char>());
    EXPECT_EQ(downloaded_bytes.size(), original_bytes.size());
    EXPECT_EQ(StreamingSha256::digest_hex(downloaded_bytes).value(), expected_pt_sha);
    EXPECT_EQ(downloaded_bytes, original_bytes);

    // Zero-plaintext scan across Postgres securecloud_files metadata + MinIO raw encrypted object
    pqxx::connection pg_files(files_conn_string());
    pqxx::work tx(pg_files);
    const auto ver_res = tx.exec("SELECT minio_object_key FROM file_versions WHERE file_id = $1 AND is_active = TRUE",
                                 pqxx::params{remote_file_id});
    ASSERT_EQ(ver_res.size(), 1);
    const std::string minio_key = ver_res[0][0].as<std::string>();

    const auto meta_res = tx.exec(
        "SELECT encode(encrypted_filename, 'hex'), client_encryption_metadata::text FROM encrypted_file_metadata "
        "WHERE file_id = $1",
        pqxx::params{remote_file_id});
    ASSERT_EQ(meta_res.size(), 1);
    const std::string enc_fn_hex = meta_res[0][0].as<std::string>();
    const auto enc_fn_bytes = hex_to_bytes_lossless(enc_fn_hex);
    const std::string enc_fn_raw(reinterpret_cast<const char*>(enc_fn_bytes.data()), enc_fn_bytes.size());
    EXPECT_FALSE(contains_bytes_or_hex(enc_fn_raw, secret_filename));
    EXPECT_FALSE(contains_bytes_or_hex(meta_res[0][1].as<std::string>(), secret_filename));
    tx.commit();

    auto s3 = open_s3_client();
    const auto obj = s3->get_object(minio_key, std::nullopt, std::chrono::milliseconds(5000));
    EXPECT_TRUE(obj.is_2xx());
    EXPECT_GT(obj.body.size(), kPayloadBytes);
    EXPECT_FALSE(contains_bytes_or_hex(obj.body, sentinel));
    EXPECT_FALSE(contains_bytes_or_hex(obj.body, secret_filename));
}

TEST_F(ClientGatewayBackendIntegrationTest, Scenario4_OfflineReconnectCatchUpSyncAndMfaDeviceRevocation) {
    const auto [alice_email, alice_pass] = seed_auth_user("s4_alice");
    const auto [bob_email, bob_pass] = seed_auth_user("s4_bob");

    auto alice = create_logged_in_workstation("s4_alice", alice_email, alice_pass, true);
    workstations_.push_back(&alice);
    auto alice_companion = create_logged_in_workstation("s4_alice_companion", alice_email, alice_pass, true);
    workstations_.push_back(&alice_companion);
    auto bob = create_logged_in_workstation("s4_bob", bob_email, bob_pass, true);
    workstations_.push_back(&bob);

    const auto conv_res = alice.bootstrap().gateway().create_direct_conversation(bob.user_id);
    ASSERT_TRUE(conv_res.is_ok()) << conv_res.error().to_string();
    const ConversationId conv_id = conv_res.value().conversation_id;
    setup_direct_conversation_locally(alice, bob, conv_id);

    // 1. Offline queuing -> online Catch-Up Sync reconciliation
    const std::string catchup_msg = "SC_E2EE_CATCHUP_" + securecloud::auth::domain::Uuid::generate_v7().to_string();
    ASSERT_TRUE(alice.bootstrap().sync_manager().set_simulated_offline(true).is_ok());
    alice.bootstrap().messaging_manager().set_offline_mode(true);

    const auto queued_res = alice.bootstrap().messaging_manager().stage_outbound_message(
        conv_id, alice.user_id, alice.device_id, catchup_msg, 0, "Alice Offline");
    ASSERT_TRUE(queued_res.is_ok()) << queued_res.error().to_string();
    EXPECT_EQ(queued_res.value().delivery_state(), DeliveryState::LocalPending);
    EXPECT_EQ(alice.bootstrap().messaging_manager().pending_outbox_count(), 1U);

    alice.bootstrap().messaging_manager().set_offline_mode(false);
    const auto reconnect_res = alice.bootstrap().sync_manager().set_simulated_offline(false);
    ASSERT_TRUE(reconnect_res.is_ok()) << reconnect_res.error().to_string();
    EXPECT_EQ(reconnect_res.value(), ConnectivityState::Online);
    EXPECT_EQ(alice.bootstrap().messaging_manager().pending_outbox_count(), 0U);

    const auto sync_report = alice.bootstrap().sync_manager().execute_catch_up_sync(alice.user_id, alice.device_id);
    ASSERT_TRUE(sync_report.is_ok()) << sync_report.error().to_string();
    EXPECT_EQ(sync_report.value().outbox_remaining_count, 0U);

    const auto bob_page = bob.bootstrap().gateway().fetch_conversation_messages(conv_id, bob.device_id, 0, 50);
    ASSERT_TRUE(bob_page.is_ok()) << bob_page.error().to_string();
    ASSERT_EQ(bob_page.value().events.size(), 1U);
    const auto bob_dec = bob.bootstrap().messaging_manager().process_inbound_realtime_event(bob_page.value().events[0]);
    ASSERT_TRUE(bob_dec.is_ok()) << bob_dec.error().to_string();
    ASSERT_TRUE(bob_dec.value().has_value());
    EXPECT_EQ(bob_dec.value()->encrypted_envelope_ref(), catchup_msg);

    // 2. Upgrade Alice session to MFA_VERIFIED and revoke companion device
    httplib::SSLClient ssl_cli(gateway_host_, gateway_port_);
    ssl_cli.set_ca_cert_path(ca_cert_path_.string());
    ssl_cli.enable_server_certificate_verification(true);
    ssl_cli.set_connection_timeout(5);
    ssl_cli.set_read_timeout(5);

    const std::string primary_tok = alice.bootstrap().auth_manager().session_token().value().expose_unredacted_secret();
    httplib::Headers primary_headers = {{"Authorization", "Bearer " + primary_tok}};

    auto enroll_res = ssl_cli.Post("/api/v1/auth/mfa/enroll", primary_headers, "{}", "application/json");
    ASSERT_TRUE(enroll_res && enroll_res->status == 200) << (enroll_res ? enroll_res->body : "null");
    const std::string base32_secret = nlohmann::json::parse(enroll_res->body).at("secret").get<std::string>();
    const auto raw_secret = securecloud::auth::crypto::Base32::decode(base32_secret);
    ASSERT_TRUE(raw_secret.has_value());

    securecloud::auth::crypto::TotpEngine totp;
    const auto now_sec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const std::string confirm_code = totp.compute_code(*raw_secret, now_sec);
    auto confirm_res = ssl_cli.Post("/api/v1/auth/mfa/confirm", primary_headers,
                                    nlohmann::json({{"code", confirm_code}}).dump(), "application/json");
    ASSERT_TRUE(confirm_res && confirm_res->status == 200) << (confirm_res ? confirm_res->body : "null");

    const auto mfa_login =
        alice.bootstrap().gateway().authenticate_user(alice_email, alice_pass, alice.device_id.value());
    ASSERT_TRUE(mfa_login.is_ok()) << mfa_login.error().to_string();
    ASSERT_TRUE(mfa_login.value().mfa_required);
    ASSERT_FALSE(mfa_login.value().mfa_challenge_id.empty());

    const std::string verify_code = totp.compute_code(*raw_secret, now_sec);
    auto verify_res = ssl_cli.Post(
        "/api/v1/auth/mfa/verify", primary_headers,
        nlohmann::json({{"challenge_id", mfa_login.value().mfa_challenge_id}, {"code", verify_code}}).dump(),
        "application/json");
    ASSERT_TRUE(verify_res && verify_res->status == 200) << (verify_res ? verify_res->body : "null");
    const std::string upgraded_tok = nlohmann::json::parse(verify_res->body).at("access_token").get<std::string>();

    ASSERT_TRUE(
        alice.bootstrap().secure_storage().store_secret("session_auth_token", SecretString(upgraded_tok)).is_ok());

    const auto rev_res = alice.bootstrap().device_manager().revoke_device(alice_companion.device_id, verify_code);
    ASSERT_TRUE(rev_res.is_ok()) << rev_res.error().to_string();

    // Assert companion device is removed/revoked from directory & receives zero new fan-out envelopes
    const auto dir_after = bob.bootstrap().gateway().get_device_crypto_directory(alice.user_id);
    ASSERT_TRUE(dir_after.is_ok()) << dir_after.error().to_string();
    for (const auto& entry : dir_after.value()) {
        if (entry.device_id == alice_companion.device_id) {
            EXPECT_NE(entry.status, DeviceAuthorizationStatus::Authorized);
        }
    }

    auto scylla = open_scylla_session();
    const auto pre_rev_rows =
        scylla->execute("SELECT message_id FROM securecloud_messaging.pending_deliveries_by_device "
                        "WHERE device_id = '" +
                        alice_companion.device_id.value() + "' ALLOW FILTERING;");
    const std::size_t companion_rows_before = pre_rev_rows.size();

    const std::string post_rev_msg =
        "SC_E2EE_POST_REVOKE_" + securecloud::auth::domain::Uuid::generate_v7().to_string();
    const auto bob_send = bob.bootstrap().messaging_manager().stage_outbound_message(
        conv_id, bob.user_id, bob.device_id, post_rev_msg, 0, "Bob Post-Revoke");
    ASSERT_TRUE(bob_send.is_ok()) << bob_send.error().to_string();

    const auto post_rev_rows =
        scylla->execute("SELECT message_id FROM securecloud_messaging.pending_deliveries_by_device "
                        "WHERE device_id = '" +
                        alice_companion.device_id.value() + "' ALLOW FILTERING;");
    EXPECT_EQ(post_rev_rows.size(), companion_rows_before);

    // Revoked device authentication/prekey update must fail closed
    const auto revoked_login = alice_companion.bootstrap().gateway().authenticate_user(
        alice_email, alice_pass, alice_companion.device_id.value());
    EXPECT_TRUE(revoked_login.is_error());
}

TEST_F(ClientGatewayBackendIntegrationTest, Scenario5_EmergencyPanicWipeAuditContinuityAndLiveLatencyMetrics) {
    const int64_t window_start_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count() -
        5000LL;

    const auto [alice_email, alice_pass] = seed_auth_user("s5_alice");
    const auto [bob_email, bob_pass] = seed_auth_user("s5_bob");

    auto alice = create_logged_in_workstation("s5_alice", alice_email, alice_pass, true);
    workstations_.push_back(&alice);
    auto bob = create_logged_in_workstation("s5_bob", bob_email, bob_pass, true);
    workstations_.push_back(&bob);

    const auto conv_res = alice.bootstrap().gateway().create_direct_conversation(bob.user_id);
    ASSERT_TRUE(conv_res.is_ok()) << conv_res.error().to_string();
    const ConversationId conv_id = conv_res.value().conversation_id;
    setup_direct_conversation_locally(alice, bob, conv_id);

    // Exercise live Messaging + Files traffic for correlated Audit trail + latency capture
    const std::string msg_sentinel = "SC_E2EE_AUDIT_MSG_" + securecloud::auth::domain::Uuid::generate_v7().to_string();
    const auto msg_t0 = std::chrono::steady_clock::now();
    const auto msg_res = alice.bootstrap().messaging_manager().stage_outbound_message(
        conv_id, alice.user_id, alice.device_id, msg_sentinel, 0, "Alice S5");
    const double msg_send_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - msg_t0).count();
    ASSERT_TRUE(msg_res.is_ok()) << msg_res.error().to_string();

    const std::string file_sentinel =
        "SC_E2EE_AUDIT_FILE_" + securecloud::auth::domain::Uuid::generate_v7().to_string();
    const std::filesystem::path s5_file = temp_dir_ / "s5_secret_upload.bin";
    {
        std::vector<uint8_t> buf(4096U, 0x5AU);
        std::memcpy(buf.data(), file_sentinel.data(), file_sentinel.size());
        std::ofstream ofs(s5_file, std::ios::binary | std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    }
    const auto up_t0 = std::chrono::steady_clock::now();
    const auto up_res = alice.bootstrap().file_manager().start_upload(FileUploadRequest{
        .conversation_id = conv_id,
        .owner_user_id = alice.user_id,
        .owner_device_id = alice.device_id,
        .peer_user_id = bob.user_id,
        .local_file_path = s5_file.string(),
        .mime_type = "application/octet-stream",
        .sender_display_name = "Alice S5",
        .dispatch_key_envelope = true,
    });
    const double file_upload_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - up_t0).count();
    ASSERT_TRUE(up_res.is_ok()) << up_res.error().to_string();

    // Measure 20 live TLS 1.3 Gateway health probes for benchmark addendum
    std::vector<double> probe_samples_ms;
    probe_samples_ms.reserve(20U);
    for (int i = 0; i < 20; ++i) {
        const auto t0 = std::chrono::steady_clock::now();
        const auto probe = alice.bootstrap().gateway().probe_gateway("/health");
        const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        ASSERT_TRUE(probe.is_ok() && probe.value());
        probe_samples_ms.push_back(ms);
    }
    std::sort(probe_samples_ms.begin(), probe_samples_ms.end());
    const double probe_mean_ms = std::accumulate(probe_samples_ms.begin(), probe_samples_ms.end(), 0.0) /
                                 static_cast<double>(probe_samples_ms.size());
    const auto snap = alice.bootstrap().diagnostics_manager().collect_telemetry();
    std::cout << "[LiveComposeBenchmark] tls13_probes=" << probe_samples_ms.size() << " probe_mean_ms=" << probe_mean_ms
              << " probe_p50_ms=" << sorted_percentile(probe_samples_ms, 50.0)
              << " probe_p95_ms=" << sorted_percentile(probe_samples_ms, 95.0)
              << " probe_p99_ms=" << sorted_percentile(probe_samples_ms, 99.0)
              << " probe_max_ms=" << probe_samples_ms.back() << " msg_send_ms=" << msg_send_ms
              << " file_upload_ms=" << file_upload_ms << " gateway_avg_rtt_ms=" << snap.avg_gateway_rtt_ms
              << " gateway_requests_total=" << snap.gateway_requests_total << std::endl;

    // Emergency panic wipe on Alice: SQLCipher DB, secrets, and local_audit_log shredded
    const auto wipe_res = alice.bootstrap().emergency_manager().execute_panic_wipe(PanicTriggerSource::UiPanicButton,
                                                                                   PostWipeMode::EmergencyLocked);
    ASSERT_TRUE(wipe_res.is_ok()) << wipe_res.error().to_string();
    EXPECT_TRUE(wipe_res.value().all_critical_steps_succeeded);
    EXPECT_FALSE(std::filesystem::exists(alice.db_path));
    EXPECT_TRUE(alice.bootstrap().secure_storage().list_secret_keys().value().empty());
    EXPECT_FALSE(alice.bootstrap().auth_manager().is_authenticated());

    // Trigger a live Gateway TokenRejected audit event inside the query window
    {
        httplib::SSLClient probe_cli(gateway_host_, gateway_port_);
        probe_cli.set_ca_cert_path(ca_cert_path_.string());
        probe_cli.enable_server_certificate_verification(true);
        probe_cli.set_connection_timeout(5);
        probe_cli.set_read_timeout(5);
        httplib::Headers bad_headers = {{"Authorization", "Bearer invalid-token-probe"}};
        auto bad_res = probe_cli.Get("/api/v1/conversations", bad_headers);
        ASSERT_TRUE(bad_res);
        EXPECT_EQ(bad_res->status, 401);
    }

    // Query internal AuditQueryService over mTLS confirming cross-service ClickHouse continuity
    securecloud::common::security::SecurityCredentialsConfig audit_creds{
        .ca_cert_path = ca_cert_path_,
        .service_cert_path = audit_cert_path_,
        .service_key_path = audit_key_path_,
    };
    auto audit_channel =
        securecloud::common::security::MtlsCredentialLoader::create_mtls_channel(audit_endpoint_, audit_creds, "audit");
    ASSERT_NE(audit_channel, nullptr);
    auto query_stub = securecloud::audit::v1::AuditQueryService::NewStub(audit_channel);

    std::set<securecloud::audit::v1::ProducerServiceProto> seen_producers;
    std::vector<securecloud::audit::v1::PersistedAuditEventProto> captured_events;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (std::chrono::steady_clock::now() < deadline) {
        seen_producers.clear();
        captured_events.clear();

        securecloud::audit::v1::QueryAuditEventsRequest req;
        const int64_t query_end_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count() +
            60000LL;
        req.set_start_occurred_at_ms(window_start_ms);
        req.set_end_occurred_at_ms(query_end_ms);
        req.set_page_size(500U);

        securecloud::audit::v1::QueryAuditEventsResponse resp;
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));
        const auto status = query_stub->QueryAuditEvents(&ctx, req, &resp);
        ASSERT_TRUE(status.ok()) << status.error_message();

        for (const auto& ev : resp.events()) {
            seen_producers.insert(ev.event().producer_service());
            captured_events.push_back(ev);
        }

        if (seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY) &&
            seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_AUTH) &&
            seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING) &&
            seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_FILES)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    EXPECT_TRUE(seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_GATEWAY));
    EXPECT_TRUE(seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_AUTH));
    EXPECT_TRUE(seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_MESSAGING));
    EXPECT_TRUE(seen_producers.contains(securecloud::audit::v1::PRODUCER_SERVICE_FILES));

    for (const auto& persisted : captured_events) {
        const auto& ev = persisted.event();
        EXPECT_FALSE(contains_subsequence(ev.actor_id(), msg_sentinel));
        EXPECT_FALSE(contains_subsequence(ev.target_id(), msg_sentinel));
        EXPECT_FALSE(contains_subsequence(ev.actor_id(), file_sentinel));
        EXPECT_FALSE(contains_subsequence(ev.target_id(), file_sentinel));
        for (const auto& [k, v] : ev.metadata()) {
            EXPECT_FALSE(contains_subsequence(k, msg_sentinel));
            EXPECT_FALSE(contains_subsequence(v, msg_sentinel));
            EXPECT_FALSE(contains_subsequence(k, file_sentinel));
            EXPECT_FALSE(contains_subsequence(v, file_sentinel));
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
