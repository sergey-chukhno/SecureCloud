#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/settings_manager.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/user_settings.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/qt_http_gateway_client.hpp"
#include "infrastructure/adapters/switchable_gateway_client.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <QAbstractSocket>
#include <QByteArray>
#include <QHostAddress>
#include <QMetaObject>
#include <QObject>
#include <QPointer>
#include <QSsl>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QThread>
#include <QTimer>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
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

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct X509Deleter {
    void operator()(X509* x) const noexcept { X509_free(x); }
};
struct X509NameDeleter {
    void operator()(X509_NAME* n) const noexcept { X509_NAME_free(n); }
};
struct X509ExtDeleter {
    void operator()(X509_EXTENSION* e) const noexcept { X509_EXTENSION_free(e); }
};
struct BioDeleter {
    void operator()(BIO* b) const noexcept { BIO_free(b); }
};

using UniquePkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;
using UniqueName = std::unique_ptr<X509_NAME, X509NameDeleter>;
using UniqueExt = std::unique_ptr<X509_EXTENSION, X509ExtDeleter>;
using UniqueBio = std::unique_ptr<BIO, BioDeleter>;

struct CertBundle {
    UniquePkey key;
    UniqueX509 cert;
    std::string cert_pem{};
    std::string key_pem{};
    std::string spki_sha256_hex{};
    QSslCertificate qs_cert{};
    QSslKey qs_key{};
};

std::string bio_to_string(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    if (mem == nullptr || mem->data == nullptr) {
        return {};
    }
    return std::string(mem->data, mem->length);
}

std::string compute_x509_spki_sha256(X509* cert) {
    const X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(cert);
    const int len = i2d_X509_PUBKEY(pubkey, nullptr);
    EXPECT_GT(len, 0);
    std::vector<uint8_t> der(static_cast<std::size_t>(len));
    unsigned char* p = der.data();
    EXPECT_EQ(i2d_X509_PUBKEY(pubkey, &p), len);
    return StreamingSha256::digest_hex(der).value();
}

UniquePkey generate_ec_p256_key() {
    const char* curve = "P-256";
    UniquePkey pkey(EVP_EC_gen(curve));
    EXPECT_NE(pkey, nullptr);
    return pkey;
}

void add_x509_ext(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer != nullptr ? issuer : cert, cert, nullptr, nullptr, 0);
    std::string val_copy(value);
    UniqueExt ext(X509V3_EXT_conf_nid(nullptr, &ctx, nid, val_copy.data()));
    ASSERT_NE(ext, nullptr);
    ASSERT_EQ(X509_add_ext(cert, ext.get(), -1), 1);
}

CertBundle generate_root_ca(const char* common_name) {
    CertBundle out;
    out.key = generate_ec_p256_key();
    out.cert.reset(X509_new());
    EXPECT_NE(out.cert, nullptr);

    X509_set_version(out.cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(out.cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(out.cert.get()), -3600L);
    X509_gmtime_adj(X509_getm_notAfter(out.cert.get()), 86400L);
    X509_set_pubkey(out.cert.get(), out.key.get());

    UniqueName name(X509_NAME_new());
    X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("SecureCloud"), -1,
                               -1, 0);
    X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name), -1,
                               -1, 0);
    X509_set_subject_name(out.cert.get(), name.get());
    X509_set_issuer_name(out.cert.get(), name.get());

    add_x509_ext(out.cert.get(), nullptr, NID_basic_constraints, "critical,CA:TRUE");
    add_x509_ext(out.cert.get(), nullptr, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_x509_ext(out.cert.get(), nullptr, NID_subject_key_identifier, "hash");

    EXPECT_GT(X509_sign(out.cert.get(), out.key.get(), EVP_sha256()), 0);

    UniqueBio cert_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(cert_bio.get(), out.cert.get());
    out.cert_pem = bio_to_string(cert_bio.get());

    UniqueBio key_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(key_bio.get(), out.key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    out.key_pem = bio_to_string(key_bio.get());

    out.spki_sha256_hex = compute_x509_spki_sha256(out.cert.get());
    out.qs_cert = QSslCertificate(QByteArray::fromStdString(out.cert_pem), QSsl::Pem);
    out.qs_key = QSslKey(QByteArray::fromStdString(out.key_pem), QSsl::Ec, QSsl::Pem);
    return out;
}

CertBundle generate_leaf_cert(const CertBundle& ca, const char* common_name, long serial) {
    CertBundle out;
    out.key = generate_ec_p256_key();
    out.cert.reset(X509_new());
    EXPECT_NE(out.cert, nullptr);

    X509_set_version(out.cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(out.cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(out.cert.get()), -3600L);
    X509_gmtime_adj(X509_getm_notAfter(out.cert.get()), 86400L);
    X509_set_pubkey(out.cert.get(), out.key.get());

    UniqueName subj(X509_NAME_new());
    X509_NAME_add_entry_by_txt(subj.get(), "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("SecureCloud"), -1,
                               -1, 0);
    X509_NAME_add_entry_by_txt(subj.get(), "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name), -1,
                               -1, 0);
    X509_set_subject_name(out.cert.get(), subj.get());
    X509_set_issuer_name(out.cert.get(), X509_get_subject_name(ca.cert.get()));

    add_x509_ext(out.cert.get(), ca.cert.get(), NID_basic_constraints, "critical,CA:FALSE");
    add_x509_ext(out.cert.get(), ca.cert.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_x509_ext(out.cert.get(), ca.cert.get(), NID_ext_key_usage, "serverAuth");
    add_x509_ext(out.cert.get(), ca.cert.get(), NID_subject_alt_name, "IP:127.0.0.1,DNS:localhost");

    EXPECT_GT(X509_sign(out.cert.get(), ca.key.get(), EVP_sha256()), 0);

    UniqueBio cert_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_X509(cert_bio.get(), out.cert.get());
    out.cert_pem = bio_to_string(cert_bio.get());

    UniqueBio key_bio(BIO_new(BIO_s_mem()));
    PEM_write_bio_PrivateKey(key_bio.get(), out.key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    out.key_pem = bio_to_string(key_bio.get());

    out.spki_sha256_hex = compute_x509_spki_sha256(out.cert.get());
    out.qs_cert = QSslCertificate(QByteArray::fromStdString(out.cert_pem), QSsl::Pem);
    out.qs_key = QSslKey(QByteArray::fromStdString(out.key_pem), QSsl::Ec, QSsl::Pem);
    return out;
}

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

struct RecordedHttpRequest {
    std::string method{};
    std::string target{};
    std::string authorization_header{};
    std::string request_id_header{};
    std::unordered_map<std::string, std::string> headers{};
    std::string body{};
};

struct LoopbackHttpResponse {
    int status{200};
    std::string content_type{"application/json"};
    std::string body{"{}"};
    std::vector<std::pair<std::string, std::string>> headers{};
    int delay_ms{0};
};

class LoopbackSslServer final : public QTcpServer {
  public:
    using HandlerFn = std::function<LoopbackHttpResponse(const RecordedHttpRequest&)>;

    LoopbackSslServer() = default;
    ~LoopbackSslServer() override { stop(); }

    bool start_tls(const QSslCertificate& leaf_cert, const QSslKey& leaf_key, const QSslCertificate& ca_cert,
                   HandlerFn handler) {
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            leaf_cert_ = leaf_cert;
            leaf_key_ = leaf_key;
            ca_cert_ = ca_cert;
            handler_ = std::move(handler);
        }

        moveToThread(&server_thread_);
        server_thread_.start();

        std::promise<uint16_t> port_promise;
        auto port_future = port_promise.get_future();
        QMetaObject::invokeMethod(
            this,
            [this, &port_promise]() {
                if (!listen(QHostAddress::LocalHost, 0)) {
                    port_promise.set_value(0U);
                    return;
                }
                port_promise.set_value(serverPort());
            },
            Qt::QueuedConnection);

        port_ = port_future.get();
        return port_ != 0U;
    }

    void stop() {
        if (server_thread_.isRunning()) {
            QMetaObject::invokeMethod(
                this,
                [this]() {
                    close();
                    server_thread_.quit();
                },
                Qt::BlockingQueuedConnection);
            server_thread_.wait();
        }
    }

    void set_server_certificate(const QSslCertificate& leaf_cert, const QSslKey& leaf_key) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        leaf_cert_ = leaf_cert;
        leaf_key_ = leaf_key;
    }

    void set_handler(HandlerFn handler) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        handler_ = std::move(handler);
    }

    [[nodiscard]] uint16_t port() const noexcept { return port_; }

    [[nodiscard]] std::vector<RecordedHttpRequest> recorded_requests() const {
        std::lock_guard<std::mutex> lock(req_mutex_);
        return recorded_requests_;
    }

    void clear_recorded_requests() {
        std::lock_guard<std::mutex> lock(req_mutex_);
        recorded_requests_.clear();
    }

  protected:
    void incomingConnection(qintptr socketDescriptor) override {
        auto* sock = new QSslSocket(this);
        if (!sock->setSocketDescriptor(socketDescriptor)) {
            sock->deleteLater();
            return;
        }

        QSslConfiguration ssl_cfg;
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            ssl_cfg.setProtocol(QSsl::TlsV1_3OrLater);
            ssl_cfg.setLocalCertificateChain({leaf_cert_, ca_cert_});
            ssl_cfg.setPrivateKey(leaf_key_);
            ssl_cfg.setPeerVerifyMode(QSslSocket::VerifyNone);
        }
        sock->setSslConfiguration(ssl_cfg);

        auto rx_buf = std::make_shared<QByteArray>();
        auto handled = std::make_shared<bool>(false);

        QObject::connect(sock, &QSslSocket::readyRead, sock, [this, sock, rx_buf, handled]() {
            rx_buf->append(sock->readAll());
            if (*handled) {
                return;
            }
            const qsizetype hdr_end = rx_buf->indexOf("\r\n\r\n");
            if (hdr_end < 0) {
                return;
            }

            const QByteArray hdr_bytes = rx_buf->left(hdr_end);
            const QList<QByteArray> lines = hdr_bytes.split('\n');
            if (lines.isEmpty()) {
                return;
            }

            const QList<QByteArray> req_line = lines.front().trimmed().split(' ');
            if (req_line.size() < 2) {
                return;
            }

            RecordedHttpRequest rec;
            rec.method = req_line[0].toStdString();
            rec.target = req_line[1].toStdString();

            std::size_t content_len = 0U;
            for (qsizetype i = 1; i < lines.size(); ++i) {
                const QByteArray line = lines[i].trimmed();
                const qsizetype colon = line.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                const std::string hk = to_lower_ascii(line.left(colon).trimmed().toStdString());
                const std::string hv = line.mid(colon + 1).trimmed().toStdString();
                rec.headers[hk] = hv;
                if (hk == "authorization") {
                    rec.authorization_header = hv;
                } else if (hk == "x-request-id") {
                    rec.request_id_header = hv;
                } else if (hk == "content-length") {
                    try {
                        content_len = static_cast<std::size_t>(std::stoull(hv));
                    } catch (...) {
                    }
                }
            }

            const qsizetype total_needed = hdr_end + 4 + static_cast<qsizetype>(content_len);
            if (rx_buf->size() < total_needed) {
                return;
            }

            *handled = true;
            rec.body.assign(rx_buf->constData() + hdr_end + 4, content_len);
            {
                std::lock_guard<std::mutex> lock(req_mutex_);
                recorded_requests_.push_back(rec);
            }

            HandlerFn fn;
            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                fn = handler_;
            }
            const LoopbackHttpResponse resp = fn ? fn(rec) : LoopbackHttpResponse{};

            auto write_resp = [sock_ptr = QPointer<QSslSocket>(sock), resp]() {
                if (sock_ptr.isNull()) {
                    return;
                }
                std::string raw = "HTTP/1.1 " + std::to_string(resp.status) + " OK\r\n";
                raw += "Content-Type: " + resp.content_type + "\r\n";
                raw += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
                raw += "Connection: close\r\n";
                for (const auto& [k, v] : resp.headers) {
                    raw += k + ": " + v + "\r\n";
                }
                raw += "\r\n";
                raw.append(resp.body);
                sock_ptr->write(raw.data(), static_cast<qint64>(raw.size()));
                sock_ptr->flush();
                sock_ptr->disconnectFromHost();
            };

            if (resp.delay_ms > 0) {
                QTimer::singleShot(resp.delay_ms, sock, std::move(write_resp));
            } else {
                write_resp();
            }
        });

        QObject::connect(sock, &QSslSocket::disconnected, sock, &QSslSocket::deleteLater);
        sock->startServerEncryption();
    }

  private:
    QThread server_thread_;
    uint16_t port_{0};
    mutable std::mutex state_mutex_;
    QSslCertificate leaf_cert_{};
    QSslKey leaf_key_{};
    QSslCertificate ca_cert_{};
    HandlerFn handler_{};

    mutable std::mutex req_mutex_;
    std::vector<RecordedHttpRequest> recorded_requests_;
};

class QtHttpGatewayClientTest : public ::testing::Test {
  protected:
    void SetUp() override {
        if (QSslSocket::activeBackend().isEmpty()) {
            const auto backends = QSslSocket::availableBackends();
            if (backends.contains(QStringLiteral("openssl"))) {
                (void)QSslSocket::setActiveBackend(QStringLiteral("openssl"));
            }
        }

        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_t05_qt_http_" + suffix);
        std::filesystem::create_directories(temp_dir_);

        ca_ = generate_root_ca("SecureCloud Test Root CA");
        leaf_a_ = generate_leaf_cert(ca_, "127.0.0.1", 1001);
        leaf_b_ = generate_leaf_cert(ca_, "127.0.0.1", 1002);
        ASSERT_NE(leaf_a_.spki_sha256_hex, leaf_b_.spki_sha256_hex);

        ca_pem_path_ = temp_dir_ / "test-ca.pem";
        std::ofstream ofs(ca_pem_path_, std::ios::binary);
        ofs << ca_.cert_pem;
        ofs.close();

        server_ = std::make_unique<LoopbackSslServer>();
    }

    void TearDown() override {
        if (server_) {
            server_->stop();
            server_.reset();
        }
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    ClientConfig make_live_config(uint16_t port, std::string pin_hex = {}) {
        ClientConfig cfg = ClientConfig::create_default();
        cfg.gateway_url = "https://127.0.0.1";
        cfg.gateway_port = port;
        cfg.tls_ca_cert_path = ca_pem_path_.string();
        cfg.use_live_gateway_transport = true;
        cfg.auth_token = SecretString("live-jwt-bearer-secret-token");
        cfg.pinned_tls_spki_sha256 = std::move(pin_hex);
        cfg.enforce_tls_pinning = true;
        return cfg;
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path ca_pem_path_;
    CertBundle ca_;
    CertBundle leaf_a_;
    CertBundle leaf_b_;
    std::unique_ptr<LoopbackSslServer> server_;
};

TEST_F(QtHttpGatewayClientTest, Tls13HealthProbeAndAuthenticatedRestContracts) {
    ASSERT_TRUE(server_->start_tls(
        leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert, [](const RecordedHttpRequest& req) -> LoopbackHttpResponse {
            if (req.method == "GET" && req.target == "/health/live") {
                return {.status = 200, .body = R"({"status":"SERVING"})"};
            }
            if (req.method == "POST" && req.target == "/api/v1/messages") {
                const auto j = nlohmann::json::parse(req.body);
                EXPECT_EQ(j.value("conversation_id", std::string{}), "conv-live-01");
                EXPECT_EQ(j["delivery_targets"].size(), 1U);
                return {.status = 201, .body = R"({"message_id":"msg-live-9001"})"};
            }
            if (req.method == "GET" && req.target.rfind("/api/v1/conversations/conv-live-01/messages", 0) == 0) {
                return {
                    .status = 200,
                    .body =
                        R"({"has_more":false,"next_sequence":5,"latest_sequence":5,"messages":[{"message_id":"msg-live-9001","conversation_id":"conv-live-01","sender_user_id":"bob","sender_device_id":"dev-bob","created_at_unix_ms":1700000100000,"sequence_number":5,"delivery_targets":[{"recipient_user_id":"alice","recipient_device_id":"dev-alice","encrypted_payload":{"ciphertext_blob":"cipher-hex","ephemeral_public_key":"","initialization_vector":"","auth_tag":"","algorithm":"AES-256-GCM"}}]}]})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/files/upload/init") {
                return {
                    .status = 201,
                    .body =
                        R"({"upload_id":"up-live-1","file_id":"file-live-1","status":"TRANSFER_STATUS_PENDING","expires_at_unix_ms":1700003600000})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/files/upload/chunk") {
                EXPECT_EQ(req.headers.at("upload-id"), "up-live-1");
                EXPECT_EQ(req.headers.at("chunk-index"), "0");
                EXPECT_EQ(req.body, "ENCRYPTED_BINARY_CHUNK");
                const std::string sha =
                    StreamingSha256::digest_hex(
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(req.body.data()), req.body.size()))
                        .value();
                nlohmann::json resp;
                resp["upload_id"] = "up-live-1";
                resp["chunk_index"] = 0;
                resp["accepted"] = true;
                resp["received_sha256"] = sha;
                return {.status = 200, .body = resp.dump()};
            }
            if (req.method == "GET" && req.target == "/api/v1/files/file-live-1/chunks/0") {
                const std::string body = "ENCRYPTED_BINARY_CHUNK";
                const std::string sha =
                    StreamingSha256::digest_hex(
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(body.data()), body.size()))
                        .value();
                return {.status = 200,
                        .content_type = "application/octet-stream",
                        .body = body,
                        .headers = {{"X-Ciphertext-SHA256", sha}}};
            }
            if (req.method == "GET" && req.target == "/api/v1/users/me") {
                return {
                    .status = 200,
                    .body =
                        R"({"user":{"user_id":"alice","credential_identifier":"alice.sec","created_at_epoch_ms":1700000000000,"updated_at_epoch_ms":1700000200000}})",
                };
            }
            if (req.method == "PUT" && req.target == "/api/v1/users/me") {
                return {.status = 501, .body = R"({"error":{"code":"NOT_IMPLEMENTED","message":"Not implemented"}})"};
            }
            return {.status = 404, .body = R"({"error":{"code":"NOT_FOUND","message":"Not found"}})"};
        }));

    QtHttpGatewayClient client(make_live_config(server_->port(), leaf_a_.spki_sha256_hex));

    const auto probe = client.probe_gateway("/health");
    ASSERT_TRUE(probe.is_ok()) << probe.error().to_string();
    EXPECT_TRUE(probe.value());

    FanOutSubmissionRequest send_req;
    send_req.conversation_id = ConversationId("conv-live-01");
    send_req.idempotency_key = "idemp-live-1";
    send_req.device_payloads.push_back(PerDeviceDeliveryPayload{
        .recipient_user_id = UserId("bob"),
        .recipient_device_id = DeviceId("dev-bob"),
        .ciphertext_blob = "cipher-hex",
        .ephemeral_public_key = {1U, 2U, 3U},
        .iv = {4U, 5U, 6U},
        .auth_tag = {7U, 8U, 9U},
    });
    const auto send_res = client.submit_encrypted_message(send_req);
    ASSERT_TRUE(send_res.is_ok()) << send_res.error().to_string();
    EXPECT_EQ(send_res.value(), "msg-live-9001");

    const auto page_res = client.fetch_conversation_messages(ConversationId("conv-live-01"), DeviceId("dev-alice"), 0);
    ASSERT_TRUE(page_res.is_ok()) << page_res.error().to_string();
    ASSERT_EQ(page_res.value().events.size(), 1U);
    EXPECT_EQ(page_res.value().events[0].message_id.value(), "msg-live-9001");

    const auto init_res = client.init_file_upload(FileUploadInitRequest{
        .file_id = "file-live-1",
        .owner_user_id = UserId("alice"),
        .owner_device_id = DeviceId("dev-alice"),
        .conversation_id = ConversationId("conv-live-01"),
        .encrypted_size_bytes = 22U,
        .expected_chunk_count = 1U,
    });
    ASSERT_TRUE(init_res.is_ok()) << init_res.error().to_string();
    EXPECT_EQ(init_res.value().upload_id, "up-live-1");

    const std::vector<uint8_t> raw_chunk = {'E', 'N', 'C', 'R', 'Y', 'P', 'T', 'E', 'D', '_', 'B',
                                            'I', 'N', 'A', 'R', 'Y', '_', 'C', 'H', 'U', 'N', 'K'};
    const auto up_chunk = client.upload_file_chunk(FileChunkUploadRequest{
        .upload_id = "up-live-1",
        .chunk_index = 0U,
        .encrypted_data = raw_chunk,
        .ciphertext_sha256 = StreamingSha256::digest_hex(raw_chunk).value(),
    });
    ASSERT_TRUE(up_chunk.is_ok()) << up_chunk.error().to_string();
    EXPECT_TRUE(up_chunk.value().accepted);

    const auto dl_chunk = client.download_file_chunk("file-live-1", 0U);
    ASSERT_TRUE(dl_chunk.is_ok()) << dl_chunk.error().to_string();
    EXPECT_EQ(dl_chunk.value().encrypted_data, raw_chunk);

    const auto prof_res = client.get_user_profile(UserId("alice"));
    ASSERT_TRUE(prof_res.is_ok()) << prof_res.error().to_string();
    EXPECT_EQ(prof_res.value().public_handle, "alice.sec");

    UserProfile update_p = prof_res.value();
    update_p.display_name = "Alice Live";
    update_p.allow_handle_discovery = true;
    const auto sync_res = client.update_user_profile(update_p);
    ASSERT_TRUE(sync_res.is_ok()) << sync_res.error().to_string();
    EXPECT_EQ(sync_res.value().sync_status, ProfileSyncStatus::LocalOnlyServerUnsupported);

    // Verify Bearer token & X-Request-ID attached on authenticated calls, NOT on public /health/live.
    const auto recorded = server_->recorded_requests();
    ASSERT_GE(recorded.size(), 8U);
    EXPECT_TRUE(recorded[0].authorization_header.empty());
    EXPECT_FALSE(recorded[0].request_id_header.empty());
    EXPECT_EQ(recorded[1].authorization_header, "Bearer live-jwt-bearer-secret-token");
    EXPECT_NE(recorded[1].request_id_header, recorded[0].request_id_header);
}

TEST_F(QtHttpGatewayClientTest, InspectTlsAndSpkiPinningFailsClosedBeforeBearerTransmission) {
    ASSERT_TRUE(server_->start_tls(
        leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert,
        [](const RecordedHttpRequest&) -> LoopbackHttpResponse { return {.status = 200, .body = R"({"ok":true})"}; }));

    QtHttpGatewayClient client(make_live_config(server_->port(), leaf_a_.spki_sha256_hex));

    const auto cert_info = client.inspect_tls_certificate("127.0.0.1", server_->port());
    ASSERT_TRUE(cert_info.is_ok()) << cert_info.error().to_string();
    EXPECT_EQ(cert_info.value().spki_sha256_hex, leaf_a_.spki_sha256_hex);
    EXPECT_EQ(cert_info.value().subject_cn, "127.0.0.1");
    EXPECT_EQ(cert_info.value().issuer_cn, "SecureCloud Test Root CA");
    EXPECT_TRUE(cert_info.value().has_pinned_key);
    EXPECT_TRUE(cert_info.value().matches_pinned_key);
    EXPECT_GT(cert_info.value().valid_until_ms, cert_info.value().valid_from_ms);

    // Rotate server certificate to leaf_b (still chained to trusted CA, different SPKI public key!).
    server_->clear_recorded_requests();
    server_->set_server_certificate(leaf_b_.qs_cert, leaf_b_.qs_key);

    const auto rejected_res = client.get_user_profile(UserId("alice"));
    ASSERT_TRUE(rejected_res.is_error());
    EXPECT_EQ(rejected_res.error().category(), ClientErrorCategory::Network);
    EXPECT_EQ(rejected_res.error().code(), ClientErrorCode::TlsHandshakeFailed);

    // Critical security invariant: 0 HTTP requests and 0 Bearer tokens ever left the client.
    EXPECT_TRUE(server_->recorded_requests().empty());
}

TEST_F(QtHttpGatewayClientTest, HttpErrorMappingAndRequestTimeoutCancellation) {
    std::atomic<int> mode{0};
    ASSERT_TRUE(server_->start_tls(
        leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert, [&mode](const RecordedHttpRequest&) -> LoopbackHttpResponse {
            switch (mode.load()) {
            case 0:
                return {.status = 400, .body = R"({"error":{"code":"BAD_REQUEST","message":"Invalid field"}})"};
            case 1:
                return {.status = 401, .body = R"({"error":{"code":"UNAUTHENTICATED","message":"Token expired"}})"};
            case 2:
                return {.status = 503, .body = R"({"error":{"code":"SERVICE_UNAVAILABLE","message":"Overloaded"}})"};
            default:
                return {.status = 200, .body = R"({"status":"SERVING"})", .delay_ms = 600};
            }
        }));

    ClientConfig cfg = make_live_config(server_->port(), leaf_a_.spki_sha256_hex);
    cfg.connect_timeout_ms = std::chrono::milliseconds(150);
    cfg.request_timeout_ms = std::chrono::milliseconds(150);
    QtHttpGatewayClient client(cfg);

    mode.store(0);
    const auto r400 = client.get_user_profile(UserId("alice"));
    ASSERT_TRUE(r400.is_error());
    EXPECT_EQ(r400.error().category(), ClientErrorCategory::Validation);

    mode.store(1);
    const auto r401 = client.get_user_profile(UserId("alice"));
    ASSERT_TRUE(r401.is_error());
    EXPECT_EQ(r401.error().category(), ClientErrorCategory::Authentication);
    EXPECT_EQ(r401.error().code(), ClientErrorCode::AuthenticationRequired);

    mode.store(2);
    const auto r503 = client.get_user_profile(UserId("alice"));
    ASSERT_TRUE(r503.is_error());
    EXPECT_EQ(r503.error().category(), ClientErrorCategory::Network);

    mode.store(3);
    const auto timeout_res = client.probe_gateway("/health");
    ASSERT_TRUE(timeout_res.is_error());
    EXPECT_EQ(timeout_res.error().category(), ClientErrorCategory::Network);
    EXPECT_EQ(timeout_res.error().code(), ClientErrorCode::ConnectionTimeout);
}

TEST_F(QtHttpGatewayClientTest, ProxyConfigurationHotReloadAndClosedProxyFailure) {
    ClientConfig cfg = make_live_config(8443U, leaf_a_.spki_sha256_hex);
    cfg.proxy_type = ProxyType::Socks5;
    cfg.proxy_host = "127.0.0.1";
    cfg.proxy_port = 1080U;
    cfg.proxy_username = "proxy-user";
    cfg.proxy_password = SecretString("super-secret-proxy-pw");

    QtHttpGatewayClient client(cfg);
    const auto snap = client.effective_proxy_snapshot();
    EXPECT_EQ(snap.type, ProxyType::Socks5);
    EXPECT_EQ(snap.host, "127.0.0.1");
    EXPECT_EQ(snap.port, 1080U);
    EXPECT_EQ(snap.username, "proxy-user");
    EXPECT_TRUE(snap.has_password);
    EXPECT_EQ(client.current_config_snapshot().to_safe_string().find("super-secret-proxy-pw"), std::string::npos);

    // Find an unused closed localhost port for deterministic unreachable proxy verification.
    QTcpServer probe_port_finder;
    ASSERT_TRUE(probe_port_finder.listen(QHostAddress::LocalHost, 0));
    const uint16_t closed_port = probe_port_finder.serverPort();
    probe_port_finder.close();

    cfg.proxy_type = ProxyType::Http;
    cfg.proxy_host = "127.0.0.1";
    cfg.proxy_port = closed_port;
    cfg.connect_timeout_ms = std::chrono::milliseconds(500);
    cfg.request_timeout_ms = std::chrono::milliseconds(500);
    client.reconfigure(cfg);

    const auto fail_res = client.probe_gateway("/health");
    ASSERT_TRUE(fail_res.is_error());
    EXPECT_EQ(fail_res.error().category(), ClientErrorCategory::Network);
}

TEST_F(QtHttpGatewayClientTest, SwitchableGatewayHotReloadsBetweenSimulatedAndLiveTls13ViaSettingsManager) {
    ASSERT_TRUE(server_->start_tls(leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert,
                                   [](const RecordedHttpRequest& req) -> LoopbackHttpResponse {
                                       if (req.method == "GET" && req.target == "/health/live") {
                                           return {.status = 200, .body = R"({"status":"SERVING"})"};
                                       }
                                       return {.status = 404, .body = "{}"};
                                   }));

    ClientConfig boot_cfg = ClientConfig::create_default();
    boot_cfg.database_path = (temp_dir_ / "vault.db").string();
    boot_cfg.tls_ca_cert_path = ca_pem_path_.string();
    boot_cfg.use_live_gateway_transport = false;

    ClientBootstrap bootstrap(boot_cfg);
    EXPECT_FALSE(bootstrap.is_live_gateway_transport_active());
    EXPECT_NE(dynamic_cast<DefaultGatewayClient*>(&bootstrap.gateway()), nullptr);

    // In simulated mode, probing leaves 0 network requests on the loopback TLS server.
    ASSERT_TRUE(bootstrap.gateway().probe_gateway("/health").is_ok());
    EXPECT_TRUE(server_->recorded_requests().empty());

    // Flip live mode ON + set pin via SettingsManager -> hot-reloads SwitchableGatewayClient seamlessly.
    UserSettings live_settings;
    live_settings.use_live_gateway_transport = true;
    live_settings.tls.custom_gateway_host = "127.0.0.1";
    live_settings.tls.custom_gateway_port = server_->port();
    live_settings.tls.pinned_spki_sha256_hex = leaf_a_.spki_sha256_hex;
    ASSERT_TRUE(bootstrap.settings_manager().save_settings(live_settings).is_ok());

    EXPECT_TRUE(bootstrap.is_live_gateway_transport_active());
    EXPECT_NE(dynamic_cast<QtHttpGatewayClient*>(&bootstrap.gateway()), nullptr);
    ASSERT_TRUE(bootstrap.gateway().probe_gateway("/health").is_ok());
    EXPECT_EQ(server_->recorded_requests().size(), 1U);

    // Flip back to simulated mode cleanly without restart.
    live_settings.use_live_gateway_transport = false;
    ASSERT_TRUE(bootstrap.settings_manager().save_settings(live_settings).is_ok());
    EXPECT_FALSE(bootstrap.is_live_gateway_transport_active());
    EXPECT_NE(dynamic_cast<DefaultGatewayClient*>(&bootstrap.gateway()), nullptr);
    ASSERT_TRUE(bootstrap.gateway().probe_gateway("/health").is_ok());
    EXPECT_EQ(server_->recorded_requests().size(), 1U);

    // Save live mode again and simulate restart sharing persisted vault/keychain storage:
    // load_settings() must immediately re-activate live TLS 1.3 transport on SwitchableGatewayClient.
    live_settings.use_live_gateway_transport = true;
    ASSERT_TRUE(bootstrap.settings_manager().save_settings(live_settings).is_ok());

    ClientConfig restarted_cfg = ClientConfig::create_default();
    restarted_cfg.tls_ca_cert_path = ca_pem_path_.string();
    restarted_cfg.use_live_gateway_transport = false;
    SwitchableGatewayClient restarted_switchable(restarted_cfg);
    SettingsManager restarted_settings(bootstrap.local_store(), bootstrap.secure_storage(), restarted_switchable,
                                       restarted_cfg);
    restarted_settings.set_network_config_reload_callback(
        [&restarted_switchable](const ClientConfig& updated) { restarted_switchable.reconfigure(updated); });

    EXPECT_FALSE(restarted_switchable.is_live_transport_active());
    ASSERT_TRUE(restarted_settings.load_settings().is_ok());
    EXPECT_TRUE(restarted_switchable.is_live_transport_active());
    ASSERT_TRUE(restarted_switchable.probe_gateway("/health").is_ok());
    EXPECT_EQ(server_->recorded_requests().size(), 2U);
}

TEST_F(QtHttpGatewayClientTest, ConcurrentMultiThreadedCallsExecuteSafelyAcrossWorkerThread) {
    std::atomic<int> hit_count{0};
    ASSERT_TRUE(server_->start_tls(leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert,
                                   [&hit_count](const RecordedHttpRequest&) -> LoopbackHttpResponse {
                                       hit_count.fetch_add(1);
                                       return {.status = 200, .body = R"({"status":"SERVING"})"};
                                   }));

    QtHttpGatewayClient client(make_live_config(server_->port(), leaf_a_.spki_sha256_hex));

    constexpr std::size_t kWorkers = 4U;
    std::vector<std::thread> threads;
    std::atomic<std::size_t> ok_count{0U};
    threads.reserve(kWorkers);
    for (std::size_t i = 0U; i < kWorkers; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < 3; ++j) {
                if (client.probe_gateway("/health").is_ok()) {
                    ok_count.fetch_add(1U);
                }
            }
        });
    }
    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(ok_count.load(), kWorkers * 3U);
    EXPECT_EQ(hit_count.load(), static_cast<int>(kWorkers * 3U));
}

TEST_F(QtHttpGatewayClientTest, AuthLifecycleCreateDirectConversationAndBinaryCiphertextRoundTrip) {
    const std::string binary_ct = std::string("\x00\xff\x81\x10\xfe\x7f\x01\x99\x02\xab\xcd\xef\x00\x05\xee\x11", 16);
    std::string echoed_b64_ct;

    ASSERT_TRUE(server_->start_tls(
        leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert,
        [&echoed_b64_ct](const RecordedHttpRequest& req) -> LoopbackHttpResponse {
            if (req.method == "POST" && req.target == "/api/v1/auth/login") {
                EXPECT_TRUE(req.authorization_header.empty());
                const auto j = nlohmann::json::parse(req.body);
                EXPECT_EQ(j.value("identifier", std::string{}), "alice@securecloud.io");
                EXPECT_EQ(j.value("credential", std::string{}), "SuperPass#2026");
                EXPECT_EQ(j.value("device_id", std::string{}), "dev-alice-1");
                return {
                    .status = 200,
                    .body =
                        R"({"session_id":"sess-live-1","access_token":"jwt-live-1","refresh_token":"ref-live-1","authentication_level":1,"expires_at_epoch_ms":1799999999000,"user_id":"usr-alice-uuid","mfa_required":false})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/conversations") {
                EXPECT_EQ(req.authorization_header, "Bearer jwt-live-1");
                const auto j = nlohmann::json::parse(req.body);
                EXPECT_EQ(j.value("type", std::string{}), "direct");
                const bool has_participants = j.contains("participant_user_ids") &&
                                              j["participant_user_ids"].is_array() &&
                                              j["participant_user_ids"].size() == 1U;
                EXPECT_TRUE(has_participants);
                if (has_participants) {
                    EXPECT_EQ(j["participant_user_ids"][0].get<std::string>(), "usr-bob-uuid");
                }
                return {
                    .status = 201,
                    .body =
                        R"({"conversation":{"conversation_id":"conv-direct-99","type":"direct","title":"","creator_user_id":"usr-alice-uuid","created_at_unix_ms":1700000100000,"participant_user_ids":["usr-alice-uuid","usr-bob-uuid"]}})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/messages") {
                EXPECT_EQ(req.authorization_header, "Bearer jwt-live-1");
                const auto j = nlohmann::json::parse(req.body);
                echoed_b64_ct = j["delivery_targets"][0]["encrypted_payload"]["ciphertext_blob"].get<std::string>();
                return {.status = 201, .body = R"({"message_id":"msg-bin-1"})"};
            }
            if (req.method == "GET" && req.target.rfind("/api/v1/conversations/conv-direct-99/messages", 0) == 0) {
                EXPECT_EQ(req.authorization_header, "Bearer jwt-live-1");
                nlohmann::json msg;
                msg["message_id"] = "msg-bin-1";
                msg["conversation_id"] = "conv-direct-99";
                msg["sender_user_id"] = "usr-alice-uuid";
                msg["sender_device_id"] = "dev-alice-1";
                msg["created_at_unix_ms"] = 1700000105000LL;
                msg["sequence_number"] = 1;
                msg["delivery_targets"] = nlohmann::json::array({{
                    {"recipient_user_id", "usr-bob-uuid"},
                    {"recipient_device_id", "dev-bob-1"},
                    {"encrypted_payload",
                     {{"ciphertext_blob", echoed_b64_ct},
                      {"ephemeral_public_key", ""},
                      {"initialization_vector", ""},
                      {"auth_tag", ""},
                      {"algorithm", "AES-256-GCM"}}},
                }});
                nlohmann::json resp;
                resp["has_more"] = false;
                resp["next_sequence"] = 2;
                resp["latest_sequence"] = 1;
                resp["messages"] = nlohmann::json::array({msg});
                return {.status = 200, .body = resp.dump()};
            }
            if (req.method == "POST" && req.target == "/api/v1/auth/refresh") {
                EXPECT_TRUE(req.authorization_header.empty());
                const auto j = nlohmann::json::parse(req.body);
                EXPECT_EQ(j.value("refresh_token", std::string{}), "ref-live-1");
                return {
                    .status = 200,
                    .body =
                        R"({"session_id":"sess-live-1","access_token":"jwt-live-2","refresh_token":"ref-live-2","expires_at_epoch_ms":1800000999000})",
                };
            }
            if (req.method == "GET" && req.target == "/api/v1/users/me") {
                if (req.authorization_header != "Bearer jwt-live-2") {
                    return {.status = 401,
                            .body = R"({"error":{"code":"UNAUTHORIZED","message":"Missing or bad JWT"}})"};
                }
                return {
                    .status = 200,
                    .body =
                        R"({"user":{"user_id":"usr-alice-uuid","credential_identifier":"alice@securecloud.io","created_at_epoch_ms":1700000000000,"updated_at_epoch_ms":1700000200000}})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/auth/revoke") {
                EXPECT_EQ(req.authorization_header, "Bearer jwt-live-2");
                const auto j = nlohmann::json::parse(req.body);
                EXPECT_EQ(j.value("session_id", std::string{}), "sess-live-1");
                EXPECT_EQ(j.value("reason", std::string{}), "user_logout");
                return {.status = 200, .body = R"({"revoked":true})"};
            }
            return {.status = 404, .body = R"({"error":{"code":"NOT_FOUND","message":"Not found"}})"};
        }));

    ClientConfig cfg = make_live_config(server_->port(), leaf_a_.spki_sha256_hex);
    cfg.auth_token = SecretString("");
    QtHttpGatewayClient client(cfg);

    const auto login_res = client.authenticate_user("alice@securecloud.io", "SuperPass#2026", "dev-alice-1");
    ASSERT_TRUE(login_res.is_ok()) << login_res.error().to_string();
    EXPECT_EQ(login_res.value().user_id, UserId("usr-alice-uuid"));
    EXPECT_EQ(login_res.value().session_id, "sess-live-1");
    EXPECT_EQ(login_res.value().authentication_level, "AUTH_LEVEL_PASSWORD");
    EXPECT_EQ(login_res.value().access_token.expose_unredacted_secret(), "jwt-live-1");
    EXPECT_EQ(login_res.value().refresh_token.expose_unredacted_secret(), "ref-live-1");
    EXPECT_FALSE(login_res.value().mfa_required);

    const auto conv_res = client.create_direct_conversation(UserId("usr-bob-uuid"));
    ASSERT_TRUE(conv_res.is_ok()) << conv_res.error().to_string();
    EXPECT_EQ(conv_res.value().conversation_id, ConversationId("conv-direct-99"));
    EXPECT_EQ(conv_res.value().type, ConversationType::Direct);
    EXPECT_EQ(conv_res.value().creator_user_id, UserId("usr-alice-uuid"));
    ASSERT_EQ(conv_res.value().participant_user_ids.size(), 2U);

    FanOutSubmissionRequest send_req;
    send_req.conversation_id = conv_res.value().conversation_id;
    send_req.idempotency_key = "idemp-bin-1";
    send_req.device_payloads.push_back(PerDeviceDeliveryPayload{
        .recipient_user_id = UserId("usr-bob-uuid"),
        .recipient_device_id = DeviceId("dev-bob-1"),
        .ciphertext_blob = binary_ct,
        .ephemeral_public_key = {1U, 2U, 3U},
        .iv = {4U, 5U, 6U},
        .auth_tag = {7U, 8U, 9U},
    });
    const auto msg_res = client.submit_encrypted_message(send_req);
    ASSERT_TRUE(msg_res.is_ok()) << msg_res.error().to_string();
    EXPECT_EQ(msg_res.value(), "msg-bin-1");
    EXPECT_FALSE(echoed_b64_ct.empty());

    const auto sync_res =
        client.fetch_conversation_messages(conv_res.value().conversation_id, DeviceId("dev-bob-1"), 0);
    ASSERT_TRUE(sync_res.is_ok()) << sync_res.error().to_string();
    ASSERT_EQ(sync_res.value().events.size(), 1U);
    ASSERT_TRUE(sync_res.value().events[0].direct_payload.has_value());
    EXPECT_EQ(sync_res.value().events[0].direct_payload->ciphertext_blob, binary_ct);

    const auto refresh_res = client.refresh_session("ref-live-1", "dev-alice-1");
    ASSERT_TRUE(refresh_res.is_ok()) << refresh_res.error().to_string();
    EXPECT_EQ(refresh_res.value().access_token.expose_unredacted_secret(), "jwt-live-2");
    EXPECT_EQ(refresh_res.value().refresh_token.expose_unredacted_secret(), "ref-live-2");

    const auto me_res = client.get_user_profile(UserId("usr-alice-uuid"));
    ASSERT_TRUE(me_res.is_ok()) << me_res.error().to_string();

    const auto revoke_res = client.revoke_session("sess-live-1", "user_logout");
    ASSERT_TRUE(revoke_res.is_ok()) << revoke_res.error().to_string();

    const auto unauth_res = client.get_user_profile(UserId("usr-alice-uuid"));
    ASSERT_TRUE(unauth_res.is_error());
    EXPECT_EQ(unauth_res.error().category(), ClientErrorCategory::Authentication);
}

TEST_F(QtHttpGatewayClientTest, AuthManagerLiveLoginRefreshLogoutAndZeroNetworkDuressPin) {
    ASSERT_TRUE(server_->start_tls(
        leaf_a_.qs_cert, leaf_a_.qs_key, ca_.qs_cert, [](const RecordedHttpRequest& req) -> LoopbackHttpResponse {
            if (req.method == "POST" && req.target == "/api/v1/auth/login") {
                return {
                    .status = 200,
                    .body =
                        R"({"session_id":"sess-mgr-1","access_token":"jwt-mgr-1","refresh_token":"ref-mgr-1","authentication_level":1,"expires_at_epoch_ms":1799999999000,"user_id":"usr-mgr-alice","mfa_required":false})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/auth/refresh") {
                return {
                    .status = 200,
                    .body =
                        R"({"session_id":"sess-mgr-1","access_token":"jwt-mgr-2","refresh_token":"ref-mgr-2","expires_at_epoch_ms":1800000999000})",
                };
            }
            if (req.method == "POST" && req.target == "/api/v1/auth/revoke") {
                EXPECT_EQ(req.authorization_header, "Bearer jwt-mgr-2");
                return {.status = 200, .body = R"({"revoked":true})"};
            }
            return {.status = 404, .body = "{}"};
        }));

    ClientConfig boot_cfg = ClientConfig::create_default();
    boot_cfg.database_path = (temp_dir_ / "auth_live.db").string();
    boot_cfg.tls_ca_cert_path = ca_pem_path_.string();
    boot_cfg.use_live_gateway_transport = false;

    ClientBootstrap bootstrap(boot_cfg);
    UserSettings live_settings;
    live_settings.use_live_gateway_transport = true;
    live_settings.tls.custom_gateway_host = "127.0.0.1";
    live_settings.tls.custom_gateway_port = server_->port();
    live_settings.tls.pinned_spki_sha256_hex = leaf_a_.spki_sha256_hex;
    ASSERT_TRUE(bootstrap.settings_manager().save_settings(live_settings).is_ok());

    const auto login_res = bootstrap.auth_manager().authenticate_with_duress_check("alice", "real-pw");
    ASSERT_TRUE(login_res.is_ok()) << login_res.error().to_string();
    EXPECT_EQ(login_res.value().outcome, AuthOutcome::Authenticated);
    EXPECT_EQ(login_res.value().session_id, "sess-mgr-1");
    EXPECT_EQ(bootstrap.auth_manager().current_user(), UserId("usr-mgr-alice"));
    EXPECT_EQ(bootstrap.auth_manager().current_session_id(), "sess-mgr-1");
    EXPECT_EQ(bootstrap.secure_storage().get_secret("session_auth_token").value().expose_unredacted_secret(),
              "jwt-mgr-1");
    EXPECT_EQ(bootstrap.secure_storage().get_secret("session_refresh_token").value().expose_unredacted_secret(),
              "ref-mgr-1");

    ASSERT_TRUE(bootstrap.auth_manager().refresh_session().is_ok());
    EXPECT_EQ(bootstrap.secure_storage().get_secret("session_auth_token").value().expose_unredacted_secret(),
              "jwt-mgr-2");
    EXPECT_EQ(bootstrap.secure_storage().get_secret("session_refresh_token").value().expose_unredacted_secret(),
              "ref-mgr-2");

    const std::string duress_pin = "Panic#9999";
    ASSERT_TRUE(bootstrap.emergency_manager()
                    .configure_duress_pin(SecretString(duress_pin), PostWipeMode::EmergencyLocked)
                    .is_ok());

    ASSERT_TRUE(bootstrap.auth_manager().logout().is_ok());
    EXPECT_FALSE(bootstrap.auth_manager().is_authenticated());
    EXPECT_TRUE(bootstrap.secure_storage().get_secret("session_auth_token").is_error());
    EXPECT_TRUE(bootstrap.secure_storage().get_secret("session_refresh_token").is_error());
    EXPECT_TRUE(bootstrap.secure_storage().get_secret("session_id").is_error());
    EXPECT_EQ(server_->recorded_requests().size(), 3U);

    server_->clear_recorded_requests();
    const auto duress_res = bootstrap.auth_manager().authenticate_with_duress_check("alice", duress_pin);
    ASSERT_TRUE(duress_res.is_ok());
    EXPECT_EQ(duress_res.value().outcome, AuthOutcome::DuressWipeTriggered);
    EXPECT_TRUE(server_->recorded_requests().empty());
}

} // namespace
