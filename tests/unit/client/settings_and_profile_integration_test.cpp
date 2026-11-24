#include "application/client_application.hpp"
#include "application/client_bootstrap.hpp"
#include "application/client_config.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/contact.hpp"
#include "domain/conversation.hpp"
#include "domain/conversation_id.hpp"
#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/crypto/recovery_phrase_engine.hpp"
#include "domain/emergency_models.hpp"
#include "domain/user_id.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "ui/app_view_model.hpp"
#include "ui/navigation_controller.hpp"
#include "ui/ui_theme.hpp"
#include "ui/window_state_manager.hpp"
#include "ui/workspace_view_model.hpp"

#include <QCoreApplication>
#include <QHostAddress>
#include <QMetaObject>
#include <QPointer>
#include <QQmlApplicationEngine>
#include <QQmlComponent>
#include <QQmlContext>
#include <QQuickStyle>
#include <QSsl>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslKey>
#include <QSslSocket>
#include <QTcpServer>
#include <QThread>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
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
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::client::integration::test {
namespace {

using namespace std::chrono_literals;
using namespace securecloud::client::application;
using namespace securecloud::client::application::interfaces;
using namespace securecloud::client::domain;
using namespace securecloud::client::domain::crypto;
using namespace securecloud::client::infrastructure::adapters;
using namespace securecloud::client::ui;
using securecloud::common::configuration::SecretString;

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

struct QmlWarningCapture {
    inline static std::vector<std::string> warnings;
    inline static QtMessageHandler previous{nullptr};

    static void handler(QtMsgType type, const QMessageLogContext& context, const QString& msg) {
        if (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg) {
            const std::string category = (context.category != nullptr) ? std::string(context.category) : std::string{};
            const std::string text = msg.toStdString();
            if (category.find("qt.qpa.fonts") == std::string::npos && text.find("qt.qpa.fonts") == std::string::npos &&
                text.find("Populating font family aliases") == std::string::npos) {
                warnings.push_back(text);
            }
        }
        if (previous != nullptr) {
            previous(type, context, msg);
        }
    }
};

struct ScopedQmlWarningCapture {
    ScopedQmlWarningCapture() {
        QmlWarningCapture::warnings.clear();
        QmlWarningCapture::previous = qInstallMessageHandler(&QmlWarningCapture::handler);
    }
    ~ScopedQmlWarningCapture() { qInstallMessageHandler(QmlWarningCapture::previous); }
};

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

struct RecordedRequest {
    std::string method{};
    std::string target{};
    std::string authorization_header{};
    std::string body{};
};

struct LoopbackHttpResponse {
    int status{200};
    std::string content_type{"application/json"};
    std::string body{"{}"};
};

class LoopbackTls13Server final : public QTcpServer {
  public:
    using HandlerFn = std::function<LoopbackHttpResponse(const RecordedRequest&)>;

    LoopbackTls13Server() = default;
    ~LoopbackTls13Server() override { stop(); }

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

    [[nodiscard]] uint16_t port() const noexcept { return port_; }

    [[nodiscard]] std::vector<RecordedRequest> recorded_requests() const {
        std::lock_guard<std::mutex> lock(req_mutex_);
        return recorded_requests_;
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

            RecordedRequest rec;
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
                if (hk == "authorization") {
                    rec.authorization_header = hv;
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

            std::string raw = "HTTP/1.1 " + std::to_string(resp.status) + " OK\r\n";
            raw += "Content-Type: " + resp.content_type + "\r\n";
            raw += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
            raw += "Connection: close\r\n\r\n";
            raw.append(resp.body);
            sock->write(raw.data(), static_cast<qint64>(raw.size()));
            sock->flush();
            sock->disconnectFromHost();
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
    HandlerFn handler_;

    mutable std::mutex req_mutex_;
    std::vector<RecordedRequest> recorded_requests_;
};

class SettingsAndProfileIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        const std::string suffix = std::string(info->test_suite_name()) + "_" + std::string(info->name()) + "_" +
                                   std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        temp_dir_ = std::filesystem::temp_directory_path() / ("sc_client014_e2e_" + suffix);
        std::filesystem::create_directories(temp_dir_);
        db_path_ = temp_dir_ / "vault.db";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(temp_dir_, ec);
    }

    std::unique_ptr<ClientApplication> create_persistent_app(std::shared_ptr<MemorySecureStorage> shared_storage,
                                                             DefaultGatewayClient** out_gateway = nullptr) {
        ClientConfig config = ClientConfig::create_default();
        config.database_path = db_path_.string();

        auto gateway = std::make_unique<DefaultGatewayClient>(config);
        if (out_gateway != nullptr) {
            *out_gateway = gateway.get();
        }
        auto crypto = std::make_unique<OpenSslCryptoProvider>();
        auto secure_storage = std::make_unique<ForwardingSecureStorage>(shared_storage);
        auto local_store = std::make_unique<SqlCipherLocalStore>(*shared_storage, *crypto);

        auto bootstrap =
            ClientBootstrap::create_with_adapters(std::move(config), std::move(gateway), std::move(local_store),
                                                  std::move(secure_storage), std::move(crypto));
        auto app = std::make_unique<ClientApplication>(std::move(bootstrap));
        EXPECT_TRUE(app->initialize().is_ok());
        EXPECT_TRUE(app->start().is_ok());
        return app;
    }

    static std::string read_raw_file_bytes(const std::filesystem::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open()) {
            return {};
        }
        return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path db_path_;
};

TEST_F(SettingsAndProfileIntegrationTest,
       Scenario1_EncryptedSettingsMfaProxyAndProfilePersistAcrossSqlCipherRestartWithZeroPlaintextLeak) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    const QString expected_pin = QString(64, QLatin1Char('c'));

    {
        auto app = create_persistent_app(shared_storage);
        NavigationController nav;
        AppViewModel app_vm(*app, nav);
        WorkspaceViewModel vm(*app, nav);
        UiTheme theme;
        app_vm.setWorkspaceViewModel(&vm);
        vm.setUiTheme(&theme);
        app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("MasterVaultPass!2026"));

        ASSERT_TRUE(vm.saveUserProfile(QStringLiteral("Alice Classified Profile"), QStringLiteral("alice.secret_ops"),
                                       QStringLiteral("Zero-Trust Field Cryptographer"), false, true));
        ASSERT_TRUE(vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 1.25, true));
        vm.setMfaRequiredOnLogin(false);
        vm.setHardwareKeyEnforced(false);
        vm.setReadReceiptsEnabled(false);

        ASSERT_TRUE(vm.saveNetworkAndProxyConfig(false, QStringLiteral("gw.internal.local"), 9443,
                                                 static_cast<int>(ProxyType::Http), QStringLiteral("proxy.corp.secret"),
                                                 8080, QStringLiteral("field-proxy"),
                                                 QStringLiteral("SuperSecretProxyPass!99"), false, expected_pin, true));
        EXPECT_TRUE(vm.hasProxyPassword());

        (void)app->shutdown();
    }

    // Raw SQLCipher vault binary scan must contain zero plaintext secrets, profiles, or proxy settings.
    const std::string raw_db = read_raw_file_bytes(db_path_);
    ASSERT_FALSE(raw_db.empty());
    EXPECT_EQ(raw_db.find("Alice Classified Profile"), std::string::npos);
    EXPECT_EQ(raw_db.find("alice.secret_ops"), std::string::npos);
    EXPECT_EQ(raw_db.find("Zero-Trust Field Cryptographer"), std::string::npos);
    EXPECT_EQ(raw_db.find("proxy.corp.secret"), std::string::npos);
    EXPECT_EQ(raw_db.find("SuperSecretProxyPass!99"), std::string::npos);

    // Reopen fresh ClientApplication + ViewModels + UiTheme against the same SQLCipher database.
    {
        auto app2 = create_persistent_app(shared_storage);
        NavigationController nav2;
        AppViewModel app_vm2(*app2, nav2);
        WorkspaceViewModel vm2(*app2, nav2);
        UiTheme theme2;
        app_vm2.setWorkspaceViewModel(&vm2);
        app_vm2.requestLogin(QStringLiteral("alice"), QStringLiteral("MasterVaultPass!2026"));
        vm2.reloadFromLocalStore();
        vm2.setUiTheme(&theme2);

        EXPECT_EQ(vm2.profileDisplayName(), QStringLiteral("Alice Classified Profile"));
        EXPECT_EQ(vm2.profileHandle(), QStringLiteral("alice.secret_ops"));
        EXPECT_EQ(vm2.profileBio(), QStringLiteral("Zero-Trust Field Cryptographer"));
        EXPECT_FALSE(vm2.profileAllowDiscovery());

        EXPECT_EQ(theme2.themeMode(), ThemeMode::Light);
        EXPECT_DOUBLE_EQ(theme2.fontScale(), 1.25);
        EXPECT_TRUE(theme2.highContrastEnabled());
        EXPECT_EQ(theme2.backgroundPrimary(), QStringLiteral("#FFFFFF"));

        EXPECT_FALSE(vm2.mfaRequiredOnLogin());
        EXPECT_FALSE(vm2.hardwareKeyEnforced());
        EXPECT_FALSE(vm2.readReceiptsEnabled());

        EXPECT_EQ(vm2.gatewayHost(), QStringLiteral("gw.internal.local"));
        EXPECT_EQ(vm2.gatewayPort(), 9443);
        EXPECT_EQ(vm2.proxyType(), static_cast<int>(ProxyType::Http));
        EXPECT_EQ(vm2.proxyHost(), QStringLiteral("proxy.corp.secret"));
        EXPECT_EQ(vm2.proxyPort(), 8080);
        EXPECT_EQ(vm2.proxyUsername(), QStringLiteral("field-proxy"));
        EXPECT_TRUE(vm2.hasProxyPassword());
        EXPECT_EQ(vm2.tlsPinnedFingerprint(), expected_pin);
        EXPECT_TRUE(vm2.tlsEnforceStrictPinning());

        (void)app2->shutdown();
    }
}

TEST_F(SettingsAndProfileIntegrationTest, Scenario2_E2eeAvatarUploadAndGracefulProfileSyncPrivacyGate) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    DefaultGatewayClient* raw_gw = nullptr;
    auto app = create_persistent_app(shared_storage, &raw_gw);
    ASSERT_NE(raw_gw, nullptr);

    NavigationController nav;
    AppViewModel app_vm(*app, nav);
    WorkspaceViewModel vm(*app, nav);
    app_vm.setWorkspaceViewModel(&vm);
    app_vm.requestLogin(QStringLiteral("alice"), QStringLiteral("Strong-Password!2026"));

    // Write local PNG with identifiable plaintext bytes and upload via E2EE avatar flow.
    const std::filesystem::path avatar_path = temp_dir_ / "field_avatar.png";
    const std::string sentinel = "AVATAR_SECRET_RAW_PNG_MARKER_8812";
    {
        std::ofstream ofs(avatar_path, std::ios::binary);
        const std::string header = "\x89PNG\r\n\x1a\n";
        ofs.write(header.data(), static_cast<std::streamsize>(header.size()));
        ofs.write(sentinel.data(), static_cast<std::streamsize>(sentinel.size()));
    }

    ASSERT_TRUE(vm.uploadAvatarImage(QUrl::fromLocalFile(QString::fromStdString(avatar_path.string())).toString()));
    const std::string file_id = vm.profileAvatarFileId().toStdString();
    ASSERT_FALSE(file_id.empty());
    EXPECT_EQ(vm.profileAvatarSha256().size(), 64);

    // Server only ever receives AES-256 encrypted bytes; raw plaintext PNG sentinel must not exist on Gateway.
    ASSERT_TRUE(raw_gw->has_stored_file(file_id));
    const std::vector<uint8_t> remote_bytes = raw_gw->stored_file_raw_bytes(file_id);
    ASSERT_FALSE(remote_bytes.empty());
    const std::string remote_str(remote_bytes.begin(), remote_bytes.end());
    EXPECT_EQ(remote_str.find(sentinel), std::string::npos);

    // Privacy gate blocks outbound profile update calls when allow_handle_discovery == false.
    const std::size_t calls_before = raw_gw->profile_update_call_count();
    ASSERT_TRUE(vm.saveUserProfile(QStringLiteral("Alice E2EE"), QStringLiteral("alice.e2ee"),
                                   QStringLiteral("Encrypted Bio"), false, true));
    EXPECT_EQ(raw_gw->profile_update_call_count(), calls_before);
    EXPECT_EQ(vm.profileSyncStatusText(), QStringLiteral("Local Only (Discovery Disabled)"));

    // Simulate backend lacking UpdateUserProfile RPC -> saves locally and degrades cleanly via ProfileSyncStatus.
    raw_gw->set_simulated_profile_sync_unsupported(true);
    ASSERT_TRUE(vm.saveUserProfile(QStringLiteral("Alice E2EE"), QStringLiteral("alice.e2ee"),
                                   QStringLiteral("Encrypted Bio"), true, true));
    EXPECT_EQ(raw_gw->profile_update_call_count(), calls_before + 1U);
    EXPECT_EQ(vm.profileSyncStatusText(), QStringLiteral("Saved Locally (Gateway Sync Pending Server Support)"));

    (void)app->shutdown();
}

TEST_F(SettingsAndProfileIntegrationTest, Scenario3_RuntimeThemeHighContrastAndDynamicFontScalingWithoutRestart) {
    // Regression guard for cross-platform Windows Qt 6.8 native style customization warnings.
    EXPECT_EQ(QQuickStyle::name(), QStringLiteral("Basic"));

    ScopedQmlWarningCapture capture;

    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);

    NavigationController nav;
    AppViewModel app_vm(*app, nav);
    WorkspaceViewModel workspace_vm(*app, nav);
    UiTheme theme;
    WindowStateManager win_state;
    app_vm.setWorkspaceViewModel(&workspace_vm);
    workspace_vm.setUiTheme(&theme);

    QQmlApplicationEngine engine;
    qmlRegisterSingletonInstance<UiTheme>("SecureCloud.Theme", 1, 0, "Theme", &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("navigationController"), &nav);
    engine.rootContext()->setContextProperty(QStringLiteral("appViewModel"), &app_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("workspaceViewModel"), &workspace_vm);
    engine.rootContext()->setContextProperty(QStringLiteral("Theme"), &theme);
    engine.rootContext()->setContextProperty(QStringLiteral("windowStateManager"), &win_state);

    for (const char* qrc_url : {"qrc:/qml/SettingsPlaceholder.qml", "qrc:/qml/Main.qml"}) {
        QQmlComponent component(&engine, QUrl(QString::fromUtf8(qrc_url)));
        ASSERT_TRUE(component.isReady()) << qrc_url << ": " << component.errorString().toStdString();
        QObject* root = component.create();
        ASSERT_NE(root, nullptr) << qrc_url;

        // Exercise zero-restart live transitions across Dark, Light, High-Contrast Dark/Light, and 0.85x-1.40x scale.
        ASSERT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Dark), 1.0, false));
        QCoreApplication::processEvents();
        EXPECT_EQ(theme.fontBody(), 13);
        EXPECT_EQ(theme.backgroundPrimary(), QStringLiteral("#0B0F17"));

        ASSERT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 1.20, false));
        QCoreApplication::processEvents();
        EXPECT_EQ(theme.fontBody(), 16);
        EXPECT_EQ(theme.backgroundPrimary(), QStringLiteral("#F1F5F9"));

        ASSERT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Dark), 1.30, true));
        QCoreApplication::processEvents();
        EXPECT_EQ(theme.fontBody(), 17);
        EXPECT_EQ(theme.backgroundPrimary(), QStringLiteral("#000000"));
        EXPECT_EQ(theme.textPrimary(), QStringLiteral("#FFFFFF"));

        ASSERT_TRUE(workspace_vm.applyAndSaveAppearance(static_cast<int>(ThemeMode::Light), 1.40, true));
        QCoreApplication::processEvents();
        EXPECT_EQ(theme.fontBody(), 18);
        EXPECT_EQ(theme.backgroundPrimary(), QStringLiteral("#FFFFFF"));
        EXPECT_EQ(theme.textPrimary(), QStringLiteral("#000000"));

        delete root;
        QCoreApplication::sendPostedEvents();
        QCoreApplication::processEvents();
    }

    EXPECT_TRUE(QmlWarningCapture::warnings.empty())
        << (QmlWarningCapture::warnings.empty() ? "" : QmlWarningCapture::warnings.front());

    (void)app->shutdown();
}

TEST_F(SettingsAndProfileIntegrationTest, Scenario4_DisappearingMessageTimersAndAutomaticPurgeEnforcement) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    auto app = create_persistent_app(shared_storage);

    const UserId alice("alice-ttl-e2e");
    const DeviceId alice_dev("dev-alice-e2e");
    const UserId bob("bob-ttl-e2e");
    const DeviceId bob_dev("dev-bob-e2e");

    ASSERT_TRUE(app->bootstrap()
                    .contact_manager()
                    .add_or_update_contact(Contact(bob, "Bob TTL", KeyVerificationStatus::Verified, "fp-bob", false))
                    .is_ok());

    NavigationController nav;
    AppViewModel app_vm(*app, nav);
    WorkspaceViewModel vm(*app, nav);
    app_vm.setWorkspaceViewModel(&vm);
    app_vm.requestLogin(QStringLiteral("alice-ttl-e2e"), QStringLiteral("Strong-Password!2026"));

    auto& msg_mgr = app->bootstrap().messaging_manager();
    msg_mgr.set_local_device_id(alice_dev);

    // 1. Create a persistent conversation while workspace default timer is Off (0s).
    ASSERT_TRUE(vm.setDefaultDisappearingTimer(0));
    const auto persist_res = msg_mgr.open_direct_conversation(alice, UserId("carol-persist"), "Persistent Off");
    ASSERT_TRUE(persist_res.is_ok());
    const auto out_off =
        msg_mgr.stage_outbound_message(persist_res.value().conversation_id(), alice, alice_dev, "keep-forever");
    ASSERT_TRUE(out_off.is_ok());
    EXPECT_EQ(out_off.value().expires_at_ms(), 0LL);

    // 2. Configure 1h default disappearing timer via ViewModel -> new 1:1 & group conversations inherit 3600s TTL.
    ASSERT_TRUE(vm.setDefaultDisappearingTimer(3600));
    const auto direct_res = msg_mgr.open_direct_conversation(alice, bob, "Direct Disappearing 1h");
    ASSERT_TRUE(direct_res.is_ok());
    EXPECT_EQ(direct_res.value().disappearing_ttl_seconds(), 3600LL);

    const auto group_res = msg_mgr.create_group_conversation(alice, "Group Disappearing 1h", {bob});
    ASSERT_TRUE(group_res.is_ok());
    EXPECT_EQ(group_res.value().disappearing_ttl_seconds(), 3600LL);

    const auto out_1h =
        msg_mgr.stage_outbound_message(direct_res.value().conversation_id(), alice, alice_dev, "burn-after-1h-direct");
    ASSERT_TRUE(out_1h.is_ok());
    ASSERT_GT(out_1h.value().expires_at_ms(), 0LL);

    const auto enc_in = app->bootstrap().crypto_provider().encrypt_message(bob_dev, "burn-after-1h-group");
    ASSERT_TRUE(enc_in.is_ok());
    PerDeviceDeliveryPayload grp_payload{};
    grp_payload.recipient_user_id = alice;
    grp_payload.recipient_device_id = alice_dev;
    grp_payload.ciphertext_blob = enc_in.value();
    grp_payload.algorithm = "Stub";
    const auto out_grp =
        msg_mgr.process_inbound_message(group_res.value().conversation_id(), bob, bob_dev, grp_payload);
    ASSERT_TRUE(out_grp.is_ok());
    ASSERT_GT(out_grp.value().expires_at_ms(), 0LL);

    vm.reloadFromLocalStore();
    vm.selectConversation(QString::fromStdString(direct_res.value().conversation_id().value()));
    EXPECT_EQ(vm.activeMessages().size(), 1);

    const int64_t max_exp_ms = std::max(out_1h.value().expires_at_ms(), out_grp.value().expires_at_ms());
    const auto purge_res = msg_mgr.purge_expired_messages(max_exp_ms + 1000LL);
    ASSERT_TRUE(purge_res.is_ok());
    EXPECT_EQ(purge_res.value(), 2U);

    vm.reloadFromLocalStore();
    vm.selectConversation(QString::fromStdString(direct_res.value().conversation_id().value()));
    EXPECT_TRUE(vm.activeMessages().isEmpty());

    vm.selectConversation(QString::fromStdString(group_res.value().conversation_id().value()));
    EXPECT_TRUE(vm.activeMessages().isEmpty());

    vm.selectConversation(QString::fromStdString(persist_res.value().conversation_id().value()));
    EXPECT_EQ(vm.activeMessages().size(), 1);

    (void)app->shutdown();
}

TEST_F(SettingsAndProfileIntegrationTest, Scenario5_EndpointOnlyBip39Recovery12And24WordLifecycleAndPanicWipePurge) {
    auto shared_storage = std::make_shared<MemorySecureStorage>();
    DefaultGatewayClient* raw_gw = nullptr;
    auto app = create_persistent_app(shared_storage, &raw_gw);
    ASSERT_NE(raw_gw, nullptr);
    app->bootstrap().initialize_ratchet_session_manager(UserId("alice-bip39"), DeviceId("dev-bip39"));

    NavigationController nav;
    WorkspaceViewModel vm(*app, nav);

    // Save a proxy secret too so we verify panic wipe clears both BIP-39 verifier and proxy secret.
    ASSERT_TRUE(vm.saveNetworkAndProxyConfig(false, QStringLiteral("127.0.0.1"), 8443,
                                             static_cast<int>(ProxyType::Http), QStringLiteral("proxy.bip39.local"),
                                             8080, QStringLiteral("u"), QStringLiteral("ProxyToShred!7"), false,
                                             QString(), true));
    EXPECT_TRUE(vm.hasProxyPassword());

    const std::size_t gw_calls_before = raw_gw->submitted_fanouts().size() + raw_gw->sent_delivery_acks().size() +
                                        raw_gw->sent_read_receipts().size() + raw_gw->profile_update_call_count();

    // 1. Default 12-word BIP-39 lifecycle + 3-word confirmation quiz + deterministic 64-byte recovery seed.
    const QVariantMap payload12 = vm.generateRecoveryPhraseWords(false);
    const QStringList words12 = payload12.value(QStringLiteral("words")).toStringList();
    const QVariantList indices12 = payload12.value(QStringLiteral("challengeIndices")).toList();
    ASSERT_EQ(words12.size(), 12);
    ASSERT_EQ(indices12.size(), 3);

    QVariantList bad_answers{QStringLiteral("notaword"), QStringLiteral("wrong"), QStringLiteral("fail")};
    EXPECT_FALSE(vm.confirmRecoveryPhraseChallenge(indices12, bad_answers));
    EXPECT_FALSE(vm.recoveryPhraseVerified());

    QVariantList good_answers12;
    for (const auto& idxVar : indices12) {
        good_answers12.append(words12[idxVar.toInt()]);
    }
    EXPECT_TRUE(vm.confirmRecoveryPhraseChallenge(indices12, good_answers12));
    EXPECT_TRUE(vm.recoveryPhraseVerified());

    const SecretString mn12(words12.join(QLatin1Char(' ')).toStdString());
    EXPECT_TRUE(RecoveryPhraseEngine::validate_mnemonic(mn12).value());
    const auto seed12 = RecoveryPhraseEngine::derive_recovery_seed(mn12);
    ASSERT_TRUE(seed12.is_ok());
    EXPECT_EQ(seed12.value().size(), RecoveryPhraseEngine::kSeedBytes);

    // Try up to two distinct leading words so 1/16 accidental 4-bit checksum collisions never cause flakiness.
    QStringList tampered_list = words12;
    const QString orig_first = tampered_list[0];
    tampered_list[0] =
        (orig_first == QStringLiteral("abandon")) ? QStringLiteral("ability") : QStringLiteral("abandon");
    if (RecoveryPhraseEngine::validate_mnemonic(SecretString(tampered_list.join(QLatin1Char(' ')).toStdString()))
            .value()) {
        tampered_list[0] = (orig_first == QStringLiteral("able")) ? QStringLiteral("about") : QStringLiteral("able");
    }
    EXPECT_FALSE(
        RecoveryPhraseEngine::validate_mnemonic(SecretString(tampered_list.join(QLatin1Char(' ')).toStdString()))
            .value());

    // 2. Optional 24-word BIP-39 lifecycle.
    const QVariantMap payload24 = vm.generateRecoveryPhraseWords(true);
    const QStringList words24 = payload24.value(QStringLiteral("words")).toStringList();
    const QVariantList indices24 = payload24.value(QStringLiteral("challengeIndices")).toList();
    ASSERT_EQ(words24.size(), 24);
    QVariantList good_answers24;
    for (const auto& idxVar : indices24) {
        good_answers24.append(words24[idxVar.toInt()]);
    }
    EXPECT_TRUE(vm.confirmRecoveryPhraseChallenge(indices24, good_answers24));
    EXPECT_TRUE(vm.verifyRecoveryPhraseInput(words24.join(QLatin1Char(' '))));

    // Zero Gateway calls permitted across entire BIP-39 generation/challenge/verification flow.
    const std::size_t gw_calls_after = raw_gw->submitted_fanouts().size() + raw_gw->sent_delivery_acks().size() +
                                       raw_gw->sent_read_receipts().size() + raw_gw->profile_update_call_count();
    EXPECT_EQ(gw_calls_after, gw_calls_before);

    // 3. Emergency panic wipe must completely destroy recovery verifier and proxy password.
    const auto wipe_res = app->bootstrap().emergency_manager().execute_panic_wipe(PanicTriggerSource::UiPanicButton);
    ASSERT_TRUE(wipe_res.is_ok());
    vm.resetForEmergencyWipe();

    EXPECT_FALSE(app->bootstrap().secure_storage().has_secret(kRecoveryVerifierStorageKey).value());
    EXPECT_FALSE(app->bootstrap().secure_storage().has_secret(kProxyPasswordStorageKey).value());
    EXPECT_FALSE(vm.recoveryPhraseVerified());
    EXPECT_FALSE(vm.hasProxyPassword());

    (void)app->shutdown();
}

TEST_F(SettingsAndProfileIntegrationTest, Scenario6_LiveLoopbackTls13GatewayHandshakeSpkiPinEnforcementAndHotReload) {
    const CertBundle ca = generate_root_ca("SecureCloud E2E Root CA");
    const CertBundle leaf_a = generate_leaf_cert(ca, "127.0.0.1", 101L);
    const CertBundle leaf_b = generate_leaf_cert(ca, "127.0.0.1", 102L);
    ASSERT_NE(leaf_a.spki_sha256_hex, leaf_b.spki_sha256_hex);

    const std::filesystem::path ca_pem_path = temp_dir_ / "e2e_ca.pem";
    {
        std::ofstream ofs(ca_pem_path, std::ios::binary);
        ofs.write(ca.cert_pem.data(), static_cast<std::streamsize>(ca.cert_pem.size()));
    }

    LoopbackTls13Server server;
    ASSERT_TRUE(server.start_tls(leaf_a.qs_cert, leaf_a.qs_key, ca.qs_cert, [](const RecordedRequest& req) {
        if (req.target == "/health/live") {
            return LoopbackHttpResponse{.status = 200, .body = "{\"status\":\"LIVE\"}"};
        }
        if (req.target == "/api/v1/users/me") {
            nlohmann::json user_obj = nlohmann::json::object();
            user_obj["user_id"] = "alice-live";
            user_obj["credential_identifier"] = "alice.live";
            user_obj["display_name"] = "Alice Live TLS";
            nlohmann::json root = nlohmann::json::object();
            root["user"] = user_obj;
            return LoopbackHttpResponse{.status = 200, .body = root.dump()};
        }
        return LoopbackHttpResponse{.status = 404, .body = "{\"error\":\"not_found\"}"};
    }));

    // Boot real ClientBootstrap starting in Simulated mode so initialize() succeeds cleanly without remote Gateway.
    ClientConfig cfg = ClientConfig::create_default();
    cfg.database_path = db_path_.string();
    cfg.tls_ca_cert_path = ca_pem_path.string();
    cfg.gateway_url = "https://127.0.0.1";
    cfg.gateway_port = server.port();
    cfg.use_live_gateway_transport = false;

    ClientApplication app(cfg);
    ASSERT_TRUE(app.initialize().is_ok());
    ASSERT_TRUE(app.start().is_ok());
    ASSERT_TRUE(app.bootstrap()
                    .secure_storage()
                    .store_secret("session_auth_token", SecretString("bearer-live-e2e-token"))
                    .is_ok());

    EXPECT_FALSE(app.bootstrap().is_live_gateway_transport_active());

    {
        NavigationController nav;
        WorkspaceViewModel vm(app, nav);

        // 1. Hot-reload SwitchableGatewayClient from Simulator -> Live TLS 1.3 via WorkspaceViewModel.
        ASSERT_TRUE(vm.saveNetworkAndProxyConfig(true, QStringLiteral("127.0.0.1"), server.port(),
                                                 static_cast<int>(ProxyType::None), QString(), 0, QString(), QString(),
                                                 false, QString(), true));
        EXPECT_TRUE(app.bootstrap().is_live_gateway_transport_active());

        // 2. Inspect live server certificate SPKI SHA-256 and save pin into encrypted SQLCipher settings.
        const QVariantMap inspected = vm.inspectGatewayTlsFingerprint(QStringLiteral("127.0.0.1"), server.port(), true);
        EXPECT_EQ(inspected.value(QStringLiteral("spkiSha256")).toString(),
                  QString::fromStdString(leaf_a.spki_sha256_hex));
        EXPECT_EQ(vm.tlsPinnedFingerprint(), QString::fromStdString(leaf_a.spki_sha256_hex));
        EXPECT_TRUE(vm.tlsPinMatches());

        // 3. Execute live TLS 1.3 REST calls using matching SPKI pin.
        const auto probe_res = app.bootstrap().gateway().probe_gateway("/health");
        ASSERT_TRUE(probe_res.is_ok()) << probe_res.error().user_message();
        EXPECT_TRUE(probe_res.value());

        const auto prof_res = app.bootstrap().gateway().get_user_profile(UserId("alice-live"));
        ASSERT_TRUE(prof_res.is_ok()) << prof_res.error().user_message();
        EXPECT_EQ(prof_res.value().display_name, "Alice Live TLS");
        EXPECT_EQ(prof_res.value().public_handle, "alice.live");

        const auto reqs_before_rotation = server.recorded_requests();
        ASSERT_GE(reqs_before_rotation.size(), 2U);
        EXPECT_EQ(reqs_before_rotation.back().authorization_header, "Bearer bearer-live-e2e-token");

        // 4. Rotate server leaf certificate to leaf_b -> pinned client MUST fail closed BEFORE sending Bearer token.
        server.set_server_certificate(leaf_b.qs_cert, leaf_b.qs_key);
        const auto rotated_res = app.bootstrap().gateway().get_user_profile(UserId("alice-live"));
        ASSERT_TRUE(rotated_res.is_error());
        EXPECT_EQ(rotated_res.error().category(), ClientErrorCategory::Network);

        // Server must NOT have received any HTTP request or Bearer header after SPKI pin mismatch.
        EXPECT_EQ(server.recorded_requests().size(), reqs_before_rotation.size());
    }

    (void)app.shutdown();
    server.stop();
}

} // namespace
} // namespace securecloud::client::integration::test
