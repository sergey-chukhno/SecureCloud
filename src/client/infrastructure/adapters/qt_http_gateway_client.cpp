#include "infrastructure/adapters/qt_http_gateway_client.hpp"

#include "domain/crypto/file_crypto_engine.hpp"
#include "infrastructure/client_logger.hpp"

#include <QByteArray>
#include <QDateTime>
#include <QMetaObject>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QObject>
#include <QSsl>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QSslSocket>
#include <QString>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace securecloud::client::infrastructure::adapters {
namespace {

using application::ClientConfig;
using application::ClientError;
using application::ClientErrorCategory;
using application::ClientErrorCode;
using application::ClientResult;
using namespace application::interfaces;
using common::configuration::SecretString;

constexpr std::string_view kLogTag = "QtHttpGatewayClient";
constexpr int kMinDeadlineMs = 1;

void ensure_qt_openssl_tls_backend() {
    static std::once_flag once;
    std::call_once(once, []() {
        if (!QSslSocket::activeBackend().isEmpty()) {
            return;
        }
        const auto backends = QSslSocket::availableBackends();
        const QString openssl_name = QStringLiteral("openssl");
        if (backends.contains(openssl_name)) {
            (void)QSslSocket::setActiveBackend(openssl_name);
        }
    });
}

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

[[nodiscard]] std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4U) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

[[nodiscard]] std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
    if (hex.empty() || (hex.size() % 2U) != 0U) {
        return std::nullopt;
    }
    auto nibble = [](char ch) noexcept -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return 10 + (ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
            return 10 + (ch - 'A');
        }
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

[[nodiscard]] std::string bytes_to_base64(std::span<const uint8_t> bytes) {
    if (bytes.empty()) {
        return {};
    }
    const QByteArray raw(reinterpret_cast<const char*>(bytes.data()), static_cast<qsizetype>(bytes.size()));
    return raw.toBase64().toStdString();
}

[[nodiscard]] std::vector<uint8_t> decode_wire_bytes(std::string_view encoded) {
    if (encoded.empty()) {
        return {};
    }
    if (const auto hex_res = hex_to_bytes(encoded); hex_res.has_value()) {
        return *hex_res;
    }
    const QByteArray raw_b64(encoded.data(), static_cast<qsizetype>(encoded.size()));
    const QByteArray decoded = QByteArray::fromBase64(raw_b64);
    if (decoded.isEmpty()) {
        return {};
    }
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(decoded.constData()),
                                reinterpret_cast<const uint8_t*>(decoded.constData()) + decoded.size());
}

[[nodiscard]] bool is_printable_ascii_wire(std::string_view raw) noexcept {
    for (const char ch : raw) {
        const unsigned char u = static_cast<unsigned char>(ch);
        if ((u < 0x20U || u > 0x7EU) && ch != '\n' && ch != '\r' && ch != '\t') {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool is_valid_standard_base64(std::string_view encoded) noexcept {
    if (encoded.empty() || (encoded.size() % 4U) != 0U) {
        return false;
    }
    std::size_t pad = 0U;
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        const char ch = encoded[i];
        if (ch == '=') {
            ++pad;
            if (pad > 2U || i + 1U < encoded.size() - 1U) {
                if (i < encoded.size() - 2U) {
                    return false;
                }
            }
            continue;
        }
        if (pad > 0U) {
            return false;
        }
        const bool ok =
            (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/';
        if (!ok) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string encode_ciphertext_for_json(std::string_view raw) {
    if (raw.empty() || is_printable_ascii_wire(raw)) {
        return std::string(raw);
    }
    const std::span<const uint8_t> bytes(reinterpret_cast<const uint8_t*>(raw.data()), raw.size());
    return bytes_to_base64(bytes);
}

[[nodiscard]] std::string decode_ciphertext_from_json(std::string_view value) {
    if (is_valid_standard_base64(value)) {
        const QByteArray raw_b64(value.data(), static_cast<qsizetype>(value.size()));
        const QByteArray decoded = QByteArray::fromBase64(raw_b64);
        if (!decoded.isEmpty()) {
            std::size_t printable = 0U;
            const std::size_t sample_len = std::min<std::size_t>(static_cast<std::size_t>(decoded.size()), 256U);
            for (std::size_t i = 0; i < sample_len; ++i) {
                const unsigned char ch = static_cast<unsigned char>(decoded.at(static_cast<qsizetype>(i)));
                if ((ch >= 0x20U && ch <= 0x7EU) || ch == '\n' || ch == '\r' || ch == '\t') {
                    ++printable;
                }
            }
            if (static_cast<double>(printable) / static_cast<double>(sample_len) < 0.90) {
                return std::string(decoded.constData(), static_cast<std::size_t>(decoded.size()));
            }
        }
    }
    return std::string(value);
}

[[nodiscard]] std::string parse_authentication_level(const nlohmann::json& j) {
    if (!j.contains("authentication_level")) {
        return {};
    }
    const auto& lvl = j["authentication_level"];
    if (lvl.is_string()) {
        return lvl.get<std::string>();
    }
    if (lvl.is_number_integer()) {
        const int code = lvl.get<int>();
        if (code == 0) {
            return "AUTH_LEVEL_UNSPECIFIED";
        }
        if (code == 1) {
            return "AUTH_LEVEL_PASSWORD";
        }
        if (code == 2) {
            return "AUTH_LEVEL_MFA";
        }
        return std::to_string(code);
    }
    return {};
}

[[nodiscard]] std::optional<domain::RemoteConversationSummary> parse_conversation_summary(const nlohmann::json& cj) {
    if (!cj.is_object()) {
        return std::nullopt;
    }
    const std::string cid = cj.value("conversation_id", std::string{});
    if (cid.empty()) {
        return std::nullopt;
    }
    domain::RemoteConversationSummary sum;
    sum.conversation_id = domain::ConversationId(cid);
    const std::string t = cj.value("type", std::string{"direct"});
    sum.type = (t == "group") ? domain::ConversationType::Group : domain::ConversationType::Direct;
    sum.title = cj.value("title", std::string{});
    if (const std::string cr = cj.value("creator_user_id", std::string{}); !cr.empty()) {
        sum.creator_user_id = domain::UserId(cr);
    }
    sum.created_at_ms = cj.value("created_at_unix_ms", int64_t{0});
    if (cj.contains("participant_user_ids") && cj["participant_user_ids"].is_array()) {
        for (const auto& p : cj["participant_user_ids"]) {
            if (p.is_string() && !p.get<std::string>().empty()) {
                sum.participant_user_ids.emplace_back(p.get<std::string>());
            }
        }
    }
    return sum;
}

[[nodiscard]] ClientResult<AuthSessionResult> parse_auth_session_result(std::string_view body,
                                                                        std::string_view fallback_user_id = "",
                                                                        std::string_view error_context = "auth") {
    try {
        const auto j = nlohmann::json::parse(body);
        if (!j.is_object()) {
            return ClientResult<AuthSessionResult>::error(
                ClientError::network("Malformed Gateway " + std::string(error_context) + " JSON response"));
        }
        AuthSessionResult out;
        out.session_id = j.value("session_id", std::string{});
        out.device_id = j.value("device_id", std::string{});
        const std::string uid = j.value("user_id", std::string{fallback_user_id});
        if (!uid.empty()) {
            out.user_id = domain::UserId(uid);
        }
        if (const std::string access = j.value("access_token", std::string{}); !access.empty()) {
            out.access_token = SecretString(access);
        }
        if (const std::string refresh = j.value("refresh_token", std::string{}); !refresh.empty()) {
            out.refresh_token = SecretString(refresh);
        }
        out.authentication_level = parse_authentication_level(j);
        out.expires_at_epoch_ms = j.value("expires_at_epoch_ms", int64_t{0});
        out.mfa_required = j.value("mfa_required", false);
        out.mfa_challenge_id = j.value("mfa_challenge_id", std::string{});
        if (!out.mfa_required && out.access_token.empty()) {
            return ClientResult<AuthSessionResult>::error(ClientError::authentication(
                "Gateway " + std::string(error_context) + " response missing access_token"));
        }
        return ClientResult<AuthSessionResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<AuthSessionResult>::error(
            ClientError::network("Malformed Gateway " + std::string(error_context) + " JSON response"));
    }
}

[[nodiscard]] std::optional<std::string> compute_spki_sha256_hex(const QSslCertificate& cert) {
    if (cert.isNull()) {
        return std::nullopt;
    }
    const QByteArray cert_der = cert.toDer();
    if (cert_der.isEmpty()) {
        return std::nullopt;
    }

    const unsigned char* der_ptr = reinterpret_cast<const unsigned char*>(cert_der.constData());
    X509* raw_x509 = d2i_X509(nullptr, &der_ptr, cert_der.size());
    if (raw_x509 == nullptr) {
        return std::nullopt;
    }
    std::unique_ptr<X509, decltype(&X509_free)> x509(raw_x509, &X509_free);

    const X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(x509.get());
    if (pubkey == nullptr) {
        return std::nullopt;
    }

    const int spki_len = i2d_X509_PUBKEY(pubkey, nullptr);
    if (spki_len <= 0) {
        return std::nullopt;
    }

    std::vector<uint8_t> spki_der(static_cast<std::size_t>(spki_len));
    unsigned char* out_ptr = spki_der.data();
    if (i2d_X509_PUBKEY(pubkey, &out_ptr) != spki_len) {
        return std::nullopt;
    }

    const auto digest_res = domain::crypto::StreamingSha256::digest_hex(spki_der);
    if (digest_res.is_error()) {
        return std::nullopt;
    }
    return digest_res.value();
}

[[nodiscard]] bool spki_pin_matches(std::string_view expected_pin_hex, std::string_view actual_spki_hex) noexcept {
    if (expected_pin_hex.size() != domain::kSha256HexLength || actual_spki_hex.size() != domain::kSha256HexLength) {
        return false;
    }
    return CRYPTO_memcmp(expected_pin_hex.data(), actual_spki_hex.data(), domain::kSha256HexLength) == 0;
}

[[nodiscard]] QNetworkProxy build_qt_proxy(const ClientConfig& cfg) {
    QNetworkProxy proxy;
    switch (cfg.proxy_type) {
    case domain::ProxyType::Http:
        proxy.setType(QNetworkProxy::HttpProxy);
        break;
    case domain::ProxyType::Socks5:
        proxy.setType(QNetworkProxy::Socks5Proxy);
        break;
    case domain::ProxyType::None:
    default:
        proxy.setType(QNetworkProxy::NoProxy);
        return proxy;
    }

    proxy.setHostName(QString::fromStdString(cfg.proxy_host));
    proxy.setPort(cfg.proxy_port);
    if (!cfg.proxy_username.empty()) {
        proxy.setUser(QString::fromStdString(cfg.proxy_username));
    }
    if (!cfg.proxy_password.empty()) {
        proxy.setPassword(QString::fromStdString(cfg.proxy_password.expose_unredacted_secret()));
    }
    return proxy;
}

[[nodiscard]] ClientResult<QSslConfiguration> build_tls13_ssl_config(const ClientConfig& cfg) {
    QSslConfiguration ssl_cfg = QSslConfiguration::defaultConfiguration();
    ssl_cfg.setProtocol(QSsl::TlsV1_3OrLater);
    ssl_cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);

    if (!cfg.tls_ca_cert_path.empty()) {
        const QString ca_path = QString::fromStdString(cfg.tls_ca_cert_path);
        const QList<QSslCertificate> ca_certs = QSslCertificate::fromPath(ca_path, QSsl::Pem);
        if (ca_certs.isEmpty()) {
            return ClientResult<QSslConfiguration>::error(ClientError(
                ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                "Failed to load custom TLS CA certificate bundle", "tls_ca_cert_path yielded zero valid certificates"));
        }
        ssl_cfg.setCaCertificates(ca_certs);
    }

    return ClientResult<QSslConfiguration>::ok(std::move(ssl_cfg));
}

[[nodiscard]] std::string join_ssl_errors(const QList<QSslError>& errors) {
    std::string combined;
    for (int i = 0; i < errors.size(); ++i) {
        if (i > 0) {
            combined += "; ";
        }
        combined += errors[i].errorString().toStdString();
    }
    return ClientLogger::sanitize(combined);
}

[[nodiscard]] std::string url_encode(std::string_view value) {
    const QByteArray raw(value.data(), static_cast<qsizetype>(value.size()));
    return QByteArray(QUrl::toPercentEncoding(QString::fromUtf8(raw))).toStdString();
}

[[nodiscard]] ClientResult<QUrl>
build_endpoint_url(const ClientConfig& cfg, std::string_view path,
                   const std::vector<std::pair<std::string, std::string>>& query = {}) {
    QUrl url(QString::fromStdString(cfg.gateway_url));
    if (!url.isValid() || url.scheme().isEmpty() || url.host().isEmpty()) {
        return ClientResult<QUrl>::error(ClientError::validation("Invalid Gateway URL configuration"));
    }

    if (url.port(-1) == -1 && cfg.gateway_port != 0U) {
        url.setPort(static_cast<int>(cfg.gateway_port));
    }

    std::string normalized_path(path);
    if (normalized_path.empty() || normalized_path.front() != '/') {
        normalized_path.insert(normalized_path.begin(), '/');
    }
    url.setPath(QString::fromStdString(normalized_path));

    if (!query.empty()) {
        QUrlQuery q;
        for (const auto& [k, v] : query) {
            q.addQueryItem(QString::fromStdString(k), QString::fromStdString(v));
        }
        url.setQuery(q);
    }

    return ClientResult<QUrl>::ok(std::move(url));
}

[[nodiscard]] std::string extract_gateway_error_message(std::string_view raw_body, int http_status,
                                                        std::string_view fallback_reason) {
    if (!raw_body.empty()) {
        try {
            const auto j = nlohmann::json::parse(raw_body);
            if (j.is_object()) {
                if (j.contains("error") && j["error"].is_object()) {
                    const auto& err_obj = j["error"];
                    if (err_obj.contains("message") && err_obj["message"].is_string()) {
                        const std::string msg = err_obj["message"].get<std::string>();
                        if (!msg.empty()) {
                            return ClientLogger::sanitize(msg);
                        }
                    }
                }
                if (j.contains("detail") && j["detail"].is_string()) {
                    const std::string detail = j["detail"].get<std::string>();
                    if (!detail.empty()) {
                        return ClientLogger::sanitize(detail);
                    }
                }
                if (j.contains("message") && j["message"].is_string()) {
                    const std::string msg = j["message"].get<std::string>();
                    if (!msg.empty()) {
                        return ClientLogger::sanitize(msg);
                    }
                }
            }
        } catch (...) {
        }
    }
    if (!fallback_reason.empty()) {
        return ClientLogger::sanitize(fallback_reason);
    }
    return "Gateway HTTP error " + std::to_string(http_status);
}

[[nodiscard]] ClientError map_http_status_error(int status_code, std::string_view body, std::string_view reason_phrase,
                                                std::string correlation_id) {
    const std::string msg = extract_gateway_error_message(body, status_code, reason_phrase);
    const std::string details = "HTTP " + std::to_string(status_code);

    if (status_code == 400 || status_code == 409 || status_code == 412 || status_code == 422) {
        return ClientError(ClientErrorCode::ValidationFailed, ClientErrorCategory::Validation, msg, details,
                           std::move(correlation_id));
    }
    if (status_code == 401 || status_code == 403) {
        const ClientErrorCode code =
            (status_code == 401) ? ClientErrorCode::AuthenticationRequired : ClientErrorCode::Unauthorized;
        return ClientError(code, ClientErrorCategory::Authentication, msg, details, std::move(correlation_id));
    }
    if (status_code == 404 || status_code == 405 || status_code == 501) {
        return ClientError(ClientErrorCode::ProtocolError, ClientErrorCategory::Network, msg, details,
                           std::move(correlation_id));
    }
    if (status_code == 504) {
        return ClientError(ClientErrorCode::ConnectionTimeout, ClientErrorCategory::Network, msg, details,
                           std::move(correlation_id));
    }
    return ClientError(ClientErrorCode::NetworkUnavailable, ClientErrorCategory::Network, msg, details,
                       std::move(correlation_id));
}

[[nodiscard]] domain::DeliveryState parse_delivery_state_string(std::string_view raw) noexcept {
    const std::string lower = to_lower_ascii(raw);
    if (lower == "read") {
        return domain::DeliveryState::Read;
    }
    if (lower == "delivered") {
        return domain::DeliveryState::Delivered;
    }
    if (lower == "delivering" || lower == "retry_wait") {
        return domain::DeliveryState::Delivering;
    }
    if (lower == "failed" || lower == "expired") {
        return domain::DeliveryState::Failed;
    }
    return domain::DeliveryState::Accepted;
}

[[nodiscard]] domain::DeviceAuthorizationStatus parse_device_auth_status(const nlohmann::json& j,
                                                                         const char* key) noexcept {
    if (!j.contains(key)) {
        return domain::DeviceAuthorizationStatus::Authorized;
    }
    if (j[key].is_number_integer()) {
        const int code = j[key].get<int>();
        if (code == 2) {
            return domain::DeviceAuthorizationStatus::Revoked;
        }
        if (code == 3) {
            return domain::DeviceAuthorizationStatus::Pending;
        }
        return domain::DeviceAuthorizationStatus::Authorized;
    }
    if (j[key].is_string()) {
        const std::string lower = to_lower_ascii(j[key].get<std::string>());
        if (lower.find("revoked") != std::string::npos) {
            return domain::DeviceAuthorizationStatus::Revoked;
        }
        if (lower.find("pending") != std::string::npos) {
            return domain::DeviceAuthorizationStatus::Pending;
        }
    }
    return domain::DeviceAuthorizationStatus::Authorized;
}

struct HttpResponse {
    int status_code{0};
    std::string body{};
    std::string header_ciphertext_sha256{};
    std::string request_id{};
};

} // namespace

struct QtHttpGatewayClient::Impl {
    Impl(ClientConfig cfg, BearerTokenProvider provider)
        : config_(std::move(cfg)), token_provider_(std::move(provider)) {
        ensure_qt_openssl_tls_backend();
        config_.pinned_tls_spki_sha256 = domain::normalize_hex_lower(config_.pinned_tls_spki_sha256);
    }

    ~Impl() { shutdown_worker(); }

    void reconfigure(const ClientConfig& cfg) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        config_ = cfg;
        config_.pinned_tls_spki_sha256 = domain::normalize_hex_lower(config_.pinned_tls_spki_sha256);
        config_generation_.fetch_add(1U, std::memory_order_relaxed);
    }

    [[nodiscard]] ClientConfig snapshot_config() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return config_;
    }

    [[nodiscard]] std::optional<SecretString> resolve_bearer_token(const ClientConfig& cfg) const {
        if (!cfg.auth_token.empty()) {
            return cfg.auth_token;
        }
        if (token_provider_) {
            if (auto provided = token_provider_(); provided.has_value() && !provided->empty()) {
                return provided;
            }
        }
        std::lock_guard<std::mutex> lock(runtime_token_mutex_);
        return runtime_auth_token_;
    }

    void set_runtime_auth_token(const SecretString& token) {
        if (token.empty()) {
            return;
        }
        std::lock_guard<std::mutex> lock(runtime_token_mutex_);
        runtime_auth_token_ = token;
    }

    void clear_runtime_auth_token() {
        std::lock_guard<std::mutex> lock(runtime_token_mutex_);
        runtime_auth_token_.reset();
    }

    void ensure_worker_started() {
        std::lock_guard<std::mutex> lock(worker_mutex_);
        if (shutting_down_.load(std::memory_order_acquire)) {
            return;
        }
        if (worker_started_) {
            return;
        }
        worker_obj_ = new QObject();
        worker_obj_->moveToThread(&worker_thread_);
        worker_thread_.setObjectName(QStringLiteral("SecureCloudHttpWorker"));
        worker_thread_.start();
        worker_started_ = true;
    }

    void shutdown_worker() {
        shutting_down_.store(true, std::memory_order_release);
        std::lock_guard<std::mutex> lock(worker_mutex_);
        if (!worker_started_) {
            return;
        }

        if (worker_thread_.isRunning()) {
            if (QThread::currentThread() != &worker_thread_) {
                QMetaObject::invokeMethod(
                    worker_obj_,
                    [this]() {
                        if (poll_timer_ != nullptr) {
                            poll_timer_->stop();
                            delete poll_timer_;
                            poll_timer_ = nullptr;
                        }
                        if (nam_ != nullptr) {
                            delete nam_;
                            nam_ = nullptr;
                        }
                        worker_thread_.quit();
                    },
                    Qt::BlockingQueuedConnection);
                worker_thread_.wait();
            }
        }
        delete worker_obj_;
        worker_obj_ = nullptr;
        worker_started_ = false;
    }

    [[nodiscard]] std::string next_request_id() {
        const uint64_t seq = request_seq_.fetch_add(1U, std::memory_order_relaxed);
        return "sc-req-" + std::to_string(seq);
    }

    ClientResult<HttpResponse>
    perform_http(std::string method, std::string_view path, const std::string& request_body = {},
                 std::string content_type = "application/json",
                 const std::vector<std::pair<std::string, std::string>>& extra_headers = {},
                 const std::vector<std::pair<std::string, std::string>>& query = {}, bool include_auth = true,
                 std::optional<std::string> bearer_override = std::nullopt,
                 std::size_t max_response_bytes = QtHttpGatewayClient::kMaxJsonResponseBytes) {
        if (shutting_down_.load(std::memory_order_acquire)) {
            return ClientResult<HttpResponse>::error(ClientError::network("Gateway transport is shutting down"));
        }

        const ClientConfig cfg = snapshot_config();
        const std::string request_id = next_request_id();

        const auto url_res = build_endpoint_url(cfg, path, query);
        if (url_res.is_error()) {
            return ClientResult<HttpResponse>::error(url_res.error());
        }
        const QUrl url = url_res.value();
        const bool is_https = (url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0);
        const std::string normalized_pin = domain::normalize_hex_lower(cfg.pinned_tls_spki_sha256);

        if (cfg.enforce_tls_pinning && !normalized_pin.empty() && !is_https) {
            return ClientResult<HttpResponse>::error(ClientError(
                ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                "TLS SPKI pinning requires an https:// Gateway URL", "Non-HTTPS gateway_url rejected", request_id));
        }

        QSslConfiguration ssl_cfg;
        if (is_https) {
            const auto ssl_res = build_tls13_ssl_config(cfg);
            if (ssl_res.is_error()) {
                return ClientResult<HttpResponse>::error(ssl_res.error());
            }
            ssl_cfg = ssl_res.value();
        }

        std::optional<SecretString> token_secret;
        if (include_auth) {
            if (bearer_override.has_value()) {
                if (!bearer_override->empty()) {
                    token_secret = SecretString(*bearer_override);
                }
            } else {
                token_secret = resolve_bearer_token(cfg);
            }
        }

        const QNetworkProxy proxy = build_qt_proxy(cfg);
        const uint64_t expected_gen = config_generation_.load(std::memory_order_relaxed);
        const auto req_start = std::chrono::steady_clock::now();

        ensure_worker_started();
        if (worker_obj_ == nullptr || !worker_thread_.isRunning()) {
            return ClientResult<HttpResponse>::error(
                ClientError::network("HTTP worker thread is unavailable", "", request_id));
        }

        auto promise = std::make_shared<std::promise<ClientResult<HttpResponse>>>();
        auto future = promise->get_future();

        const int connect_ms = std::max(kMinDeadlineMs, static_cast<int>(cfg.connect_timeout_ms.count()));
        const int request_ms = std::max(kMinDeadlineMs, static_cast<int>(cfg.request_timeout_ms.count()));
        const bool require_pin = is_https && cfg.enforce_tls_pinning && !normalized_pin.empty();

        const bool invoked = QMetaObject::invokeMethod(
            worker_obj_,
            [this, promise, method = std::move(method), url, request_body, content_type = std::move(content_type),
             extra_headers, token_secret = std::move(token_secret), ssl_cfg, proxy, request_id, normalized_pin,
             require_pin, is_https, connect_ms, request_ms, max_response_bytes, expected_gen]() mutable {
                if (shutting_down_.load(std::memory_order_acquire) || worker_obj_ == nullptr) {
                    promise->set_value(ClientResult<HttpResponse>::error(
                        ClientError::network("Gateway transport shut down before dispatch", "", request_id)));
                    return;
                }

                if (nam_ == nullptr) {
                    nam_ = new QNetworkAccessManager(worker_obj_);
                    last_nam_gen_ = expected_gen;
                }
                if (last_nam_gen_ != expected_gen) {
                    nam_->clearAccessCache();
                    nam_->clearConnectionCache();
                    last_nam_gen_ = expected_gen;
                }
                nam_->setProxy(proxy);

                auto launch_http = [this, promise, method = std::move(method), url,
                                    request_body = std::move(request_body), content_type = std::move(content_type),
                                    extra_headers = std::move(extra_headers), token_secret = std::move(token_secret),
                                    ssl_cfg, request_id, normalized_pin, require_pin, is_https, request_ms,
                                    max_response_bytes]() {
                    if (shutting_down_.load(std::memory_order_acquire) || nam_ == nullptr) {
                        promise->set_value(ClientResult<HttpResponse>::error(
                            ClientError::network("Gateway transport unavailable", "", request_id)));
                        return;
                    }

                    QNetworkRequest req(url);
                    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
                    if (is_https) {
                        req.setSslConfiguration(ssl_cfg);
                    }
                    req.setRawHeader("Accept", "application/json");
                    req.setRawHeader("X-Request-ID", QByteArray::fromStdString(request_id));

                    if (!request_body.empty() && !content_type.empty()) {
                        req.setHeader(QNetworkRequest::ContentTypeHeader, QString::fromStdString(content_type));
                    }
                    if (token_secret.has_value() && !token_secret->empty()) {
                        const QByteArray auth_header =
                            "Bearer " + QByteArray::fromStdString(token_secret->expose_unredacted_secret());
                        req.setRawHeader("Authorization", auth_header);
                    }
                    for (const auto& [hk, hv] : extra_headers) {
                        req.setRawHeader(QByteArray::fromStdString(hk), QByteArray::fromStdString(hv));
                    }

                    const QByteArray body_bytes(request_body.data(), static_cast<qsizetype>(request_body.size()));
                    const QByteArray verb = QByteArray::fromStdString(method);
                    QNetworkReply* reply = nam_->sendCustomRequest(req, verb, body_bytes);
                    if (reply == nullptr) {
                        promise->set_value(ClientResult<HttpResponse>::error(
                            ClientError::network("Failed to create QNetworkReply", "", request_id)));
                        return;
                    }

                    struct ReplyState {
                        bool done{false};
                        bool timed_out{false};
                        bool oversized{false};
                        bool pin_mismatch{false};
                        std::string tls_error{};
                        std::string pin_details{};
                        QByteArray rx_buffer{};
                    };
                    auto state = std::make_shared<ReplyState>();
                    auto* deadline = new QTimer(worker_obj_);
                    deadline->setSingleShot(true);

                    QObject::connect(deadline, &QTimer::timeout, reply, [reply, state]() {
                        state->timed_out = true;
                        reply->abort();
                    });

                    QObject::connect(
                        reply, &QNetworkReply::encrypted, reply,
                        [reply, state, require_pin, normalized_pin]() {
                            if (!require_pin) {
                                return;
                            }
                            const QSslCertificate leaf = reply->sslConfiguration().peerCertificate();
                            const auto actual_pin = compute_spki_sha256_hex(leaf);
                            if (!actual_pin.has_value() || !spki_pin_matches(normalized_pin, *actual_pin)) {
                                state->pin_mismatch = true;
                                state->pin_details = "Observed SPKI: " + actual_pin.value_or(std::string("<none>"));
                                reply->abort();
                            }
                        },
                        Qt::DirectConnection);

                    QObject::connect(reply, &QNetworkReply::sslErrors, reply, [state](const QList<QSslError>& errors) {
                        state->tls_error = join_ssl_errors(errors);
                    });

                    QObject::connect(reply, &QNetworkReply::readyRead, reply, [reply, state, max_response_bytes]() {
                        const QByteArray chunk = reply->readAll();
                        if (static_cast<std::size_t>(state->rx_buffer.size()) + static_cast<std::size_t>(chunk.size()) >
                            max_response_bytes) {
                            state->oversized = true;
                            reply->abort();
                            return;
                        }
                        state->rx_buffer.append(chunk);
                    });

                    QObject::connect(
                        reply, &QNetworkReply::finished, worker_obj_,
                        [reply, deadline, promise, state, max_response_bytes, request_id]() {
                            deadline->stop();
                            deadline->deleteLater();
                            if (state->done) {
                                reply->deleteLater();
                                return;
                            }
                            state->done = true;

                            if (!state->timed_out && !state->oversized && !state->pin_mismatch && reply->isOpen()) {
                                const QByteArray rem = reply->readAll();
                                if (static_cast<std::size_t>(state->rx_buffer.size()) +
                                        static_cast<std::size_t>(rem.size()) >
                                    max_response_bytes) {
                                    state->oversized = true;
                                } else {
                                    state->rx_buffer.append(rem);
                                }
                            }

                            if (state->pin_mismatch) {
                                ClientLogger::warn(kLogTag, "Fail-closed TLS SPKI pin mismatch", request_id);
                                promise->set_value(ClientResult<HttpResponse>::error(ClientError(
                                    ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                                    "Gateway TLS SPKI fingerprint mismatch", state->pin_details, request_id)));
                                reply->deleteLater();
                                return;
                            }

                            if (!state->tls_error.empty() || reply->error() == QNetworkReply::SslHandshakeFailedError) {
                                const std::string detail =
                                    state->tls_error.empty() ? reply->errorString().toStdString() : state->tls_error;
                                ClientLogger::warn(kLogTag, "TLS handshake failed: " + detail, request_id);
                                promise->set_value(ClientResult<HttpResponse>::error(ClientError(
                                    ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                                    "TLS 1.3 verification failed", ClientLogger::sanitize(detail), request_id)));
                                reply->deleteLater();
                                return;
                            }

                            if (state->timed_out) {
                                promise->set_value(ClientResult<HttpResponse>::error(
                                    ClientError::timeout("Gateway request timed out", "", request_id)));
                                reply->deleteLater();
                                return;
                            }

                            if (state->oversized) {
                                promise->set_value(ClientResult<HttpResponse>::error(
                                    ClientError(ClientErrorCode::ProtocolError, ClientErrorCategory::Network,
                                                "Gateway response exceeded bounded byte limit", "", request_id)));
                                reply->deleteLater();
                                return;
                            }

                            const QVariant status_attr = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
                            const int status_code = status_attr.isValid() ? status_attr.toInt() : 0;
                            if (status_code == 0 || (reply->error() != QNetworkReply::NoError &&
                                                     reply->error() < QNetworkReply::ContentAccessDenied)) {
                                const std::string err_str = ClientLogger::sanitize(reply->errorString().toStdString());
                                const ClientErrorCode err_code = (reply->error() == QNetworkReply::TimeoutError)
                                                                     ? ClientErrorCode::ConnectionTimeout
                                                                     : ClientErrorCode::NetworkUnavailable;
                                promise->set_value(ClientResult<HttpResponse>::error(
                                    ClientError(err_code, ClientErrorCategory::Network,
                                                "Gateway network error: " + err_str, "", request_id)));
                                reply->deleteLater();
                                return;
                            }

                            HttpResponse resp;
                            resp.status_code = status_code;
                            resp.body.assign(state->rx_buffer.constData(),
                                             static_cast<std::size_t>(state->rx_buffer.size()));
                            resp.request_id = request_id;
                            if (reply->hasRawHeader("X-Ciphertext-SHA256")) {
                                resp.header_ciphertext_sha256 = reply->rawHeader("X-Ciphertext-SHA256").toStdString();
                            } else if (reply->hasRawHeader("X-Ciphertext-Sha256")) {
                                resp.header_ciphertext_sha256 = reply->rawHeader("X-Ciphertext-Sha256").toStdString();
                            }

                            if (status_code >= 200 && status_code < 300) {
                                promise->set_value(ClientResult<HttpResponse>::ok(std::move(resp)));
                            } else {
                                const std::string reason = reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute)
                                                               .toString()
                                                               .toStdString();
                                promise->set_value(ClientResult<HttpResponse>::error(
                                    map_http_status_error(status_code, resp.body, reason, request_id)));
                            }
                            reply->deleteLater();
                        });

                    deadline->start(request_ms);
                };

                if (!require_pin) {
                    launch_http();
                    return;
                }

                // Stage 1 pre-flight QSslSocket SPKI gate: verify server leaf SPKI BEFORE any HTTP/Bearer bytes write.
                auto* sock = new QSslSocket(worker_obj_);
                sock->setProxy(proxy);
                sock->setSslConfiguration(ssl_cfg);

                struct PreflightState {
                    bool finished{false};
                    std::string ssl_err{};
                };
                auto pstate = std::make_shared<PreflightState>();
                auto* ptimer = new QTimer(worker_obj_);
                ptimer->setSingleShot(true);

                QObject::connect(ptimer, &QTimer::timeout, sock, [sock, ptimer, promise, pstate, request_id]() {
                    if (pstate->finished) {
                        return;
                    }
                    pstate->finished = true;
                    ptimer->stop();
                    ptimer->deleteLater();
                    sock->abort();
                    sock->deleteLater();
                    promise->set_value(ClientResult<HttpResponse>::error(
                        ClientError::timeout("TLS pre-flight handshake timed out", "", request_id)));
                });

                QObject::connect(sock, &QSslSocket::sslErrors, sock, [pstate](const QList<QSslError>& errors) {
                    pstate->ssl_err = join_ssl_errors(errors);
                });

                QObject::connect(
                    sock, &QAbstractSocket::errorOccurred, sock,
                    [sock, ptimer, promise, pstate, request_id](QAbstractSocket::SocketError sock_err) {
                        if (pstate->finished) {
                            return;
                        }
                        pstate->finished = true;
                        ptimer->stop();
                        ptimer->deleteLater();
                        const std::string detail = pstate->ssl_err.empty()
                                                       ? ClientLogger::sanitize(sock->errorString().toStdString())
                                                       : pstate->ssl_err;
                        const bool is_tls = !pstate->ssl_err.empty() ||
                                            sock_err == QAbstractSocket::SslHandshakeFailedError ||
                                            sock_err == QAbstractSocket::SslInvalidUserDataError ||
                                            sock_err == QAbstractSocket::SslInternalError;
                        sock->abort();
                        sock->deleteLater();
                        if (is_tls) {
                            promise->set_value(ClientResult<HttpResponse>::error(
                                ClientError(ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                                            "TLS pre-flight verification failed", detail, request_id)));
                        } else {
                            promise->set_value(ClientResult<HttpResponse>::error(
                                ClientError::network("Gateway TCP pre-flight failed: " + detail, "", request_id)));
                        }
                    });

                QObject::connect(
                    sock, &QSslSocket::encrypted, sock,
                    [sock, ptimer, promise, pstate, normalized_pin, request_id,
                     launch_http = std::move(launch_http)]() mutable {
                        if (pstate->finished) {
                            return;
                        }
                        pstate->finished = true;
                        ptimer->stop();
                        ptimer->deleteLater();

                        const QSslCertificate leaf = sock->peerCertificate();
                        const auto actual_pin = compute_spki_sha256_hex(leaf);
                        const bool pin_ok = actual_pin.has_value() && spki_pin_matches(normalized_pin, *actual_pin);
                        sock->abort();
                        sock->deleteLater();

                        if (!pin_ok) {
                            ClientLogger::warn(kLogTag, "Pre-flight TLS SPKI pin mismatch", request_id);
                            promise->set_value(ClientResult<HttpResponse>::error(ClientError(
                                ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                                "Gateway TLS SPKI fingerprint mismatch",
                                "Observed SPKI: " + actual_pin.value_or(std::string("<none>")), request_id)));
                            return;
                        }

                        launch_http();
                    });

                const int effective_port = url.port(443);
                sock->connectToHostEncrypted(url.host(), static_cast<quint16>(effective_port));
                ptimer->start(connect_ms);
            },
            Qt::QueuedConnection);

        if (!invoked) {
            const int64_t rtt_ms = std::max<int64_t>(
                0, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - req_start)
                       .count());
            record_request_metric(rtt_ms, false);
            return ClientResult<HttpResponse>::error(
                ClientError::network("Failed to dispatch request onto HTTP worker thread", "", request_id));
        }

        auto result = future.get();
        const int64_t rtt_ms = std::max<int64_t>(
            0, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - req_start)
                   .count());
        record_request_metric(rtt_ms, result.is_ok());
        return result;
    }

    ClientResult<TlsCertificateInfo> inspect_tls(std::string_view host, uint16_t port) {
        if (host.empty()) {
            return ClientResult<TlsCertificateInfo>::error(
                ClientError::validation("TLS inspection host cannot be empty"));
        }
        if (port == 0U) {
            return ClientResult<TlsCertificateInfo>::error(
                ClientError::validation("TLS inspection port must be non-zero"));
        }
        if (shutting_down_.load(std::memory_order_acquire)) {
            return ClientResult<TlsCertificateInfo>::error(ClientError::network("Gateway transport is shutting down"));
        }

        const ClientConfig cfg = snapshot_config();
        const auto ssl_res = build_tls13_ssl_config(cfg);
        if (ssl_res.is_error()) {
            return ClientResult<TlsCertificateInfo>::error(ssl_res.error());
        }
        const QSslConfiguration ssl_cfg = ssl_res.value();
        const QNetworkProxy proxy = build_qt_proxy(cfg);
        const std::string normalized_pin = domain::normalize_hex_lower(cfg.pinned_tls_spki_sha256);
        const int connect_ms = std::max(kMinDeadlineMs, static_cast<int>(cfg.connect_timeout_ms.count()));
        const std::string host_str(host);

        ensure_worker_started();
        if (worker_obj_ == nullptr || !worker_thread_.isRunning()) {
            return ClientResult<TlsCertificateInfo>::error(ClientError::network("HTTP worker thread is unavailable"));
        }

        auto promise = std::make_shared<std::promise<ClientResult<TlsCertificateInfo>>>();
        auto future = promise->get_future();

        const bool invoked = QMetaObject::invokeMethod(
            worker_obj_,
            [this, promise, host_str, port, ssl_cfg, proxy, normalized_pin, connect_ms]() {
                if (shutting_down_.load(std::memory_order_acquire) || worker_obj_ == nullptr) {
                    promise->set_value(
                        ClientResult<TlsCertificateInfo>::error(ClientError::network("Gateway transport shut down")));
                    return;
                }

                auto* sock = new QSslSocket(worker_obj_);
                sock->setProxy(proxy);
                sock->setSslConfiguration(ssl_cfg);

                struct InspectState {
                    bool finished{false};
                    std::string ssl_err{};
                };
                auto state = std::make_shared<InspectState>();
                auto* timer = new QTimer(worker_obj_);
                timer->setSingleShot(true);

                QObject::connect(timer, &QTimer::timeout, sock, [sock, timer, promise, state]() {
                    if (state->finished) {
                        return;
                    }
                    state->finished = true;
                    timer->stop();
                    timer->deleteLater();
                    sock->abort();
                    sock->deleteLater();
                    promise->set_value(ClientResult<TlsCertificateInfo>::error(
                        ClientError::timeout("TLS certificate inspection timed out")));
                });

                QObject::connect(sock, &QSslSocket::sslErrors, sock,
                                 [state](const QList<QSslError>& errors) { state->ssl_err = join_ssl_errors(errors); });

                QObject::connect(sock, &QAbstractSocket::errorOccurred, sock,
                                 [sock, timer, promise, state](QAbstractSocket::SocketError sock_err) {
                                     if (state->finished) {
                                         return;
                                     }
                                     state->finished = true;
                                     timer->stop();
                                     timer->deleteLater();
                                     const std::string detail =
                                         state->ssl_err.empty()
                                             ? ClientLogger::sanitize(sock->errorString().toStdString())
                                             : state->ssl_err;
                                     const bool is_tls = !state->ssl_err.empty() ||
                                                         sock_err == QAbstractSocket::SslHandshakeFailedError ||
                                                         sock_err == QAbstractSocket::SslInvalidUserDataError ||
                                                         sock_err == QAbstractSocket::SslInternalError;
                                     sock->abort();
                                     sock->deleteLater();
                                     if (is_tls) {
                                         promise->set_value(ClientResult<TlsCertificateInfo>::error(ClientError(
                                             ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                                             "TLS certificate inspection failed verification", detail)));
                                     } else {
                                         promise->set_value(ClientResult<TlsCertificateInfo>::error(
                                             ClientError::network("Failed to connect for TLS inspection: " + detail)));
                                     }
                                 });

                QObject::connect(sock, &QSslSocket::encrypted, sock,
                                 [sock, timer, promise, state, host_str, port, normalized_pin]() {
                                     if (state->finished) {
                                         return;
                                     }
                                     state->finished = true;
                                     timer->stop();
                                     timer->deleteLater();

                                     const QSslCertificate leaf = sock->peerCertificate();
                                     const auto spki_opt = compute_spki_sha256_hex(leaf);
                                     sock->abort();
                                     sock->deleteLater();

                                     if (leaf.isNull() || !spki_opt.has_value()) {
                                         promise->set_value(ClientResult<TlsCertificateInfo>::error(ClientError(
                                             ClientErrorCode::TlsHandshakeFailed, ClientErrorCategory::Network,
                                             "Gateway did not present a readable X.509 certificate")));
                                         return;
                                     }

                                     TlsCertificateInfo info;
                                     info.host = host_str;
                                     info.port = port;
                                     const QStringList subj_cns = leaf.subjectInfo(QSslCertificate::CommonName);
                                     if (!subj_cns.isEmpty()) {
                                         info.subject_cn = subj_cns.front().toStdString();
                                     } else {
                                         info.subject_cn = host_str;
                                     }
                                     const QStringList iss_cns = leaf.issuerInfo(QSslCertificate::CommonName);
                                     if (!iss_cns.isEmpty()) {
                                         info.issuer_cn = iss_cns.front().toStdString();
                                     }
                                     info.spki_sha256_hex = *spki_opt;
                                     if (leaf.effectiveDate().isValid()) {
                                         info.valid_from_ms = leaf.effectiveDate().toMSecsSinceEpoch();
                                     }
                                     if (leaf.expiryDate().isValid()) {
                                         info.valid_until_ms = leaf.expiryDate().toMSecsSinceEpoch();
                                     }
                                     info.has_pinned_key = !normalized_pin.empty();
                                     info.matches_pinned_key =
                                         !info.has_pinned_key || spki_pin_matches(normalized_pin, info.spki_sha256_hex);

                                     promise->set_value(ClientResult<TlsCertificateInfo>::ok(std::move(info)));
                                 });

                sock->connectToHostEncrypted(QString::fromStdString(host_str), port);
                timer->start(connect_ms);
            },
            Qt::QueuedConnection);

        if (!invoked) {
            return ClientResult<TlsCertificateInfo>::error(
                ClientError::network("Failed to dispatch TLS inspection onto worker thread"));
        }

        return future.get();
    }

    void update_polling_timer_async(bool has_subscribers) {
        if (shutting_down_.load(std::memory_order_acquire)) {
            return;
        }
        if (has_subscribers) {
            ensure_worker_started();
        }
        if (!worker_started_ || worker_obj_ == nullptr || !worker_thread_.isRunning()) {
            return;
        }
        const int interval_ms = std::max(250, static_cast<int>(snapshot_config().sync_poll_interval_ms.count()));
        QMetaObject::invokeMethod(
            worker_obj_,
            [this, has_subscribers, interval_ms]() {
                if (!has_subscribers) {
                    if (poll_timer_ != nullptr) {
                        poll_timer_->stop();
                    }
                    return;
                }
                if (poll_timer_ == nullptr) {
                    poll_timer_ = new QTimer(worker_obj_);
                    QObject::connect(poll_timer_, &QTimer::timeout, worker_obj_, [this]() {
                        std::lock_guard<std::mutex> lock(event_mutex_);
                        if (event_subscribers_.empty()) {
                            if (poll_timer_ != nullptr) {
                                poll_timer_->stop();
                            }
                            return;
                        }
                    });
                }
                poll_timer_->start(interval_ms);
            },
            Qt::QueuedConnection);
    }

    void record_request_metric(int64_t rtt_ms, bool succeeded) noexcept {
        last_rtt_ms_.store(rtt_ms, std::memory_order_relaxed);
        rtt_sum_ms_.fetch_add(rtt_ms, std::memory_order_relaxed);
        request_count_.fetch_add(1U, std::memory_order_relaxed);
        if (!succeeded) {
            failure_count_.fetch_add(1U, std::memory_order_relaxed);
        }
    }

    mutable std::mutex config_mutex_;
    ClientConfig config_;
    BearerTokenProvider token_provider_;
    mutable std::mutex runtime_token_mutex_;
    std::optional<SecretString> runtime_auth_token_;
    std::atomic<uint64_t> config_generation_{1U};
    std::atomic<uint64_t> request_seq_{1U};
    std::atomic<bool> shutting_down_{false};
    std::atomic<int64_t> last_rtt_ms_{0};
    std::atomic<int64_t> rtt_sum_ms_{0};
    std::atomic<uint64_t> request_count_{0U};
    std::atomic<uint64_t> failure_count_{0U};

    std::mutex worker_mutex_;
    bool worker_started_{false};
    QThread worker_thread_;
    QObject* worker_obj_{nullptr};
    QNetworkAccessManager* nam_{nullptr};
    QTimer* poll_timer_{nullptr};
    uint64_t last_nam_gen_{0U};

    mutable std::mutex event_mutex_;
    uint64_t next_subscription_id_{1U};
    std::unordered_map<uint64_t, RealtimeEventHandler> event_subscribers_;
};

QtHttpGatewayClient::QtHttpGatewayClient(ClientConfig config, BearerTokenProvider token_provider)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(token_provider))) {}

QtHttpGatewayClient::~QtHttpGatewayClient() = default;

void QtHttpGatewayClient::reconfigure(const ClientConfig& config) {
    impl_->reconfigure(config);
}

ClientConfig QtHttpGatewayClient::current_config_snapshot() const {
    return impl_->snapshot_config();
}

QtHttpGatewayClient::EffectiveProxySnapshot QtHttpGatewayClient::effective_proxy_snapshot() const {
    const ClientConfig cfg = impl_->snapshot_config();
    return EffectiveProxySnapshot{
        .type = cfg.proxy_type,
        .host = cfg.proxy_host,
        .port = cfg.proxy_port,
        .username = cfg.proxy_username,
        .has_password = !cfg.proxy_password.empty(),
    };
}

domain::GatewayTransportMetrics QtHttpGatewayClient::transport_metrics() const noexcept {
    domain::GatewayTransportMetrics metrics;
    metrics.last_rtt_ms = impl_->last_rtt_ms_.load(std::memory_order_relaxed);
    metrics.requests_total = impl_->request_count_.load(std::memory_order_relaxed);
    metrics.requests_failed = impl_->failure_count_.load(std::memory_order_relaxed);
    if (metrics.requests_total > 0U) {
        const int64_t total_ms = impl_->rtt_sum_ms_.load(std::memory_order_relaxed);
        metrics.avg_rtt_ms = total_ms / static_cast<int64_t>(metrics.requests_total);
    }
    return metrics;
}

ClientResult<bool> QtHttpGatewayClient::probe_gateway(std::string_view path) {
    const std::string target_path = (path.empty() || path == "/health") ? "/health/live" : std::string(path);
    auto res = impl_->perform_http("GET", target_path, {}, "", {}, {}, /*include_auth=*/false);
    if (res.is_error() && target_path == "/health/live" && res.error().code() == ClientErrorCode::ProtocolError &&
        res.error().details() == "HTTP 404") {
        res = impl_->perform_http("GET", "/health/ready", {}, "", {}, {}, /*include_auth=*/false);
    }
    if (res.is_error()) {
        return ClientResult<bool>::error(res.error());
    }
    return ClientResult<bool>::ok(true);
}

ClientResult<std::string> QtHttpGatewayClient::send_message(const domain::ConversationId& conversation_id,
                                                            std::string_view encrypted_envelope) {
    if (conversation_id.empty()) {
        return ClientResult<std::string>::error(ClientError::validation("Conversation ID cannot be empty"));
    }

    const std::string idemp = "msg-" + std::to_string(current_unix_ms());
    nlohmann::json payload;
    payload["conversation_id"] = conversation_id.value();
    payload["client_idempotency_token"] = idemp;
    payload["priority"] = "normal";
    payload["encrypted_envelope"] = std::string(encrypted_envelope);
    const std::string json_body = payload.dump();

    const std::vector<std::pair<std::string, std::string>> headers = {{"X-Idempotency-Token", idemp}};
    const auto res = impl_->perform_http("POST", "/api/v1/messages", json_body, "application/json", headers);
    if (res.is_error()) {
        return ClientResult<std::string>::error(res.error());
    }
    try {
        const auto j = nlohmann::json::parse(res.value().body);
        if (j.contains("message_id") && j["message_id"].is_string()) {
            return ClientResult<std::string>::ok(j["message_id"].get<std::string>());
        }
    } catch (...) {
    }
    return ClientResult<std::string>::error(ClientError::network("Malformed Gateway send_message response"));
}

ClientResult<std::string> QtHttpGatewayClient::submit_encrypted_message(const FanOutSubmissionRequest& request) {
    if (request.conversation_id.empty()) {
        return ClientResult<std::string>::error(ClientError::validation("Conversation ID cannot be empty"));
    }
    if (request.device_payloads.empty() && !request.group_envelope_bytes.has_value()) {
        return ClientResult<std::string>::error(
            ClientError::validation("Encrypted message submission requires ciphertext payloads"));
    }

    nlohmann::json payload;
    payload["conversation_id"] = request.conversation_id.value();
    payload["client_idempotency_token"] = request.idempotency_key;
    payload["idempotency_token"] = request.idempotency_key;
    payload["priority"] = (request.priority >= 3) ? "emergency" : (request.priority == 2 ? "urgent" : "normal");

    nlohmann::json targets = nlohmann::json::array();
    for (const auto& target : request.device_payloads) {
        nlohmann::json ep;
        ep["ciphertext_blob"] = encode_ciphertext_for_json(target.ciphertext_blob);
        ep["ephemeral_public_key"] = bytes_to_base64(target.ephemeral_public_key);
        ep["initialization_vector"] = bytes_to_base64(target.iv);
        ep["auth_tag"] = bytes_to_base64(target.auth_tag);
        ep["algorithm"] = target.algorithm;

        nlohmann::json t_json;
        t_json["recipient_user_id"] = target.recipient_user_id.value();
        t_json["recipient_device_id"] = target.recipient_device_id.value();
        t_json["encrypted_payload"] = std::move(ep);
        targets.push_back(std::move(t_json));
    }
    payload["delivery_targets"] = std::move(targets);
    if (request.group_envelope_bytes.has_value()) {
        payload["group_envelope_b64"] = bytes_to_base64(*request.group_envelope_bytes);
    }

    const std::string json_body = payload.dump();
    std::vector<std::pair<std::string, std::string>> headers;
    if (!request.idempotency_key.empty()) {
        headers.emplace_back("X-Idempotency-Token", request.idempotency_key);
    }

    const auto res = impl_->perform_http("POST", "/api/v1/messages", json_body, "application/json", headers);
    if (res.is_error()) {
        return ClientResult<std::string>::error(res.error());
    }
    try {
        const auto j = nlohmann::json::parse(res.value().body);
        if (j.contains("message_id") && j["message_id"].is_string() && !j["message_id"].get<std::string>().empty()) {
            return ClientResult<std::string>::ok(j["message_id"].get<std::string>());
        }
    } catch (...) {
    }
    return ClientResult<std::string>::error(ClientError::network("Gateway send response omitted message_id"));
}

ClientResult<std::vector<std::string>> QtHttpGatewayClient::sync_messages(std::string_view /*cursor*/) {
    return ClientResult<std::vector<std::string>>::ok(std::vector<std::string>{});
}

ClientResult<domain::DeliveryState>
QtHttpGatewayClient::acknowledge_delivery(const domain::MessageId& message_id,
                                          const domain::DeviceId& recipient_device_id, int64_t delivered_at_ms) {
    if (message_id.empty() || recipient_device_id.empty()) {
        return ClientResult<domain::DeliveryState>::error(
            ClientError::validation("Message ID and recipient device ID are required for delivery ack"));
    }

    nlohmann::json payload;
    payload["recipient_device_id"] = recipient_device_id.value();
    payload["device_id"] = recipient_device_id.value();
    payload["delivered_at_unix_ms"] = delivered_at_ms;
    const std::string json_body = payload.dump();

    const std::string path = "/api/v1/messages/" + url_encode(message_id.value()) + "/ack";
    const auto res = impl_->perform_http("POST", path, json_body);
    if (res.is_error()) {
        return ClientResult<domain::DeliveryState>::error(res.error());
    }
    try {
        const auto j = nlohmann::json::parse(res.value().body);
        if (j.contains("state") && j["state"].is_string()) {
            return ClientResult<domain::DeliveryState>::ok(parse_delivery_state_string(j["state"].get<std::string>()));
        }
    } catch (...) {
    }
    return ClientResult<domain::DeliveryState>::ok(domain::DeliveryState::Delivered);
}

ClientResult<domain::DeliveryState>
QtHttpGatewayClient::send_read_receipt(const domain::ConversationId& conversation_id,
                                       const domain::MessageId& message_id, const domain::DeviceId& reader_device_id,
                                       int64_t read_at_ms) {
    if (conversation_id.empty() || message_id.empty() || reader_device_id.empty()) {
        return ClientResult<domain::DeliveryState>::error(
            ClientError::validation("Conversation ID, message ID, and reader device ID are required for read receipt"));
    }

    nlohmann::json payload;
    payload["conversation_id"] = conversation_id.value();
    payload["reader_device_id"] = reader_device_id.value();
    payload["read_at_unix_ms"] = read_at_ms;
    const std::string json_body = payload.dump();

    const std::string path = "/api/v1/conversations/" + url_encode(conversation_id.value()) + "/messages/" +
                             url_encode(message_id.value()) + "/read";
    const auto res = impl_->perform_http("POST", path, json_body);
    if (res.is_error()) {
        return ClientResult<domain::DeliveryState>::error(res.error());
    }
    return ClientResult<domain::DeliveryState>::ok(domain::DeliveryState::Read);
}

ClientResult<domain::MessageDeliveryStatusInfo>
QtHttpGatewayClient::get_message_delivery_status(const domain::ConversationId& conversation_id,
                                                 const domain::MessageId& message_id) {
    if (conversation_id.empty() || message_id.empty()) {
        return ClientResult<domain::MessageDeliveryStatusInfo>::error(
            ClientError::validation("Conversation ID and message ID are required"));
    }

    const std::string path = "/api/v1/conversations/" + url_encode(conversation_id.value()) + "/messages/" +
                             url_encode(message_id.value()) + "/delivery-status";
    const auto res = impl_->perform_http("GET", path);
    if (res.is_error()) {
        return ClientResult<domain::MessageDeliveryStatusInfo>::error(res.error());
    }

    domain::MessageDeliveryStatusInfo info;
    info.message_id = message_id;
    try {
        const auto j = nlohmann::json::parse(res.value().body);
        bool any_read = false;
        if (j.contains("recipient_read_statuses") && j["recipient_read_statuses"].is_array()) {
            for (const auto& rs : j["recipient_read_statuses"]) {
                if (rs.is_object() && rs.value("is_read", false)) {
                    any_read = true;
                    info.updated_at_ms = std::max(info.updated_at_ms, rs.value("read_at_unix_ms", int64_t{0}));
                }
            }
        }

        const int delivered =
            (j.contains("summary") && j["summary"].is_object()) ? j["summary"].value("delivered_targets", 0) : 0;
        const int pending =
            (j.contains("summary") && j["summary"].is_object()) ? j["summary"].value("pending_targets", 0) : 0;

        if (any_read) {
            info.delivery_state = domain::DeliveryState::Read;
        } else if (delivered > 0) {
            info.delivery_state = domain::DeliveryState::Delivered;
        } else if (pending > 0) {
            info.delivery_state = domain::DeliveryState::Delivering;
        } else {
            info.delivery_state = domain::DeliveryState::Accepted;
        }
        return ClientResult<domain::MessageDeliveryStatusInfo>::ok(std::move(info));
    } catch (...) {
        return ClientResult<domain::MessageDeliveryStatusInfo>::error(
            ClientError::network("Malformed Gateway delivery status JSON response"));
    }
}

ClientResult<domain::ConversationMessagesPage>
QtHttpGatewayClient::fetch_conversation_messages(const domain::ConversationId& conversation_id,
                                                 const domain::DeviceId& recipient_device_id, uint64_t since_sequence,
                                                 std::size_t max_results) {
    if (conversation_id.empty() || recipient_device_id.empty()) {
        return ClientResult<domain::ConversationMessagesPage>::error(
            ClientError::validation("Conversation ID and recipient device ID are required"));
    }

    const std::string path = "/api/v1/conversations/" + url_encode(conversation_id.value()) + "/messages";
    const std::size_t clamped_limit = (max_results == 0U) ? 50U : std::min<std::size_t>(max_results, 100U);
    const std::vector<std::pair<std::string, std::string>> query = {
        {"recipient_device_id", recipient_device_id.value()},
        {"since_sequence", std::to_string(since_sequence)},
        {"limit", std::to_string(clamped_limit)},
    };

    const auto res = impl_->perform_http("GET", path, {}, "", {}, query);
    if (res.is_error()) {
        return ClientResult<domain::ConversationMessagesPage>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        domain::ConversationMessagesPage page;
        page.has_more = j.value("has_more", false);
        page.next_sequence = j.value("next_sequence", since_sequence);
        page.latest_sequence = j.value("latest_sequence", page.next_sequence);

        if (j.contains("cursor") && j["cursor"].is_object()) {
            const auto& cj = j["cursor"];
            domain::SyncCursorRecord cursor;
            const std::string dev_id = cj.value("device_id", recipient_device_id.value());
            if (!dev_id.empty()) {
                cursor.device_id = domain::DeviceId(dev_id);
            }
            const std::string cid = cj.value("conversation_id", conversation_id.value());
            if (!cid.empty()) {
                cursor.conversation_id = domain::ConversationId(cid);
            }
            cursor.last_delivered_sequence = cj.value("last_delivered_sequence", uint64_t{0});
            cursor.last_sync_timestamp_ms = cj.value("last_sync_timestamp_unix_ms", int64_t{0});
            page.cursor = std::move(cursor);
        }

        if (j.contains("messages") && j["messages"].is_array()) {
            uint64_t fallback_seq = since_sequence + 1U;
            for (const auto& mj : j["messages"]) {
                if (!mj.is_object()) {
                    continue;
                }
                domain::RealtimeEvent ev;
                ev.type = domain::RealtimeEventType::InboundDirectMessage;
                ev.server_sequence_number = mj.value("sequence_number", fallback_seq++);
                ev.timestamp_ms = mj.value("created_at_unix_ms", int64_t{0});
                const std::string prio_str = mj.value("priority", std::string{"normal"});
                if (prio_str == "emergency") {
                    ev.priority = 3;
                } else if (prio_str == "urgent") {
                    ev.priority = 2;
                } else {
                    ev.priority = 1;
                }
                const std::string ev_cid = mj.value("conversation_id", conversation_id.value());
                if (!ev_cid.empty()) {
                    ev.conversation_id = domain::ConversationId(ev_cid);
                }
                if (const std::string mid = mj.value("message_id", std::string{}); !mid.empty()) {
                    ev.message_id = domain::MessageId(mid);
                }
                if (const std::string suid = mj.value("sender_user_id", std::string{}); !suid.empty()) {
                    ev.actor_user_id = domain::UserId(suid);
                }
                if (const std::string sdid = mj.value("sender_device_id", std::string{}); !sdid.empty()) {
                    ev.actor_device_id = domain::DeviceId(sdid);
                }
                if (mj.contains("group_envelope_b64") && mj["group_envelope_b64"].is_string()) {
                    ev.type = domain::RealtimeEventType::InboundGroupMessage;
                    ev.group_envelope_bytes = decode_wire_bytes(mj["group_envelope_b64"].get<std::string>());
                }
                if (mj.contains("delivery_targets") && mj["delivery_targets"].is_array()) {
                    const nlohmann::json* chosen = nullptr;
                    for (const auto& dt : mj["delivery_targets"]) {
                        if (!dt.is_object()) {
                            continue;
                        }
                        if (chosen == nullptr) {
                            chosen = &dt;
                        }
                        if (dt.value("recipient_device_id", std::string{}) == recipient_device_id.value()) {
                            chosen = &dt;
                            break;
                        }
                    }
                    if (chosen != nullptr && chosen->contains("encrypted_payload") &&
                        (*chosen)["encrypted_payload"].is_object()) {
                        const auto& ep = (*chosen)["encrypted_payload"];
                        domain::crypto::PerDeviceDeliveryPayload dp;
                        if (const std::string ruid = chosen->value("recipient_user_id", std::string{}); !ruid.empty()) {
                            dp.recipient_user_id = domain::UserId(ruid);
                        }
                        if (const std::string rdid = chosen->value("recipient_device_id", std::string{});
                            !rdid.empty()) {
                            dp.recipient_device_id = domain::DeviceId(rdid);
                        } else {
                            dp.recipient_device_id = recipient_device_id;
                        }
                        dp.ciphertext_blob = decode_ciphertext_from_json(ep.value("ciphertext_blob", std::string{}));
                        dp.ephemeral_public_key = decode_wire_bytes(ep.value("ephemeral_public_key", std::string{}));
                        dp.iv = decode_wire_bytes(ep.value("initialization_vector", std::string{}));
                        dp.auth_tag = decode_wire_bytes(ep.value("auth_tag", std::string{}));
                        dp.algorithm = ep.value("algorithm", std::string{"AES-256-GCM"});
                        ev.direct_payload = std::move(dp);
                    }
                }
                page.events.push_back(std::move(ev));
            }
        }

        return ClientResult<domain::ConversationMessagesPage>::ok(std::move(page));
    } catch (...) {
        return ClientResult<domain::ConversationMessagesPage>::error(
            ClientError::network("Malformed Gateway conversation messages JSON response"));
    }
}

ClientResult<domain::SyncCursorRecord>
QtHttpGatewayClient::get_sync_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id) {
    if (device_id.empty()) {
        return ClientResult<domain::SyncCursorRecord>::error(
            ClientError::validation("Device ID is required for get_sync_cursor"));
    }

    const std::string path = "/api/v1/devices/" + url_encode(device_id.value()) + "/cursor";
    std::vector<std::pair<std::string, std::string>> query;
    if (!conversation_id.empty()) {
        query.emplace_back("conversation_id", conversation_id.value());
    }

    const auto res = impl_->perform_http("GET", path, {}, "", {}, query);
    if (res.is_error()) {
        return ClientResult<domain::SyncCursorRecord>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        domain::SyncCursorRecord cursor;
        cursor.device_id = device_id;
        cursor.conversation_id = conversation_id;
        cursor.last_delivered_sequence = j.value("last_delivered_sequence", uint64_t{0});
        cursor.last_sync_timestamp_ms = j.value("last_sync_timestamp_unix_ms", int64_t{0});
        return ClientResult<domain::SyncCursorRecord>::ok(std::move(cursor));
    } catch (...) {
        return ClientResult<domain::SyncCursorRecord>::error(
            ClientError::network("Malformed Gateway get_sync_cursor JSON response"));
    }
}

ClientResult<domain::SyncCursorRecord> QtHttpGatewayClient::update_sync_cursor(const domain::SyncCursorRecord& cursor) {
    if (cursor.device_id.empty()) {
        return ClientResult<domain::SyncCursorRecord>::error(
            ClientError::validation("Device ID is required for update_sync_cursor"));
    }

    nlohmann::json payload;
    payload["conversation_id"] = cursor.conversation_id.value();
    payload["last_delivered_sequence"] = cursor.last_delivered_sequence;
    payload["last_sync_timestamp_unix_ms"] =
        cursor.last_sync_timestamp_ms > 0 ? cursor.last_sync_timestamp_ms : current_unix_ms();
    const std::string json_body = payload.dump();

    const std::string path = "/api/v1/devices/" + url_encode(cursor.device_id.value()) + "/cursor";
    const auto res = impl_->perform_http("PUT", path, json_body);
    if (res.is_error()) {
        return ClientResult<domain::SyncCursorRecord>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        domain::SyncCursorRecord updated = cursor;
        if (j.contains("cursor") && j["cursor"].is_object()) {
            const auto& cj = j["cursor"];
            updated.last_delivered_sequence = cj.value("last_delivered_sequence", cursor.last_delivered_sequence);
            updated.last_sync_timestamp_ms = cj.value("last_sync_timestamp_unix_ms", cursor.last_sync_timestamp_ms);
        }
        return ClientResult<domain::SyncCursorRecord>::ok(std::move(updated));
    } catch (...) {
        return ClientResult<domain::SyncCursorRecord>::ok(cursor);
    }
}

ClientResult<std::vector<domain::RemoteConversationSummary>>
QtHttpGatewayClient::list_remote_conversations(const domain::UserId& user_id, std::size_t max_results) {
    if (user_id.empty()) {
        return ClientResult<std::vector<domain::RemoteConversationSummary>>::error(
            ClientError::validation("User ID is required for list_remote_conversations"));
    }

    const std::size_t limit = max_results == 0U ? 100U : max_results;
    const std::vector<std::pair<std::string, std::string>> query = {{"limit", std::to_string(limit)}};
    const auto res = impl_->perform_http("GET", "/api/v1/conversations", {}, "", {}, query);
    if (res.is_error()) {
        return ClientResult<std::vector<domain::RemoteConversationSummary>>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        std::vector<domain::RemoteConversationSummary> out;
        if (j.contains("conversations") && j["conversations"].is_array()) {
            for (const auto& cj : j["conversations"]) {
                if (auto sum = parse_conversation_summary(cj); sum.has_value()) {
                    out.push_back(std::move(*sum));
                }
            }
        }
        return ClientResult<std::vector<domain::RemoteConversationSummary>>::ok(std::move(out));
    } catch (...) {
        return ClientResult<std::vector<domain::RemoteConversationSummary>>::error(
            ClientError::network("Malformed Gateway list_conversations JSON response"));
    }
}

uint64_t QtHttpGatewayClient::subscribe_realtime_events(RealtimeEventHandler handler) {
    bool has_subs = false;
    uint64_t id = 0U;
    {
        std::lock_guard<std::mutex> lock(impl_->event_mutex_);
        id = impl_->next_subscription_id_++;
        if (handler) {
            impl_->event_subscribers_.emplace(id, std::move(handler));
        }
        has_subs = !impl_->event_subscribers_.empty();
    }
    impl_->update_polling_timer_async(has_subs);
    return id;
}

void QtHttpGatewayClient::unsubscribe_realtime_events(uint64_t subscription_id) {
    bool has_subs = false;
    {
        std::lock_guard<std::mutex> lock(impl_->event_mutex_);
        impl_->event_subscribers_.erase(subscription_id);
        has_subs = !impl_->event_subscribers_.empty();
    }
    impl_->update_polling_timer_async(has_subs);
}

ClientResult<bool> QtHttpGatewayClient::validate_token(std::string_view token) {
    if (token.empty()) {
        return ClientResult<bool>::ok(false);
    }
    const auto res =
        impl_->perform_http("GET", "/api/v1/users/me", {}, "", {}, {}, /*include_auth=*/true, std::string(token));
    if (res.is_ok()) {
        return ClientResult<bool>::ok(true);
    }
    if (res.error().category() == ClientErrorCategory::Authentication) {
        return ClientResult<bool>::ok(false);
    }
    return ClientResult<bool>::error(res.error());
}

ClientResult<void> QtHttpGatewayClient::disconnect() {
    {
        std::lock_guard<std::mutex> lock(impl_->event_mutex_);
        impl_->event_subscribers_.clear();
    }
    impl_->update_polling_timer_async(false);
    return ClientResult<void>::ok();
}

ClientResult<DeviceRegistrationResult> QtHttpGatewayClient::register_device(const domain::UserId& user_id,
                                                                            const domain::PrekeyBundle& bundle) {
    if (user_id.empty()) {
        return ClientResult<DeviceRegistrationResult>::error(
            ClientError::validation("User ID cannot be empty for device registration"));
    }

    nlohmann::json otpks = nlohmann::json::array();
    for (const auto& rec : bundle.one_time_prekeys()) {
        otpks.push_back(rec.public_key_hex());
    }

    nlohmann::json payload;
    payload["user_id"] = user_id.value();
    payload["identity_key"] = bundle.identity_key_hex();
    payload["signed_prekey"] = bundle.signed_prekey_hex();
    payload["signed_prekey_signature"] = bundle.signed_prekey_signature_hex();
    payload["one_time_prekeys"] = std::move(otpks);
    const std::string json_body = payload.dump();

    const auto res = impl_->perform_http("POST", "/api/v1/devices", json_body);
    if (res.is_error()) {
        return ClientResult<DeviceRegistrationResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        const std::string dev_id = j.value("device_id", std::string{});
        if (dev_id.empty()) {
            return ClientResult<DeviceRegistrationResult>::error(
                ClientError::network("Gateway register_device omitted device_id"));
        }
        DeviceRegistrationResult reg;
        reg.device_id = domain::DeviceId(dev_id);
        reg.status = parse_device_auth_status(j, "status");
        if (const int64_t ts_ms = j.value("registered_at_epoch_ms", int64_t{0}); ts_ms > 0) {
            reg.registered_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(ts_ms));
        }
        return ClientResult<DeviceRegistrationResult>::ok(std::move(reg));
    } catch (...) {
        return ClientResult<DeviceRegistrationResult>::error(
            ClientError::network("Malformed Gateway register_device JSON response"));
    }
}

ClientResult<PrekeyUpdateResult>
QtHttpGatewayClient::update_crypto_prekeys(const domain::DeviceId& device_id,
                                           std::optional<std::vector<uint8_t>> signed_prekey,
                                           std::optional<std::vector<uint8_t>> signed_prekey_signature,
                                           std::vector<domain::OneTimePrekeyRecord> one_time_prekeys) {
    if (device_id.empty()) {
        return ClientResult<PrekeyUpdateResult>::error(
            ClientError::validation("Device ID cannot be empty for prekey update"));
    }

    nlohmann::json payload;
    if (signed_prekey.has_value()) {
        payload["signed_prekey"] = bytes_to_hex(*signed_prekey);
    }
    if (signed_prekey_signature.has_value()) {
        payload["signed_prekey_signature"] = bytes_to_hex(*signed_prekey_signature);
    }
    nlohmann::json otpks = nlohmann::json::array();
    for (const auto& rec : one_time_prekeys) {
        otpks.push_back(rec.public_key_hex());
    }
    payload["one_time_prekeys"] = std::move(otpks);
    const std::string json_body = payload.dump();

    const std::string path = "/api/v1/devices/" + url_encode(device_id.value()) + "/prekeys";
    const auto res = impl_->perform_http("POST", path, json_body);
    if (res.is_error()) {
        return ClientResult<PrekeyUpdateResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        PrekeyUpdateResult out;
        out.active_one_time_prekey_count = j.value("active_one_time_prekey_count", 0);
        if (const int64_t ts_ms = j.value("updated_at_epoch_ms", int64_t{0}); ts_ms > 0) {
            out.updated_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(ts_ms));
        }
        return ClientResult<PrekeyUpdateResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<PrekeyUpdateResult>::error(
            ClientError::network("Malformed Gateway update_crypto_prekeys JSON response"));
    }
}

ClientResult<domain::PrekeyInventoryStatus>
QtHttpGatewayClient::get_prekey_inventory_status(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return ClientResult<domain::PrekeyInventoryStatus>::error(
            ClientError::validation("Device ID cannot be empty for inventory status query"));
    }

    const std::string path = "/api/v1/devices/" + url_encode(device_id.value()) + "/prekeys/inventory";
    const auto res = impl_->perform_http("GET", path);
    if (res.is_error()) {
        return ClientResult<domain::PrekeyInventoryStatus>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        const int32_t active = j.value("active_one_time_prekeys", int32_t{0});
        const int32_t claimed = j.value("claimed_one_time_prekeys", int32_t{0});
        const int32_t threshold =
            j.value("low_inventory_threshold", static_cast<int32_t>(domain::PrekeyPolicy::kLowPrekeyThreshold));
        const int64_t created_ms = j.value("signed_prekey_created_at_epoch_ms", int64_t{0});
        const auto created_tp = created_ms > 0
                                    ? std::chrono::system_clock::time_point(std::chrono::milliseconds(created_ms))
                                    : std::chrono::system_clock::now();
        const int64_t age_sec = j.value("signed_prekey_age_seconds", int64_t{0});
        const bool needs_rot = j.value("signed_prekey_needs_rotation", false);

        return ClientResult<domain::PrekeyInventoryStatus>::ok(domain::PrekeyInventoryStatus(
            active, claimed, threshold, created_tp, std::chrono::seconds(age_sec), needs_rot));
    } catch (...) {
        return ClientResult<domain::PrekeyInventoryStatus>::error(
            ClientError::network("Malformed Gateway prekey inventory JSON response"));
    }
}

ClientResult<std::vector<DeviceCryptoDirectoryEntry>>
QtHttpGatewayClient::get_device_crypto_directory(const domain::UserId& user_id,
                                                 const std::vector<domain::DeviceId>& device_ids) {
    if (user_id.empty()) {
        return ClientResult<std::vector<DeviceCryptoDirectoryEntry>>::error(
            ClientError::validation("User ID cannot be empty for crypto directory query"));
    }

    const std::string path = "/api/v1/users/" + url_encode(user_id.value()) + "/devices/crypto-directory";
    std::vector<std::pair<std::string, std::string>> query;
    if (!device_ids.empty()) {
        std::string joined;
        for (std::size_t i = 0; i < device_ids.size(); ++i) {
            if (i > 0U) {
                joined.push_back(',');
            }
            joined += device_ids[i].value();
        }
        query.emplace_back("device_ids", std::move(joined));
    }

    const auto res = impl_->perform_http("GET", path, {}, "", {}, query);
    if (res.is_error()) {
        return ClientResult<std::vector<DeviceCryptoDirectoryEntry>>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        std::vector<DeviceCryptoDirectoryEntry> entries;
        if (j.contains("devices") && j["devices"].is_array()) {
            for (const auto& dj : j["devices"]) {
                if (!dj.is_object()) {
                    continue;
                }
                const std::string did = dj.value("device_id", std::string{});
                if (did.empty()) {
                    continue;
                }
                DeviceCryptoDirectoryEntry e;
                e.device_id = domain::DeviceId(did);
                e.identity_key = decode_wire_bytes(dj.value("identity_key", std::string{}));
                e.signed_prekey = decode_wire_bytes(dj.value("signed_prekey", std::string{}));
                e.signed_prekey_signature = decode_wire_bytes(dj.value("signed_prekey_signature", std::string{}));
                if (const std::string otpk = dj.value("one_time_prekey", std::string{}); !otpk.empty()) {
                    e.one_time_prekey = decode_wire_bytes(otpk);
                }
                e.one_time_prekey_id = dj.value("one_time_prekey_id", std::string{});
                e.status = parse_device_auth_status(dj, "status");
                e.identity_key_fingerprint = dj.value("identity_key_fingerprint", std::string{});
                e.remaining_one_time_prekeys = dj.value("remaining_one_time_prekeys", int32_t{0});
                if (const int64_t created_ms = dj.value("signed_prekey_created_at_epoch_ms", int64_t{0});
                    created_ms > 0) {
                    e.signed_prekey_created_at =
                        std::chrono::system_clock::time_point(std::chrono::milliseconds(created_ms));
                }
                entries.push_back(std::move(e));
            }
        }
        return ClientResult<std::vector<DeviceCryptoDirectoryEntry>>::ok(std::move(entries));
    } catch (...) {
        return ClientResult<std::vector<DeviceCryptoDirectoryEntry>>::error(
            ClientError::network("Malformed Gateway crypto directory JSON response"));
    }
}

ClientResult<PairingInitiationResult> QtHttpGatewayClient::initiate_device_pairing(const domain::DeviceId& device_id) {
    if (device_id.empty()) {
        return ClientResult<PairingInitiationResult>::error(
            ClientError::validation("Device ID cannot be empty for pairing initiation"));
    }

    nlohmann::json payload;
    payload["device_id"] = device_id.value();
    const std::string json_body = payload.dump();

    const auto res = impl_->perform_http("POST", "/api/v1/devices/pairing", json_body);
    if (res.is_error()) {
        return ClientResult<PairingInitiationResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        PairingInitiationResult out;
        out.device_id = device_id;
        out.pairing_code = j.value("pairing_code", std::string{});
        if (const int64_t exp_ms = j.value("expires_at_epoch_ms", int64_t{0}); exp_ms > 0) {
            out.expires_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(exp_ms));
        }
        return ClientResult<PairingInitiationResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<PairingInitiationResult>::error(
            ClientError::network("Malformed Gateway initiate_device_pairing JSON response"));
    }
}

ClientResult<void> QtHttpGatewayClient::authorize_device_pairing(const domain::DeviceId& device_id,
                                                                 std::string_view pairing_code,
                                                                 std::string_view mfa_token) {
    if (device_id.empty() || pairing_code.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Device ID and pairing code are required for authorization"));
    }

    nlohmann::json payload;
    payload["device_id"] = device_id.value();
    payload["pairing_code"] = std::string(pairing_code);
    if (!mfa_token.empty()) {
        payload["mfa_token"] = std::string(mfa_token);
    }
    const std::string json_body = payload.dump();

    const std::string path = "/api/v1/devices/" + url_encode(device_id.value()) + "/authorize";
    const auto res = impl_->perform_http("POST", path, json_body);
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    return ClientResult<void>::ok();
}

ClientResult<std::vector<domain::Device>> QtHttpGatewayClient::list_user_devices(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return ClientResult<std::vector<domain::Device>>::error(
            ClientError::validation("User ID cannot be empty to list devices"));
    }

    const auto res = impl_->perform_http("GET", "/api/v1/devices");
    if (res.is_error()) {
        return ClientResult<std::vector<domain::Device>>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        std::vector<domain::Device> devices;
        if (j.contains("devices") && j["devices"].is_array()) {
            for (const auto& dj : j["devices"]) {
                if (!dj.is_object()) {
                    continue;
                }
                const std::string did = dj.value("device_id", std::string{});
                if (did.empty()) {
                    continue;
                }
                const std::string uid = dj.value("user_id", user_id.value());
                const domain::DeviceAuthorizationStatus st = parse_device_auth_status(dj, "device_status");
                const int64_t reg_ms = dj.value("registered_at_epoch_ms", int64_t{0});
                const auto last_seen = reg_ms > 0
                                           ? std::chrono::system_clock::time_point(std::chrono::milliseconds(reg_ms))
                                           : std::chrono::system_clock::now();
                devices.emplace_back(domain::DeviceId(did), domain::UserId(uid), dj.value("display_name", did),
                                     domain::CryptoIdentity{}, st, last_seen);
            }
        }
        return ClientResult<std::vector<domain::Device>>::ok(std::move(devices));
    } catch (...) {
        return ClientResult<std::vector<domain::Device>>::error(
            ClientError::network("Malformed Gateway list_user_devices JSON response"));
    }
}

ClientResult<void> QtHttpGatewayClient::revoke_device(const domain::DeviceId& device_id, std::string_view mfa_token) {
    if (device_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Device ID cannot be empty to revoke device"));
    }

    nlohmann::json payload;
    payload["device_id"] = device_id.value();
    if (!mfa_token.empty()) {
        payload["mfa_token"] = std::string(mfa_token);
    }
    const std::string json_body = payload.dump();

    const std::string path = "/api/v1/devices/" + url_encode(device_id.value()) + "/revoke";
    const auto res = impl_->perform_http("POST", path, json_body);
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    return ClientResult<void>::ok();
}

ClientResult<std::vector<domain::DirectoryUserEntry>>
QtHttpGatewayClient::search_directory_users(std::string_view query, std::size_t limit) {
    const std::vector<std::pair<std::string, std::string>> q_params = {
        {"q", std::string(query)},
        {"limit", std::to_string(limit == 0U ? 20U : limit)},
    };
    const auto res = impl_->perform_http("GET", "/api/v1/users/directory", {}, "", {}, q_params);
    if (res.is_error()) {
        return ClientResult<std::vector<domain::DirectoryUserEntry>>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        std::vector<domain::DirectoryUserEntry> out;
        if (j.contains("users") && j["users"].is_array()) {
            for (const auto& uj : j["users"]) {
                if (!uj.is_object()) {
                    continue;
                }
                const std::string uid = uj.value("user_id", std::string{});
                if (uid.empty()) {
                    continue;
                }
                out.emplace_back(domain::UserId(uid), uj.value("handle", std::string{}), uj.value("display_name", uid),
                                 decode_wire_bytes(uj.value("identity_public_key", std::string{})),
                                 uj.value("identity_fingerprint", std::string{}),
                                 uj.value("active_device_count", uint32_t{1}));
            }
        }
        return ClientResult<std::vector<domain::DirectoryUserEntry>>::ok(std::move(out));
    } catch (...) {
        return ClientResult<std::vector<domain::DirectoryUserEntry>>::error(
            ClientError::network("Malformed Gateway search_directory_users JSON response"));
    }
}

ClientResult<domain::DirectoryUserEntry> QtHttpGatewayClient::lookup_user_identity(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return ClientResult<domain::DirectoryUserEntry>::error(ClientError::validation("User ID cannot be empty"));
    }

    const std::string path = "/api/v1/users/" + url_encode(user_id.value());
    const auto res = impl_->perform_http("GET", path);
    if (res.is_error()) {
        return ClientResult<domain::DirectoryUserEntry>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        const auto& uj = (j.contains("user") && j["user"].is_object()) ? j["user"] : j;
        const std::string uid = uj.value("user_id", user_id.value());
        return ClientResult<domain::DirectoryUserEntry>::ok(domain::DirectoryUserEntry(
            domain::UserId(uid), uj.value("handle", uj.value("credential_identifier", std::string{})),
            uj.value("display_name", uid), decode_wire_bytes(uj.value("identity_public_key", std::string{})),
            uj.value("identity_fingerprint", std::string{}), uj.value("active_device_count", uint32_t{1})));
    } catch (...) {
        return ClientResult<domain::DirectoryUserEntry>::error(
            ClientError::network("Malformed Gateway lookup_user_identity JSON response"));
    }
}

ClientResult<FileUploadInitResult> QtHttpGatewayClient::init_file_upload(const FileUploadInitRequest& request) {
    if (request.file_id.empty() || request.owner_user_id.empty() || request.owner_device_id.empty()) {
        return ClientResult<FileUploadInitResult>::error(
            ClientError::validation("File ID, owner user ID, and owner device ID are required"));
    }

    nlohmann::json payload;
    payload["file_id"] = request.file_id;
    payload["owner_user_id"] = request.owner_user_id.value();
    payload["owner_device_id"] = request.owner_device_id.value();
    if (!request.conversation_id.empty() && request.conversation_id.value().rfind("profile-avatar:", 0) != 0) {
        payload["conversation_id"] = request.conversation_id.value();
    }
    payload["encrypted_size_bytes"] = request.encrypted_size_bytes;
    payload["expected_chunk_count"] = request.expected_chunk_count;
    payload["encryption_version"] = request.encryption_version;
    if (!request.client_crypto_metadata.empty()) {
        payload["client_crypto_metadata"] = request.client_crypto_metadata;
    }
    const std::string json_body = payload.dump();

    const auto res = impl_->perform_http("POST", "/api/v1/files/upload/init", json_body);
    if (res.is_error()) {
        return ClientResult<FileUploadInitResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        FileUploadInitResult out;
        out.upload_id = j.value("upload_id", std::string{});
        out.file_id = j.value("file_id", request.file_id);
        out.status = j.value("status", std::string{"TRANSFER_STATUS_PENDING"});
        out.expires_at_unix_ms = j.value("expires_at_unix_ms", int64_t{0});
        if (out.upload_id.empty()) {
            return ClientResult<FileUploadInitResult>::error(
                ClientError::network("Gateway init_file_upload omitted upload_id"));
        }
        return ClientResult<FileUploadInitResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<FileUploadInitResult>::error(
            ClientError::network("Malformed Gateway init_file_upload JSON response"));
    }
}

ClientResult<FileChunkUploadResult> QtHttpGatewayClient::upload_file_chunk(const FileChunkUploadRequest& request) {
    if (request.upload_id.empty() || request.encrypted_data.empty()) {
        return ClientResult<FileChunkUploadResult>::error(
            ClientError::validation("Upload ID and encrypted chunk bytes are required"));
    }

    std::vector<std::pair<std::string, std::string>> headers = {
        {"Upload-Id", request.upload_id},
        {"Chunk-Index", std::to_string(request.chunk_index)},
    };
    if (!request.ciphertext_sha256.empty()) {
        headers.emplace_back("X-Ciphertext-SHA256", request.ciphertext_sha256);
    }

    const std::string binary_body(reinterpret_cast<const char*>(request.encrypted_data.data()),
                                  request.encrypted_data.size());
    const auto res =
        impl_->perform_http("POST", "/api/v1/files/upload/chunk", binary_body, "application/octet-stream", headers);
    if (res.is_error()) {
        return ClientResult<FileChunkUploadResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        FileChunkUploadResult out;
        out.upload_id = j.value("upload_id", request.upload_id);
        out.chunk_index = j.value("chunk_index", request.chunk_index);
        out.accepted = j.value("accepted", false);
        out.received_sha256 = j.value("received_sha256", std::string{});
        return ClientResult<FileChunkUploadResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<FileChunkUploadResult>::error(
            ClientError::network("Malformed Gateway upload_file_chunk JSON response"));
    }
}

ClientResult<FileUploadFinalizeResult>
QtHttpGatewayClient::finalize_file_upload(const FileUploadFinalizeRequest& request) {
    if (request.upload_id.empty() || request.file_id.empty()) {
        return ClientResult<FileUploadFinalizeResult>::error(
            ClientError::validation("Upload ID and file ID are required to finalize upload"));
    }

    nlohmann::json payload;
    payload["upload_id"] = request.upload_id;
    payload["file_id"] = request.file_id;
    if (!request.expected_ciphertext_sha256.empty()) {
        payload["expected_ciphertext_sha256"] = request.expected_ciphertext_sha256;
    }
    const std::string json_body = payload.dump();

    const auto res = impl_->perform_http("POST", "/api/v1/files/upload/finalize", json_body);
    if (res.is_error()) {
        return ClientResult<FileUploadFinalizeResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        FileUploadFinalizeResult out;
        out.file_id = j.value("file_id", request.file_id);
        out.lifecycle_state = j.value("lifecycle_state", std::string{"FILE_LIFECYCLE_STATE_AVAILABLE"});
        out.available_at_unix_ms = j.value("available_at_unix_ms", int64_t{0});
        return ClientResult<FileUploadFinalizeResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<FileUploadFinalizeResult>::error(
            ClientError::network("Malformed Gateway finalize_file_upload JSON response"));
    }
}

ClientResult<void> QtHttpGatewayClient::cancel_file_upload(std::string_view upload_id, std::string_view reason) {
    if (upload_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Upload ID is required to cancel upload"));
    }

    nlohmann::json payload;
    payload["upload_id"] = std::string(upload_id);
    if (!reason.empty()) {
        payload["reason"] = std::string(reason);
    }
    const std::string json_body = payload.dump();

    const auto res = impl_->perform_http("POST", "/api/v1/files/upload/cancel", json_body);
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    return ClientResult<void>::ok();
}

ClientResult<RemoteFileMetadata> QtHttpGatewayClient::get_file_metadata(std::string_view file_id) {
    if (file_id.empty()) {
        return ClientResult<RemoteFileMetadata>::error(
            ClientError::validation("File ID is required for metadata lookup"));
    }

    const std::string path = "/api/v1/files/" + url_encode(file_id) + "/metadata";
    const auto res = impl_->perform_http("GET", path);
    if (res.is_error()) {
        return ClientResult<RemoteFileMetadata>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        RemoteFileMetadata meta;
        meta.file_id = j.value("file_id", std::string(file_id));
        if (const std::string oid = j.value("owner_user_id", std::string{}); !oid.empty()) {
            meta.owner_user_id = domain::UserId(oid);
        }
        if (const std::string cid = j.value("conversation_id", std::string{}); !cid.empty()) {
            meta.conversation_id = domain::ConversationId(cid);
        }
        meta.lifecycle_state = j.value("lifecycle_state", std::string{"FILE_LIFECYCLE_STATE_AVAILABLE"});
        meta.encrypted_size_bytes = j.value("encrypted_size_bytes", uint64_t{0});
        meta.chunk_count = j.value("chunk_count", uint32_t{0});
        meta.encryption_version = j.value("encryption_version", std::string{"v1"});
        meta.ciphertext_integrity_hash = j.value("ciphertext_integrity_hash", std::string{});
        meta.created_at_unix_ms = j.value("created_at_unix_ms", int64_t{0});
        meta.available_at_unix_ms = j.value("available_at_unix_ms", int64_t{0});
        return ClientResult<RemoteFileMetadata>::ok(std::move(meta));
    } catch (...) {
        return ClientResult<RemoteFileMetadata>::error(
            ClientError::network("Malformed Gateway get_file_metadata JSON response"));
    }
}

ClientResult<FileChunkDownloadResult> QtHttpGatewayClient::download_file_chunk(std::string_view file_id,
                                                                               uint32_t chunk_index) {
    if (file_id.empty()) {
        return ClientResult<FileChunkDownloadResult>::error(
            ClientError::validation("File ID is required for chunk download"));
    }

    const std::string path = "/api/v1/files/" + url_encode(file_id) + "/chunks/" + std::to_string(chunk_index);
    const auto res =
        impl_->perform_http("GET", path, {}, "", {}, {}, /*include_auth=*/true, std::nullopt, kMaxBinaryResponseBytes);
    if (res.is_error()) {
        return ClientResult<FileChunkDownloadResult>::error(res.error());
    }

    FileChunkDownloadResult out;
    out.file_id = std::string(file_id);
    out.chunk_index = chunk_index;
    out.encrypted_data.assign(reinterpret_cast<const uint8_t*>(res.value().body.data()),
                              reinterpret_cast<const uint8_t*>(res.value().body.data()) + res.value().body.size());
    if (!res.value().header_ciphertext_sha256.empty()) {
        out.ciphertext_sha256 = domain::normalize_hex_lower(res.value().header_ciphertext_sha256);
    } else {
        const auto sha_res = domain::crypto::StreamingSha256::digest_hex(out.encrypted_data);
        if (sha_res.is_error()) {
            return ClientResult<FileChunkDownloadResult>::error(sha_res.error());
        }
        out.ciphertext_sha256 = sha_res.value();
    }
    return ClientResult<FileChunkDownloadResult>::ok(std::move(out));
}

ClientResult<void> QtHttpGatewayClient::delete_file(std::string_view file_id) {
    if (file_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("File ID is required for deletion"));
    }

    const std::string path = "/api/v1/files/" + url_encode(file_id);
    const auto res = impl_->perform_http("DELETE", path);
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    return ClientResult<void>::ok();
}

ClientResult<domain::UserProfile> QtHttpGatewayClient::get_user_profile(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return ClientResult<domain::UserProfile>::error(ClientError::validation("User ID cannot be empty"));
    }

    const auto res = impl_->perform_http("GET", "/api/v1/users/me");
    if (res.is_error()) {
        return ClientResult<domain::UserProfile>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        const auto& uj = (j.contains("user") && j["user"].is_object()) ? j["user"] : j;

        domain::UserProfile profile;
        const std::string resp_uid = uj.value("user_id", user_id.value());
        profile.user_id = resp_uid.empty() ? user_id : domain::UserId(resp_uid);
        const std::string cred = uj.value("credential_identifier", std::string{});
        profile.display_name = uj.value("display_name", cred.empty() ? profile.user_id.value() : cred);
        profile.public_handle = uj.value("public_handle", std::string{});
        if (profile.public_handle.empty() && cred.size() >= domain::kMinPublicHandleLength &&
            cred.size() <= domain::kMaxPublicHandleLength) {
            domain::UserProfile probe = profile;
            probe.public_handle = cred;
            if (probe.is_valid()) {
                profile.public_handle = cred;
            }
        }
        profile.bio_status = uj.value("bio_status", std::string{});
        profile.avatar_file_id = uj.value("avatar_file_id", std::string{});
        profile.avatar_sha256 = domain::normalize_hex_lower(uj.value("avatar_sha256", std::string{}));
        profile.allow_handle_discovery = uj.value("allow_handle_discovery", true);
        profile.updated_at_ms = uj.value("updated_at_epoch_ms", uj.value("updated_at_ms", current_unix_ms()));
        return ClientResult<domain::UserProfile>::ok(std::move(profile));
    } catch (...) {
        return ClientResult<domain::UserProfile>::error(
            ClientError::network("Malformed Gateway get_user_profile JSON response"));
    }
}

ClientResult<UserProfileSyncResult>
QtHttpGatewayClient::update_user_profile(const domain::UserProfile& public_profile) {
    const auto errors = public_profile.validate();
    if (!errors.empty()) {
        return ClientResult<UserProfileSyncResult>::error(ClientError::validation(errors.front()));
    }

    if (!public_profile.allow_handle_discovery) {
        UserProfileSyncResult local_only;
        local_only.profile = public_profile;
        local_only.sync_status = ProfileSyncStatus::SyncDisabledByPrivacyPolicy;
        return ClientResult<UserProfileSyncResult>::ok(std::move(local_only));
    }

    nlohmann::json payload;
    payload["user_id"] = public_profile.user_id.value();
    payload["public_handle"] = public_profile.public_handle;
    payload["display_name"] = public_profile.display_name;
    payload["bio_status"] = public_profile.bio_status;
    payload["avatar_file_id"] = public_profile.avatar_file_id;
    payload["avatar_sha256"] = domain::normalize_hex_lower(public_profile.avatar_sha256);
    payload["allow_handle_discovery"] = public_profile.allow_handle_discovery;
    payload["updated_at_ms"] = public_profile.updated_at_ms;
    const std::string json_body = payload.dump();

    const auto res = impl_->perform_http("PUT", "/api/v1/users/me", json_body);
    if (res.is_error()) {
        if (res.error().code() == ClientErrorCode::ProtocolError &&
            (res.error().details() == "HTTP 404" || res.error().details() == "HTTP 405" ||
             res.error().details() == "HTTP 501")) {
            UserProfileSyncResult fallback;
            fallback.profile = public_profile;
            fallback.sync_status = ProfileSyncStatus::LocalOnlyServerUnsupported;
            return ClientResult<UserProfileSyncResult>::ok(std::move(fallback));
        }
        return ClientResult<UserProfileSyncResult>::error(res.error());
    }

    UserProfileSyncResult synced;
    synced.profile = public_profile;
    synced.sync_status = ProfileSyncStatus::Synced;
    if (!res.value().body.empty()) {
        try {
            const auto j = nlohmann::json::parse(res.value().body);
            if (j.is_object()) {
                const auto& pj = (j.contains("profile") && j["profile"].is_object())
                                     ? j["profile"]
                                     : ((j.contains("user") && j["user"].is_object()) ? j["user"] : j);
                if (pj.contains("display_name") && pj["display_name"].is_string()) {
                    synced.profile.display_name = pj["display_name"].get<std::string>();
                }
                if (pj.contains("public_handle") && pj["public_handle"].is_string()) {
                    synced.profile.public_handle = pj["public_handle"].get<std::string>();
                }
            }
        } catch (...) {
        }
    }
    return ClientResult<UserProfileSyncResult>::ok(std::move(synced));
}

ClientResult<TlsCertificateInfo> QtHttpGatewayClient::inspect_tls_certificate(std::string_view host, uint16_t port) {
    return impl_->inspect_tls(host, port);
}

ClientResult<AuthSessionResult> QtHttpGatewayClient::authenticate_user(std::string_view identifier,
                                                                       std::string_view credential,
                                                                       std::string_view device_id) {
    if (identifier.empty() || credential.empty()) {
        return ClientResult<AuthSessionResult>::error(
            ClientError::validation("Identifier and credential cannot be empty"));
    }

    nlohmann::json payload;
    payload["identifier"] = std::string(identifier);
    payload["credential"] = std::string(credential);
    if (!device_id.empty()) {
        payload["device_id"] = std::string(device_id);
    }

    const auto res = impl_->perform_http("POST", "/api/v1/auth/login", payload.dump(), "application/json", {}, {},
                                         /*include_auth=*/false);
    if (res.is_error()) {
        return ClientResult<AuthSessionResult>::error(res.error());
    }

    auto parsed = parse_auth_session_result(res.value().body, identifier, "login");
    if (parsed.is_ok() && !parsed.value().access_token.empty()) {
        impl_->set_runtime_auth_token(parsed.value().access_token);
    }
    return parsed;
}

ClientResult<AuthSessionResult> QtHttpGatewayClient::refresh_session(std::string_view refresh_token,
                                                                     std::string_view device_id) {
    if (refresh_token.empty()) {
        return ClientResult<AuthSessionResult>::error(ClientError::validation("Refresh token cannot be empty"));
    }

    nlohmann::json payload;
    payload["refresh_token"] = std::string(refresh_token);
    if (!device_id.empty()) {
        payload["device_id"] = std::string(device_id);
    }

    const auto res = impl_->perform_http("POST", "/api/v1/auth/refresh", payload.dump(), "application/json", {}, {},
                                         /*include_auth=*/false);
    if (res.is_error()) {
        return ClientResult<AuthSessionResult>::error(res.error());
    }

    auto parsed = parse_auth_session_result(res.value().body, "", "refresh");
    if (parsed.is_ok() && !parsed.value().access_token.empty()) {
        impl_->set_runtime_auth_token(parsed.value().access_token);
    }
    return parsed;
}

ClientResult<void> QtHttpGatewayClient::revoke_session(std::string_view session_id, std::string_view reason) {
    if (session_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Session ID cannot be empty"));
    }

    nlohmann::json payload;
    payload["session_id"] = std::string(session_id);
    payload["reason"] = reason.empty() ? "user_logout" : std::string(reason);

    const auto res = impl_->perform_http("POST", "/api/v1/auth/revoke", payload.dump());
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    impl_->clear_runtime_auth_token();
    return ClientResult<void>::ok();
}

ClientResult<ConversationCreateResult>
QtHttpGatewayClient::create_direct_conversation(const domain::UserId& peer_user_id) {
    if (peer_user_id.empty()) {
        return ClientResult<ConversationCreateResult>::error(ClientError::validation("Peer user ID cannot be empty"));
    }

    nlohmann::json payload;
    payload["type"] = "direct";
    payload["participant_user_ids"] = nlohmann::json::array({peer_user_id.value()});

    const auto res = impl_->perform_http("POST", "/api/v1/conversations", payload.dump());
    if (res.is_error()) {
        return ClientResult<ConversationCreateResult>::error(res.error());
    }

    try {
        const auto j = nlohmann::json::parse(res.value().body);
        const auto& conv_json = (j.contains("conversation") && j["conversation"].is_object()) ? j["conversation"] : j;
        const auto parsed = parse_conversation_summary(conv_json);
        if (!parsed.has_value()) {
            return ClientResult<ConversationCreateResult>::error(
                ClientError::network("Gateway create_direct_conversation response missing conversation_id"));
        }
        ConversationCreateResult out;
        out.conversation_id = parsed->conversation_id;
        out.type = parsed->type;
        out.title = parsed->title;
        out.creator_user_id = parsed->creator_user_id;
        out.created_at_ms = parsed->created_at_ms;
        out.participant_user_ids = parsed->participant_user_ids;
        return ClientResult<ConversationCreateResult>::ok(std::move(out));
    } catch (...) {
        return ClientResult<ConversationCreateResult>::error(
            ClientError::network("Malformed Gateway create_direct_conversation JSON response"));
    }
}

ClientResult<void> QtHttpGatewayClient::update_presence(std::string_view status,
                                                        std::string_view custom_status_message) {
    nlohmann::json payload = {
        {"status", std::string(status)},
    };
    if (!custom_status_message.empty()) {
        payload["custom_status_message"] = std::string(custom_status_message);
    }
    const auto res = impl_->perform_http("PUT", "/api/v1/presence/me", payload.dump());
    if (res.is_error()) {
        return ClientResult<void>::error(res.error());
    }
    return ClientResult<void>::ok();
}

ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>
QtHttpGatewayClient::batch_get_presence(const std::vector<domain::UserId>& user_ids) {
    if (user_ids.empty()) {
        return ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>::ok({});
    }
    nlohmann::json ids = nlohmann::json::array();
    for (const auto& uid : user_ids) {
        if (!uid.empty()) {
            ids.push_back(uid.value());
        }
    }
    if (ids.empty()) {
        return ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>::ok({});
    }
    nlohmann::json payload = {{"user_ids", std::move(ids)}};
    const auto res = impl_->perform_http("POST", "/api/v1/presence/batch", payload.dump());
    if (res.is_error()) {
        return ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>::error(res.error());
    }
    try {
        const auto j = nlohmann::json::parse(res.value().body);
        std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo> out;
        if (j.is_array()) {
            for (const auto& item : j) {
                if (!item.is_object()) {
                    continue;
                }
                const std::string uid_str = item.value("user_id", std::string{});
                if (uid_str.empty()) {
                    continue;
                }
                application::interfaces::IGatewayClient::PeerPresenceInfo info;
                info.user_id = domain::UserId(uid_str);
                info.status = item.value("status", std::string{"offline"});
                info.last_active_unix_ms = item.value("last_active_unix_ms", int64_t{0});
                info.custom_status_message = item.value("custom_status_message", std::string{});
                out.push_back(std::move(info));
            }
        }
        return ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>::ok(std::move(out));
    } catch (...) {
        return ClientResult<std::vector<application::interfaces::IGatewayClient::PeerPresenceInfo>>::error(
            ClientError::network("Malformed Gateway batch_get_presence JSON response"));
    }
}

} // namespace securecloud::client::infrastructure::adapters
