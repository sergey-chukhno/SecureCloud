#include "files/storage/s3_client.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sstream>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace securecloud::files::storage {

namespace {

#ifdef _WIN32
inline void init_winsock() noexcept {
    struct WinsockGuard {
        WinsockGuard() noexcept {
            WSADATA wsa_data{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wsa_data);
        }
        ~WinsockGuard() noexcept { ::WSACleanup(); }
    };
    static WinsockGuard guard;
}
inline void close_socket(SOCKET s) noexcept {
    if (s != INVALID_SOCKET) {
        ::closesocket(s);
    }
}
#else
inline void init_winsock() noexcept {}
inline void close_socket(int s) noexcept {
    if (s >= 0) {
        ::close(s);
    }
}
#endif

std::string to_lower(std::string_view str) {
    std::string result;
    result.reserve(str.size());
    for (char c : str) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

std::string trim(std::string_view str) {
    size_t first = 0;
    while (first < str.size() && std::isspace(static_cast<unsigned char>(str[first]))) {
        first++;
    }
    size_t last = str.size();
    while (last > first && std::isspace(static_cast<unsigned char>(str[last - 1]))) {
        last--;
    }
    return std::string(str.substr(first, last - first));
}

} // namespace

// --- S3ClientConfig Implementation ---

S3ClientConfig S3ClientConfig::from_files_config(const FilesConfig& config) {
    S3ClientConfig s3_cfg;
    s3_cfg.endpoint = config.s3_endpoint;
    s3_cfg.bucket = config.s3_bucket;
    s3_cfg.access_key = config.s3_access_key;
    s3_cfg.secret_key = config.s3_secret_key;
    return s3_cfg;
}

void S3ClientConfig::validate() const {
    if (endpoint.empty()) {
        throw S3ClientException("S3ClientConfig: endpoint cannot be empty");
    }
    if (bucket.empty()) {
        throw S3ClientException("S3ClientConfig: bucket cannot be empty");
    }
    if (access_key.empty()) {
        throw S3ClientException("S3ClientConfig: access_key cannot be empty");
    }
    if (secret_key.empty()) {
        throw S3AuthenticationException("S3ClientConfig: secret_key cannot be empty");
    }
}

// --- SigV4Signer Cryptographic Implementation ---

std::string SigV4Signer::hex_encode(const uint8_t* data, size_t len) {
    static constexpr char k_hex_digits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        hex.push_back(k_hex_digits[(data[i] >> 4) & 0x0F]);
        hex.push_back(k_hex_digits[data[i] & 0x0F]);
    }
    return hex;
}

std::string SigV4Signer::sha256_hex(std::string_view data) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash);
    return hex_encode(hash, SHA256_DIGEST_LENGTH);
}

std::vector<uint8_t> SigV4Signer::hmac_sha256(const void* key, size_t key_len, std::string_view data) {
    std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
    unsigned int result_len = 0;
    HMAC(EVP_sha256(), key, static_cast<int>(key_len), reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         result.data(), &result_len);
    result.resize(result_len);
    return result;
}

std::vector<uint8_t> SigV4Signer::derive_signing_key(const std::string& secret_key, const std::string& date_stamp,
                                                     const std::string& region, const std::string& service) {
    const std::string k_secret = "AWS4" + secret_key;
    const auto k_date = hmac_sha256(k_secret.data(), k_secret.size(), date_stamp);
    const auto k_region = hmac_sha256(k_date.data(), k_date.size(), region);
    const auto k_service = hmac_sha256(k_region.data(), k_region.size(), service);
    return hmac_sha256(k_service.data(), k_service.size(), "aws4_request");
}

void SigV4Signer::sign_request(HttpRequest& req, const std::string& access_key, const std::string& secret_key,
                               const std::string& region, const std::string& service,
                               const std::chrono::system_clock::time_point& now) {
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm gm{};
#ifdef _WIN32
    gmtime_s(&gm, &t);
#else
    gmtime_r(&t, &gm);
#endif

    char amz_date_buf[32];
    std::strftime(amz_date_buf, sizeof(amz_date_buf), "%Y%m%dT%H%M%SZ", &gm);
    const std::string amz_date(amz_date_buf);
    const std::string date_stamp = amz_date.substr(0, 8);

    // Payload Hash
    const std::string payload_hash = sha256_hex(req.body);

    // Host header representation
    std::string host_header_val = req.host;
    if (req.port != 80 && req.port != 443) {
        host_header_val += ":" + std::to_string(req.port);
    }

    req.headers["host"] = host_header_val;
    req.headers["x-amz-date"] = amz_date;
    req.headers["x-amz-content-sha256"] = payload_hash;

    // Build Canonical Headers and Signed Headers
    std::map<std::string, std::string> canonical_headers_map;
    for (const auto& [k, v] : req.headers) {
        canonical_headers_map[to_lower(k)] = trim(v);
    }

    std::string canonical_headers;
    std::string signed_headers;
    bool first = true;
    for (const auto& [k, v] : canonical_headers_map) {
        canonical_headers += k + ":" + v + "\n";
        if (!first) {
            signed_headers += ";";
        }
        signed_headers += k;
        first = false;
    }

    // Canonical URI
    std::string canonical_uri = req.path;
    if (canonical_uri.empty() || canonical_uri.front() != '/') {
        canonical_uri = "/" + canonical_uri;
    }

    // Canonical Request
    std::string canonical_request =
        req.method + "\n" + canonical_uri + "\n\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash;

    // String to Sign
    const std::string credential_scope = date_stamp + "/" + region + "/" + service + "/aws4_request";
    const std::string string_to_sign =
        "AWS4-HMAC-SHA256\n" + amz_date + "\n" + credential_scope + "\n" + sha256_hex(canonical_request);

    // Signature calculation
    const auto signing_key = derive_signing_key(secret_key, date_stamp, region, service);
    const auto signature_bytes = hmac_sha256(signing_key.data(), signing_key.size(), string_to_sign);
    const std::string signature = hex_encode(signature_bytes.data(), signature_bytes.size());

    // Authorization Header
    req.headers["authorization"] = "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + credential_scope +
                                   ", SignedHeaders=" + signed_headers + ", Signature=" + signature;
}

// --- DefaultHttpTransport Implementation ---

HttpResponse DefaultHttpTransport::execute(const HttpRequest& req) {
    init_winsock();

#ifdef _WIN32
    using sock_t = SOCKET;
    constexpr sock_t k_invalid = INVALID_SOCKET;
#else
    using sock_t = int;
    constexpr sock_t k_invalid = -1;
#endif

    sock_t sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == k_invalid) {
        return HttpResponse{0, "Socket creation failed", {}, ""};
    }

    // Configure timeout
#ifdef _WIN32
    DWORD timeout_ms = static_cast<DWORD>(req.timeout.count());
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(req.timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((req.timeout.count() % 1000) * 1000);
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    // Resolve address
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res_info = nullptr;
    const std::string port_str = std::to_string(req.port);

    if (::getaddrinfo(req.host.c_str(), port_str.c_str(), &hints, &res_info) != 0 || !res_info) {
        close_socket(sock);
        return HttpResponse{0, "DNS resolution failed", {}, ""};
    }

    if (::connect(sock, res_info->ai_addr, res_info->ai_addrlen) != 0) {
        ::freeaddrinfo(res_info);
        close_socket(sock);
        return HttpResponse{0, "TCP connection failed", {}, ""};
    }
    ::freeaddrinfo(res_info);

    // Format HTTP/1.1 wire request
    std::ostringstream wire_req;
    wire_req << req.method << " " << req.path << " HTTP/1.1\r\n";
    for (const auto& [k, v] : req.headers) {
        wire_req << k << ": " << v << "\r\n";
    }
    wire_req << "Connection: close\r\n";
    wire_req << "Content-Length: " << req.body.size() << "\r\n\r\n";
    wire_req << req.body;

    const std::string req_str = wire_req.str();
#ifdef _WIN32
    if (::send(sock, req_str.c_str(), static_cast<int>(req_str.size()), 0) < 0) {
#else
    if (::send(sock, req_str.c_str(), req_str.size(), 0) < 0) {
#endif
        close_socket(sock);
        return HttpResponse{0, "Socket send failed", {}, ""};
    }

    // Read HTTP response header
    std::string response_data;
    char buffer[4096];
#ifdef _WIN32
    int bytes_read = 0;
    while ((bytes_read = ::recv(sock, buffer, static_cast<int>(sizeof(buffer) - 1), 0)) > 0) {
#else
    ssize_t bytes_read = 0;
    while ((bytes_read = ::recv(sock, buffer, sizeof(buffer) - 1, 0)) > 0) {
#endif
        response_data.append(buffer, static_cast<size_t>(bytes_read));
        if (req.method == "HEAD" && response_data.find("\r\n\r\n") != std::string::npos) {
            break; // Finished reading headers for HEAD
        }
    }
    close_socket(sock);

    // Parse HTTP status line: "HTTP/1.1 <code status_message>\r\n"
    HttpResponse res;
    if (response_data.rfind("HTTP/", 0) == 0) {
        const size_t first_space = response_data.find(' ');
        if (first_space != std::string::npos) {
            const size_t second_space = response_data.find(' ', first_space + 1);
            const size_t eol = response_data.find("\r\n");
            if (second_space != std::string::npos && second_space < eol) {
                res.status_code =
                    std::atoi(response_data.substr(first_space + 1, second_space - first_space - 1).c_str());
                res.status_message = response_data.substr(second_space + 1, eol - second_space - 1);
            } else if (eol != std::string::npos) {
                res.status_code = std::atoi(response_data.substr(first_space + 1, eol - first_space - 1).c_str());
            }
        }
    }

    return res;
}

// --- S3Client Implementation ---

S3Client::S3Client(S3ClientConfig config, std::shared_ptr<IHttpTransport> transport)
    : config_(std::move(config)), transport_(std::move(transport)) {
    config_.validate();
    parse_endpoint();

    if (!transport_) {
        transport_ = std::make_shared<DefaultHttpTransport>();
    }
}

void S3Client::parse_endpoint() {
    std::string ep = config_.endpoint;
    if (ep.rfind("https://", 0) == 0) {
        is_https_ = true;
        ep = ep.substr(8);
        port_ = 443;
    } else if (ep.rfind("http://", 0) == 0) {
        is_https_ = false;
        ep = ep.substr(7);
        port_ = 80;
    }

    // Strip trailing slash
    if (!ep.empty() && ep.back() == '/') {
        ep.pop_back();
    }

    // Extract host and port
    const size_t colon_pos = ep.find(':');
    if (colon_pos != std::string::npos) {
        host_ = ep.substr(0, colon_pos);
        port_ = static_cast<uint16_t>(std::atoi(ep.substr(colon_pos + 1).c_str()));
    } else {
        host_ = ep;
    }
}

bool S3Client::ping_bucket(std::chrono::milliseconds timeout) noexcept {
    try {
        HttpRequest req;
        req.method = "HEAD";
        req.path = "/" + config_.bucket;
        req.host = host_;
        req.port = port_;
        req.timeout = timeout;

        SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(),
                                  config_.region, "s3");

        const HttpResponse res = transport_->execute(req);
        return res.status_code == 200;
    } catch (...) {
        return false;
    }
}

bool S3Client::object_exists(const std::string& object_key, std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "HEAD";
    req.path = "/" + config_.bucket + "/" + object_key;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = transport_->execute(req);

    if (res.status_code == 200) {
        return true;
    }
    if (res.status_code == 404) {
        return false;
    }
    if (res.status_code == 403) {
        throw S3AuthenticationException("MinIO S3 rejected request: 403 Forbidden");
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 response status: " + std::to_string(res.status_code));
}

const S3ClientConfig& S3Client::config() const noexcept {
    return config_;
}

const std::string& S3Client::endpoint_host() const noexcept {
    return host_;
}

uint16_t S3Client::endpoint_port() const noexcept {
    return port_;
}

} // namespace securecloud::files::storage
