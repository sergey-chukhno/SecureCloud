#include "files/storage/s3_client.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <thread>

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

constexpr size_t kDateStampLen = 8;
constexpr uint16_t kDefaultHttpPort = 80;
constexpr uint16_t kDefaultHttpsPort = 443;
constexpr int64_t kMsPerSec = 1000;
constexpr int64_t kUsPerMs = 1000;
constexpr size_t kSocketBufferSize = 4096;
constexpr int kBase10 = 10;
constexpr int kHttpStatusOk = 200;
constexpr int kHttpStatusForbidden = 403;
constexpr int kHttpStatusNotFound = 404;

inline std::string unquote(std::string_view s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return std::string(s.substr(1, s.size() - 2));
    }
    return std::string(s);
}

inline std::string extract_xml_tag(std::string_view xml, std::string_view tag) {
    const std::string open_tag = "<" + std::string(tag) + ">";
    const std::string close_tag = "</" + std::string(tag) + ">";
    size_t start = xml.find(open_tag);
    if (start == std::string_view::npos) {
        return "";
    }
    start += open_tag.size();
    const size_t end = xml.find(close_tag, start);
    if (end == std::string_view::npos) {
        return "";
    }
    return std::string(xml.substr(start, end - start));
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

    std::array<char, 32> amz_date_buf{};
    std::strftime(amz_date_buf.data(), amz_date_buf.size(), "%Y%m%dT%H%M%SZ", &gm);
    const std::string amz_date(amz_date_buf.data());
    const std::string date_stamp = amz_date.substr(0, kDateStampLen);

    // Payload Hash
    std::string payload_hash;
    const auto sha_it = req.headers.find("x-amz-content-sha256");
    if (sha_it != req.headers.end() && !sha_it->second.empty()) {
        payload_hash = sha_it->second;
    } else {
        payload_hash = sha256_hex(req.body);
    }

    // Host header representation
    std::string host_header_val = req.host;
    if (req.port != kDefaultHttpPort && req.port != kDefaultHttpsPort) {
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

    // Canonical URI and Query String
    std::string canonical_uri = req.path;
    std::string canonical_query_string;
    const size_t q_pos = req.path.find('?');
    if (q_pos != std::string::npos) {
        canonical_uri = req.path.substr(0, q_pos);
        const std::string raw_query = req.path.substr(q_pos + 1);

        std::map<std::string, std::string> query_map;
        std::istringstream q_stream(raw_query);
        std::string param;
        while (std::getline(q_stream, param, '&')) {
            if (param.empty()) {
                continue;
            }
            const size_t eq_pos = param.find('=');
            if (eq_pos != std::string::npos) {
                query_map[param.substr(0, eq_pos)] = param.substr(eq_pos + 1);
            } else {
                query_map[param] = "";
            }
        }

        bool first_param = true;
        for (const auto& [k, v] : query_map) {
            if (!first_param) {
                canonical_query_string += "&";
            }
            canonical_query_string += k + "=" + v;
            first_param = false;
        }
    }

    if (canonical_uri.empty() || canonical_uri.front() != '/') {
        canonical_uri = "/" + canonical_uri;
    }

    // Canonical Request
    const std::string canonical_request = req.method + "\n" + canonical_uri + "\n" + canonical_query_string + "\n" +
                                          canonical_headers + "\n" + signed_headers + "\n" + payload_hash;

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

// --- S3RetryPolicy Implementation ---

std::chrono::milliseconds S3RetryPolicy::calculate_backoff(uint32_t attempt) const noexcept {
    if (attempt == 0) {
        attempt = 1;
    }
    const double multiplier = std::pow(2.0, static_cast<double>(attempt - 1));
    const double raw_backoff_ms = static_cast<double>(initial_backoff.count()) * multiplier;
    double capped_ms = std::min(raw_backoff_ms, static_cast<double>(max_backoff.count()));
    if (jitter_factor > 0.0) {
        static thread_local std::mt19937 gen(std::random_device{}());
        std::uniform_real_distribution<double> dist(1.0 - jitter_factor, 1.0 + jitter_factor);
        capped_ms *= dist(gen);
    }
    return std::chrono::milliseconds(static_cast<long long>(std::max(0.0, std::round(capped_ms))));
}

// --- DefaultHttpTransport Implementation ---

DefaultHttpTransport::DefaultHttpTransport() = default;

DefaultHttpTransport::~DefaultHttpTransport() {
    close_current_socket();
}

void DefaultHttpTransport::close_current_socket() noexcept {
#ifdef _WIN32
    if (cached_sock_ != ~static_cast<uintptr_t>(0)) {
        close_socket(static_cast<SOCKET>(cached_sock_));
        cached_sock_ = ~static_cast<uintptr_t>(0);
    }
#else
    if (cached_sock_ >= 0) {
        close_socket(cached_sock_);
        cached_sock_ = -1;
    }
#endif
    cached_host_.clear();
    cached_port_ = 0;
}

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
        return HttpResponse{.status_code = 0, .status_message = "Socket creation failed", .headers = {}, .body = ""};
    }

    // Configure timeout
#ifdef _WIN32
    DWORD timeout_ms = static_cast<DWORD>(req.timeout.count());
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    ::setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(req.timeout.count() / kMsPerSec);
    tv.tv_usec = static_cast<suseconds_t>((req.timeout.count() % kMsPerSec) * kUsPerMs);
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
        return HttpResponse{.status_code = 0, .status_message = "DNS resolution failed", .headers = {}, .body = ""};
    }

#ifdef _WIN32
    if (::connect(sock, res_info->ai_addr, static_cast<int>(res_info->ai_addrlen)) != 0) {
#else
    if (::connect(sock, res_info->ai_addr, res_info->ai_addrlen) != 0) {
#endif
        ::freeaddrinfo(res_info);
        close_socket(sock);
        return HttpResponse{.status_code = 0, .status_message = "TCP connection failed", .headers = {}, .body = ""};
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
        return HttpResponse{.status_code = 0, .status_message = "Socket send failed", .headers = {}, .body = ""};
    }

    // Read HTTP response header
    std::string response_data;
    std::array<char, kSocketBufferSize> buffer{};
#ifdef _WIN32
    int bytes_read = 0;
    while ((bytes_read = ::recv(sock, buffer.data(), static_cast<int>(buffer.size() - 1), 0)) > 0) {
#else
    ssize_t bytes_read = 0;
    while ((bytes_read = ::recv(sock, buffer.data(), buffer.size() - 1, 0)) > 0) {
#endif
        response_data.append(buffer.data(), static_cast<size_t>(bytes_read));
        if (req.method == "HEAD" && response_data.find("\r\n\r\n") != std::string::npos) {
            break; // Finished reading headers for HEAD
        }
    }
    close_socket(sock);

    // Parse HTTP response status line, headers and body
    HttpResponse res;
    const size_t header_end = response_data.find("\r\n\r\n");
    if (header_end != std::string::npos) {
        const std::string header_str = response_data.substr(0, header_end);
        if (req.method != "HEAD") {
            res.body = response_data.substr(header_end + 4);
        }

        std::istringstream stream(header_str);
        std::string line;
        // Parse status line: "HTTP/1.1 <code status_message>\r\n"
        if (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.starts_with("HTTP/")) {
                const size_t first_space = line.find(' ');
                if (first_space != std::string::npos) {
                    const size_t second_space = line.find(' ', first_space + 1);
                    if (second_space != std::string::npos) {
                        res.status_code = static_cast<int>(std::strtol(
                            line.substr(first_space + 1, second_space - first_space - 1).c_str(), nullptr, kBase10));
                        res.status_message = line.substr(second_space + 1);
                    } else {
                        res.status_code =
                            static_cast<int>(std::strtol(line.substr(first_space + 1).c_str(), nullptr, kBase10));
                    }
                }
            }
        }

        // Parse HTTP headers
        while (std::getline(stream, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                continue;
            }
            const size_t colon = line.find(':');
            if (colon != std::string::npos) {
                const std::string k = to_lower(trim(line.substr(0, colon)));
                const std::string v = trim(line.substr(colon + 1));
                res.headers[k] = v;
            }
        }
    } else if (response_data.starts_with("HTTP/")) {
        const size_t first_space = response_data.find(' ');
        if (first_space != std::string::npos) {
            const size_t second_space = response_data.find(' ', first_space + 1);
            const size_t eol = response_data.find("\r\n");
            if (second_space != std::string::npos && second_space < eol) {
                res.status_code = static_cast<int>(std::strtol(
                    response_data.substr(first_space + 1, second_space - first_space - 1).c_str(), nullptr, kBase10));
                res.status_message = response_data.substr(second_space + 1, eol - second_space - 1);
            } else if (eol != std::string::npos) {
                res.status_code = static_cast<int>(std::strtol(
                    response_data.substr(first_space + 1, eol - first_space - 1).c_str(), nullptr, kBase10));
            }
        }
    }

    return res;
}

// --- S3Client Implementation ---

S3Client::S3Client(S3ClientConfig config, std::shared_ptr<IHttpTransport> transport)
    : config_(std::move(config)), transport_(std::move(transport)), retry_policy_(config_.retry_policy) {
    config_.validate();
    parse_endpoint();

    if (!transport_) {
        transport_ = std::make_shared<DefaultHttpTransport>();
    }
}

void S3Client::parse_endpoint() {
    constexpr std::string_view kHttpsPrefix = "https://";
    constexpr std::string_view kHttpPrefix = "http://";

    std::string ep = config_.endpoint;
    if (ep.starts_with(kHttpsPrefix)) {
        is_https_ = true;
        ep = ep.substr(kHttpsPrefix.size());
        port_ = kDefaultHttpsPort;
    } else if (ep.starts_with(kHttpPrefix)) {
        is_https_ = false;
        ep = ep.substr(kHttpPrefix.size());
        port_ = kDefaultHttpPort;
    }

    // Strip trailing slash
    if (!ep.empty() && ep.back() == '/') {
        ep.pop_back();
    }

    // Extract host and port
    const size_t colon_pos = ep.find(':');
    if (colon_pos != std::string::npos) {
        host_ = ep.substr(0, colon_pos);
        port_ = static_cast<uint16_t>(std::strtol(ep.substr(colon_pos + 1).c_str(), nullptr, kBase10));
    } else {
        host_ = ep;
    }
}

HttpResponse S3Client::execute_with_retry(HttpRequest req) {
    uint32_t attempt = 0;
    while (true) {
        attempt++;
        HttpResponse res = transport_->execute(req);
        if (res.status_code >= 200 && res.status_code < 300) {
            return res;
        }
        if (!retry_policy_.is_retryable(res.status_code) || attempt > retry_policy_.max_retries) {
            return res;
        }
        const auto backoff = retry_policy_.calculate_backoff(attempt);
        if (backoff.count() > 0) {
            std::this_thread::sleep_for(backoff);
        }
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

        const HttpResponse res = execute_with_retry(req);
        return res.status_code == kHttpStatusOk;
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

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk) {
        return true;
    }
    if (res.status_code == kHttpStatusNotFound) {
        return false;
    }
    if (res.status_code == kHttpStatusForbidden) {
        throw S3AuthenticationException("MinIO S3 rejected request: 403 Forbidden");
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 response status: " + std::to_string(res.status_code));
}

bool S3Client::put_object(const std::string& object_key, std::string_view payload, const std::string& content_type,
                          const std::string& sha256_hex, std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "PUT";
    req.path = "/" + config_.bucket + "/" + object_key;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;
    req.body = std::string(payload);
    req.headers["content-type"] = content_type;
    req.headers["content-length"] = std::to_string(payload.size());

    const std::string payload_hash = sha256_hex.empty() ? SigV4Signer::sha256_hex(payload) : sha256_hex;
    req.headers["x-amz-content-sha256"] = payload_hash;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk || res.status_code == 201) {
        return true;
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected PUT request: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on PUT: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on PUT: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 PUT response status: " + std::to_string(res.status_code));
}

S3ObjectResponse S3Client::get_object(const std::string& object_key, std::optional<ByteRange> range,
                                      std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "GET";
    req.path = "/" + config_.bucket + "/" + object_key;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    if (range.has_value()) {
        req.headers["range"] = range->to_header_value();
    }

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk || res.status_code == 206) {
        S3ObjectResponse obj;
        obj.status_code = res.status_code;
        obj.body = res.body;
        obj.content_length = obj.body.size();
        obj.headers = res.headers;

        const auto etag_it = res.headers.find("etag");
        if (etag_it != res.headers.end()) {
            obj.etag = unquote(etag_it->second);
        }
        const auto ct_it = res.headers.find("content-type");
        if (ct_it != res.headers.end()) {
            obj.content_type = ct_it->second;
        }
        const auto cl_it = res.headers.find("content-length");
        if (cl_it != res.headers.end()) {
            obj.content_length = static_cast<size_t>(std::strtoull(cl_it->second.c_str(), nullptr, kBase10));
        }
        return obj;
    }
    if (res.status_code == kHttpStatusNotFound) {
        throw S3ObjectNotFoundException("Object not found: " + object_key);
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected GET request: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on GET: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on GET: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 GET response status: " + std::to_string(res.status_code));
}

S3ObjectMetadata S3Client::head_object(const std::string& object_key, std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "HEAD";
    req.path = "/" + config_.bucket + "/" + object_key;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk) {
        S3ObjectMetadata meta;
        meta.headers = res.headers;
        const auto etag_it = res.headers.find("etag");
        if (etag_it != res.headers.end()) {
            meta.etag = unquote(etag_it->second);
        }
        const auto ct_it = res.headers.find("content-type");
        if (ct_it != res.headers.end()) {
            meta.content_type = ct_it->second;
        }
        const auto cl_it = res.headers.find("content-length");
        if (cl_it != res.headers.end()) {
            meta.content_length = static_cast<size_t>(std::strtoull(cl_it->second.c_str(), nullptr, kBase10));
        }
        return meta;
    }
    if (res.status_code == kHttpStatusNotFound) {
        throw S3ObjectNotFoundException("Object not found: " + object_key);
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected HEAD request: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on HEAD: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on HEAD: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 HEAD response status: " + std::to_string(res.status_code));
}

bool S3Client::delete_object(const std::string& object_key, std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "DELETE";
    req.path = "/" + config_.bucket + "/" + object_key;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == 204 || res.status_code == kHttpStatusOk || res.status_code == kHttpStatusNotFound) {
        return true;
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected DELETE request: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on DELETE: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on DELETE: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 DELETE response status: " + std::to_string(res.status_code));
}

std::string S3Client::create_multipart_upload(const std::string& object_key, const std::string& content_type,
                                              std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "POST";
    req.path = "/" + config_.bucket + "/" + object_key + "?uploads";
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;
    req.headers["content-type"] = content_type;
    req.headers["content-length"] = "0";

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk) {
        std::string upload_id = extract_xml_tag(res.body, "UploadId");
        if (upload_id.empty()) {
            throw S3ClientException("Failed to parse UploadId from S3 create_multipart_upload response");
        }
        return upload_id;
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected create_multipart_upload: " +
                                        std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on create_multipart_upload: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on create_multipart_upload: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 create_multipart_upload response status: " +
                            std::to_string(res.status_code));
}

std::string S3Client::upload_part(const std::string& object_key, const std::string& upload_id, uint32_t part_number,
                                  std::string_view payload, const std::string& sha256_hex,
                                  std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "PUT";
    req.path = "/" + config_.bucket + "/" + object_key + "?partNumber=" + std::to_string(part_number) +
               "&uploadId=" + upload_id;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;
    req.body = std::string(payload);
    req.headers["content-length"] = std::to_string(payload.size());

    const std::string payload_hash = sha256_hex.empty() ? SigV4Signer::sha256_hex(payload) : sha256_hex;
    req.headers["x-amz-content-sha256"] = payload_hash;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk) {
        const auto etag_it = res.headers.find("etag");
        if (etag_it != res.headers.end()) {
            return unquote(etag_it->second);
        }
        throw S3ClientException("Missing ETag header in upload_part response");
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected upload_part: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on upload_part: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on upload_part: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 upload_part response status: " + std::to_string(res.status_code));
}

bool S3Client::complete_multipart_upload(const std::string& object_key, const std::string& upload_id,
                                         const std::vector<CompletedPart>& parts, std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "POST";
    req.path = "/" + config_.bucket + "/" + object_key + "?uploadId=" + upload_id;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    std::ostringstream xml;
    xml << "<CompleteMultipartUpload>";
    for (const auto& part : parts) {
        xml << "<Part>";
        xml << "<PartNumber>" << part.part_number << "</PartNumber>";
        std::string etag = part.etag;
        if (!etag.empty() && etag.front() != '"') {
            etag = "\"" + etag + "\"";
        }
        xml << "<ETag>" << etag << "</ETag>";
        xml << "</Part>";
    }
    xml << "</CompleteMultipartUpload>";

    req.body = xml.str();
    req.headers["content-type"] = "application/xml";
    req.headers["content-length"] = std::to_string(req.body.size());

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk) {
        return true;
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected complete_multipart_upload: " +
                                        std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on complete_multipart_upload: " +
                                std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on complete_multipart_upload: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 complete_multipart_upload response status: " +
                            std::to_string(res.status_code));
}

bool S3Client::abort_multipart_upload(const std::string& object_key, const std::string& upload_id,
                                      std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "DELETE";
    req.path = "/" + config_.bucket + "/" + object_key + "?uploadId=" + upload_id;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == 204 || res.status_code == kHttpStatusOk || res.status_code == kHttpStatusNotFound) {
        return true;
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected abort_multipart_upload: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on abort_multipart_upload: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on abort_multipart_upload: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 abort_multipart_upload response status: " + std::to_string(res.status_code));
}

ListObjectsResult S3Client::list_objects(const std::string& prefix, size_t max_keys,
                                         const std::string& continuation_token, std::chrono::milliseconds timeout) {
    HttpRequest req;
    req.method = "GET";
    std::string path = "/" + config_.bucket + "?list-type=2";
    if (!continuation_token.empty()) {
        path += "&continuation-token=" + continuation_token;
    }
    if (max_keys > 0) {
        path += "&max-keys=" + std::to_string(max_keys);
    }
    if (!prefix.empty()) {
        path += "&prefix=" + prefix;
    }
    req.path = path;
    req.host = host_;
    req.port = port_;
    req.timeout = timeout;

    SigV4Signer::sign_request(req, config_.access_key, config_.secret_key.expose_unredacted_secret(), config_.region,
                              "s3");

    const HttpResponse res = execute_with_retry(req);

    if (res.status_code == kHttpStatusOk) {
        ListObjectsResult result;
        const std::string& xml = res.body;

        const std::string is_truncated_str = extract_xml_tag(xml, "IsTruncated");
        result.is_truncated = (is_truncated_str == "true");
        result.next_continuation_token = extract_xml_tag(xml, "NextContinuationToken");

        constexpr std::string_view kOpenContents = "<Contents>";
        constexpr std::string_view kCloseContents = "</Contents>";
        size_t pos = 0;
        while ((pos = xml.find(kOpenContents, pos)) != std::string::npos) {
            pos += kOpenContents.size();
            const size_t end_pos = xml.find(kCloseContents, pos);
            if (end_pos == std::string::npos) {
                break;
            }
            std::string_view item_xml(xml.data() + pos, end_pos - pos);
            S3ObjectInfo info;
            info.key = extract_xml_tag(item_xml, "Key");
            info.etag = unquote(extract_xml_tag(item_xml, "ETag"));
            info.last_modified = extract_xml_tag(item_xml, "LastModified");
            const std::string size_str = extract_xml_tag(item_xml, "Size");
            if (!size_str.empty()) {
                info.size = static_cast<size_t>(std::strtoull(size_str.c_str(), nullptr, kBase10));
            }
            if (!info.key.empty()) {
                result.objects.push_back(std::move(info));
            }
            pos = end_pos + kCloseContents.size();
        }
        result.key_count = result.objects.size();
        return result;
    }
    if (res.status_code == kHttpStatusForbidden || res.status_code == 401) {
        throw S3AuthenticationException("MinIO S3 rejected list_objects: " + std::to_string(res.status_code));
    }
    if (res.status_code >= 500 && res.status_code <= 599) {
        throw S3ServerException("MinIO S3 server error on list_objects: " + std::to_string(res.status_code));
    }
    if (res.status_code == 0) {
        throw S3ConnectionException("Failed to reach S3 endpoint on list_objects: " + config_.endpoint);
    }

    throw S3ClientException("Unexpected S3 list_objects response status: " + std::to_string(res.status_code));
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
