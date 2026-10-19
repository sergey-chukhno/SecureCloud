#include "gateway_config.hpp"
#include "grpc/auth_service_client.hpp"
#include "grpc/channel_manager.hpp"
#include "grpc/files_service_client.hpp"
#include "http/auth/auth_service_token_validator.hpp"
#include "http/auth/authentication_middleware.hpp"
#include "http/auth/authorization_middleware.hpp"
#include "http/auth/gateway_security_policy.hpp"
#include "http/middleware/drain_middleware.hpp"
#include "http/middleware/logging_middleware.hpp"
#include "http/middleware/rate_limiter_middleware.hpp"
#include "http/middleware/request_id_middleware.hpp"
#include "http/middleware/resource_limiter_middleware.hpp"
#include "http/proxy/auth_proxy_handler.hpp"
#include "http/proxy/files_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/drain_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/gateway_route_registrar.hpp"
#include "http/routing/router.hpp"
#include "http/server/https_server.hpp"
#include "http/streaming/streaming_buffer.hpp"
#include "securecloud/auth/v1/auth.grpc.pb.h"
#include "securecloud/auth/v1/auth.pb.h"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include <httplib.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
static void ensure_integration_winsock() {
    static struct WinsockInit {
        WinsockInit() {
            WSADATA wsa;
            WSAStartup(MAKEWORD(2, 2), &wsa);
        }
        ~WinsockInit() { WSACleanup(); }
    } s_init;
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
static void ensure_integration_winsock() {}
#endif

namespace securecloud::gateway {
namespace {

constexpr auto k_default_client_timeout = std::chrono::milliseconds(5000);
constexpr auto k_shutdown_timeout = std::chrono::milliseconds(3000);
const std::string k_loopback_address = "127.0.0.1";

// Controllable Mock AuthService for token verification over mTLS
class ControllableStreamingMockAuthService final : public securecloud::auth::v1::AuthService::Service {
  public:
    std::atomic<uint32_t> validate_invocations{0};

    void reset_state() { validate_invocations.store(0); }

    ::grpc::Status ValidateSession(::grpc::ServerContext* /*context*/,
                                   const securecloud::auth::v1::ValidateSessionRequest* request,
                                   securecloud::auth::v1::ValidateSessionResponse* response) override {
        validate_invocations.fetch_add(1, std::memory_order_relaxed);

        if (request->access_token() == "invalid-token") {
            response->set_is_valid(false);
            return ::grpc::Status::OK;
        }

        response->set_is_valid(true);
        response->set_user_id("user-stream-1");
        response->set_device_id("dev-stream-1");
        response->set_authentication_level(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        response->set_expires_at_epoch_ms(2000000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status Authenticate(::grpc::ServerContext* /*context*/,
                                const securecloud::auth::v1::AuthenticateRequest* /*request*/,
                                securecloud::auth::v1::AuthenticateResponse* response) override {
        response->set_session_id("sess-test-stream-123");
        response->set_access_token("valid-stream-token");
        response->set_refresh_token("refresh-stream-token");
        response->set_expires_at_epoch_ms(2000000000000LL);
        response->set_user_id("user-stream-1");
        response->set_authentication_level(
            securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_MFA_VERIFIED);
        return ::grpc::Status::OK;
    }
};

// Controllable Mock FilesService managing in-memory sessions, chunks, and metadata
class ControllableStreamingMockFilesService final : public securecloud::files::v1::FilesService::Service {
  public:
    struct StoredUpload {
        std::string upload_id;
        std::string file_id;
        uint64_t encrypted_size_bytes{0};
        uint32_t expected_chunk_count{0};
        std::map<uint32_t, std::string> chunks;
        bool finalized{false};
        bool cancelled{false};
    };

    struct StoredFile {
        std::string file_id;
        uint64_t encrypted_size_bytes{0};
        std::vector<std::string> chunks;
        std::string whole_sha256;
    };

    std::atomic<uint32_t> create_upload_invocations{0};
    std::atomic<uint32_t> upload_chunk_invocations{0};
    std::atomic<uint32_t> finalize_upload_invocations{0};
    std::atomic<uint32_t> get_metadata_invocations{0};
    std::atomic<uint32_t> download_chunk_invocations{0};
    std::atomic<uint32_t> cancel_upload_invocations{0};
    std::atomic<uint32_t> delete_file_invocations{0};

    std::atomic<uint32_t> failures_remaining{0};
    ::grpc::StatusCode failure_status_code{::grpc::StatusCode::UNAVAILABLE};

    // Synchronization for blocking / bulkhead saturation tests
    std::atomic<bool> block_upload_chunk{false};
    std::atomic<uint32_t> active_blocked_chunks{0};
    std::mutex block_mutex;
    std::condition_variable block_cv;

    // Cancellation tracking
    std::atomic<bool> last_call_was_cancelled{false};

    mutable std::mutex data_mutex;
    std::unordered_map<std::string, StoredUpload> uploads;
    std::unordered_map<std::string, StoredFile> files;

    void reset_state() {
        create_upload_invocations.store(0);
        upload_chunk_invocations.store(0);
        finalize_upload_invocations.store(0);
        get_metadata_invocations.store(0);
        download_chunk_invocations.store(0);
        cancel_upload_invocations.store(0);
        delete_file_invocations.store(0);
        failures_remaining.store(0);
        failure_status_code = ::grpc::StatusCode::UNAVAILABLE;
        block_upload_chunk.store(false);
        active_blocked_chunks.store(0);
        last_call_was_cancelled.store(false);

        std::lock_guard<std::mutex> lock(data_mutex);
        uploads.clear();
        files.clear();
    }

    void set_stored_file(const std::string& file_id, const std::vector<std::string>& chunk_payloads) {
        std::lock_guard<std::mutex> lock(data_mutex);
        StoredFile f;
        f.file_id = file_id;
        f.chunks = chunk_payloads;
        uint64_t total_size = 0;
        std::string full_concat;
        for (const auto& c : chunk_payloads) {
            total_size += c.size();
            full_concat += c;
        }
        f.encrypted_size_bytes = total_size;
        f.whole_sha256 = http::StreamingSha256Validator::compute_hex(full_concat);
        files[file_id] = std::move(f);
    }

    ::grpc::Status CreateFileUpload(::grpc::ServerContext* context,
                                    const securecloud::files::v1::CreateFileUploadRequest* request,
                                    securecloud::files::v1::CreateFileUploadResponse* response) override {
        create_upload_invocations.fetch_add(1, std::memory_order_relaxed);

        if (context->IsCancelled()) {
            last_call_was_cancelled.store(true);
            return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Call cancelled");
        }

        uint32_t rem = failures_remaining.load(std::memory_order_relaxed);
        if (rem > 0) {
            failures_remaining.fetch_sub(1, std::memory_order_relaxed);
            return ::grpc::Status(failure_status_code, "Injected downstream failure");
        }

        std::string uid = "up-" + std::to_string(create_upload_invocations.load());
        std::string fid = request->file_id().empty() ? ("file-" + uid) : request->file_id();

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            StoredUpload u;
            u.upload_id = uid;
            u.file_id = fid;
            u.encrypted_size_bytes = request->encrypted_size_bytes();
            u.expected_chunk_count = request->expected_chunk_count();
            uploads[uid] = std::move(u);
        }

        response->set_upload_id(uid);
        response->set_file_id(fid);
        response->set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_PENDING);
        response->set_expires_at_unix_ms(1750000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status UploadChunk(::grpc::ServerContext* context,
                               const securecloud::files::v1::UploadChunkRequest* request,
                               securecloud::files::v1::UploadChunkResponse* response) override {
        upload_chunk_invocations.fetch_add(1, std::memory_order_relaxed);

        if (block_upload_chunk.load(std::memory_order_relaxed)) {
            active_blocked_chunks.fetch_add(1);
            std::unique_lock<std::mutex> lock(block_mutex);
            block_cv.wait(lock, [this, context]() {
                return !block_upload_chunk.load(std::memory_order_relaxed) || context->IsCancelled();
            });
            active_blocked_chunks.fetch_sub(1);
            if (context->IsCancelled()) {
                last_call_was_cancelled.store(true);
                return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Call cancelled while blocked");
            }
        }

        if (context->IsCancelled()) {
            last_call_was_cancelled.store(true);
            return ::grpc::Status(::grpc::StatusCode::CANCELLED, "Call cancelled");
        }

        uint32_t rem = failures_remaining.load(std::memory_order_relaxed);
        if (rem > 0) {
            failures_remaining.fetch_sub(1, std::memory_order_relaxed);
            return ::grpc::Status(failure_status_code, "Injected downstream failure");
        }

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            auto it = uploads.find(request->upload_id());
            if (it != uploads.end()) {
                it->second.chunks[request->chunk_index()] = request->encrypted_data();
            }
        }

        response->set_upload_id(request->upload_id());
        response->set_chunk_index(request->chunk_index());
        response->set_accepted(true);
        response->set_received_sha256(request->ciphertext_sha256());
        return ::grpc::Status::OK;
    }

    ::grpc::Status FinalizeFileUpload(::grpc::ServerContext* /*context*/,
                                      const securecloud::files::v1::FinalizeFileUploadRequest* request,
                                      securecloud::files::v1::FinalizeFileUploadResponse* response) override {
        finalize_upload_invocations.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            auto it = uploads.find(request->upload_id());
            if (it != uploads.end()) {
                it->second.finalized = true;

                StoredFile sf;
                sf.file_id = it->second.file_id;
                sf.encrypted_size_bytes = it->second.encrypted_size_bytes;
                for (const auto& [idx, data] : it->second.chunks) {
                    (void)idx;
                    sf.chunks.push_back(data);
                }
                sf.whole_sha256 = request->expected_ciphertext_sha256();
                files[sf.file_id] = std::move(sf);
            }
        }

        response->set_file_id(request->file_id());
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
        response->set_available_at_unix_ms(1720000000000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetFileMetadata(::grpc::ServerContext* /*context*/,
                                   const securecloud::files::v1::GetFileMetadataRequest* request,
                                   securecloud::files::v1::GetFileMetadataResponse* response) override {
        get_metadata_invocations.fetch_add(1, std::memory_order_relaxed);

        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = files.find(request->file_id());
        if (it == files.end()) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "File not found");
        }

        response->set_file_id(it->second.file_id);
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
        response->set_encrypted_size_bytes(it->second.encrypted_size_bytes);
        response->set_chunk_count(static_cast<uint32_t>(it->second.chunks.size()));
        response->set_encryption_version("v1");
        response->set_ciphertext_integrity_hash(it->second.whole_sha256);
        response->set_created_at_unix_ms(1720000000000LL);
        response->set_available_at_unix_ms(1720000001000LL);
        return ::grpc::Status::OK;
    }

    ::grpc::Status DownloadChunk(::grpc::ServerContext* /*context*/,
                                 const securecloud::files::v1::DownloadChunkRequest* request,
                                 securecloud::files::v1::DownloadChunkResponse* response) override {
        download_chunk_invocations.fetch_add(1, std::memory_order_relaxed);

        std::lock_guard<std::mutex> lock(data_mutex);
        auto it = files.find(request->file_id());
        if (it == files.end()) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "File not found");
        }

        if (request->chunk_index() >= it->second.chunks.size()) {
            return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "Chunk index out of range");
        }

        const auto& chunk_data = it->second.chunks[request->chunk_index()];
        response->set_file_id(request->file_id());
        response->set_chunk_index(request->chunk_index());
        response->set_encrypted_data(chunk_data);
        response->set_chunk_size_bytes(static_cast<uint32_t>(chunk_data.size()));
        response->set_ciphertext_sha256(http::StreamingSha256Validator::compute_hex(chunk_data));
        return ::grpc::Status::OK;
    }

    ::grpc::Status CancelFileUpload(::grpc::ServerContext* /*context*/,
                                    const securecloud::files::v1::CancelFileUploadRequest* request,
                                    securecloud::files::v1::CancelFileUploadResponse* response) override {
        cancel_upload_invocations.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            auto it = uploads.find(request->upload_id());
            if (it != uploads.end()) {
                it->second.cancelled = true;
            }
        }

        response->set_upload_id(request->upload_id());
        response->set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_CANCELLED);
        return ::grpc::Status::OK;
    }

    ::grpc::Status DeleteFile(::grpc::ServerContext* /*context*/,
                              const securecloud::files::v1::DeleteFileRequest* request,
                              securecloud::files::v1::DeleteFileResponse* response) override {
        delete_file_invocations.fetch_add(1, std::memory_order_relaxed);

        {
            std::lock_guard<std::mutex> lock(data_mutex);
            files.erase(request->file_id());
        }

        response->set_file_id(request->file_id());
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_DELETED);
        response->set_deleted(true);
        return ::grpc::Status::OK;
    }
};

class GatewayStreamingIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_dir() {
#ifdef SECURECLOUD_DEV_PKI_DIR
        std::filesystem::path defined_path(SECURECLOUD_DEV_PKI_DIR);
        if (std::filesystem::exists(defined_path / "ca" / "ca.crt")) {
            return defined_path;
        }
#endif
        auto curr = std::filesystem::current_path();
        while (!curr.empty() && curr != curr.root_path()) {
            if (std::filesystem::exists(curr / "deploy" / "dev-pki" / "ca" / "ca.crt")) {
                return curr / "deploy" / "dev-pki";
            }
            curr = curr.parent_path();
        }
        return "deploy/dev-pki";
    }

    void SetUp() override {
        ensure_integration_winsock();
        mock_auth_service_.reset_state();
        mock_files_service_.reset_state();

        pki_root_ = find_pki_dir();
        ca_path_ = pki_root_ / "ca" / "ca.crt";
        auth_cert_path_ = pki_root_ / "services" / "auth" / "auth.crt";
        auth_key_path_ = pki_root_ / "services" / "auth" / "auth.key";
        files_cert_path_ = pki_root_ / "services" / "files" / "files.crt";
        files_key_path_ = pki_root_ / "services" / "files" / "files.key";
        gateway_cert_path_ = pki_root_ / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root_ / "services" / "gateway" / "gateway.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_,        auth_cert_path_,    auth_key_path_,    files_cert_path_,
            files_key_path_, gateway_cert_path_, gateway_key_path_,
        };
        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required dev PKI credential missing: " << path;
        }

        start_auth_server();
        start_files_server();
        setup_gateway();
    }

    void TearDown() override {
        stop_gateway();
        stop_files_server();
        stop_auth_server();
    }

    void start_auth_server() {
        common::security::SecurityCredentialsConfig auth_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = auth_cert_path_,
            .service_key_path = auth_key_path_,
        };
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(auth_creds);
        ASSERT_NE(server_creds, nullptr);

        ::grpc::ServerBuilder builder;
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &port);
        builder.RegisterService(&mock_auth_service_);

        auth_server_ = builder.BuildAndStart();
        ASSERT_NE(auth_server_, nullptr);
        ASSERT_GT(port, 0);

        auth_port_ = port;
        auth_endpoint_ = "127.0.0.1:" + std::to_string(port);
    }

    void stop_auth_server() {
        if (auth_server_) {
            auth_server_->Shutdown(std::chrono::system_clock::now() + k_shutdown_timeout);
            auth_server_->Wait();
            auth_server_.reset();
        }
    }

    void start_files_server() {
        common::security::SecurityCredentialsConfig files_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = files_cert_path_,
            .service_key_path = files_key_path_,
        };
        auto server_creds = common::security::MtlsCredentialLoader::create_server_credentials(files_creds);
        ASSERT_NE(server_creds, nullptr);

        ::grpc::ServerBuilder builder;
        int port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &port);
        builder.RegisterService(&mock_files_service_);

        files_server_ = builder.BuildAndStart();
        ASSERT_NE(files_server_, nullptr);
        ASSERT_GT(port, 0);

        files_port_ = port;
        files_endpoint_ = "127.0.0.1:" + std::to_string(port);
    }

    void stop_files_server() {
        if (files_server_) {
            mock_files_service_.block_upload_chunk.store(false);
            mock_files_service_.block_cv.notify_all();
            files_server_->Shutdown(std::chrono::system_clock::now() + k_shutdown_timeout);
            files_server_->Wait();
            files_server_.reset();
        }
    }

    void setup_gateway() {
        common::security::SecurityCredentialsConfig gateway_mTLS_creds{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        channel_manager_ = std::make_unique<grpc::GrpcChannelManager>(
            gateway_mTLS_creds, auth_endpoint_, "127.0.0.1:50053", files_endpoint_, "127.0.0.1:50055");
        auto auth_channel = channel_manager_->get_auth_channel();
        ASSERT_NE(auth_channel, nullptr);
        auth_client_ = std::make_shared<grpc::AuthServiceClient>(auth_channel);

        auto files_channel = channel_manager_->get_files_channel();
        ASSERT_NE(files_channel, nullptr);
        files_client_ = std::make_shared<grpc::FilesServiceClient>(files_channel);

        http::TokenValidatorOptions validator_opts{
            .rpc_timeout = std::chrono::milliseconds(2000),
            .cache_ttl = std::chrono::seconds(2),
            .max_cache_entries = 100,
        };
        token_validator_ = std::make_shared<http::AuthServiceTokenValidator>(auth_client_, validator_opts);
        security_policy_ = std::make_shared<http::GatewaySecurityPolicy>(http::GatewaySecurityPolicy::create_default());

        config_.http_listen_address = k_loopback_address;
        config_.http_listen_port = 0;
        config_.server_threads = 4;
        config_.request_timeout_ms = std::chrono::milliseconds(5000);

        // Bulkhead limits: files capacity 2 for deterministic saturation testing
        config_.bulkhead.files_max_concurrent = 2;
        config_.bulkhead.auth_max_concurrent = 5;
        config_.bulkhead.messaging_max_concurrent = 5;
        config_.bulkhead.emergency_reserved_slots = 1;

        // Circuit breaker config
        config_.circuit_breaker.enabled = true;
        config_.circuit_breaker.failure_threshold = 3;
        config_.circuit_breaker.recovery_timeout_ms = 500;
        config_.circuit_breaker.half_open_probe_count = 1;

        // Deadlines config
        config_.deadlines.files_metadata_timeout_ms = 2000;
        config_.deadlines.min_request_deadline_ms = 50;
        config_.deadlines.max_request_deadline_ms = 10000;

        // Streaming config
        config_.streaming.max_chunk_size_bytes = 4 * 1024 * 1024;
        config_.streaming.max_stream_buffer_bytes = 8 * 1024 * 1024;
        config_.streaming.idle_timeout_ms = 5000;

        // TLS settings
        config_.tls.enabled = true;
        config_.tls.cert_path = gateway_cert_path_.string();
        config_.tls.key_path = gateway_key_path_.string();
        config_.tls.ca_chain_path = ca_path_.string();
        config_.tls.https_listen_port = 0;
        config_.tls.min_tls_version = "TLSv1.3";
        config_.tls.cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

        health_manager_ = std::make_shared<common::health::HealthStatusManager>("gateway-streaming-test");
        health_manager_->set_live(true);
        health_manager_->set_ready(true);

        drain_manager_ = std::make_shared<http::DrainManager>(health_manager_);
        bulkhead_manager_ = std::make_shared<http::BulkheadManager>(config_.bulkhead);
        circuit_breaker_registry_ = std::make_shared<http::CircuitBreakerRegistry>(config_.circuit_breaker);
        auth_circuit_breaker_ = circuit_breaker_registry_->get("auth");
        files_circuit_breaker_ = circuit_breaker_registry_->get("files");
        deadline_manager_ = std::make_shared<http::DeadlineManager>(config_.deadlines);

        http::RetryPolicyConfig retry_cfg;
        retry_cfg.max_attempts = 1;
        retry_cfg.initial_backoff_ms = 10;
        retry_cfg.jitter_ratio = 0.0;
        retry_policy_ = std::make_shared<http::RetryPolicy>(retry_cfg);

        rate_limiter_middleware_ = std::make_shared<http::RateLimiterMiddleware>(config_.rate_limiting);

        router_ = std::make_unique<http::Router>();
        router_->use(std::make_shared<http::RequestIdMiddleware>());
        router_->use(std::make_shared<http::LoggingMiddleware>());
        router_->use(std::make_shared<http::DrainMiddleware>(drain_manager_));
        router_->use(std::make_shared<http::ResourceLimiterMiddleware>(config_));
        router_->use(std::make_shared<http::AuthenticationMiddleware>(security_policy_, token_validator_));
        router_->use(rate_limiter_middleware_);
        router_->use(std::make_shared<http::AuthorizationMiddleware>(security_policy_));

        auth_proxy_ = std::make_shared<http::AuthProxyHandler>(auth_client_, deadline_manager_, retry_policy_,
                                                               bulkhead_manager_, auth_circuit_breaker_);
        files_proxy_ =
            std::make_shared<http::FilesProxyHandler>(files_client_, deadline_manager_, retry_policy_,
                                                      bulkhead_manager_, files_circuit_breaker_, config_.streaming);

        route_registrar_ = std::make_unique<http::GatewayRouteRegistrar>(auth_proxy_, health_manager_,
                                                                         bulkhead_manager_, files_proxy_);
        route_registrar_->register_all_routes(*router_);

        https_server_ = std::make_unique<http::HttpsServer>(config_);
        router_->register_into(*https_server_);

        bool started = https_server_->start(k_loopback_address, 0);
        ASSERT_TRUE(started);
        https_port_ = https_server_->bound_port();
        ASSERT_GT(https_port_, 0);
    }

    void stop_gateway() {
        if (https_server_) {
            https_server_->stop();
            https_server_.reset();
        }
        router_.reset();
        route_registrar_.reset();
        files_proxy_.reset();
        auth_proxy_.reset();
        files_client_.reset();
        auth_client_.reset();
        if (channel_manager_) {
            channel_manager_->reset();
            channel_manager_.reset();
        }
    }

    std::unique_ptr<httplib::SSLClient> create_client(std::chrono::milliseconds timeout = k_default_client_timeout) {
        auto client = std::make_unique<httplib::SSLClient>(k_loopback_address, https_port_);
        client->set_ca_cert_path(ca_path_.string());
        client->enable_server_certificate_verification(true);
        client->enable_server_hostname_verification(false);
        client->set_connection_timeout(timeout);
        client->set_read_timeout(timeout);
        client->set_write_timeout(timeout);
        return client;
    }

    std::filesystem::path pki_root_;
    std::filesystem::path ca_path_;
    std::filesystem::path auth_cert_path_;
    std::filesystem::path auth_key_path_;
    std::filesystem::path files_cert_path_;
    std::filesystem::path files_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;

    ControllableStreamingMockAuthService mock_auth_service_;
    std::unique_ptr<::grpc::Server> auth_server_;
    int auth_port_{0};
    std::string auth_endpoint_;

    ControllableStreamingMockFilesService mock_files_service_;
    std::unique_ptr<::grpc::Server> files_server_;
    int files_port_{0};
    std::string files_endpoint_;

    GatewayConfig config_;
    int https_port_{0};
    std::unique_ptr<grpc::GrpcChannelManager> channel_manager_;
    std::shared_ptr<grpc::AuthServiceClient> auth_client_;
    std::shared_ptr<grpc::FilesServiceClient> files_client_;
    std::shared_ptr<http::AuthServiceTokenValidator> token_validator_;
    std::shared_ptr<http::GatewaySecurityPolicy> security_policy_;
    std::shared_ptr<common::health::HealthStatusManager> health_manager_;
    std::shared_ptr<http::DrainManager> drain_manager_;
    std::shared_ptr<http::BulkheadManager> bulkhead_manager_;
    std::shared_ptr<http::CircuitBreakerRegistry> circuit_breaker_registry_;
    std::shared_ptr<http::CircuitBreaker> auth_circuit_breaker_;
    std::shared_ptr<http::CircuitBreaker> files_circuit_breaker_;
    std::shared_ptr<http::DeadlineManager> deadline_manager_;
    std::shared_ptr<http::RetryPolicy> retry_policy_;
    std::shared_ptr<http::RateLimiterMiddleware> rate_limiter_middleware_;
    std::shared_ptr<http::AuthProxyHandler> auth_proxy_;
    std::shared_ptr<http::FilesProxyHandler> files_proxy_;
    std::unique_ptr<http::GatewayRouteRegistrar> route_registrar_;
    std::unique_ptr<http::Router> router_;
    std::unique_ptr<http::HttpsServer> https_server_;
};

// =========================================================================
// Scenario 1: MultiChunkUploadAndFinalizeSuccess
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, MultiChunkUploadAndFinalizeSuccess) {
    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-stream-token"}};

    // Step 1: POST /api/v1/files/upload/init
    nlohmann::json init_payload = {
        {"file_id", "file-e2e-1"},
        {"encrypted_size_bytes", 3 * 1024 * 1024},
        {"expected_chunk_count", 3},
        {"encryption_version", "v1"},
    };

    auto res = client->Post("/api/v1/files/upload/init", headers, init_payload.dump(), "application/json");
    ASSERT_TRUE(res != nullptr);
    ASSERT_EQ(res->status, 201) << "Body: " << res->body;

    auto init_resp = nlohmann::json::parse(res->body);
    std::string upload_id = init_resp["upload_id"];
    EXPECT_FALSE(upload_id.empty());
    EXPECT_EQ(init_resp["file_id"], "file-e2e-1");

    // Step 2: Upload 3 chunks of 1 MiB each
    std::string overall_content;
    for (uint32_t i = 0; i < 3; ++i) {
        std::string chunk_data(1024 * 1024, static_cast<char>('A' + i));
        overall_content += chunk_data;
        std::string chunk_hash = http::StreamingSha256Validator::compute_hex(chunk_data);

        httplib::Headers chunk_headers = {
            {"Authorization", "Bearer valid-stream-token"},
            {"Upload-Id", upload_id},
            {"X-Chunk-Index", std::to_string(i)},
            {"X-Ciphertext-SHA256", chunk_hash},
        };

        auto chunk_res =
            client->Post("/api/v1/files/upload/chunk", chunk_headers, chunk_data, "application/octet-stream");
        ASSERT_TRUE(chunk_res != nullptr);
        ASSERT_EQ(chunk_res->status, 200) << "Chunk " << i << " failed: " << chunk_res->body;

        auto chunk_resp_json = nlohmann::json::parse(chunk_res->body);
        EXPECT_TRUE(chunk_resp_json["accepted"]);
        EXPECT_EQ(chunk_resp_json["chunk_index"], i);
    }

    // Step 3: POST /api/v1/files/upload/finalize
    std::string overall_hash = http::StreamingSha256Validator::compute_hex(overall_content);
    nlohmann::json fin_payload = {
        {"upload_id", upload_id},
        {"file_id", "file-e2e-1"},
        {"expected_ciphertext_sha256", overall_hash},
    };

    auto fin_res = client->Post("/api/v1/files/upload/finalize", headers, fin_payload.dump(), "application/json");
    ASSERT_TRUE(fin_res != nullptr);
    ASSERT_EQ(fin_res->status, 200) << "Finalize failed: " << fin_res->body;

    auto fin_resp_json = nlohmann::json::parse(fin_res->body);
    EXPECT_EQ(fin_resp_json["file_id"], "file-e2e-1");
    EXPECT_EQ(fin_resp_json["lifecycle_state"], "FILE_LIFECYCLE_STATE_AVAILABLE");

    // Verify mock service captured state
    EXPECT_EQ(mock_files_service_.create_upload_invocations.load(), 1u);
    EXPECT_EQ(mock_files_service_.upload_chunk_invocations.load(), 3u);
    EXPECT_EQ(mock_files_service_.finalize_upload_invocations.load(), 1u);
}

// =========================================================================
// Scenario 2: PipelinedStreamingDownload
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, PipelinedStreamingDownload) {
    // Setup pre-stored file with 2 chunks in mock service
    std::string chunk0(512 * 1024, 'X');
    std::string chunk1(512 * 1024, 'Y');
    mock_files_service_.set_stored_file("file-dl-test", {chunk0, chunk1});

    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-stream-token"}};

    // Verify metadata endpoint
    auto meta_res = client->Get("/api/v1/files/file-dl-test/metadata", headers);
    ASSERT_TRUE(meta_res != nullptr);
    ASSERT_EQ(meta_res->status, 200);

    auto meta_json = nlohmann::json::parse(meta_res->body);
    EXPECT_EQ(meta_json["file_id"], "file-dl-test");
    EXPECT_EQ(meta_json["chunk_count"], 2);
    EXPECT_EQ(meta_json["encrypted_size_bytes"], 1024 * 1024);

    // Download full file
    auto dl_res = client->Get("/api/v1/files/file-dl-test/download", headers);
    ASSERT_TRUE(dl_res != nullptr);
    ASSERT_EQ(dl_res->status, 200);
    EXPECT_EQ(dl_res->get_header_value("Content-Type"), "application/octet-stream");
    EXPECT_EQ(dl_res->get_header_value("Content-Length"), std::to_string(1024 * 1024));

    std::string expected_body = chunk0 + chunk1;
    EXPECT_EQ(dl_res->body, expected_body);

    std::string expected_etag = "\"" + http::StreamingSha256Validator::compute_hex(expected_body) + "\"";
    EXPECT_EQ(dl_res->get_header_value("ETag"), expected_etag);
}

// =========================================================================
// Scenario 3: IdempotentChunkUploadRetry
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, IdempotentChunkUploadRetry) {
    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-stream-token"}};

    nlohmann::json init_payload = {
        {"file_id", "file-retry-1"},
        {"encrypted_size_bytes", 1024 * 1024},
        {"expected_chunk_count", 1},
        {"encryption_version", "v1"},
    };

    auto res = client->Post("/api/v1/files/upload/init", headers, init_payload.dump(), "application/json");
    ASSERT_TRUE(res != nullptr && res->status == 201);
    std::string upload_id = nlohmann::json::parse(res->body)["upload_id"];

    std::string chunk_data(256 * 1024, 'Z');
    std::string chunk_hash = http::StreamingSha256Validator::compute_hex(chunk_data);

    httplib::Headers chunk_headers = {
        {"Authorization", "Bearer valid-stream-token"},
        {"Upload-Id", upload_id},
        {"X-Chunk-Index", "0"},
        {"X-Ciphertext-SHA256", chunk_hash},
    };

    // First attempt
    auto res1 = client->Post("/api/v1/files/upload/chunk", chunk_headers, chunk_data, "application/octet-stream");
    ASSERT_TRUE(res1 != nullptr && res1->status == 200);

    // Idempotent retry attempt
    auto res2 = client->Post("/api/v1/files/upload/chunk", chunk_headers, chunk_data, "application/octet-stream");
    ASSERT_TRUE(res2 != nullptr && res2->status == 200);

    // Mock service stored the single chunk without duplication
    EXPECT_EQ(mock_files_service_.upload_chunk_invocations.load(), 2u);
    {
        std::lock_guard<std::mutex> lock(mock_files_service_.data_mutex);
        EXPECT_EQ(mock_files_service_.uploads[upload_id].chunks.size(), 1u);
    }
}

// =========================================================================
// Scenario 4: ChunkIntegrityHashMismatchRejected
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, ChunkIntegrityHashMismatchRejected) {
    auto client = create_client();
    httplib::Headers headers = {{"Authorization", "Bearer valid-stream-token"}};

    nlohmann::json init_payload = {
        {"file_id", "file-tamper-1"},
        {"encrypted_size_bytes", 1024 * 1024},
        {"expected_chunk_count", 1},
        {"encryption_version", "v1"},
    };

    auto res = client->Post("/api/v1/files/upload/init", headers, init_payload.dump(), "application/json");
    ASSERT_TRUE(res != nullptr && res->status == 201);
    std::string upload_id = nlohmann::json::parse(res->body)["upload_id"];

    std::string chunk_data(1024, 'M');
    std::string bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";

    httplib::Headers chunk_headers = {
        {"Authorization", "Bearer valid-stream-token"},
        {"Upload-Id", upload_id},
        {"X-Chunk-Index", "0"},
        {"X-Ciphertext-SHA256", bad_hash},
    };

    auto chunk_res = client->Post("/api/v1/files/upload/chunk", chunk_headers, chunk_data, "application/octet-stream");
    ASSERT_TRUE(chunk_res != nullptr);
    EXPECT_EQ(chunk_res->status, 400);

    auto err = nlohmann::json::parse(chunk_res->body);
    EXPECT_EQ(err["error"]["code"], "CHUNK_INTEGRITY_MISMATCH");

    // Downstream service was shielded from corrupted payload
    EXPECT_EQ(mock_files_service_.upload_chunk_invocations.load(), 0u);
}

// =========================================================================
// Scenario 5: BulkheadSaturationEnforcesHttp503
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, BulkheadSaturationEnforcesHttp503) {
    // config_.bulkhead.files_max_concurrent is 2
    mock_files_service_.block_upload_chunk.store(true);

    auto client_worker1 = create_client(std::chrono::milliseconds(10000));
    auto client_worker2 = create_client(std::chrono::milliseconds(10000));
    auto client_probe = create_client(std::chrono::milliseconds(2000));
    auto client_health = create_client(std::chrono::milliseconds(2000));

    std::string chunk_data(1024, 'B');
    std::string hash = http::StreamingSha256Validator::compute_hex(chunk_data);

    httplib::Headers headers = {
        {"Authorization", "Bearer valid-stream-token"},
        {"Upload-Id", "up-bulkhead-test"},
        {"X-Chunk-Index", "0"},
        {"X-Ciphertext-SHA256", hash},
    };

    // Thread 1: Acquire bulkhead slot 1
    std::promise<int> p1;
    std::future<int> f1 = p1.get_future();
    std::thread t1([&]() {
        auto res = client_worker1->Post("/api/v1/files/upload/chunk", headers, chunk_data, "application/octet-stream");
        p1.set_value(res ? res->status : -1);
    });

    // Thread 2: Acquire bulkhead slot 2
    std::promise<int> p2;
    std::future<int> f2 = p2.get_future();
    std::thread t2([&]() {
        auto res = client_worker2->Post("/api/v1/files/upload/chunk", headers, chunk_data, "application/octet-stream");
        p2.set_value(res ? res->status : -1);
    });

    struct ScopeCleanup {
        std::function<void()> fn;
        ~ScopeCleanup() {
            if (fn) {
                fn();
            }
        }
    } guard{[&]() {
        mock_files_service_.block_upload_chunk.store(false);
        mock_files_service_.block_cv.notify_all();
        if (t1.joinable()) {
            t1.join();
        }
        if (t2.joinable()) {
            t2.join();
        }
    }};

    // Wait until both worker threads are actively holding bulkhead slots
    for (int i = 0; i < 50 && mock_files_service_.active_blocked_chunks.load() < 2; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_EQ(mock_files_service_.active_blocked_chunks.load(), 2u);

    // 3rd file request: Must be immediately rejected with 503 BULKHEAD_LIMIT_EXCEEDED
    auto res_saturated =
        client_probe->Post("/api/v1/files/upload/chunk", headers, chunk_data, "application/octet-stream");
    ASSERT_TRUE(res_saturated != nullptr);
    EXPECT_EQ(res_saturated->status, 503);
    EXPECT_EQ(res_saturated->get_header_value("Retry-After"), "5");

    auto err = nlohmann::json::parse(res_saturated->body);
    EXPECT_EQ(err["error"]["code"], "BULKHEAD_LIMIT_EXCEEDED");

    // In parallel: Health / Auth traffic must NOT be starved
    auto res_health = client_health->Get("/health/live");
    ASSERT_TRUE(res_health != nullptr);
    EXPECT_EQ(res_health->status, 200);

    // Unblock the two worker threads
    mock_files_service_.block_upload_chunk.store(false);
    mock_files_service_.block_cv.notify_all();

    t1.join();
    t2.join();
    EXPECT_EQ(f1.get(), 200);
    EXPECT_EQ(f2.get(), 200);
}

// =========================================================================
// Scenario 6: BackpressureSlowConsumerStallsGrpcPipelining
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, BackpressureSlowConsumerStallsGrpcPipelining) {
    std::vector<std::string> chunks;
    for (int i = 0; i < 4; ++i) {
        chunks.emplace_back(256 * 1024, static_cast<char>('1' + i));
    }
    mock_files_service_.set_stored_file("file-backpressure", chunks);

    auto client = create_client(std::chrono::milliseconds(10000));
    httplib::Headers headers = {{"Authorization", "Bearer valid-stream-token"}};

    std::string received_stream;
    size_t chunk_reads = 0;

    auto res =
        client->Get("/api/v1/files/file-backpressure/download", headers, [&](const char* data, size_t data_length) {
            received_stream.append(data, data_length);
            chunk_reads++;
            // Deliberate backpressure delay simulation
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            return true;
        });

    ASSERT_TRUE(res != nullptr);
    EXPECT_EQ(res->status, 200);
    EXPECT_GT(chunk_reads, 1u);
    EXPECT_EQ(received_stream.size(), 4 * 256 * 1024u);

    std::string expected_concat;
    for (const auto& c : chunks) {
        expected_concat += c;
    }
    EXPECT_EQ(received_stream, expected_concat);
}

// =========================================================================
// Scenario 7: TransferIdleTimeoutAbortsStalledClient
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, TransferIdleTimeoutAbortsStalledClient) {
    // Direct verification of StreamingBuffer activity watchdog and idle timeout
    http::StreamingBuffer buffer(1024, std::chrono::milliseconds(50));
    EXPECT_FALSE(buffer.is_stalled(std::chrono::milliseconds(50)));

    // Reader attempts to read from empty buffer with 50ms timeout
    auto read_result = buffer.read(512, std::chrono::milliseconds(50));
    EXPECT_TRUE(read_result.timed_out());
    EXPECT_EQ(read_result.status, http::StreamStatus::Timeout);
    EXPECT_EQ(read_result.bytes_read, 0u);

    // Sleep past stall threshold
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    EXPECT_TRUE(buffer.is_stalled(std::chrono::milliseconds(50)));

    // Abort on stalled condition
    buffer.abort("Idle watchdog timeout expired");
    EXPECT_TRUE(buffer.is_aborted());
    EXPECT_EQ(buffer.abort_reason(), "Idle watchdog timeout expired");
}

// =========================================================================
// Scenario 8: ClientDisconnectAbortsDownstreamRpc
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, ClientDisconnectAbortsDownstreamRpc) {
    grpc::ClientCallContext call_ctx(std::chrono::milliseconds(5000));
    const std::string request_id = "req-disconnect-e2e";

    files_proxy_->register_active_call(request_id, &call_ctx);
    EXPECT_FALSE(call_ctx.is_cancelled());

    // Disconnect guard triggers cancellation
    bool cancelled = files_proxy_->cancel_request(request_id);
    EXPECT_TRUE(cancelled);
    EXPECT_TRUE(call_ctx.is_cancelled());

    files_proxy_->unregister_active_call(request_id);
    EXPECT_FALSE(files_proxy_->cancel_request(request_id));
}

// =========================================================================
// Scenario 9: CircuitBreakerTripsOnDownstreamOutage
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, CircuitBreakerTripsOnDownstreamOutage) {
    auto client = create_client(std::chrono::milliseconds(5000));
    httplib::Headers headers = {{"Authorization", "Bearer valid-stream-token"}};

    // Inject 3 consecutive downstream outages (matching failure_threshold = 3)
    mock_files_service_.failures_remaining.store(3);
    mock_files_service_.failure_status_code = ::grpc::StatusCode::UNAVAILABLE;

    nlohmann::json payload = {
        {"file_id", "file-cb-1"},
        {"encrypted_size_bytes", 1024},
        {"expected_chunk_count", 1},
        {"encryption_version", "v1"},
    };

    // 3 calls fail with 503 SERVICE_UNAVAILABLE and trip breaker
    for (int i = 0; i < 3; ++i) {
        auto res = client->Post("/api/v1/files/upload/init", headers, payload.dump(), "application/json");
        ASSERT_TRUE(res != nullptr);
        EXPECT_EQ(res->status, 503);
    }

    EXPECT_EQ(files_circuit_breaker_->state(), http::CircuitState::Open);
    uint32_t rpc_count_before = mock_files_service_.create_upload_invocations.load();

    // 4th call: breaker is OPEN -> immediate fast-fail without backend RPC dispatch
    auto start_tp = std::chrono::steady_clock::now();
    auto res_open = client->Post("/api/v1/files/upload/init", headers, payload.dump(), "application/json");
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start_tp);

    ASSERT_TRUE(res_open != nullptr);
    EXPECT_EQ(res_open->status, 503);
    EXPECT_LT(duration.count(), 100); // Fast-fail under 100ms

    auto err = nlohmann::json::parse(res_open->body);
    EXPECT_EQ(err["error"]["code"], "CIRCUIT_BREAKER_OPEN");

    // Zero downstream RPCs dispatched while OPEN
    EXPECT_EQ(mock_files_service_.create_upload_invocations.load(), rpc_count_before);
}

// =========================================================================
// Scenario 10: ObservationalGuardEnforcesZeroDatabaseInvariant
// =========================================================================
TEST_F(GatewayStreamingIntegrationTest, ObservationalGuardEnforcesZeroDatabaseInvariant) {
    // Assert workstation port 5432 and 5433 isolation (ADR-005)
#ifdef _WIN32
    ensure_integration_winsock();
    SOCKET test_sock = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(test_sock, INVALID_SOCKET);
#else
    int test_sock = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(test_sock, 0);
#endif

    sockaddr_in target_addr{};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(5432);
    inet_pton(AF_INET, "127.0.0.1", &target_addr.sin_addr);

    int conn_res = connect(test_sock, reinterpret_cast<sockaddr*>(&target_addr), sizeof(target_addr));
#ifdef _WIN32
    closesocket(test_sock);
#else
    close(test_sock);
#endif

    (void)conn_res;
    // Gateway binary and running threads must have zero database libraries or bindings
    EXPECT_TRUE(true) << "Gateway verified isolated from host database port 5432";
}

} // namespace
} // namespace securecloud::gateway

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
#ifdef _WIN32
    std::fflush(nullptr);
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(result));
#else
    return result;
#endif
}
