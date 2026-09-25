#include "files/db/files_connection_pool.hpp"
#include "files/files_config.hpp"
#include "files/health/files_health_evaluator.hpp"
#include "files/service/files_service_impl.hpp"
#include "files/storage/s3_client.hpp"
#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/health/health_service_impl.hpp"
#include "securecloud/health/health_status_manager.hpp"
#include "securecloud/health/transport_probe.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on
#ifdef DeleteFile
#undef DeleteFile
#endif
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace securecloud::files {
namespace {

using common::health::HealthServiceImpl;
using common::health::HealthStatusManager;
using common::health::probe_tcp_connectivity;
using common::security::MtlsCredentialLoader;
using common::security::SecurityCredentialsConfig;

#ifdef _WIN32
using socket_handle_t = SOCKET;
constexpr socket_handle_t k_invalid_socket = INVALID_SOCKET;

inline void close_socket_handle(socket_handle_t s) noexcept {
    if (s != INVALID_SOCKET) {
        linger l{1, 0};
        ::setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&l), sizeof(l));
        ::closesocket(s);
    }
}

inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}

using socklen_val_t = int;
#else
using socket_handle_t = int;
constexpr socket_handle_t k_invalid_socket = -1;

inline void close_socket_handle(socket_handle_t s) noexcept {
    if (s >= 0) {
        ::close(s);
    }
}

inline void ensure_integration_winsock() noexcept {}

using socklen_val_t = socklen_t;
#endif

constexpr int k_listen_backlog = 5;
constexpr std::chrono::milliseconds k_test_probe_timeout{250};
constexpr std::chrono::milliseconds k_server_shutdown_timeout{500};
constexpr std::chrono::seconds k_rpc_deadline{2};

/// RAII helper managing an ephemeral listening TCP socket for probing.
class ScopedTcpListener {
  public:
    ScopedTcpListener() {
        ensure_integration_winsock();
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ == k_invalid_socket) {
            return;
        }

#ifndef _WIN32
        int opt = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            stop();
            return;
        }

        if (::listen(listen_fd_, k_listen_backlog) != 0) {
            stop();
            return;
        }

        socklen_val_t len = sizeof(addr);
        if (::getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &len) == 0) {
            port_ = ntohs(addr.sin_port);
        }
    }

    ~ScopedTcpListener() noexcept { stop(); }

    ScopedTcpListener(const ScopedTcpListener&) = delete;
    ScopedTcpListener& operator=(const ScopedTcpListener&) = delete;
    ScopedTcpListener(ScopedTcpListener&&) = delete;
    ScopedTcpListener& operator=(ScopedTcpListener&&) = delete;

    void stop() noexcept {
        if (listen_fd_ != k_invalid_socket) {
            close_socket_handle(listen_fd_);
            listen_fd_ = k_invalid_socket;
        }
    }

    [[nodiscard]] uint16_t port() const noexcept { return port_; }
    [[nodiscard]] bool is_listening() const noexcept { return listen_fd_ != k_invalid_socket; }

  private:
    socket_handle_t listen_fd_{k_invalid_socket};
    uint16_t port_{0};
};

class FilesIntegrationTest : public ::testing::Test {
  protected:
    static std::filesystem::path find_pki_root() {
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

        auto pki_root = find_pki_root();
        ca_path_ = pki_root / "ca" / "ca.crt";
        files_cert_path_ = pki_root / "services" / "files" / "files.crt";
        files_key_path_ = pki_root / "services" / "files" / "files.key";
        gateway_cert_path_ = pki_root / "services" / "gateway" / "gateway.crt";
        gateway_key_path_ = pki_root / "services" / "gateway" / "gateway.key";
        audit_cert_path_ = pki_root / "services" / "audit" / "audit.crt";
        audit_key_path_ = pki_root / "services" / "audit" / "audit.key";

        const std::vector<std::filesystem::path> required_paths = {
            ca_path_,          files_cert_path_, files_key_path_, gateway_cert_path_,
            gateway_key_path_, audit_cert_path_, audit_key_path_};

        for (const auto& path : required_paths) {
            ASSERT_TRUE(std::filesystem::exists(path)) << "Required dev PKI credential missing: " << path;
        }

        files_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = files_cert_path_,
            .service_key_path = files_key_path_,
        };

        gateway_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = gateway_cert_path_,
            .service_key_path = gateway_key_path_,
        };

        audit_config_ = SecurityCredentialsConfig{
            .ca_cert_path = ca_path_,
            .service_cert_path = audit_cert_path_,
            .service_key_path = audit_key_path_,
        };

        // Initialize mock/noop pool and client for FilesServiceImpl
        db::ConnectionPoolConfig db_cfg;
        db_cfg.host = "127.0.0.1";
        db_cfg.port = 5433;
        db_pool_ = std::make_shared<db::FilesDbConnectionPool>(db_cfg);

        storage::S3ClientConfig s3_cfg;
        s3_cfg.endpoint = "http://127.0.0.1:9000";
        s3_cfg.bucket = "securecloud-files-encrypted";
        s3_cfg.access_key = "minio_admin";
        s3_cfg.secret_key = common::configuration::SecretString("minio_admin_secret");
        s3_client_ = std::make_shared<storage::S3Client>(s3_cfg);
    }

    struct RunningServer {
        std::unique_ptr<grpc::Server> server;
        std::string address;
    };

    RunningServer start_files_mtls_server(service::FilesServiceImpl* files_svc, HealthServiceImpl* health_svc) {
        auto server_creds = MtlsCredentialLoader::create_server_credentials(files_config_);
        EXPECT_NE(server_creds, nullptr);

        grpc::ServerBuilder builder;
        int selected_port = 0;
        builder.AddListeningPort("127.0.0.1:0", server_creds, &selected_port);
        if (files_svc) {
            builder.RegisterService(files_svc);
        }
        if (health_svc) {
            builder.RegisterService(health_svc);
        }

        auto server = builder.BuildAndStart();
        EXPECT_NE(server, nullptr);
        EXPECT_GT(selected_port, 0);

        std::string server_address = "127.0.0.1:" + std::to_string(selected_port);
        return RunningServer{std::move(server), server_address};
    }

    void shutdown_server(RunningServer& rs) {
        if (rs.server) {
            rs.server->Shutdown(std::chrono::system_clock::now() + k_server_shutdown_timeout);
            rs.server.reset();
        }
    }

    std::filesystem::path ca_path_;
    std::filesystem::path files_cert_path_;
    std::filesystem::path files_key_path_;
    std::filesystem::path gateway_cert_path_;
    std::filesystem::path gateway_key_path_;
    std::filesystem::path audit_cert_path_;
    std::filesystem::path audit_key_path_;

    SecurityCredentialsConfig files_config_;
    SecurityCredentialsConfig gateway_config_;
    SecurityCredentialsConfig audit_config_;

    std::shared_ptr<db::FilesDbConnectionPool> db_pool_;
    std::shared_ptr<storage::S3Client> s3_client_;
};

// Test 1: Service starts with valid mTLS certificates (files.crt, files.key, ca.crt)
TEST_F(FilesIntegrationTest, ServiceStartsSuccessfullyWithValidMtlsCredentials) {
    HealthStatusManager health_manager("files");
    health_manager.set_live(true);
    HealthServiceImpl health_service("files", health_manager);
    service::FilesServiceImpl files_service(db_pool_, s3_client_, "gateway");

    auto running = start_files_mtls_server(&files_service, &health_service);
    EXPECT_NE(running.server, nullptr);
    EXPECT_FALSE(running.address.empty());

    shutdown_server(running);
}

// Test 2: In-process client with Gateway identity (gateway.crt) establishes mTLS channel
TEST_F(FilesIntegrationTest, GatewayClientEstablishesMtlsChannelSuccessfully) {
    HealthStatusManager health_manager("files");
    health_manager.set_live(true);
    health_manager.set_ready(true);
    HealthServiceImpl health_service("files", health_manager, "gateway");
    service::FilesServiceImpl files_service(db_pool_, s3_client_, "gateway");

    auto running = start_files_mtls_server(&files_service, &health_service);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "files");
    auto stub = common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    common::v1::HealthCheckRequest req;
    common::v1::HealthCheckResponse resp;

    grpc::Status status = stub->Check(&context, req, &resp);
    EXPECT_TRUE(status.ok()) << "mTLS handshake failed: " << status.error_message();
    EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);

    shutdown_server(running);
}

// Test 3: Unauthenticated or untrusted clients are rejected at TLS handshake / authorization
TEST_F(FilesIntegrationTest, RejectsUnauthenticatedOrUntrustedMtlsCallers) {
    HealthStatusManager health_manager("files");
    health_manager.set_live(true);
    health_manager.set_ready(true);
    HealthServiceImpl health_service("files", health_manager, "gateway");
    service::FilesServiceImpl files_service(db_pool_, s3_client_, "gateway");

    auto running = start_files_mtls_server(&files_service, &health_service);

    // 3a. Insecure/plaintext channel rejected at TLS layer
    {
        auto insecure_channel = grpc::CreateChannel(running.address, grpc::InsecureChannelCredentials());
        auto stub = common::v1::HealthService::NewStub(insecure_channel);

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(500));
        common::v1::HealthCheckRequest req;
        common::v1::HealthCheckResponse resp;

        grpc::Status status = stub->Check(&context, req, &resp);
        EXPECT_FALSE(status.ok()) << "Plaintext call unexpectedly succeeded against mTLS server";
        EXPECT_EQ(status.error_code(), grpc::StatusCode::UNAVAILABLE);
    }

    // 3b. Unauthorized peer service identity (audit identity instead of gateway) rejected
    {
        auto audit_channel = MtlsCredentialLoader::create_mtls_channel(running.address, audit_config_, "files");
        auto files_stub = v1::FilesService::NewStub(audit_channel);

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::CreateFileUploadRequest req;
        v1::CreateFileUploadResponse resp;

        grpc::Status status = files_stub->CreateFileUpload(&context, req, &resp);
        EXPECT_FALSE(status.ok());
        EXPECT_EQ(status.error_code(), grpc::StatusCode::PERMISSION_DENIED);
        EXPECT_NE(status.error_message().find("Caller peer identity not authorized"), std::string::npos);
    }

    shutdown_server(running);
}

// Test 4: All 7 RPCs return deterministic grpc::StatusCode::UNIMPLEMENTED
TEST_F(FilesIntegrationTest, AllSevenRpcMethodsReturnDeterministicUnimplemented) {
    HealthStatusManager health_manager("files");
    health_manager.set_live(true);
    health_manager.set_ready(true);
    service::FilesServiceImpl files_service(db_pool_, s3_client_, "gateway");

    auto running = start_files_mtls_server(&files_service, nullptr);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "files");
    auto stub = v1::FilesService::NewStub(channel);

    const std::string expected_msg = "FilesService method not implemented in FILES-001 skeleton";

    // 1. CreateFileUpload
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::CreateFileUploadRequest req;
        v1::CreateFileUploadResponse resp;
        auto st = stub->CreateFileUpload(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    // 2. UploadChunk
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::UploadChunkRequest req;
        v1::UploadChunkResponse resp;
        auto st = stub->UploadChunk(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    // 3. FinalizeFileUpload
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::FinalizeFileUploadRequest req;
        v1::FinalizeFileUploadResponse resp;
        auto st = stub->FinalizeFileUpload(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    // 4. GetFileMetadata
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::GetFileMetadataRequest req;
        v1::GetFileMetadataResponse resp;
        auto st = stub->GetFileMetadata(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    // 5. DownloadChunk
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::DownloadChunkRequest req;
        v1::DownloadChunkResponse resp;
        auto st = stub->DownloadChunk(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    // 6. CancelFileUpload
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::CancelFileUploadRequest req;
        v1::CancelFileUploadResponse resp;
        auto st = stub->CancelFileUpload(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    // 7. DeleteFile
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        v1::DeleteFileRequest req;
        v1::DeleteFileResponse resp;
        auto st = stub->DeleteFile(&ctx, req, &resp);
        EXPECT_EQ(st.error_code(), grpc::StatusCode::UNIMPLEMENTED);
        EXPECT_EQ(st.error_message(), expected_msg);
    }

    shutdown_server(running);
}

// Test 5: Readiness check returns SERVING when PostgreSQL (5433) and MinIO (9000) are reachable
TEST_F(FilesIntegrationTest, ReadinessReturnsServingWhenBothDependenciesHealthy) {
    ScopedTcpListener db_listener;
    ScopedTcpListener s3_listener;
    ASSERT_TRUE(db_listener.is_listening());
    ASSERT_TRUE(s3_listener.is_listening());

    const uint16_t db_port = db_listener.port();
    const uint16_t s3_port = s3_listener.port();

    HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    health::FilesHealthEvaluatorConfig eval_cfg;
    eval_cfg.check_interval = std::chrono::milliseconds(20);
    eval_cfg.probe_timeout = k_test_probe_timeout;
    eval_cfg.auto_start = false;

    health::FilesHealthEvaluator health_evaluator(
        health_manager, [db_port] { return probe_tcp_connectivity("127.0.0.1", db_port, k_test_probe_timeout); },
        [s3_port] { return probe_tcp_connectivity("127.0.0.1", s3_port, k_test_probe_timeout); }, eval_cfg);

    health_evaluator.evaluate_once();

    HealthServiceImpl health_service("files", health_manager, "gateway");
    auto running = start_files_mtls_server(nullptr, &health_service);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "files");
    auto stub = common::v1::HealthService::NewStub(channel);

    grpc::ClientContext ctx;
    ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
    common::v1::HealthCheckRequest req;
    req.set_service("readiness");
    common::v1::HealthCheckResponse resp;

    EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
    EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);

    shutdown_server(running);
}

// Test 6: Readiness degrades when MinIO or PostgreSQL port is unreachable while liveness remains SERVING
TEST_F(FilesIntegrationTest, ReadinessDegradesWhenEitherDependencyFailsWhileLivenessRemainsServing) {
    auto db_listener = std::make_unique<ScopedTcpListener>();
    auto s3_listener = std::make_unique<ScopedTcpListener>();
    ASSERT_TRUE(db_listener->is_listening());
    ASSERT_TRUE(s3_listener->is_listening());

    const uint16_t db_port = db_listener->port();
    const uint16_t s3_port = s3_listener->port();

    HealthStatusManager health_manager("files");
    health_manager.set_live(true);

    health::FilesHealthEvaluatorConfig eval_cfg;
    eval_cfg.check_interval = std::chrono::milliseconds(20);
    eval_cfg.probe_timeout = k_test_probe_timeout;
    eval_cfg.auto_start = false;

    health::FilesHealthEvaluator health_evaluator(
        health_manager, [db_port] { return probe_tcp_connectivity("127.0.0.1", db_port, k_test_probe_timeout); },
        [s3_port] { return probe_tcp_connectivity("127.0.0.1", s3_port, k_test_probe_timeout); }, eval_cfg);

    health_evaluator.evaluate_once();

    HealthServiceImpl health_service("files", health_manager, "gateway");
    auto running = start_files_mtls_server(nullptr, &health_service);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "files");
    auto stub = common::v1::HealthService::NewStub(channel);

    // Initial check: SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // Degrade PostgreSQL dependency
    db_listener->stop();
    health_evaluator.evaluate_once();

    // Readiness must degrade to NOT_SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::NOT_SERVING);
    }

    // Liveness must remain SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // Degrade S3 as well
    s3_listener->stop();
    health_evaluator.evaluate_once();

    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::NOT_SERVING);
    }

    shutdown_server(running);
}

// Test 7: Observational Guard check: Asserts test never connects to host port 5432
TEST_F(FilesIntegrationTest, ObservationalGuardEnforcesPort5432Invariant) {
    FilesConfig config;
    config.db_host = "127.0.0.1";
    config.db_port = 5433;

    ASSERT_NE(config.db_port, 5432)
        << "CRITICAL: Tests and Files service must NEVER connect to host PostgreSQL on port 5432!";
    EXPECT_EQ(config.db_port, 5433);

    auto pool_config = db::ConnectionPoolConfig::from_files_config(config);
    ASSERT_NE(pool_config.port, 5432);
    EXPECT_EQ(pool_config.port, 5433);

    // Verify rejection of 5432 at pool creation
    db::ConnectionPoolConfig bad_config = pool_config;
    bad_config.port = 5432;
    EXPECT_THROW({ db::FilesDbConnectionPool bad_pool(bad_config); }, db::PortForbiddenException);
}

// Test 8: Deterministic graceful shutdown completes without memory leaks or deadlocks
TEST_F(FilesIntegrationTest, GracefulShutdownCompletesDeterministically) {
    HealthStatusManager health_manager("files");
    health_manager.set_live(true);
    health_manager.set_ready(true);

    health::FilesHealthEvaluatorConfig eval_cfg;
    eval_cfg.auto_start = true;
    eval_cfg.check_interval = std::chrono::milliseconds(20);

    health::FilesHealthEvaluator health_evaluator(health_manager, [] { return true; }, [] { return true; }, eval_cfg);

    HealthServiceImpl health_service("files", health_manager, "gateway");
    service::FilesServiceImpl files_service(db_pool_, s3_client_, "gateway");

    auto running = start_files_mtls_server(&files_service, &health_service);

    auto channel = MtlsCredentialLoader::create_mtls_channel(running.address, gateway_config_, "files");
    auto stub = common::v1::HealthService::NewStub(channel);

    // 1. Initial healthy state
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // 2. Initiate graceful shutdown
    health_manager.set_shutting_down(true);
    health_evaluator.stop();

    // Readiness immediately drops to NOT_SERVING
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("readiness");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::NOT_SERVING);
    }

    // Liveness remains SERVING during drain
    {
        grpc::ClientContext ctx;
        ctx.set_deadline(std::chrono::system_clock::now() + k_rpc_deadline);
        common::v1::HealthCheckRequest req;
        req.set_service("");
        common::v1::HealthCheckResponse resp;
        EXPECT_TRUE(stub->Check(&ctx, req, &resp).ok());
        EXPECT_EQ(resp.status(), common::v1::HealthCheckResponse::SERVING);
    }

    // 3. Complete shutdown and pool drain
    shutdown_server(running);
    db_pool_->drain();
    db_pool_->close();

    EXPECT_FALSE(health_evaluator.is_running());
}

} // namespace
} // namespace securecloud::files

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
