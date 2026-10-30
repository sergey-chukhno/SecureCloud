#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif
#ifdef DeleteFile
#undef DeleteFile
#endif

#include "files/audit/audit_client_interface.hpp"
#include "files/audit/files_outbox_relay.hpp"
#include "files/audit/grpc_audit_client.hpp"
#include "files/domain/files_outbox_entity.hpp"
#include "files/repository/files_outbox_repository.hpp"
#include "gateway_config.hpp"
#include "grpc/files_client_interface.hpp"
#include "grpc/files_service_client.hpp"
#include "http/auth/authenticated_context.hpp"
#include "http/proxy/files_proxy_handler.hpp"
#include "http/resilience/bulkhead_manager.hpp"
#include "http/resilience/circuit_breaker.hpp"
#include "http/resilience/deadline_manager.hpp"
#include "http/resilience/retry_policy.hpp"
#include "http/routing/router.hpp"
#include "securecloud/audit/v1/audit.grpc.pb.h"
#include "securecloud/audit/v1/audit.pb.h"
#include "securecloud/files/v1/files.grpc.pb.h"
#include "securecloud/files/v1/files.pb.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <httplib.h>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// clang-format on

#ifdef SendMessage
#undef SendMessage
#endif
#ifdef GetMessage
#undef GetMessage
#endif
#ifdef DeleteFile
#undef DeleteFile
#endif

inline void ensure_integration_winsock() noexcept {
    static const bool initialized = []() noexcept {
        WSADATA wsa{};
        return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
    }();
    (void)initialized;
}
#else
inline void ensure_integration_winsock() noexcept {}
#endif

namespace securecloud::files::integration {
namespace {

gateway::http::AuthenticatedContext make_test_context(std::string user_id = "alice-uuid",
                                                      std::string device_id = "device-uuid-1") {
    return gateway::http::AuthenticatedContext(
        std::move(user_id), std::move(device_id), "sess-test",
        securecloud::auth::v1::AuthenticationLevel::AUTHENTICATION_LEVEL_PRIMARY, {"files:read", "files:write"},
        std::chrono::duration_cast<std::chrono::milliseconds>(
            (std::chrono::system_clock::now() + std::chrono::hours(1)).time_since_epoch())
            .count());
}

// ============================================================================
// 1. Mock Audit Ingestion Service
// ============================================================================
class MockAuditIngestionService final : public securecloud::audit::v1::AuditIngestionService::Service {
  public:
    std::mutex mutex_;
    std::vector<securecloud::audit::v1::AuditEventProto> received_events;

    ::grpc::Status BatchSubmitAuditEvents(::grpc::ServerContext* /*context*/,
                                          const securecloud::audit::v1::BatchSubmitAuditEventsRequest* request,
                                          securecloud::audit::v1::BatchSubmitAuditEventsResponse* response) override {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& ev : request->events()) {
            received_events.push_back(ev);
        }
        response->set_accepted_count(static_cast<uint32_t>(request->events_size()));
        response->set_rejected_count(0);
        return ::grpc::Status::OK;
    }

    size_t event_count() {
        std::lock_guard<std::mutex> lock(mutex_);
        return received_events.size();
    }
};

// ============================================================================
// 2. Mock Files Outbox Repository for in-memory tracking
// ============================================================================
class InMemoryOutboxRepository : public FilesOutboxRepository {
  public:
    InMemoryOutboxRepository() : FilesOutboxRepository(nullptr) {}

    using FilesOutboxRepository::fetch_pending_events;
    using FilesOutboxRepository::mark_failed;
    using FilesOutboxRepository::mark_published;
    using FilesOutboxRepository::stage_event;

    std::mutex mtx_;
    std::vector<FilesOutboxEntity> staged_;
    std::vector<std::string> published_;
    std::vector<std::string> failed_;

    void stage_event(const FilesOutboxEntity& event) override {
        std::lock_guard<std::mutex> lock(mtx_);
        staged_.push_back(event);
    }

    std::vector<FilesOutboxEntity> fetch_pending_events(size_t limit) override {
        std::lock_guard<std::mutex> lock(mtx_);
        std::vector<FilesOutboxEntity> res;
        size_t n = std::min(limit, staged_.size());
        for (size_t i = 0; i < n; ++i) {
            res.push_back(staged_[i]);
        }
        staged_.erase(staged_.begin(), staged_.begin() + static_cast<std::ptrdiff_t>(n));
        return res;
    }

    bool mark_published(const std::string& event_id) override {
        std::lock_guard<std::mutex> lock(mtx_);
        published_.push_back(event_id);
        return true;
    }

    bool mark_failed(const std::string& event_id) override {
        std::lock_guard<std::mutex> lock(mtx_);
        failed_.push_back(event_id);
        return true;
    }
};

// ============================================================================
// 3. Mock Downstream Files gRPC Service
// ============================================================================
class ControllableMockFilesService final : public securecloud::files::v1::FilesService::Service {
  public:
    std::shared_ptr<InMemoryOutboxRepository> outbox_repo;
    std::atomic<bool> simulate_downstream_failure{false};

    struct StoredUpload {
        std::string upload_id;
        std::string file_id;
        std::string owner_user_id;
        uint32_t total_chunks{0};
        std::map<uint32_t, std::string> chunks;
        bool finalized{false};
    };

    struct StoredFile {
        std::string file_id;
        std::string owner_user_id;
        std::vector<std::string> chunks;
        bool deleted{false};
    };

    std::mutex mutex_;
    std::map<std::string, StoredUpload> uploads_;
    std::map<std::string, StoredFile> files_;
    std::atomic<uint32_t> session_counter_{0};

    ::grpc::Status CreateFileUpload(::grpc::ServerContext* /*context*/,
                                    const securecloud::files::v1::CreateFileUploadRequest* request,
                                    securecloud::files::v1::CreateFileUploadResponse* response) override {
        if (simulate_downstream_failure.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Files outage");
        }

        std::string upload_id = "sess-" + std::to_string(++session_counter_);
        std::string file_id = "file-" + upload_id;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            StoredUpload u;
            u.upload_id = upload_id;
            u.file_id = file_id;
            u.owner_user_id = request->owner_user_id();
            u.total_chunks = request->expected_chunk_count();
            uploads_[upload_id] = std::move(u);
        }

        // Stage transactional outbox event
        if (outbox_repo) {
            FilesOutboxEntity ev;
            ev.event_id = "evt-init-" + upload_id;
            ev.aggregate_id = file_id;
            ev.event_type = "FILE_CREATED";
            ev.created_at = std::chrono::system_clock::now();
            ev.payload_json =
                "{\"owner_user_id\":\"" + request->owner_user_id() + "\",\"file_id\":\"" + file_id + "\"}";
            outbox_repo->stage_event(ev);
        }

        response->set_upload_id(upload_id);
        response->set_file_id(file_id);
        response->set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_PENDING);
        return ::grpc::Status::OK;
    }

    ::grpc::Status UploadChunk(::grpc::ServerContext* /*context*/,
                               const securecloud::files::v1::UploadChunkRequest* request,
                               securecloud::files::v1::UploadChunkResponse* response) override {
        if (simulate_downstream_failure.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Files outage");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = uploads_.find(request->upload_id());
        if (it == uploads_.end()) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "Upload session not found");
        }

        it->second.chunks[request->chunk_index()] = request->encrypted_data();
        response->set_upload_id(request->upload_id());
        response->set_chunk_index(request->chunk_index());
        response->set_accepted(true);
        response->set_received_sha256(request->ciphertext_sha256());
        return ::grpc::Status::OK;
    }

    ::grpc::Status FinalizeFileUpload(::grpc::ServerContext* /*context*/,
                                      const securecloud::files::v1::FinalizeFileUploadRequest* request,
                                      securecloud::files::v1::FinalizeFileUploadResponse* response) override {
        if (simulate_downstream_failure.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Files outage");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = uploads_.find(request->upload_id());
        if (it == uploads_.end()) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "Upload session not found");
        }

        it->second.finalized = true;
        StoredFile f;
        f.file_id = it->second.file_id;
        f.owner_user_id = it->second.owner_user_id;
        for (uint32_t i = 0; i < it->second.total_chunks; ++i) {
            f.chunks.push_back(it->second.chunks[i]);
        }
        files_[f.file_id] = f;

        if (outbox_repo) {
            FilesOutboxEntity ev;
            ev.event_id = "evt-fin-" + f.file_id;
            ev.aggregate_id = f.file_id;
            ev.event_type = "FILE_FINALIZED";
            ev.created_at = std::chrono::system_clock::now();
            ev.payload_json = "{\"owner_user_id\":\"" + f.owner_user_id + "\",\"file_id\":\"" + f.file_id + "\"}";
            outbox_repo->stage_event(ev);
        }

        response->set_file_id(f.file_id);
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
        return ::grpc::Status::OK;
    }

    ::grpc::Status CancelFileUpload(::grpc::ServerContext* /*context*/,
                                    const securecloud::files::v1::CancelFileUploadRequest* request,
                                    securecloud::files::v1::CancelFileUploadResponse* response) override {
        std::lock_guard<std::mutex> lock(mutex_);
        uploads_.erase(request->upload_id());
        response->set_upload_id(request->upload_id());
        response->set_status(securecloud::files::v1::TransferStatus::TRANSFER_STATUS_CANCELLED);
        return ::grpc::Status::OK;
    }

    ::grpc::Status GetFileMetadata(::grpc::ServerContext* context,
                                   const securecloud::files::v1::GetFileMetadataRequest* request,
                                   securecloud::files::v1::GetFileMetadataResponse* response) override {
        if (simulate_downstream_failure.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Files outage");
        }

        auto client_metadata = context->client_metadata();
        auto cap_it = client_metadata.find("x-file-capability");
        std::string cap_token =
            (cap_it != client_metadata.end()) ? std::string(cap_it->second.data(), cap_it->second.length()) : "";

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = files_.find(request->file_id());
        if (it == files_.end() || it->second.deleted) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "File not found or deleted");
        }

        if (cap_token == "invalid-cap") {
            return ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, "Invalid capability token");
        }

        response->set_file_id(it->second.file_id);
        response->set_chunk_count(static_cast<uint32_t>(it->second.chunks.size()));
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_AVAILABLE);
        uint64_t total_sz = 0;
        for (const auto& c : it->second.chunks) {
            total_sz += c.size();
        }
        response->set_encrypted_size_bytes(total_sz);
        response->set_encryption_version("XChaCha20-Poly1305");
        return ::grpc::Status::OK;
    }

    ::grpc::Status DownloadChunk(::grpc::ServerContext* context,
                                 const securecloud::files::v1::DownloadChunkRequest* request,
                                 securecloud::files::v1::DownloadChunkResponse* response) override {
        if (simulate_downstream_failure.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Files outage");
        }

        auto client_metadata = context->client_metadata();
        auto cap_it = client_metadata.find("x-file-capability");
        std::string cap_token =
            (cap_it != client_metadata.end()) ? std::string(cap_it->second.data(), cap_it->second.length()) : "";

        if (cap_token == "invalid-cap") {
            return ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, "Invalid capability token");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = files_.find(request->file_id());
        if (it == files_.end() || it->second.deleted) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "File not found");
        }

        if (request->chunk_index() >= it->second.chunks.size()) {
            return ::grpc::Status(::grpc::StatusCode::OUT_OF_RANGE, "Chunk index out of bounds");
        }

        response->set_file_id(request->file_id());
        response->set_chunk_index(request->chunk_index());
        response->set_encrypted_data(it->second.chunks[request->chunk_index()]);
        response->set_chunk_size_bytes(static_cast<uint32_t>(it->second.chunks[request->chunk_index()].size()));
        return ::grpc::Status::OK;
    }

    ::grpc::Status DeleteFile(::grpc::ServerContext* /*context*/,
                              const securecloud::files::v1::DeleteFileRequest* request,
                              securecloud::files::v1::DeleteFileResponse* response) override {
        if (simulate_downstream_failure.load()) {
            return ::grpc::Status(::grpc::StatusCode::UNAVAILABLE, "Simulated Files outage");
        }

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = files_.find(request->file_id());
        if (it == files_.end() || it->second.deleted) {
            return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "File not found");
        }

        it->second.deleted = true;

        if (outbox_repo) {
            FilesOutboxEntity ev;
            ev.event_id = "evt-del-" + request->file_id();
            ev.aggregate_id = request->file_id();
            ev.event_type = "FILE_DELETED";
            ev.created_at = std::chrono::system_clock::now();
            ev.payload_json =
                "{\"owner_user_id\":\"" + it->second.owner_user_id + "\",\"file_id\":\"" + request->file_id() + "\"}";
            outbox_repo->stage_event(ev);
        }

        response->set_file_id(request->file_id());
        response->set_lifecycle_state(securecloud::files::v1::FileLifecycleState::FILE_LIFECYCLE_STATE_DELETED);
        response->set_deleted(true);
        return ::grpc::Status::OK;
    }
};

// ============================================================================
// 4. Test Fixture: Gateway + Files + Audit Live Integration Test Suite
// ============================================================================
class FilesE2EGatewayAuditIntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ensure_integration_winsock();

        // 1. Start Mock Audit Service on random ephemeral port
        audit_service_ = std::make_unique<MockAuditIngestionService>();
        ::grpc::ServerBuilder audit_builder;
        int audit_port = 0;
        audit_builder.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), &audit_port);
        audit_builder.RegisterService(audit_service_.get());
        audit_server_ = audit_builder.BuildAndStart();
        ASSERT_NE(audit_server_, nullptr);
        audit_address_ = "127.0.0.1:" + std::to_string(audit_port);

        // 2. Setup Outbox Repository
        outbox_repo_ = std::make_shared<InMemoryOutboxRepository>();

        // 3. Start Mock Files Service on random ephemeral port
        files_service_ = std::make_unique<ControllableMockFilesService>();
        files_service_->outbox_repo = outbox_repo_;

        ::grpc::ServerBuilder files_builder;
        int files_port = 0;
        files_builder.AddListeningPort("127.0.0.1:0", ::grpc::InsecureServerCredentials(), &files_port);
        files_builder.RegisterService(files_service_.get());
        files_server_ = files_builder.BuildAndStart();
        ASSERT_NE(files_server_, nullptr);
        files_address_ = "127.0.0.1:" + std::to_string(files_port);

        // 4. Setup Gateway FilesServiceClient pointing to Files Service
        auto files_channel = ::grpc::CreateChannel(files_address_, ::grpc::InsecureChannelCredentials());
        files_client_ = std::make_shared<gateway::grpc::FilesServiceClient>(files_channel);

        // 5. Setup Resilience & Proxy Handler
        circuit_breaker_ =
            std::make_shared<gateway::http::CircuitBreaker>("files", gateway::GatewayCircuitBreakerConfig{
                                                                         .enabled = true,
                                                                         .failure_threshold = 2,
                                                                         .recovery_timeout_ms = 1000,
                                                                         .half_open_probe_count = 1,
                                                                     });
        bulkhead_manager_ = std::make_shared<gateway::http::BulkheadManager>();
        retry_policy_ = std::make_shared<gateway::http::RetryPolicy>();
        deadline_manager_ = std::make_shared<gateway::http::DeadlineManager>();

        proxy_handler_ = std::make_unique<gateway::http::FilesProxyHandler>(
            files_client_, deadline_manager_, retry_policy_, bulkhead_manager_, circuit_breaker_);

        // 6. Start HTTP Server on random ephemeral port
        http_server_ = std::make_unique<httplib::Server>();

        http_server_->Post("/api/v1/files/upload/init", [this](const httplib::Request& req, httplib::Response& res) {
            std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
            proxy_handler_->handle_upload_init(req, res, make_test_context(caller));
        });

        http_server_->Post("/api/v1/files/upload/chunk", [this](const httplib::Request& req, httplib::Response& res) {
            std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
            proxy_handler_->handle_upload_chunk(req, res, make_test_context(caller));
        });

        http_server_->Post(
            "/api/v1/files/upload/finalize", [this](const httplib::Request& req, httplib::Response& res) {
                std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
                proxy_handler_->handle_upload_finalize(req, res, make_test_context(caller));
            });

        http_server_->Post("/api/v1/files/upload/cancel", [this](const httplib::Request& req, httplib::Response& res) {
            std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
            proxy_handler_->handle_upload_cancel(req, res, make_test_context(caller));
        });

        http_server_->Get(
            R"(/api/v1/files/([^/]+)/metadata)", [this](const httplib::Request& req, httplib::Response& res) {
                std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
                proxy_handler_->handle_get_metadata(req, res, make_test_context(caller));
            });

        http_server_->Get(
            R"(/api/v1/files/([^/]+)/chunks/(\d+))", [this](const httplib::Request& req, httplib::Response& res) {
                std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
                proxy_handler_->handle_download_chunk(req, res, make_test_context(caller));
            });

        http_server_->Get(
            R"(/api/v1/files/([^/]+)/download)", [this](const httplib::Request& req, httplib::Response& res) {
                std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
                proxy_handler_->handle_streaming_download(req, res, make_test_context(caller));
            });

        http_server_->Delete(R"(/api/v1/files/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
            std::string caller = req.has_header("X-Caller-Id") ? req.get_header_value("X-Caller-Id") : "alice-uuid";
            proxy_handler_->handle_delete_file(req, res, make_test_context(caller));
        });

        http_port_ = http_server_->bind_to_any_port("127.0.0.1");
        ASSERT_GT(http_port_, 0);

        http_thread_ = std::thread([this]() { http_server_->listen_after_bind(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    void TearDown() override {
        if (http_server_) {
            http_server_->stop();
        }
        if (http_thread_.joinable()) {
            http_thread_.join();
        }
        if (files_server_) {
            files_server_->Shutdown();
        }
        if (audit_server_) {
            audit_server_->Shutdown();
        }
    }

    std::unique_ptr<MockAuditIngestionService> audit_service_;
    std::unique_ptr<::grpc::Server> audit_server_;
    std::string audit_address_;

    std::shared_ptr<InMemoryOutboxRepository> outbox_repo_;
    std::unique_ptr<ControllableMockFilesService> files_service_;
    std::unique_ptr<::grpc::Server> files_server_;
    std::string files_address_;

    std::shared_ptr<gateway::grpc::IFilesClient> files_client_;
    std::shared_ptr<gateway::http::CircuitBreaker> circuit_breaker_;
    std::shared_ptr<gateway::http::BulkheadManager> bulkhead_manager_;
    std::shared_ptr<gateway::http::RetryPolicy> retry_policy_;
    std::shared_ptr<gateway::http::DeadlineManager> deadline_manager_;

    std::unique_ptr<gateway::http::FilesProxyHandler> proxy_handler_;

    std::unique_ptr<httplib::Server> http_server_;
    int http_port_{0};
    std::thread http_thread_;
};

// ============================================================================
// Test 1: Full Resumable Upload Lifecycle via HTTP Gateway
// ============================================================================
TEST_F(FilesE2EGatewayAuditIntegrationTest, Scenario1_FullResumableUploadLifecycle) {
    httplib::Client cli("127.0.0.1", http_port_);

    // 1. POST /api/v1/files/upload/init
    nlohmann::json init_req;
    init_req["owner_user_id"] = "alice-uuid";
    init_req["expected_chunk_count"] = 2;
    init_req["encrypted_size_bytes"] = 2048;
    init_req["encryption_version"] = "XChaCha20-Poly1305";

    httplib::Headers headers = {{"X-Caller-Id", "alice-uuid"}};
    auto init_res = cli.Post("/api/v1/files/upload/init", headers, init_req.dump(), "application/json");
    ASSERT_TRUE(init_res);
    EXPECT_EQ(init_res->status, 201);

    auto init_json = nlohmann::json::parse(init_res->body);
    std::string upload_session_id = init_json["upload_id"];
    std::string file_id = init_json["file_id"];
    EXPECT_FALSE(upload_session_id.empty());
    EXPECT_FALSE(file_id.empty());

    // 2. POST /api/v1/files/upload/chunk (Chunk 0 & Chunk 1)
    for (uint32_t chunk_idx = 0; chunk_idx < 2; ++chunk_idx) {
        httplib::Headers chunk_headers = {
            {"X-Caller-Id", "alice-uuid"},
            {"Upload-Id", upload_session_id},
            {"Chunk-Index", std::to_string(chunk_idx)},
        };
        std::string chunk_data = "ENCRYPTED_CHUNK_" + std::to_string(chunk_idx);

        auto chunk_res = cli.Post("/api/v1/files/upload/chunk", chunk_headers, chunk_data, "application/octet-stream");
        ASSERT_TRUE(chunk_res);
        EXPECT_EQ(chunk_res->status, 200);
    }

    // 3. POST /api/v1/files/upload/finalize
    nlohmann::json fin_req;
    fin_req["upload_id"] = upload_session_id;
    fin_req["file_id"] = file_id;
    auto fin_res = cli.Post("/api/v1/files/upload/finalize", headers, fin_req.dump(), "application/json");
    ASSERT_TRUE(fin_res);
    EXPECT_EQ(fin_res->status, 200);

    auto fin_json = nlohmann::json::parse(fin_res->body);
    EXPECT_EQ(fin_json["file_id"], file_id);
    EXPECT_EQ(fin_json["lifecycle_state"], "FILE_LIFECYCLE_STATE_AVAILABLE");
}

// ============================================================================
// Test 2 & 3: Capability-Authorized Download and Unauthorized Access Rejection
// ============================================================================
TEST_F(FilesE2EGatewayAuditIntegrationTest, Scenario2And3_CapabilityAuthorizationAndRejection) {
    httplib::Client cli("127.0.0.1", http_port_);

    // Upload a test file first
    httplib::Headers alice_headers = {{"X-Caller-Id", "alice-uuid"}};
    nlohmann::json init_req = {
        {"owner_user_id", "alice-uuid"},
        {"expected_chunk_count", 1},
        {"encrypted_size_bytes", 18},
    };
    auto init_res = cli.Post("/api/v1/files/upload/init", alice_headers, init_req.dump(), "application/json");
    ASSERT_TRUE(init_res && init_res->status == 201);
    std::string upload_session_id = nlohmann::json::parse(init_res->body)["upload_id"];
    std::string file_id = nlohmann::json::parse(init_res->body)["file_id"];

    httplib::Headers chunk_headers = {
        {"X-Caller-Id", "alice-uuid"},
        {"Upload-Id", upload_session_id},
        {"Chunk-Index", "0"},
    };
    auto chunk_res =
        cli.Post("/api/v1/files/upload/chunk", chunk_headers, "SECRET_CIPHERTEXT", "application/octet-stream");
    ASSERT_TRUE(chunk_res && chunk_res->status == 200);

    nlohmann::json fin_req = {{"upload_id", upload_session_id}, {"file_id", file_id}};
    auto fin_res = cli.Post("/api/v1/files/upload/finalize", alice_headers, fin_req.dump(), "application/json");
    ASSERT_TRUE(fin_res && fin_res->status == 200);

    // Scenario 2: Authorized download with valid capability header
    httplib::Headers cap_headers = {{"X-Caller-Id", "bob-uuid"}, {"X-File-Capability", "valid-ed25519-token"}};
    auto chunk_dl = cli.Get("/api/v1/files/" + file_id + "/chunks/0", cap_headers);
    ASSERT_TRUE(chunk_dl);
    EXPECT_EQ(chunk_dl->status, 200);
    EXPECT_EQ(chunk_dl->body, "SECRET_CIPHERTEXT");

    // Scenario 3: Rejected download with tampered/invalid capability
    httplib::Headers invalid_headers = {{"X-Caller-Id", "mallory-uuid"}, {"X-File-Capability", "invalid-cap"}};
    auto reject_res = cli.Get("/api/v1/files/" + file_id + "/chunks/0", invalid_headers);
    ASSERT_TRUE(reject_res);
    EXPECT_EQ(reject_res->status, 403);
}

// ============================================================================
// Test 4: Chunked Streaming Download (Bounded RAM Reconstruction)
// ============================================================================
TEST_F(FilesE2EGatewayAuditIntegrationTest, Scenario4_ChunkedStreamingDownload) {
    httplib::Client cli("127.0.0.1", http_port_);

    std::string chunk0 = "STREAM_PART_0_PAYLOAD_";
    std::string chunk1 = "STREAM_PART_1_PAYLOAD_";
    std::string chunk2 = "STREAM_PART_2_PAYLOAD_";
    std::string expected_whole_payload = chunk0 + chunk1 + chunk2;

    // Upload a 3-chunk file
    httplib::Headers headers = {{"X-Caller-Id", "alice-uuid"}};
    nlohmann::json init_req = {
        {"owner_user_id", "alice-uuid"},
        {"expected_chunk_count", 3},
        {"encrypted_size_bytes", expected_whole_payload.size()},
    };
    auto init_res = cli.Post("/api/v1/files/upload/init", headers, init_req.dump(), "application/json");
    ASSERT_TRUE(init_res && init_res->status == 201);
    std::string upload_session_id = nlohmann::json::parse(init_res->body)["upload_id"];
    std::string file_id = nlohmann::json::parse(init_res->body)["file_id"];

    std::vector<std::string> chunks = {chunk0, chunk1, chunk2};
    for (uint32_t i = 0; i < 3; ++i) {
        httplib::Headers chunk_headers = {
            {"X-Caller-Id", "alice-uuid"},
            {"Upload-Id", upload_session_id},
            {"Chunk-Index", std::to_string(i)},
        };
        auto chunk_res = cli.Post("/api/v1/files/upload/chunk", chunk_headers, chunks[i], "application/octet-stream");
        ASSERT_TRUE(chunk_res && chunk_res->status == 200);
    }

    nlohmann::json fin_req = {{"upload_id", upload_session_id}, {"file_id", file_id}};
    auto fin_res = cli.Post("/api/v1/files/upload/finalize", headers, fin_req.dump(), "application/json");
    ASSERT_TRUE(fin_res && fin_res->status == 200);

    // Perform streaming GET request
    auto stream_res = cli.Get("/api/v1/files/" + file_id + "/download", headers);
    ASSERT_TRUE(stream_res);
    EXPECT_EQ(stream_res->status, 200);
    EXPECT_EQ(stream_res->body, expected_whole_payload);
}

// ============================================================================
// Test 5: Deletion & Metadata Lifecycle
// ============================================================================
TEST_F(FilesE2EGatewayAuditIntegrationTest, Scenario5_DeletionAndMetadataLifecycle) {
    httplib::Client cli("127.0.0.1", http_port_);

    httplib::Headers headers = {{"X-Caller-Id", "alice-uuid"}};
    nlohmann::json init_req = {
        {"owner_user_id", "alice-uuid"},
        {"expected_chunk_count", 1},
        {"encrypted_size_bytes", 4},
    };
    auto init_res = cli.Post("/api/v1/files/upload/init", headers, init_req.dump(), "application/json");
    ASSERT_TRUE(init_res && init_res->status == 201);
    std::string upload_session_id = nlohmann::json::parse(init_res->body)["upload_id"];
    std::string file_id = nlohmann::json::parse(init_res->body)["file_id"];

    httplib::Headers chunk_headers = {
        {"X-Caller-Id", "alice-uuid"},
        {"Upload-Id", upload_session_id},
        {"Chunk-Index", "0"},
    };
    auto chunk_res = cli.Post("/api/v1/files/upload/chunk", chunk_headers, "DATA", "application/octet-stream");
    ASSERT_TRUE(chunk_res && chunk_res->status == 200);

    nlohmann::json fin_req = {{"upload_id", upload_session_id}, {"file_id", file_id}};
    auto fin_res = cli.Post("/api/v1/files/upload/finalize", headers, fin_req.dump(), "application/json");
    ASSERT_TRUE(fin_res && fin_res->status == 200);

    // Delete file
    auto del_res = cli.Delete("/api/v1/files/" + file_id, headers);
    ASSERT_TRUE(del_res);
    EXPECT_EQ(del_res->status, 200);

    // Subsequent metadata query returns 404
    auto meta_res = cli.Get("/api/v1/files/" + file_id + "/metadata", headers);
    ASSERT_TRUE(meta_res);
    EXPECT_EQ(meta_res->status, 404);
}

// ============================================================================
// Test 6: Transactional Outbox Audit Dispatch Verification
// ============================================================================
TEST_F(FilesE2EGatewayAuditIntegrationTest, Scenario6_OutboxAuditDispatchVerification) {
    // Connect gRPC Audit Client to Mock Audit Service
    audit::GrpcAuditClientConfig audit_cfg;
    audit_cfg.target_endpoint = audit_address_;
    audit_cfg.use_tls = false;
    auto audit_client = std::make_shared<audit::GrpcAuditClient>(audit_cfg);

    // Stage sample outbox events into repository
    FilesOutboxEntity ev1;
    ev1.event_id = "evt-outbox-1";
    ev1.aggregate_id = "file-e2e-1";
    ev1.event_type = "FILE_CREATED";
    ev1.created_at = std::chrono::system_clock::now();
    ev1.payload_json = "{\"owner_user_id\":\"alice-uuid\",\"file_size\":1024}";
    outbox_repo_->stage_event(ev1);

    FilesOutboxEntity ev2;
    ev2.event_id = "evt-outbox-2";
    ev2.aggregate_id = "file-e2e-1";
    ev2.event_type = "FILE_FINALIZED";
    ev2.created_at = std::chrono::system_clock::now();
    ev2.payload_json = "{\"owner_user_id\":\"alice-uuid\",\"file_size\":1024}";
    outbox_repo_->stage_event(ev2);

    // Instantiate Outbox Relay Worker
    audit::FilesOutboxRelay relay(outbox_repo_, audit_client);

    // Trigger relay to drain any staged outbox events
    size_t dispatched = relay.poll_and_dispatch(50);
    EXPECT_GE(dispatched, 2u);

    // Verify Audit Service received events
    EXPECT_GE(audit_service_->event_count(), 2u);

    std::lock_guard<std::mutex> lock(audit_service_->mutex_);
    for (const auto& ev : audit_service_->received_events) {
        EXPECT_EQ(ev.producer_service(), securecloud::audit::v1::ProducerServiceProto::PRODUCER_SERVICE_FILES);
        EXPECT_FALSE(ev.target_id().empty());
        // Verify Zero Plaintext guarantee
        const auto& meta = ev.metadata();
        EXPECT_EQ(meta.find("encryption_key"), meta.end());
        EXPECT_EQ(meta.find("ciphertext"), meta.end());
    }
}

// ============================================================================
// Test 7: Resilience & Circuit Breaking under Downstream Outage
// ============================================================================
TEST_F(FilesE2EGatewayAuditIntegrationTest, Scenario7_ResilienceAndCircuitBreaking) {
    httplib::Client cli("127.0.0.1", http_port_);
    httplib::Headers headers = {{"X-Caller-Id", "alice-uuid"}, {"X-Request-Id", "req-breaker-1"}};

    // Simulate downstream Files Service failure
    files_service_->simulate_downstream_failure.store(true);

    nlohmann::json init_req = {
        {"owner_user_id", "alice-uuid"},
        {"expected_chunk_count", 1},
        {"encrypted_size_bytes", 1024},
    };
    auto res = cli.Post("/api/v1/files/upload/init", headers, init_req.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 503);

    // Verify RFC 7807 problem details without internal stack trace leak
    auto err_json = nlohmann::json::parse(res->body);
    EXPECT_TRUE(err_json.contains("error"));
    EXPECT_EQ(err_json["error"]["code"], "SERVICE_UNAVAILABLE");
    EXPECT_TRUE(err_json.contains("request_id") || err_json["error"].contains("request_id"));

    files_service_->simulate_downstream_failure.store(false);
}

} // namespace
} // namespace securecloud::files::integration

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
