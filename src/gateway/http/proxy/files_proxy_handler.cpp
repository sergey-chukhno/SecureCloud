#include "http/proxy/files_proxy_handler.hpp"

#include "grpc/client_call_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/errors/error_mapper.hpp"
#include "http/routing/router.hpp"
#include "http/streaming/streaming_buffer.hpp"

#include <chrono>
#include <cstdint>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr const char* k_content_type_json = "application/json";
constexpr const char* k_content_type_octet = "application/octet-stream";

class ActiveCallGuard {
  public:
    ActiveCallGuard(FilesProxyHandler& handler, const std::string& request_id, grpc::ClientCallContext& ctx)
        : handler_(handler), request_id_(request_id) {
        if (!request_id_.empty()) {
            handler_.register_active_call(request_id_, &ctx);
        }
    }
    ~ActiveCallGuard() {
        if (!request_id_.empty()) {
            handler_.unregister_active_call(request_id_);
        }
    }

  private:
    FilesProxyHandler& handler_;
    std::string request_id_;
};

} // namespace

FilesProxyHandler::FilesProxyHandler(std::shared_ptr<grpc::IFilesClient> files_client,
                                     std::shared_ptr<DeadlineManager> deadline_manager,
                                     std::shared_ptr<RetryPolicy> retry_policy,
                                     std::shared_ptr<BulkheadManager> bulkhead_manager,
                                     std::shared_ptr<CircuitBreaker> circuit_breaker,
                                     GatewayStreamingConfig streaming_config)
    : files_client_(std::move(files_client)), deadline_manager_(std::move(deadline_manager)),
      retry_policy_(std::move(retry_policy)), bulkhead_manager_(std::move(bulkhead_manager)),
      circuit_breaker_(std::move(circuit_breaker)), streaming_config_(streaming_config) {}

std::string FilesProxyHandler::extract_request_id(const httplib::Request& req) {
    if (const auto* rc = RequestContext::current()) {
        return rc->request_id();
    }
    if (req.has_header("X-Request-ID")) {
        return req.get_header_value("X-Request-ID");
    }
    if (req.has_header("X-Request-Id")) {
        return req.get_header_value("X-Request-Id");
    }
    return "";
}

std::string FilesProxyHandler::extract_file_id(const httplib::Request& req) {
    std::string fid = Router::get_path_param(req, "file_id");
    if (!fid.empty()) {
        return fid;
    }
    const std::string prefix = "/api/v1/files/";
    auto pos = req.path.find(prefix);
    if (pos != std::string::npos) {
        size_t start = pos + prefix.size();
        size_t slash = req.path.find('/', start);
        if (slash != std::string::npos) {
            return req.path.substr(start, slash - start);
        }
        return req.path.substr(start);
    }
    return "";
}

std::chrono::milliseconds FilesProxyHandler::compute_timeout(const httplib::Request& req) const {
    if (deadline_manager_) {
        return deadline_manager_->compute_effective_deadline(
            req, std::chrono::milliseconds(deadline_manager_->config().files_metadata_timeout_ms));
    }
    return std::chrono::milliseconds(5000);
}

void FilesProxyHandler::write_grpc_error(httplib::Response& res, const grpc::DependencyError& error,
                                         const std::string& request_id) const {
    int http_status = 500;
    std::string code = "INTERNAL_ERROR";
    switch (error.kind) {
    case grpc::DependencyErrorKind::InvalidArgument:
        http_status = 400;
        code = "INVALID_ARGUMENT";
        break;
    case grpc::DependencyErrorKind::Unauthenticated:
        http_status = 401;
        code = "UNAUTHENTICATED";
        break;
    case grpc::DependencyErrorKind::PermissionDenied:
        http_status = 403;
        code = "PERMISSION_DENIED";
        break;
    case grpc::DependencyErrorKind::NotFound:
        http_status = 404;
        code = "NOT_FOUND";
        break;
    case grpc::DependencyErrorKind::Timeout:
        http_status = 504;
        code = "DEADLINE_EXCEEDED";
        break;
    case grpc::DependencyErrorKind::ServiceUnavailable:
        http_status = 503;
        code = "SERVICE_UNAVAILABLE";
        break;
    default:
        http_status = 500;
        code = "DOWNSTREAM_ERROR";
        break;
    }
    ErrorMapper::write_error(res, http_status, code, error.message, request_id);
}

void FilesProxyHandler::register_active_call(const std::string& request_id, grpc::ClientCallContext* ctx) {
    std::lock_guard<std::mutex> lock(active_calls_mutex_);
    active_calls_[request_id] = ctx;
}

void FilesProxyHandler::unregister_active_call(const std::string& request_id) {
    std::lock_guard<std::mutex> lock(active_calls_mutex_);
    active_calls_.erase(request_id);
}

bool FilesProxyHandler::cancel_request(const std::string& request_id) {
    std::lock_guard<std::mutex> lock(active_calls_mutex_);
    auto it = active_calls_.find(request_id);
    if (it != active_calls_.end() && it->second != nullptr) {
        it->second->cancel();
        return true;
    }
    return false;
}

void FilesProxyHandler::register_routes(Router& router) {
    router.post_authenticated("/api/v1/files/upload/init",
                              [this](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { handle_upload_init(req, res, ctx); });

    router.post_authenticated("/api/v1/files/upload/chunk",
                              [this](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { handle_upload_chunk(req, res, ctx); });

    router.post_authenticated("/api/v1/files/upload/finalize",
                              [this](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { handle_upload_finalize(req, res, ctx); });

    router.post_authenticated("/api/v1/files/upload/cancel",
                              [this](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { handle_upload_cancel(req, res, ctx); });

    router.get_authenticated("/api/v1/files/:file_id/metadata",
                             [this](const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx) { handle_get_metadata(req, res, ctx); });

    router.get_authenticated("/api/v1/files/:file_id/chunks/:chunk_index",
                             [this](const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx) { handle_download_chunk(req, res, ctx); });

    router.get_authenticated("/api/v1/files/:file_id/download",
                             [this](const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx) { handle_streaming_download(req, res, ctx); });

    router.del_authenticated("/api/v1/files/:file_id",
                             [this](const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx) { handle_delete_file(req, res, ctx); });
}

// 1. POST /api/v1/files/upload/init
void FilesProxyHandler::handle_upload_init(const httplib::Request& req, httplib::Response& res,
                                           const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception& e) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON payload: " + std::string(e.what()),
                                 request_id);
        return;
    }

    securecloud::files::v1::CreateFileUploadRequest grpc_req;
    if (body.contains("file_id") && body["file_id"].is_string()) {
        grpc_req.set_file_id(body["file_id"].get<std::string>());
    }

    std::string owner_user = ctx.user_id();
    if (body.contains("owner_user_id") && body["owner_user_id"].is_string() &&
        !body["owner_user_id"].get<std::string>().empty()) {
        owner_user = body["owner_user_id"].get<std::string>();
    }
    grpc_req.set_owner_user_id(owner_user);

    std::string owner_dev = ctx.device_id();
    if (body.contains("owner_device_id") && body["owner_device_id"].is_string() &&
        !body["owner_device_id"].get<std::string>().empty()) {
        owner_dev = body["owner_device_id"].get<std::string>();
    }
    grpc_req.set_owner_device_id(owner_dev);

    if (body.contains("encrypted_size_bytes") && body["encrypted_size_bytes"].is_number_unsigned()) {
        grpc_req.set_encrypted_size_bytes(body["encrypted_size_bytes"].get<uint64_t>());
    } else {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing or invalid 'encrypted_size_bytes'", request_id);
        return;
    }

    if (body.contains("expected_chunk_count") && body["expected_chunk_count"].is_number_unsigned()) {
        grpc_req.set_expected_chunk_count(body["expected_chunk_count"].get<uint32_t>());
    } else {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing or invalid 'expected_chunk_count'", request_id);
        return;
    }

    if (body.contains("encryption_version") && body["encryption_version"].is_string()) {
        grpc_req.set_encryption_version(body["encryption_version"].get<std::string>());
    } else {
        grpc_req.set_encryption_version("v1");
    }

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->create_file_upload(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    nlohmann::json resp_json = {
        {"upload_id", val.upload_id()},
        {"file_id", val.file_id()},
        {"status", "TRANSFER_STATUS_PENDING"},
        {"expires_at_unix_ms", val.expires_at_unix_ms()},
    };

    res.status = 201;
    res.set_content(resp_json.dump(), k_content_type_json);
}

// 2. POST /api/v1/files/upload/chunk
void FilesProxyHandler::handle_upload_chunk(const httplib::Request& req, httplib::Response& res,
                                            const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    std::string upload_id;
    if (req.has_header("Upload-Id")) {
        upload_id = req.get_header_value("Upload-Id");
    } else if (req.has_header("X-Upload-Id")) {
        upload_id = req.get_header_value("X-Upload-Id");
    }

    if (upload_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'Upload-Id' header", request_id);
        return;
    }

    std::string chunk_idx_str;
    if (req.has_header("Chunk-Index")) {
        chunk_idx_str = req.get_header_value("Chunk-Index");
    } else if (req.has_header("X-Chunk-Index")) {
        chunk_idx_str = req.get_header_value("X-Chunk-Index");
    }

    if (chunk_idx_str.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'Chunk-Index' header", request_id);
        return;
    }

    uint32_t chunk_index = 0;
    try {
        chunk_index = static_cast<uint32_t>(std::stoul(chunk_idx_str));
    } catch (...) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid 'Chunk-Index' value: " + chunk_idx_str,
                                 request_id);
        return;
    }

    if (req.body.size() > streaming_config_.max_chunk_size_bytes) {
        ErrorMapper::write_error(res, 413, "CHUNK_TOO_LARGE",
                                 "Chunk size exceeds configured limit of " +
                                     std::to_string(streaming_config_.max_chunk_size_bytes) + " bytes",
                                 request_id);
        return;
    }

    std::string expected_sha256;
    if (req.has_header("X-Ciphertext-SHA256")) {
        expected_sha256 = req.get_header_value("X-Ciphertext-SHA256");
    } else if (req.has_header("X-Ciphertext-Sha256")) {
        expected_sha256 = req.get_header_value("X-Ciphertext-Sha256");
    }

    if (!expected_sha256.empty()) {
        StreamingSha256Validator validator;
        validator.update(req.body);
        if (!validator.verify(expected_sha256)) {
            ErrorMapper::write_error(res, 400, "CHECKSUM_MISMATCH",
                                     "Chunk SHA-256 verification failed against expected header", request_id);
            return;
        }
    }

    securecloud::files::v1::UploadChunkRequest grpc_req;
    grpc_req.set_upload_id(upload_id);
    grpc_req.set_chunk_index(chunk_index);
    grpc_req.set_encrypted_data(req.body);
    grpc_req.set_chunk_size_bytes(static_cast<uint32_t>(req.body.size()));
    grpc_req.set_ciphertext_sha256(expected_sha256.empty() ? StreamingSha256Validator::compute_hex(req.body)
                                                           : expected_sha256);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->upload_chunk(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    nlohmann::json resp_json = {
        {"upload_id", val.upload_id()},
        {"chunk_index", val.chunk_index()},
        {"accepted", val.accepted()},
        {"received_sha256", val.received_sha256()},
    };

    res.status = 200;
    res.set_content(resp_json.dump(), k_content_type_json);
}

// 3. POST /api/v1/files/upload/finalize
void FilesProxyHandler::handle_upload_finalize(const httplib::Request& req, httplib::Response& res,
                                               const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception& e) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON payload: " + std::string(e.what()),
                                 request_id);
        return;
    }

    if (!body.contains("upload_id") || !body["upload_id"].is_string()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing or invalid 'upload_id'", request_id);
        return;
    }

    if (!body.contains("file_id") || !body["file_id"].is_string()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing or invalid 'file_id'", request_id);
        return;
    }

    securecloud::files::v1::FinalizeFileUploadRequest grpc_req;
    grpc_req.set_upload_id(body["upload_id"].get<std::string>());
    grpc_req.set_file_id(body["file_id"].get<std::string>());

    if (body.contains("expected_ciphertext_sha256") && body["expected_ciphertext_sha256"].is_string()) {
        grpc_req.set_expected_ciphertext_sha256(body["expected_ciphertext_sha256"].get<std::string>());
    }

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->finalize_file_upload(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    nlohmann::json resp_json = {
        {"file_id", val.file_id()},
        {"lifecycle_state", "FILE_LIFECYCLE_STATE_AVAILABLE"},
        {"available_at_unix_ms", val.available_at_unix_ms()},
    };

    res.status = 200;
    res.set_content(resp_json.dump(), k_content_type_json);
}

// 4. POST /api/v1/files/upload/cancel
void FilesProxyHandler::handle_upload_cancel(const httplib::Request& req, httplib::Response& res,
                                             const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception& e) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON payload: " + std::string(e.what()),
                                 request_id);
        return;
    }

    if (!body.contains("upload_id") || !body["upload_id"].is_string()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing or invalid 'upload_id'", request_id);
        return;
    }

    securecloud::files::v1::CancelFileUploadRequest grpc_req;
    grpc_req.set_upload_id(body["upload_id"].get<std::string>());
    if (body.contains("reason") && body["reason"].is_string()) {
        grpc_req.set_reason(body["reason"].get<std::string>());
    }

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->cancel_file_upload(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    nlohmann::json resp_json = {
        {"upload_id", val.upload_id()},
        {"status", "TRANSFER_STATUS_CANCELLED"},
    };

    res.status = 200;
    res.set_content(resp_json.dump(), k_content_type_json);
}

// 5. GET /api/v1/files/:file_id/metadata
void FilesProxyHandler::handle_get_metadata(const httplib::Request& req, httplib::Response& res,
                                            const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);
    const std::string file_id = extract_file_id(req);

    if (file_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'file_id' path parameter", request_id);
        return;
    }

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    securecloud::files::v1::GetFileMetadataRequest grpc_req;
    grpc_req.set_file_id(file_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->get_file_metadata(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    nlohmann::json resp_json = {
        {"file_id", val.file_id()},
        {"encrypted_size_bytes", val.encrypted_size_bytes()},
        {"chunk_count", val.chunk_count()},
        {"encryption_version", val.encryption_version()},
        {"lifecycle_state", "FILE_LIFECYCLE_STATE_AVAILABLE"},
        {"created_at_unix_ms", val.created_at_unix_ms()},
        {"available_at_unix_ms", val.available_at_unix_ms()},
    };

    res.status = 200;
    res.set_content(resp_json.dump(), k_content_type_json);
}

// 6. GET /api/v1/files/:file_id/chunks/:chunk_index
void FilesProxyHandler::handle_download_chunk(const httplib::Request& req, httplib::Response& res,
                                              const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);
    const std::string file_id = extract_file_id(req);

    if (file_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'file_id' path parameter", request_id);
        return;
    }

    std::string chunk_idx_str = Router::get_path_param(req, "chunk_index");
    if (chunk_idx_str.empty()) {
        const std::string chunk_prefix = "/chunks/";
        auto pos = req.path.find(chunk_prefix);
        if (pos != std::string::npos) {
            size_t start = pos + chunk_prefix.size();
            size_t slash = req.path.find('/', start);
            if (slash != std::string::npos) {
                chunk_idx_str = req.path.substr(start, slash - start);
            } else {
                chunk_idx_str = req.path.substr(start);
            }
        }
    }

    if (chunk_idx_str.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'chunk_index' path parameter", request_id);
        return;
    }

    uint32_t chunk_index = 0;
    try {
        chunk_index = static_cast<uint32_t>(std::stoul(chunk_idx_str));
    } catch (...) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid 'chunk_index' value: " + chunk_idx_str,
                                 request_id);
        return;
    }

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    securecloud::files::v1::DownloadChunkRequest grpc_req;
    grpc_req.set_file_id(file_id);
    grpc_req.set_chunk_index(chunk_index);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->download_chunk(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    res.status = 200;
    res.set_header("Content-Type", k_content_type_octet);
    res.set_header("Content-Length", std::to_string(val.chunk_size_bytes()));
    res.set_header("X-Ciphertext-SHA256", StreamingSha256Validator::compute_hex(val.encrypted_data()));
    res.body = val.encrypted_data();
}

// 7. GET /api/v1/files/:file_id/download
void FilesProxyHandler::handle_streaming_download(const httplib::Request& req, httplib::Response& res,
                                                  const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);
    const std::string file_id = extract_file_id(req);

    if (file_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'file_id' path parameter", request_id);
        return;
    }

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    // Step 1: Query metadata
    securecloud::files::v1::GetFileMetadataRequest meta_req;
    meta_req.set_file_id(file_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto meta_result = files_client_->get_file_metadata(meta_req, call_ctx);
    if (meta_result.has_error()) {
        write_grpc_error(res, meta_result.error(), request_id);
        return;
    }

    const auto& meta = meta_result.value();
    const uint32_t chunk_count = meta.chunk_count();

    // Step 2: Stream/aggregate chunks
    std::string full_payload;
    full_payload.reserve(meta.encrypted_size_bytes());

    for (uint32_t i = 0; i < chunk_count; ++i) {
        securecloud::files::v1::DownloadChunkRequest chunk_req;
        chunk_req.set_file_id(file_id);
        chunk_req.set_chunk_index(i);

        auto chunk_res = files_client_->download_chunk(chunk_req, call_ctx);
        if (chunk_res.has_error()) {
            write_grpc_error(res, chunk_res.error(), request_id);
            return;
        }
        full_payload.append(chunk_res.value().encrypted_data());
    }

    res.status = 200;
    res.set_header("Content-Type", k_content_type_octet);
    res.set_header("Content-Length", std::to_string(full_payload.size()));
    res.set_header("ETag", "\"" + StreamingSha256Validator::compute_hex(full_payload) + "\"");
    res.body = std::move(full_payload);
}

// 8. DELETE /api/v1/files/:file_id
void FilesProxyHandler::handle_delete_file(const httplib::Request& req, httplib::Response& res,
                                           const AuthenticatedContext& /*ctx*/) {
    const std::string request_id = extract_request_id(req);
    const std::string file_id = extract_file_id(req);

    if (file_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing 'file_id' path parameter", request_id);
        return;
    }

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Files) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id, circuit_breaker_->remaining_recovery_time_sec());
        return;
    }

    securecloud::files::v1::DeleteFileRequest grpc_req;
    grpc_req.set_file_id(file_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    ActiveCallGuard call_guard(*this, request_id, call_ctx);

    auto result = files_client_->delete_file(grpc_req, call_ctx);

    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& val = result.value();
    nlohmann::json resp_json = {
        {"file_id", val.file_id()},
        {"lifecycle_state", "FILE_LIFECYCLE_STATE_DELETED"},
        {"deleted", val.deleted()},
    };

    res.status = 200;
    res.set_content(resp_json.dump(), k_content_type_json);
}

} // namespace securecloud::gateway::http
