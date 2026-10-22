#include "grpc/files_service_client.hpp"

#include <grpcpp/grpcpp.h>
#include <utility>

namespace securecloud::gateway::grpc {
namespace {

DependencyError null_stub_error() {
    return DependencyError{
        .kind = DependencyErrorKind::ServiceUnavailable,
        .message = "FilesService stub is unavailable or null",
        .grpc_code = ::grpc::StatusCode::UNAVAILABLE,
    };
}

} // namespace

FilesServiceClient::FilesServiceClient(std::shared_ptr<securecloud::files::v1::FilesService::StubInterface> stub)
    : stub_(std::move(stub)) {}

FilesServiceClient::FilesServiceClient(const std::shared_ptr<::grpc::Channel>& channel)
    : stub_(channel ? securecloud::files::v1::FilesService::NewStub(channel) : nullptr) {}

Result<securecloud::files::v1::CreateFileUploadResponse>
FilesServiceClient::create_file_upload(const securecloud::files::v1::CreateFileUploadRequest& req,
                                       ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::CreateFileUploadResponse resp;
    auto status = stub_->CreateFileUpload(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::files::v1::UploadChunkResponse>
FilesServiceClient::upload_chunk(const securecloud::files::v1::UploadChunkRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::UploadChunkResponse resp;
    auto status = stub_->UploadChunk(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::files::v1::FinalizeFileUploadResponse>
FilesServiceClient::finalize_file_upload(const securecloud::files::v1::FinalizeFileUploadRequest& req,
                                         ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::FinalizeFileUploadResponse resp;
    auto status = stub_->FinalizeFileUpload(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::files::v1::GetFileMetadataResponse>
FilesServiceClient::get_file_metadata(const securecloud::files::v1::GetFileMetadataRequest& req,
                                      ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::GetFileMetadataResponse resp;
    auto status = stub_->GetFileMetadata(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::files::v1::DownloadChunkResponse>
FilesServiceClient::download_chunk(const securecloud::files::v1::DownloadChunkRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::DownloadChunkResponse resp;
    auto status = stub_->DownloadChunk(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::files::v1::CancelFileUploadResponse>
FilesServiceClient::cancel_file_upload(const securecloud::files::v1::CancelFileUploadRequest& req,
                                       ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::CancelFileUploadResponse resp;
    auto status = stub_->CancelFileUpload(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

Result<securecloud::files::v1::DeleteFileResponse>
FilesServiceClient::delete_file(const securecloud::files::v1::DeleteFileRequest& req, ClientCallContext& ctx) {
    if (!stub_) {
        return null_stub_error();
    }
    securecloud::files::v1::DeleteFileResponse resp;
    auto status = stub_->DeleteFile(&ctx.raw_context(), req, &resp);
    if (!status.ok()) {
        return DependencyError::from_grpc_status(status);
    }
    return resp;
}

} // namespace securecloud::gateway::grpc
