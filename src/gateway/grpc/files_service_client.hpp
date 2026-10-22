#pragma once

#include "grpc/files_client_interface.hpp"
#include "securecloud/files/v1/files.grpc.pb.h"

#include <grpcpp/grpcpp.h>
#include <memory>

namespace securecloud::gateway::grpc {

class FilesServiceClient : public IFilesClient {
  public:
    explicit FilesServiceClient(std::shared_ptr<securecloud::files::v1::FilesService::StubInterface> stub);
    explicit FilesServiceClient(const std::shared_ptr<::grpc::Channel>& channel);

    ~FilesServiceClient() override = default;

    Result<securecloud::files::v1::CreateFileUploadResponse>
    create_file_upload(const securecloud::files::v1::CreateFileUploadRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::files::v1::UploadChunkResponse>
    upload_chunk(const securecloud::files::v1::UploadChunkRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::files::v1::FinalizeFileUploadResponse>
    finalize_file_upload(const securecloud::files::v1::FinalizeFileUploadRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::files::v1::GetFileMetadataResponse>
    get_file_metadata(const securecloud::files::v1::GetFileMetadataRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::files::v1::DownloadChunkResponse>
    download_chunk(const securecloud::files::v1::DownloadChunkRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::files::v1::CancelFileUploadResponse>
    cancel_file_upload(const securecloud::files::v1::CancelFileUploadRequest& req, ClientCallContext& ctx) override;

    Result<securecloud::files::v1::DeleteFileResponse> delete_file(const securecloud::files::v1::DeleteFileRequest& req,
                                                                   ClientCallContext& ctx) override;

  private:
    std::shared_ptr<securecloud::files::v1::FilesService::StubInterface> stub_;
};

} // namespace securecloud::gateway::grpc
