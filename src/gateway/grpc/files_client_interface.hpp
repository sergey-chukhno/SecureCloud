#pragma once

#include "grpc/client_call_context.hpp"
#include "grpc/dependency_error.hpp"
#include "securecloud/files/v1/files.pb.h"

namespace securecloud::gateway::grpc {

class IFilesClient {
  public:
    virtual ~IFilesClient() = default;

    virtual Result<securecloud::files::v1::CreateFileUploadResponse>
    create_file_upload(const securecloud::files::v1::CreateFileUploadRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::files::v1::UploadChunkResponse>
    upload_chunk(const securecloud::files::v1::UploadChunkRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::files::v1::FinalizeFileUploadResponse>
    finalize_file_upload(const securecloud::files::v1::FinalizeFileUploadRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::files::v1::GetFileMetadataResponse>
    get_file_metadata(const securecloud::files::v1::GetFileMetadataRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::files::v1::DownloadChunkResponse>
    download_chunk(const securecloud::files::v1::DownloadChunkRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::files::v1::CancelFileUploadResponse>
    cancel_file_upload(const securecloud::files::v1::CancelFileUploadRequest& req, ClientCallContext& ctx) = 0;

    virtual Result<securecloud::files::v1::DeleteFileResponse>
    delete_file(const securecloud::files::v1::DeleteFileRequest& req, ClientCallContext& ctx) = 0;
};

} // namespace securecloud::gateway::grpc
