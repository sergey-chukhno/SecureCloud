#include "files/service/file_finalization_service.hpp"
#include "files/domain/chunk_validator.hpp"
#include "files/storage/s3_client.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace securecloud::files::service {
namespace {

TEST(FileFinalizationServiceTest, RejectEmptyUploadId) {
    FileFinalizationService service(nullptr, nullptr);

    FinalizeUploadRequestDto req{
        .upload_id = "",
        .file_id = "018f6e80-7b23-74d1-81f8-000000000001",
        .caller_user_id = "user-123",
        .expected_ciphertext_sha256 = ""
    };

    EXPECT_THROW(service.finalize_file_upload(req), FinalizationPreconditionException);
}

TEST(FileFinalizationServiceTest, RejectUninitializedAssemblyEngine) {
    FileFinalizationService service(nullptr, nullptr);

    FinalizeUploadRequestDto req{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .file_id = "018f6e80-7b23-74d1-81f8-000000000001",
        .caller_user_id = "user-123",
        .expected_ciphertext_sha256 = ""
    };

    EXPECT_THROW(service.finalize_file_upload(req), std::runtime_error);
}

TEST(FileFinalizationServiceTest, RejectUninitializedPool) {
    storage::S3ClientConfig s3_cfg{
        .endpoint = "http://127.0.0.1:9000",
        .bucket = "securecloud-files-encrypted",
        .access_key = "test_key",
        .secret_key = common::configuration::SecretString("test_secret"),
    };
    auto s3_client = std::make_shared<storage::S3Client>(s3_cfg, nullptr);
    auto assembly_engine = std::make_shared<ObjectAssemblyEngine>(s3_client);

    FileFinalizationService service(nullptr, assembly_engine);

    FinalizeUploadRequestDto req{
        .upload_id = "018f6e80-7b23-74d1-81f8-8a8b1a2c3d4e",
        .file_id = "018f6e80-7b23-74d1-81f8-000000000001",
        .caller_user_id = "user-123",
        .expected_ciphertext_sha256 = ""
    };

    EXPECT_THROW(service.finalize_file_upload(req), std::runtime_error);
}

} // namespace
} // namespace securecloud::files::service
