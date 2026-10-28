#include "files/service/download_manager.hpp"
#include "files/storage/s3_client.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <string>

namespace securecloud::files::service {
namespace {

TEST(DownloadManagerTest, AuthorizeDownloadReturnsFalseOnEmptyUserOrNullPool) {
    DownloadManager mgr(nullptr, nullptr);
    EXPECT_FALSE(mgr.authorize_download("018f6e80-7b23-74d1-81f8-000000000001", ""));
    EXPECT_FALSE(mgr.authorize_download("018f6e80-7b23-74d1-81f8-000000000001", "user-123"));
}

TEST(DownloadManagerTest, GetChunkVersionedThrowsOnUninitializedPool) {
    DownloadManager mgr(nullptr, nullptr);
    EXPECT_THROW(mgr.get_chunk_versioned("018f6e80-7b23-74d1-81f8-000000000001", 1, 0, "user-alice"),
                 std::runtime_error);
}

TEST(DownloadManagerTest, PrepareResumeSessionThrowsOnUninitializedPool) {
    DownloadManager mgr(nullptr, nullptr);
    EXPECT_THROW(mgr.prepare_resume_session("018f6e80-7b23-74d1-81f8-000000000001", 1, 0, "user-alice"),
                 std::runtime_error);
}

TEST(DownloadManagerTest, LegacyGetChunkReturnsNulloptOnFailure) {
    DownloadManager mgr(nullptr, nullptr);
    auto res = mgr.get_chunk("018f6e80-7b23-74d1-81f8-000000000001", 0);
    EXPECT_FALSE(res.has_value());
}

} // namespace
} // namespace securecloud::files::service
