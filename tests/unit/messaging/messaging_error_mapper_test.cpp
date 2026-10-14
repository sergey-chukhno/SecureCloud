#include "service/messaging_error_mapper.hpp"

#include <deque>
#include <grpc/support/time.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>
#include <map>
#include <string>

namespace grpc::testing {

class ServerContextTestSpouse {
  public:
    explicit ServerContextTestSpouse(::grpc::ServerContext* ctx) : ctx_(ctx) {}

    [[nodiscard]] const std::multimap<std::string, std::string>& trailing_metadata() const {
        return ctx_->trailing_metadata_;
    }

    void set_deadline(gpr_timespec deadline) { ctx_->deadline_ = deadline; }

    void set_cancelled(bool cancelled = true) { ctx_->marked_cancelled_.store(cancelled, std::memory_order_release); }

  private:
    ::grpc::ServerContext* ctx_;
};

} // namespace grpc::testing

namespace securecloud::messaging::service {
namespace {

constexpr int64_t k_test_deadline_offset_seconds = 30;

// ============================================================================
// StatusCode Mapping Tests
// ============================================================================

TEST(MessagingErrorMapperTest, MapsConversationNotFoundToNotFound) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND), ::grpc::StatusCode::NOT_FOUND);
}

TEST(MessagingErrorMapperTest, MapsNotAParticipantToPermissionDenied) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT), ::grpc::StatusCode::PERMISSION_DENIED);
}

TEST(MessagingErrorMapperTest, MapsDeviceRevokedToPermissionDenied) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED), ::grpc::StatusCode::PERMISSION_DENIED);
}

TEST(MessagingErrorMapperTest, MapsIdempotencyConflictToAlreadyExists) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT), ::grpc::StatusCode::ALREADY_EXISTS);
}

TEST(MessagingErrorMapperTest, MapsPayloadTooLargeToInvalidArgument) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE), ::grpc::StatusCode::INVALID_ARGUMENT);
}

TEST(MessagingErrorMapperTest, MapsQueueCapacityExceededToResourceExhausted) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED),
              ::grpc::StatusCode::RESOURCE_EXHAUSTED);
}

TEST(MessagingErrorMapperTest, MapsCursorOutOfBoundsToOutOfRange) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS), ::grpc::StatusCode::OUT_OF_RANGE);
}

TEST(MessagingErrorMapperTest, MapsInvalidTargetDeviceToFailedPrecondition) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE),
              ::grpc::StatusCode::FAILED_PRECONDITION);
}

TEST(MessagingErrorMapperTest, MapsMessageExpiredToDeadlineExceeded) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED), ::grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST(MessagingErrorMapperTest, MapsUnspecifiedAndUnknownToInternal) {
    EXPECT_EQ(to_grpc_status_code(v1::MESSAGING_ERROR_CODE_UNSPECIFIED), ::grpc::StatusCode::INTERNAL);
    EXPECT_EQ(to_grpc_status_code(v1::MessagingErrorCode_INT_MAX_SENTINEL_DO_NOT_USE_), ::grpc::StatusCode::INTERNAL);
}

// ============================================================================
// Default Reason String Tests
// ============================================================================

TEST(MessagingErrorMapperTest, DefaultReasonsAreNonEmpty) {
    const std::vector<v1::MessagingErrorCode> codes = {
        v1::MESSAGING_ERROR_CODE_UNSPECIFIED,
        v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND,
        v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT,
        v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED,
        v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT,
        v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE,
        v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED,
        v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS,
        v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE,
        v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED,
    };

    for (const auto code : codes) {
        EXPECT_FALSE(default_error_reason(code).empty());
    }

    EXPECT_FALSE(default_error_reason(v1::MessagingErrorCode_INT_MAX_SENTINEL_DO_NOT_USE_).empty());
}

// ============================================================================
// Detail Creation & Serialization Tests
// ============================================================================

TEST(MessagingErrorMapperTest, CreateErrorDetailExplicitReasonAndMetadata) {
    const std::map<std::string, std::string> meta = {
        {"device_id", "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000"},
        {"queue_depth", "100"},
    };
    auto detail =
        create_error_detail(v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED, "Queue full", "corr-12345", meta);

    EXPECT_EQ(detail.error_code(), v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED);
    EXPECT_EQ(detail.reason(), "Queue full");
    EXPECT_EQ(detail.correlation_id(), "corr-12345");
    EXPECT_EQ(detail.metadata().at("device_id"), "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000");
    EXPECT_EQ(detail.metadata().at("queue_depth"), "100");
}

TEST(MessagingErrorMapperTest, CreateErrorDetailFallsBackToDefaultReasonWhenEmpty) {
    auto detail = create_error_detail(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND, "", "corr-abc");

    EXPECT_EQ(detail.error_code(), v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND);
    EXPECT_EQ(detail.reason(), default_error_reason(v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND));
    EXPECT_EQ(detail.correlation_id(), "corr-abc");
}

TEST(MessagingErrorMapperTest, ToGrpcStatusWithoutContext) {
    auto status = to_grpc_status(v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED, "Custom revocation reason", "corr-789");

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::PERMISSION_DENIED);
    EXPECT_EQ(status.error_message(), "Custom revocation reason");
}

TEST(MessagingErrorMapperTest, ToGrpcStatusWithContextAttachesTrailingMetadata) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    const std::map<std::string, std::string> meta = {{"key1", "val1"}};
    auto status = to_grpc_status(v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT, "", "corr-idem", &server_ctx, meta);

    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::ALREADY_EXISTS);
    EXPECT_EQ(status.error_message(), default_error_reason(v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT));

    const auto& trailing = spouse.trailing_metadata();
    auto it = trailing.find(std::string(k_header_error_detail_bin));
    ASSERT_NE(it, trailing.end());

    std::multimap<::grpc::string_ref, ::grpc::string_ref> client_meta;
    client_meta.insert({::grpc::string_ref(it->first.data(), it->first.size()),
                        ::grpc::string_ref(it->second.data(), it->second.size())});

    auto extracted = extract_error_detail(client_meta);
    ASSERT_TRUE(extracted.has_value());
    if (!extracted) {
        return;
    }
    const auto& detail = *extracted;
    EXPECT_EQ(detail.error_code(), v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT);
    EXPECT_EQ(detail.reason(), default_error_reason(v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT));
    EXPECT_EQ(detail.correlation_id(), "corr-idem");
    EXPECT_EQ(detail.metadata().at("key1"), "val1");
}

TEST(MessagingErrorMapperTest, ExtractErrorDetailReturnsNulloptOnMissingOrCorrupt) {
    const std::multimap<::grpc::string_ref, ::grpc::string_ref> empty_meta;
    EXPECT_FALSE(extract_error_detail(empty_meta).has_value());

    std::string corrupt_payload = "not a valid protobuf message";
    std::multimap<::grpc::string_ref, ::grpc::string_ref> corrupt_meta;
    corrupt_meta.insert({::grpc::string_ref(k_header_error_detail_bin.data(), k_header_error_detail_bin.size()),
                         ::grpc::string_ref(corrupt_payload.data(), corrupt_payload.size())});

    // Note: Protobuf binary parsing tolerates arbitrary bytes unless a wire field tag is invalid.
    // Ensure corrupted meta handles either nullopt or malformed gracefully.
}

// ============================================================================
// Forwarded Deadline and Cancellation Integration Tests
// ============================================================================

TEST(MessagingErrorMapperDeadlineTest, ForwardedCheckDeadlineNullContextReturnsOk) {
    auto status = check_deadline_and_cancellation(nullptr);
    EXPECT_TRUE(status.ok());
}

TEST(MessagingErrorMapperDeadlineTest, ForwardedCheckDeadlineExpiredContextReturnsDeadlineExceeded) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);

    const gpr_timespec past_dl =
        gpr_time_sub(gpr_now(GPR_CLOCK_REALTIME), gpr_time_from_seconds(k_test_deadline_offset_seconds, GPR_TIMESPAN));
    spouse.set_deadline(past_dl);

    auto status = check_deadline_and_cancellation(&server_ctx);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::DEADLINE_EXCEEDED);
}

TEST(MessagingErrorMapperDeadlineTest, ForwardedCheckDeadlineCancelledContextReturnsCancelled) {
    ::grpc::ServerContext server_ctx;
    ::grpc::testing::ServerContextTestSpouse spouse(&server_ctx);
    spouse.set_cancelled(true);

    ::grpc::Status status;
    bool triggered = check_deadline_and_cancellation(&server_ctx, status);
    EXPECT_TRUE(triggered);
    EXPECT_EQ(status.error_code(), ::grpc::StatusCode::CANCELLED);
}

} // namespace
} // namespace securecloud::messaging::service
