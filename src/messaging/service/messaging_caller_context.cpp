#include "service/messaging_caller_context.hpp"

#include <algorithm>
#include <cctype>

namespace securecloud::messaging::service {

namespace {

constexpr size_t k_min_idempotency_token_length = 16;
constexpr size_t k_max_idempotency_token_length = 64;

bool is_token_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
}

} // namespace

bool is_valid_idempotency_token(std::string_view token) noexcept {
    if (token.size() < k_min_idempotency_token_length || token.size() > k_max_idempotency_token_length) {
        return false;
    }

    return std::ranges::all_of(token, is_token_char);
}

MessagingCallerContext extract_messaging_caller_context(const ::grpc::ServerContext* context) {
    MessagingCallerContext result;
    if (!context) {
        return result;
    }

    result.base = common::rpc::extract_caller_context(context);

    const auto& metadata = context->client_metadata();
    for (const auto& [k, v] : metadata) {
        if (std::string_view(k.data(), k.size()) == k_header_idempotency_token) {
            result.idempotency_token.assign(v.data(), v.size());
            break;
        }
    }

    return result;
}

::grpc::Status validate_messaging_caller_context(const MessagingCallerContext& ctx, uint32_t requirements,
                                                 std::string& out_error_reason) {
    if ((requirements & kRequireAuthorizedPeer) != 0 && !common::rpc::is_authorized_service_peer(ctx.peer_identity())) {
        out_error_reason = "Unauthorized service peer identity: " + ctx.peer_identity();
        return {::grpc::StatusCode::PERMISSION_DENIED, out_error_reason};
    }

    if ((requirements & kRequireCorrelationId) != 0 &&
        (ctx.correlation_id().empty() || !common::rpc::is_valid_uuid(ctx.correlation_id()))) {
        out_error_reason = "Missing or invalid correlation ID header (expected RFC 4122 UUID)";
        return {::grpc::StatusCode::INVALID_ARGUMENT, out_error_reason};
    }

    if ((requirements & kRequireUserId) != 0 && (ctx.user_id().empty() || !common::rpc::is_valid_uuid(ctx.user_id()))) {
        out_error_reason = "Missing or invalid user ID header (expected RFC 4122 UUID)";
        return {::grpc::StatusCode::UNAUTHENTICATED, out_error_reason};
    }

    if ((requirements & kRequireDeviceId) != 0 &&
        (ctx.device_id().empty() || !common::rpc::is_valid_uuid(ctx.device_id()))) {
        out_error_reason = "Missing or invalid device ID header (expected RFC 4122 UUID)";
        return {::grpc::StatusCode::INVALID_ARGUMENT, out_error_reason};
    }

    if ((requirements & kRequireIdempotency) != 0 &&
        (ctx.idempotency_token.empty() || !is_valid_idempotency_token(ctx.idempotency_token))) {
        out_error_reason = "Missing or invalid idempotency token header (expected 16-64 chars [a-zA-Z0-9_-])";
        return {::grpc::StatusCode::INVALID_ARGUMENT, out_error_reason};
    }

    out_error_reason.clear();
    return ::grpc::Status::OK;
}

} // namespace securecloud::messaging::service
