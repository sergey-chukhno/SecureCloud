#include "messaging_error_mapper.hpp"

namespace securecloud::messaging::service {

std::string_view default_error_reason(v1::MessagingErrorCode code) noexcept {
    switch (code) {
    case v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND:
        return "Conversation not found";
    case v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT:
        return "Caller is not a member of the conversation";
    case v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED:
        return "Target or calling device has been revoked";
    case v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT:
        return "Idempotency key reused with conflicting request payload";
    case v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE:
        return "Encrypted payload exceeds maximum permitted size";
    case v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED:
        return "Recipient device offline queue capacity exceeded";
    case v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS:
        return "Requested sequence cursor is out of bounds";
    case v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE:
        return "Target device not registered for recipient";
    case v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED:
        return "Message TTL expired before delivery";
    case v1::MESSAGING_ERROR_CODE_UNSPECIFIED:
    default:
        return "Internal messaging service error";
    }
}

::grpc::StatusCode to_grpc_status_code(v1::MessagingErrorCode code) noexcept {
    switch (code) {
    case v1::MESSAGING_ERROR_CODE_CONVERSATION_NOT_FOUND:
        return ::grpc::StatusCode::NOT_FOUND;
    case v1::MESSAGING_ERROR_CODE_NOT_A_PARTICIPANT:
        [[fallthrough]];
    case v1::MESSAGING_ERROR_CODE_DEVICE_REVOKED:
        return ::grpc::StatusCode::PERMISSION_DENIED;
    case v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT:
        return ::grpc::StatusCode::ALREADY_EXISTS;
    case v1::MESSAGING_ERROR_CODE_PAYLOAD_TOO_LARGE:
        return ::grpc::StatusCode::INVALID_ARGUMENT;
    case v1::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED:
        return ::grpc::StatusCode::RESOURCE_EXHAUSTED;
    case v1::MESSAGING_ERROR_CODE_CURSOR_OUT_OF_BOUNDS:
        return ::grpc::StatusCode::OUT_OF_RANGE;
    case v1::MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE:
        return ::grpc::StatusCode::FAILED_PRECONDITION;
    case v1::MESSAGING_ERROR_CODE_MESSAGE_EXPIRED:
        return ::grpc::StatusCode::DEADLINE_EXCEEDED;
    case v1::MESSAGING_ERROR_CODE_UNSPECIFIED:
    default:
        return ::grpc::StatusCode::INTERNAL;
    }
}

v1::MessagingErrorDetail create_error_detail(v1::MessagingErrorCode code, std::string_view reason,
                                             std::string_view correlation_id,
                                             const std::map<std::string, std::string>& metadata) {
    v1::MessagingErrorDetail detail;
    detail.set_error_code(code);
    detail.set_reason(reason.empty() ? std::string(default_error_reason(code)) : std::string(reason));
    detail.set_correlation_id(std::string(correlation_id));
    for (const auto& [k, v] : metadata) {
        (*detail.mutable_metadata())[k] = v;
    }
    return detail;
}

::grpc::Status to_grpc_status(v1::MessagingErrorCode code, std::string_view reason, std::string_view correlation_id,
                              ::grpc::ServerContext* context, const std::map<std::string, std::string>& metadata) {
    auto detail = create_error_detail(code, reason, correlation_id, metadata);

    if (context != nullptr) {
        std::string serialized;
        if (detail.SerializeToString(&serialized)) {
            context->AddTrailingMetadata(std::string(k_header_error_detail_bin), serialized);
        }
    }

    ::grpc::StatusCode status_code = to_grpc_status_code(code);
    if (status_code == ::grpc::StatusCode::INTERNAL && !reason.empty()) {
        std::string lower;
        lower.reserve(reason.size());
        for (char c : reason) {
            lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        if (lower.find("direct conversation") != std::string::npos || lower.find("closed") != std::string::npos ||
            lower.find("inactive") != std::string::npos || lower.find("already an active") != std::string::npos) {
            status_code = ::grpc::StatusCode::FAILED_PRECONDITION;
        } else if (lower.find("admin") != std::string::npos || lower.find("permission") != std::string::npos ||
                   lower.find("not allowed") != std::string::npos) {
            status_code = ::grpc::StatusCode::PERMISSION_DENIED;
        }
    }

    std::string message = reason.empty() ? std::string(default_error_reason(code)) : std::string(reason);
    return {status_code, std::move(message)};
}

std::optional<v1::MessagingErrorDetail>
extract_error_detail(const std::multimap<::grpc::string_ref, ::grpc::string_ref>& trailing_metadata) {
    for (const auto& [key, val] : trailing_metadata) {
        if (std::string_view(key.data(), key.size()) == k_header_error_detail_bin) {
            v1::MessagingErrorDetail detail;
            if (detail.ParseFromArray(val.data(), static_cast<int>(val.size()))) {
                return detail;
            }
        }
    }
    return std::nullopt;
}

std::optional<v1::MessagingErrorDetail> extract_error_detail(const ::grpc::ClientContext& context) {
    return extract_error_detail(context.GetServerTrailingMetadata());
}

} // namespace securecloud::messaging::service
