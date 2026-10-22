#pragma once

#include "securecloud/grpc/caller_context.hpp"

#include <cstdint>
#include <grpcpp/grpcpp.h>
#include <string>
#include <string_view>

namespace securecloud::messaging::service {

/// Canonical gRPC metadata header key for client idempotency tokens
inline constexpr std::string_view k_header_idempotency_token = "x-idempotency-token";

/// Validates whether a client-supplied idempotency token conforms to the required specification:
/// 16 to 64 ASCII characters from [a-zA-Z0-9_-]
[[nodiscard]] bool is_valid_idempotency_token(std::string_view token) noexcept;

/// Messaging-specific caller context wrapping common CallerContext and adding domain idempotency
struct MessagingCallerContext {
    common::rpc::CallerContext base;
    std::string idempotency_token;

    [[nodiscard]] const std::string& user_id() const noexcept { return base.user_id; }
    [[nodiscard]] const std::string& device_id() const noexcept { return base.device_id; }
    [[nodiscard]] const std::string& correlation_id() const noexcept { return base.correlation_id; }
    [[nodiscard]] const std::string& peer_identity() const noexcept { return base.peer_identity; }
};

/// Bitmask flags for declarative context requirement validation
enum ContextRequirement : uint32_t {
    kRequireNone = 0,
    kRequireUserId = 1 << 0,
    kRequireDeviceId = 1 << 1,
    kRequireCorrelationId = 1 << 2,
    kRequireIdempotency = 1 << 3,
    kRequireAuthorizedPeer = 1 << 4,
};

/// Extracts MessagingCallerContext from incoming gRPC ServerContext
[[nodiscard]] MessagingCallerContext extract_messaging_caller_context(const ::grpc::ServerContext* context);

/// Validates MessagingCallerContext against required flags, returning canonical gRPC Status
/// and setting out_error_reason if validation fails.
[[nodiscard]] ::grpc::Status validate_messaging_caller_context(const MessagingCallerContext& ctx, uint32_t requirements,
                                                               std::string& out_error_reason);

} // namespace securecloud::messaging::service
