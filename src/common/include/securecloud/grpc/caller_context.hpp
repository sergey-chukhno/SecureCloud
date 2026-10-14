#pragma once

#include <grpcpp/server_context.h>
#include <string>
#include <string_view>

namespace securecloud::common::rpc {

/// Canonical gRPC metadata header keys (ASCII lowercase per HTTP/2 specification)
inline constexpr std::string_view k_header_correlation_id = "x-correlation-id";
inline constexpr std::string_view k_header_request_id = "x-request-id"; // Fallback trace ID
inline constexpr std::string_view k_header_user_id = "x-user-id";
inline constexpr std::string_view k_header_device_id = "x-device-id";

/// Validates whether a string matches canonical RFC 4122 UUID format:
/// 36 characters, hexadecimal, with hyphens at indices 8, 13, 18, 23
/// Example: "0191ec4d-91b4-7b4d-b6a9-8e41e3d36000"
[[nodiscard]] bool is_valid_uuid(std::string_view id) noexcept;

/// Generic caller context extracted from incoming gRPC ServerContext and mTLS peer credentials
struct CallerContext {
    std::string user_id;
    std::string device_id;
    std::string correlation_id;
    std::string peer_identity{"anonymous"}; // Extracted from mTLS SAN (e.g. "gateway", "auth")
};

/// Extracts CallerContext from a gRPC ServerContext's client_metadata and auth_context
[[nodiscard]] CallerContext extract_caller_context(const ::grpc::ServerContext* context);

/// Extracts peer SAN identity from mTLS auth_context
[[nodiscard]] std::string extract_peer_identity(const ::grpc::AuthContext* auth_context);

/// Verifies whether the peer SAN identity matches an authorized SecureCloud internal service
/// (gateway, auth, messaging, files)
[[nodiscard]] bool is_authorized_service_peer(std::string_view peer_identity) noexcept;
[[nodiscard]] bool is_authorized_service_peer(const ::grpc::AuthContext* auth_context);
[[nodiscard]] bool is_authorized_service_peer(const ::grpc::ServerContext* context);

/// Checks if the server context has been cancelled by the client or if its deadline has expired.
/// Returns StatusCode::CANCELLED if cancelled, StatusCode::DEADLINE_EXCEEDED if deadline expired,
/// or Status::OK if the call remains active. If context is null, returns Status::OK.
[[nodiscard]] ::grpc::Status check_deadline_and_cancellation(const ::grpc::ServerContext* context);

/// Overload populating out_status and returning true if cancellation or deadline expiration was detected.
/// Returns false if active (with out_status set to Status::OK).
[[nodiscard]] bool check_deadline_and_cancellation(const ::grpc::ServerContext* context, ::grpc::Status& out_status);

} // namespace securecloud::common::rpc
