#pragma once

#include "securecloud/messaging/v1/messaging.pb.h"

#include <grpcpp/grpcpp.h>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securecloud::messaging::db {

/// Standardized error codes for ScyllaDB operations (ADR-009).
enum class ScyllaErrorCode {
    Success = 0,
    ConnectionError,
    Timeout,
    Overloaded,
    AlreadyExists,
    InvalidQuery,
    Unauthorized,
    InternalError
};

/// Canonical DomainErrorCode as defined by ADR-009 (Distributed Failure & Resilience).
enum class DomainErrorCode {
    Ok = 0,
    InvalidArgument,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Internal,
    Unavailable,
    DeadlineExceeded
};

/// Exception thrown on ScyllaDB query or connection failure.
class ScyllaException : public std::runtime_error {
  public:
    ScyllaException(ScyllaErrorCode code, const std::string& message) : std::runtime_error(message), code_(code) {}

    [[nodiscard]] ScyllaErrorCode error_code() const noexcept { return code_; }

  private:
    ScyllaErrorCode code_;
};

/// Translates ScyllaDB errors into canonical domain, protobuf, and gRPC error codes.
class ScyllaErrorMapper {
  public:
    /// Maps ScyllaErrorCode to canonical DomainErrorCode (ADR-009).
    [[nodiscard]] static DomainErrorCode to_domain_error_code(ScyllaErrorCode code) noexcept;

    /// Maps ScyllaErrorCode to domain MessagingErrorCode protobuf enum.
    [[nodiscard]] static v1::MessagingErrorCode to_messaging_error_code(ScyllaErrorCode code) noexcept;

    /// Maps ScyllaErrorCode directly to gRPC StatusCode.
    [[nodiscard]] static ::grpc::StatusCode to_grpc_status_code(ScyllaErrorCode code) noexcept;

    /// Maps DomainErrorCode to gRPC StatusCode.
    [[nodiscard]] static ::grpc::StatusCode to_grpc_status_code(DomainErrorCode code) noexcept;

    /// Translates an exception (or ScyllaException) into a DomainErrorCode.
    [[nodiscard]] static DomainErrorCode to_domain_error_code(const std::exception& ex) noexcept;

    /// Translates an exception (or ScyllaException) into a protobuf MessagingErrorCode.
    [[nodiscard]] static v1::MessagingErrorCode to_messaging_error_code(const std::exception& ex) noexcept;
};

} // namespace securecloud::messaging::db
