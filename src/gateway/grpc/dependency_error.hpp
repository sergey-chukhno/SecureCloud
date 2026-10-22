#pragma once

#include <grpcpp/support/status.h>
#include <grpcpp/support/status_code_enum.h>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace securecloud::gateway::grpc {

enum class DependencyErrorKind {
    Ok,
    Timeout,            // DEADLINE_EXCEEDED
    ServiceUnavailable, // UNAVAILABLE
    Unauthenticated,    // UNAUTHENTICATED
    PermissionDenied,   // PERMISSION_DENIED
    InvalidArgument,    // INVALID_ARGUMENT
    NotFound,           // NOT_FOUND
    Internal            // INTERNAL or other unmapped codes
};

struct DependencyError {
    DependencyErrorKind kind{DependencyErrorKind::Internal};
    std::string message;
    ::grpc::StatusCode grpc_code{::grpc::StatusCode::UNKNOWN};

    [[nodiscard]] static DependencyError from_grpc_status(const ::grpc::Status& status) {
        DependencyErrorKind kind = DependencyErrorKind::Internal;
        switch (status.error_code()) {
        case ::grpc::StatusCode::OK:
            kind = DependencyErrorKind::Ok;
            break;
        case ::grpc::StatusCode::DEADLINE_EXCEEDED:
            kind = DependencyErrorKind::Timeout;
            break;
        case ::grpc::StatusCode::UNAVAILABLE:
            kind = DependencyErrorKind::ServiceUnavailable;
            break;
        case ::grpc::StatusCode::UNAUTHENTICATED:
            kind = DependencyErrorKind::Unauthenticated;
            break;
        case ::grpc::StatusCode::PERMISSION_DENIED:
            kind = DependencyErrorKind::PermissionDenied;
            break;
        case ::grpc::StatusCode::INVALID_ARGUMENT:
            kind = DependencyErrorKind::InvalidArgument;
            break;
        case ::grpc::StatusCode::NOT_FOUND:
            kind = DependencyErrorKind::NotFound;
            break;
        default:
            kind = DependencyErrorKind::Internal;
            break;
        }

        return DependencyError{
            .kind = kind,
            .message = status.error_message().empty() ? "Dependency RPC call failed" : status.error_message(),
            .grpc_code = status.error_code(),
        };
    }
};

template <typename T, typename E = DependencyError> class Result {
  public:
    Result(T val) : storage_(std::move(val)) {}
    Result(E err) : storage_(std::move(err)) {}

    [[nodiscard]] bool has_value() const noexcept { return std::holds_alternative<T>(storage_); }
    [[nodiscard]] bool has_error() const noexcept { return std::holds_alternative<E>(storage_); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] const T& value() const& { return std::get<T>(storage_); }
    [[nodiscard]] T& value() & { return std::get<T>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(storage_)); }

    [[nodiscard]] const E& error() const& { return std::get<E>(storage_); }
    [[nodiscard]] E& error() & { return std::get<E>(storage_); }
    [[nodiscard]] E&& error() && { return std::get<E>(std::move(storage_)); }

  private:
    std::variant<T, E> storage_;
};

} // namespace securecloud::gateway::grpc
