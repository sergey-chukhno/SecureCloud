#include "messaging/db/scylla_error_mapper.hpp"

namespace securecloud::messaging::db {

DomainErrorCode ScyllaErrorMapper::to_domain_error_code(ScyllaErrorCode code) noexcept {
    switch (code) {
    case ScyllaErrorCode::Success:
        return DomainErrorCode::Ok;
    case ScyllaErrorCode::ConnectionError:
        return DomainErrorCode::Unavailable;
    case ScyllaErrorCode::Timeout:
        return DomainErrorCode::DeadlineExceeded;
    case ScyllaErrorCode::Overloaded:
        return DomainErrorCode::ResourceExhausted;
    case ScyllaErrorCode::AlreadyExists:
        return DomainErrorCode::AlreadyExists;
    case ScyllaErrorCode::InvalidQuery:
        return DomainErrorCode::InvalidArgument;
    case ScyllaErrorCode::Unauthorized:
        return DomainErrorCode::PermissionDenied;
    case ScyllaErrorCode::InternalError:
    default:
        return DomainErrorCode::Internal;
    }
}

v1::MessagingErrorCode ScyllaErrorMapper::to_messaging_error_code(ScyllaErrorCode code) noexcept {
    switch (code) {
    case ScyllaErrorCode::Success:
        return v1::MessagingErrorCode::MESSAGING_ERROR_CODE_UNSPECIFIED;
    case ScyllaErrorCode::Overloaded:
        return v1::MessagingErrorCode::MESSAGING_ERROR_CODE_QUEUE_CAPACITY_EXCEEDED;
    case ScyllaErrorCode::AlreadyExists:
        return v1::MessagingErrorCode::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT;
    case ScyllaErrorCode::ConnectionError:
    case ScyllaErrorCode::Timeout:
    case ScyllaErrorCode::InvalidQuery:
    case ScyllaErrorCode::Unauthorized:
    case ScyllaErrorCode::InternalError:
    default:
        return v1::MessagingErrorCode::MESSAGING_ERROR_CODE_UNSPECIFIED;
    }
}

::grpc::StatusCode ScyllaErrorMapper::to_grpc_status_code(ScyllaErrorCode code) noexcept {
    return to_grpc_status_code(to_domain_error_code(code));
}

::grpc::StatusCode ScyllaErrorMapper::to_grpc_status_code(DomainErrorCode code) noexcept {
    switch (code) {
    case DomainErrorCode::Ok:
        return ::grpc::StatusCode::OK;
    case DomainErrorCode::InvalidArgument:
        return ::grpc::StatusCode::INVALID_ARGUMENT;
    case DomainErrorCode::NotFound:
        return ::grpc::StatusCode::NOT_FOUND;
    case DomainErrorCode::AlreadyExists:
        return ::grpc::StatusCode::ALREADY_EXISTS;
    case DomainErrorCode::PermissionDenied:
        return ::grpc::StatusCode::PERMISSION_DENIED;
    case DomainErrorCode::ResourceExhausted:
        return ::grpc::StatusCode::RESOURCE_EXHAUSTED;
    case DomainErrorCode::FailedPrecondition:
        return ::grpc::StatusCode::FAILED_PRECONDITION;
    case DomainErrorCode::Aborted:
        return ::grpc::StatusCode::ABORTED;
    case DomainErrorCode::OutOfRange:
        return ::grpc::StatusCode::OUT_OF_RANGE;
    case DomainErrorCode::Unavailable:
        return ::grpc::StatusCode::UNAVAILABLE;
    case DomainErrorCode::DeadlineExceeded:
        return ::grpc::StatusCode::DEADLINE_EXCEEDED;
    case DomainErrorCode::Internal:
    default:
        return ::grpc::StatusCode::INTERNAL;
    }
}

DomainErrorCode ScyllaErrorMapper::to_domain_error_code(const std::exception& ex) noexcept {
    if (const auto* scylla_ex = dynamic_cast<const ScyllaException*>(&ex)) {
        return to_domain_error_code(scylla_ex->error_code());
    }
    return DomainErrorCode::Internal;
}

v1::MessagingErrorCode ScyllaErrorMapper::to_messaging_error_code(const std::exception& ex) noexcept {
    if (const auto* scylla_ex = dynamic_cast<const ScyllaException*>(&ex)) {
        return to_messaging_error_code(scylla_ex->error_code());
    }
    return v1::MessagingErrorCode::MESSAGING_ERROR_CODE_UNSPECIFIED;
}

} // namespace securecloud::messaging::db
