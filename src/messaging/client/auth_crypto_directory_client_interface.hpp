#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"
#include "securecloud/auth/v1/auth.pb.h"

#include <chrono>
#include <cstdint>
#include <grpcpp/support/status.h>
#include <grpcpp/support/status_code_enum.h>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace securecloud::messaging::client {

/**
 * @brief Strongly-typed domain representation of a device's public cryptographic material.
 *
 * In accordance with ADR-008, this record contains exclusively public cryptographic material
 * managed by the Auth Service. Private keys are never present.
 */
struct DeviceCryptoRecord {
    domain::DeviceId device_id{};
    domain::UserId user_id{};
    std::vector<uint8_t> identity_key{};
    std::vector<uint8_t> signed_prekey{};
    std::vector<uint8_t> signed_prekey_signature{};
    std::vector<uint8_t> one_time_prekey{};
    std::string one_time_prekey_id{};
    securecloud::auth::v1::DeviceStatus status{securecloud::auth::v1::DEVICE_STATUS_UNSPECIFIED};
    std::string identity_key_fingerprint{};
    int64_t signed_prekey_created_at_epoch_ms{0};
    int32_t remaining_one_time_prekeys{0};

    auto operator<=>(const DeviceCryptoRecord& other) const noexcept = default;
    bool operator==(const DeviceCryptoRecord& other) const noexcept = default;
};

/**
 * @brief Classifies the failure mode when communicating with the Auth Service.
 */
enum class CryptoDirectoryErrorKind {
    Ok,
    Timeout,            // DEADLINE_EXCEEDED
    ServiceUnavailable, // UNAVAILABLE
    Unauthenticated,    // UNAUTHENTICATED
    PermissionDenied,   // PERMISSION_DENIED
    InvalidArgument,    // INVALID_ARGUMENT
    NotFound,           // NOT_FOUND
    Internal            // INTERNAL or other unmapped codes
};

/**
 * @brief Encapsulates dependency failure details for Auth Crypto Directory interactions.
 */
struct CryptoDirectoryError {
    CryptoDirectoryErrorKind kind{CryptoDirectoryErrorKind::Internal};
    std::string message{};
    ::grpc::StatusCode grpc_code{::grpc::StatusCode::UNKNOWN};

    [[nodiscard]] static CryptoDirectoryError from_grpc_status(const ::grpc::Status& status) {
        CryptoDirectoryErrorKind kind = CryptoDirectoryErrorKind::Internal;
        switch (status.error_code()) {
        case ::grpc::StatusCode::OK:
            kind = CryptoDirectoryErrorKind::Ok;
            break;
        case ::grpc::StatusCode::DEADLINE_EXCEEDED:
            kind = CryptoDirectoryErrorKind::Timeout;
            break;
        case ::grpc::StatusCode::UNAVAILABLE:
            kind = CryptoDirectoryErrorKind::ServiceUnavailable;
            break;
        case ::grpc::StatusCode::UNAUTHENTICATED:
            kind = CryptoDirectoryErrorKind::Unauthenticated;
            break;
        case ::grpc::StatusCode::PERMISSION_DENIED:
            kind = CryptoDirectoryErrorKind::PermissionDenied;
            break;
        case ::grpc::StatusCode::INVALID_ARGUMENT:
            kind = CryptoDirectoryErrorKind::InvalidArgument;
            break;
        case ::grpc::StatusCode::NOT_FOUND:
            kind = CryptoDirectoryErrorKind::NotFound;
            break;
        default:
            kind = CryptoDirectoryErrorKind::Internal;
            break;
        }

        return CryptoDirectoryError{
            .kind = kind,
            .message = status.error_message().empty() ? "Auth crypto directory RPC failed" : status.error_message(),
            .grpc_code = status.error_code(),
        };
    }
};

/**
 * @brief Generic monadic Result type for client operations.
 */
template <typename T, typename E = CryptoDirectoryError> class Result {
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

/**
 * @brief Authoritative Client Port interface for the Auth Service's public cryptographic directory.
 */
class IAuthCryptoDirectoryClient {
  public:
    virtual ~IAuthCryptoDirectoryClient() = default;

    /**
     * @brief Discovers public cryptographic records for all devices belonging to a user.
     *
     * @param user_id Canonical identifier of the user account.
     * @param timeout RPC deadline timeout.
     * @return List of public device crypto records, or error.
     */
    virtual Result<std::vector<DeviceCryptoRecord>, CryptoDirectoryError>
    get_user_device_crypto_records(const domain::UserId& user_id,
                                   std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) = 0;

    /**
     * @brief Retrieves public cryptographic material for a specific individual device.
     *
     * @param device_id Canonical identifier of the target device.
     * @param timeout RPC deadline timeout.
     * @return Public device crypto record, or error.
     */
    virtual Result<DeviceCryptoRecord, CryptoDirectoryError>
    get_device_crypto_identity(const domain::DeviceId& device_id,
                               std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) = 0;
};

} // namespace securecloud::messaging::client
